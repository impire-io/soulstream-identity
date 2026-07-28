package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

func testAgent(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	reg, err := registry.Open(filepath.Join(dir, "registry.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	srv := httptest.NewServer(New(v, reg, nil).Handler())
	t.Cleanup(srv.Close)

	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	return srv, accPub
}

func post(t *testing.T, srv *httptest.Server, path string, body any, wantStatus int, out any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	resp, err := http.Post(srv.URL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != wantStatus {
		var er map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&er)
		t.Fatalf("POST %s: status %d, want %d (%v)", path, resp.StatusCode, wantStatus, er)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("decode %s response: %v", path, err)
		}
	}
}

func TestAgentEndToEndOverHTTP(t *testing.T) {
	srv, accPub := testAgent(t)

	// Status.
	resp, err := http.Get(srv.URL + "/v1/status")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %v (%d)", err, resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Import an account signing key; the secret never comes back.
	askKP, _ := nkeys.CreateAccount()
	askSeed, _ := askKP.Seed()
	var imported struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		PublicKey string `json:"public_key"`
	}
	post(t, srv, "/v1/keys", map[string]string{
		"name": "acme/role", "kind": "nats-account-signing-key", "secret": string(askSeed),
	}, http.StatusCreated, &imported)
	if imported.PublicKey == "" || imported.Name != "acme/role" {
		t.Fatalf("import response: %+v", imported)
	}
	// Re-import conflicts.
	post(t, srv, "/v1/keys", map[string]string{
		"name": "acme/role", "kind": "nats-account-signing-key", "secret": string(askSeed),
	}, http.StatusConflict, nil)

	// Declare an identity, then mint for it.
	post(t, srv, "/v1/identities", map[string]any{
		"account": accPub, "user": "daan", "personas": []string{"daan"}, "role": "acme/role",
	}, http.StatusOK, nil)
	var minted struct {
		JWT           string `json:"jwt"`
		UserPublicKey string `json:"user_public_key"`
		Creds         string `json:"creds"`
	}
	post(t, srv, "/v1/mint", map[string]any{"account": accPub, "user": "daan"}, http.StatusOK, &minted)
	if minted.JWT == "" || minted.Creds != "" {
		t.Fatalf("mint: jwt empty or creds leaked without export_creds: %+v", minted)
	}

	// The minted user's key signs nonces via the oracle, and the signature
	// verifies against the returned public key.
	nonce := []byte("nonce-42")
	var signed struct {
		Sig string `json:"sig"`
	}
	post(t, srv, "/v1/sign/nonce", map[string]string{
		"key":   "user/" + accPub + "/daan",
		"nonce": base64.StdEncoding.EncodeToString(nonce),
	}, http.StatusOK, &signed)
	sig, err := base64.StdEncoding.DecodeString(signed.Sig)
	if err != nil {
		t.Fatalf("sig not base64: %v", err)
	}
	pub, err := nkeys.FromPublicKey(minted.UserPublicKey)
	if err != nil {
		t.Fatalf("public keypair: %v", err)
	}
	if err := pub.Verify(nonce, sig); err != nil {
		t.Fatalf("oracle signature does not verify: %v", err)
	}

	// Unknown key → 404; garbage body → 400.
	post(t, srv, "/v1/sign/nonce", map[string]string{
		"key": "missing", "nonce": base64.StdEncoding.EncodeToString(nonce),
	}, http.StatusNotFound, nil)
	post(t, srv, "/v1/mint", map[string]any{"account": "nope", "user": "daan"}, http.StatusBadRequest, nil)
}

func TestAgentCredsExportIsExplicit(t *testing.T) {
	srv, accPub := testAgent(t)
	askKP, _ := nkeys.CreateAccount()
	askSeed, _ := askKP.Seed()
	post(t, srv, "/v1/keys", map[string]string{
		"name": "acme/role", "kind": "nats-account-signing-key", "secret": string(askSeed),
	}, http.StatusCreated, nil)
	post(t, srv, "/v1/identities", map[string]any{
		"account": accPub, "user": "daan", "role": "acme/role",
	}, http.StatusOK, nil)

	var minted struct {
		Creds string `json:"creds"`
	}
	post(t, srv, "/v1/mint", map[string]any{
		"account": accPub, "user": "daan", "export_creds": true,
	}, http.StatusOK, &minted)
	if minted.Creds == "" {
		t.Fatal("explicit export returned no creds")
	}
}
