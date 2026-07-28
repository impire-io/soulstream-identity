package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

// harness: a service over a MemStore vault and a registry with an admin, a
// persona-bearing user, and a persona-less user — all in one account.
func harness(t *testing.T) (*Service, string) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	for _, id := range []registry.Identity{
		{Account: accPub, User: "ops", Admin: true},
		{Account: accPub, User: "daan", Personas: []string{"daan"}, Role: "acme/role"},
		{Account: accPub, User: "mallory"},
	} {
		if err := reg.Put(id); err != nil {
			t.Fatalf("register %s: %v", id.User, err)
		}
	}
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()
	s, err := New(v, reg, string(surfaceSeed), nil)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return s, accPub
}

// call drives one sealed round-trip through respond, exactly as a client
// would: ephemeral curve key, sealed request, opened reply.
func call(t *testing.T, s *Service, account, user, op string, body, out any) error {
	t.Helper()
	var x xkeyResponse
	if err := json.Unmarshal(s.respond(Prefix+".xkey", nil), &x); err != nil {
		t.Fatalf("xkey discovery: %v", err)
	}
	eph, _ := nkeys.CreateCurveKeys()
	ephPub, _ := eph.PublicKey()
	plain, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	sealed, err := eph.Seal(plain, x.XKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	req := marshal(envelope{XKey: ephPub, Data: sealed})
	reply := s.respond(strings.Join([]string{Prefix, account, user, op}, "."), req)

	var env envelope
	if err := json.Unmarshal(reply, &env); err != nil || len(env.Data) == 0 {
		// Not an envelope: a plaintext refusal.
		var er errorResponse
		if jerr := json.Unmarshal(reply, &er); jerr == nil && er.Error != "" {
			return &wireError{er.Error}
		}
		t.Fatalf("reply is neither envelope nor error: %s", reply)
	}
	opened, err := eph.Open(env.Data, x.XKey)
	if err != nil {
		t.Fatalf("open reply: %v", err)
	}
	var er errorResponse
	if json.Unmarshal(opened, &er) == nil && er.Error != "" {
		return &wireError{er.Error}
	}
	if out != nil {
		if err := json.Unmarshal(opened, out); err != nil {
			t.Fatalf("decode reply: %v", err)
		}
	}
	return nil
}

type wireError struct{ msg string }

func (e *wireError) Error() string { return e.msg }

func TestOpenOpsArePlaintext(t *testing.T) {
	s, _ := harness(t)
	var st statusResponse
	if err := json.Unmarshal(s.respond(Prefix+".status", nil), &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	var x xkeyResponse
	if err := json.Unmarshal(s.respond(Prefix+".xkey", nil), &x); err != nil {
		t.Fatalf("xkey: %v", err)
	}
	if !strings.HasPrefix(x.XKey, "X") {
		t.Fatalf("xkey %q is not a curve public key", x.XKey)
	}
}

func TestAdminGateOnManagementOps(t *testing.T) {
	s, acc := harness(t)
	ukp, _ := nkeys.CreateUser()
	seed, _ := ukp.Seed()
	req := importKeyRequest{Name: "imported", Kind: string(vault.KindNATSUserKey), Secret: string(seed)}

	var entry vault.Entry
	if err := call(t, s, acc, "ops", "keys.import", req, &entry); err != nil {
		t.Fatalf("admin import: %v", err)
	}
	if err := call(t, s, acc, "daan", "keys.import", req, nil); err == nil ||
		!strings.Contains(err.Error(), "admin") {
		t.Fatalf("non-admin import must refuse naming admin, got %v", err)
	}
	if err := call(t, s, acc, "ghost", "keys.list", struct{}{}, nil); err == nil {
		t.Fatal("unregistered principal listed keys")
	}
	var keys keysResponse
	if err := call(t, s, acc, "ops", "keys.list", struct{}{}, &keys); err != nil {
		t.Fatalf("admin list: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].Name != "imported" {
		t.Fatalf("list: %+v", keys.Keys)
	}

	var ids identitiesResponse
	if err := call(t, s, acc, "ops", "identities.list", struct{}{}, &ids); err != nil {
		t.Fatalf("admin identities.list: %v", err)
	}
	if len(ids.Identities) != 3 {
		t.Fatalf("identities: %+v", ids.Identities)
	}
	if err := call(t, s, acc, "daan", "identities.put",
		registry.Identity{Account: acc, User: "evil", Admin: true}, nil); err == nil {
		t.Fatal("non-admin declared an identity")
	}
}

func TestActAsIsEnforced(t *testing.T) {
	s, acc := harness(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	personaSeed := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "persona/daan", Kind: string(vault.KindPersonaSigningKey), Secret: personaSeed,
	}, nil); err != nil {
		t.Fatalf("import persona key: %v", err)
	}

	canonical := base64.StdEncoding.EncodeToString([]byte("canonical-bytes"))
	var sig signRecordResponse
	if err := call(t, s, acc, "daan", "sign.record",
		signRecordRequest{Key: "persona/daan", Canonical: canonical}, &sig); err != nil {
		t.Fatalf("allowed act-as refused: %v", err)
	}
	if sig.Sig == "" {
		t.Fatal("empty signature")
	}

	// The gate: mallory is registered but not allowed the persona.
	if err := call(t, s, acc, "mallory", "sign.record",
		signRecordRequest{Key: "persona/daan", Canonical: canonical}, nil); err == nil ||
		!strings.Contains(err.Error(), "may not act as") {
		t.Fatalf("disallowed act-as must refuse, got %v", err)
	}
	// Keys outside the persona/ convention cannot sign records at all.
	if err := call(t, s, acc, "daan", "sign.record",
		signRecordRequest{Key: "imported", Canonical: canonical}, nil); err == nil {
		t.Fatal("non-persona key name accepted for record signing")
	}
}

func TestMintSelfOrAdmin(t *testing.T) {
	s, acc := harness(t)
	askKP, _ := nkeys.CreateAccount()
	askSeed, _ := askKP.Seed()
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "acme/role", Kind: string(vault.KindNATSAccountSigningKey), Secret: string(askSeed),
	}, nil); err != nil {
		t.Fatalf("import signing key: %v", err)
	}

	var res mintResponse
	if err := call(t, s, acc, "daan", "mint",
		mintRequest{Account: acc, User: "daan"}, &res); err != nil {
		t.Fatalf("self-mint: %v", err)
	}
	if _, err := jwt.DecodeUserClaims(res.JWT); err != nil {
		t.Fatalf("minted JWT does not decode: %v", err)
	}

	if err := call(t, s, acc, "mallory", "mint",
		mintRequest{Account: acc, User: "daan"}, nil); err == nil {
		t.Fatal("non-admin minted for another identity")
	}
	var forOther mintResponse
	if err := call(t, s, acc, "ops", "mint",
		mintRequest{Account: acc, User: "daan", ExportCreds: true}, &forOther); err != nil {
		t.Fatalf("admin mint for other: %v", err)
	}
	if !strings.Contains(forOther.Creds, "-----BEGIN USER NKEY SEED-----") {
		t.Fatal("creds escape did not render a creds file")
	}
}

func TestMalformedRequestsRefusePlaintext(t *testing.T) {
	s, acc := harness(t)
	reply := s.respond(strings.Join([]string{Prefix, acc, "daan", "mint"}, "."), []byte("not-json"))
	var er errorResponse
	if err := json.Unmarshal(reply, &er); err != nil || er.Error == "" {
		t.Fatalf("malformed request must draw a plaintext error, got %s", reply)
	}
	if err := call(t, s, acc, "daan", "no.such.op", struct{}{}, nil); err == nil ||
		!strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("unknown op: %v", err)
	}
	var er2 errorResponse
	if err := json.Unmarshal(s.respond(Prefix+".nope", nil), &er2); err != nil || er2.Error == "" {
		t.Fatal("unknown open subject must draw an error")
	}
}
