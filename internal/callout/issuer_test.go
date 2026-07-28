package callout

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

// harness: an issuer over a MemStore vault (role key + AUTH signing key), a
// registry with one identity, and a token store with one live token.
func harness(t *testing.T, calloutSeed string) (*Issuer, *MemTokenStore, string, string) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	roleKP, _ := nkeys.CreateAccount()
	roleSeed, _ := roleKP.Seed()
	if _, err := v.Import("acme/role", vault.KindNATSAccountSigningKey, string(roleSeed)); err != nil {
		t.Fatalf("import role: %v", err)
	}
	authKP, _ := nkeys.CreateAccount()
	authSeed, _ := authKP.Seed()
	authEntry, err := v.Import("auth/issuer", vault.KindNATSAccountSigningKey, string(authSeed))
	if err != nil {
		t.Fatalf("import auth key: %v", err)
	}
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	if err := reg.Put(registry.Identity{Account: accPub, User: "daan", Role: "acme/role"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	tokens := NewMemTokenStore()
	token, digest, err := NewToken()
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if err := tokens.Create(digest, Record{Account: accPub, User: "daan", Label: "test"}); err != nil {
		t.Fatalf("store token: %v", err)
	}
	iss, err := NewIssuer(v, reg, tokens, "auth/issuer", time.Minute, calloutSeed, nil)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss, tokens, token, authEntry.PublicKey
}

// request crafts a server-signed authorization request, as the NATS server
// would send it.
func request(t *testing.T, token string) (string, string, string) {
	t.Helper()
	serverKP, _ := nkeys.CreateServer()
	serverPub, _ := serverKP.PublicKey()
	userKP, _ := nkeys.CreateUser()
	userPub, _ := userKP.PublicKey()
	rc := jwt.NewAuthorizationRequestClaims(userPub)
	rc.UserNkey = userPub
	rc.Server = jwt.ServerID{Name: "test", ID: serverPub}
	rc.ConnectOptions.Token = token
	rc.ClientInformation.Host = "127.0.0.1"
	encoded, err := rc.Encode(serverKP)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	return encoded, userPub, serverPub
}

func decodeResponse(t *testing.T, data []byte) *jwt.AuthorizationResponseClaims {
	t.Helper()
	resp, err := jwt.DecodeAuthorizationResponseClaims(string(data))
	if err != nil {
		t.Fatalf("response does not decode: %v", err)
	}
	return resp
}

func TestValidTokenIsAdmittedScopedAndBounded(t *testing.T) {
	iss, _, token, authPub := harness(t, "")
	reqJWT, userPub, serverPub := request(t, token)

	out := iss.respond([]byte(reqJWT), "")
	if out == nil {
		t.Fatal("no response for a valid token")
	}
	resp := decodeResponse(t, out)
	if resp.Error != "" {
		t.Fatalf("refused: %s", resp.Error)
	}
	if resp.Issuer != authPub {
		t.Fatalf("response signed by %q, want the AUTH key %q", resp.Issuer, authPub)
	}
	if resp.Subject != userPub || resp.Audience != serverPub {
		t.Fatalf("response addressed to %q/%q, want %q/%q", resp.Subject, resp.Audience, userPub, serverPub)
	}
	uc, err := jwt.DecodeUserClaims(resp.Jwt)
	if err != nil {
		t.Fatalf("issued JWT does not decode: %v", err)
	}
	if uc.Subject != userPub {
		t.Fatalf("issued for %q, want the server-assigned key %q", uc.Subject, userPub)
	}
	if !uc.HasEmptyPermissions() {
		t.Fatal("issued JWT carries its own permissions")
	}
	if uc.Expires == 0 {
		t.Fatal("issued JWT is unbounded — the TTL is the revocation bound")
	}
	if uc.Name != "daan" {
		t.Fatalf("attribution lost: name %q", uc.Name)
	}
}

func TestRefusalsAreGenericOnTheWire(t *testing.T) {
	iss, tokens, token, _ := harness(t, "")

	reqJWT, _, _ := request(t, "sit_"+strings.Repeat("00", 32))
	resp := decodeResponse(t, iss.respond([]byte(reqJWT), ""))
	if resp.Error == "" || resp.Jwt != "" {
		t.Fatalf("unknown token must refuse, got %+v", resp)
	}
	if strings.Contains(resp.Error, "unknown token") {
		t.Fatalf("wire error leaks the refusal reason: %q", resp.Error)
	}

	// Revoke the live token: same generic refusal.
	if err := tokens.Delete(Digest(token)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	reqJWT2, _, _ := request(t, token)
	resp2 := decodeResponse(t, iss.respond([]byte(reqJWT2), ""))
	if resp2.Error == "" {
		t.Fatal("revoked token admitted")
	}

	// Garbage instead of a request JWT: no response at all (fail closed).
	if out := iss.respond([]byte("not-a-jwt-at-all"), ""); out != nil {
		t.Fatalf("garbage request drew a response: %s", out)
	}
}

func TestTokenExpiryIsHonored(t *testing.T) {
	iss, tokens, _, _ := harness(t, "")
	token, digest, _ := NewToken()
	rec := Record{Account: "ignored", User: "x", Expires: time.Now().Add(-time.Minute).Format(time.RFC3339)}
	if err := tokens.Create(digest, rec); err != nil {
		t.Fatalf("store: %v", err)
	}
	reqJWT, _, _ := request(t, token)
	resp := decodeResponse(t, iss.respond([]byte(reqJWT), ""))
	if resp.Error == "" {
		t.Fatal("expired token admitted")
	}
}

func TestSealedRequestsRoundTrip(t *testing.T) {
	calloutKP, _ := nkeys.CreateCurveKeys()
	calloutSeed, _ := calloutKP.Seed()
	calloutPub, _ := calloutKP.PublicKey()
	iss, _, token, _ := harness(t, string(calloutSeed))

	serverXKP, _ := nkeys.CreateCurveKeys()
	serverXPub, _ := serverXKP.PublicKey()
	reqJWT, userPub, _ := request(t, token)
	sealed, err := serverXKP.Seal([]byte(reqJWT), calloutPub)
	if err != nil {
		t.Fatalf("seal request: %v", err)
	}

	out := iss.respond(sealed, serverXPub)
	if out == nil {
		t.Fatal("no response to a sealed request")
	}
	if strings.HasPrefix(string(out), jwtPrefix) {
		t.Fatal("response to a sealed request is plaintext")
	}
	opened, err := serverXKP.Open(out, calloutPub)
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	resp := decodeResponse(t, opened)
	if resp.Error != "" || resp.Subject != userPub {
		t.Fatalf("sealed round-trip failed: %+v", resp)
	}

	// A sealed request on an issuer WITHOUT the callout key: no response.
	issPlain, _, token2, _ := harness(t, "")
	req2, _, _ := request(t, token2)
	sealed2, _ := serverXKP.Seal([]byte(req2), calloutPub)
	if out := issPlain.respond(sealed2, serverXPub); out != nil {
		t.Fatal("sealed request answered without a callout key")
	}
}
