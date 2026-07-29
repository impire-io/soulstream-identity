package callout

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/oidcstub"
	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

// auditBuf captures the issuer's audit log for reason assertions.
type auditBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (a *auditBuf) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.b.Write(p)
}

func (a *auditBuf) String() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.b.String()
}

// oidcHarness: an issuer with the eyJ lane enabled against a live stub, two
// declared teams (engineering, platform) in different accounts, and the
// AUTH signing key. Returns the issuer, the stub, the audit buffer, and
// engineering's bound account.
func oidcHarness(t *testing.T) (*Issuer, *oidcstub.Stub, *auditBuf, string) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	engAccKP, _ := nkeys.CreateAccount()
	engAccPub, _ := engAccKP.PublicKey()
	engKP, _ := nkeys.CreateAccount()
	engSeed, _ := engKP.Seed()
	if _, err := v.Import("engineering", vault.KindNATSAccountSigningKey, string(engSeed), engAccPub); err != nil {
		t.Fatalf("import engineering: %v", err)
	}
	platAccKP, _ := nkeys.CreateAccount()
	platAccPub, _ := platAccKP.PublicKey()
	platKP, _ := nkeys.CreateAccount()
	platSeed, _ := platKP.Seed()
	if _, err := v.Import("platform", vault.KindNATSAccountSigningKey, string(platSeed), platAccPub); err != nil {
		t.Fatalf("import platform: %v", err)
	}
	authAccKP, _ := nkeys.CreateAccount()
	authAccPub, _ := authAccKP.PublicKey()
	authKP, _ := nkeys.CreateAccount()
	authSeed, _ := authKP.Seed()
	if _, err := v.Import("auth/issuer", vault.KindNATSAccountSigningKey, string(authSeed), authAccPub); err != nil {
		t.Fatalf("import auth key: %v", err)
	}
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	stub, err := oidcstub.New("soulidentity-test-client")
	if err != nil {
		t.Fatalf("stub: %v", err)
	}
	t.Cleanup(stub.Close)
	val, err := NewOIDCValidator(context.Background(), stub.Issuer(), stub.ClientID())
	if err != nil {
		t.Fatalf("oidc validator: %v", err)
	}
	audit := &auditBuf{}
	iss, err := NewIssuer(v, reg, NewMemTokenStore(), "auth/issuer", time.Minute, "",
		slog.New(slog.NewTextHandler(audit, nil)), WithOIDC(val))
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return iss, stub, audit, engAccPub
}

func respondWith(t *testing.T, iss *Issuer, credential string) *jwt.AuthorizationResponseClaims {
	t.Helper()
	reqJWT, _, _ := request(t, credential)
	out := iss.respond([]byte(reqJWT), "")
	if out == nil {
		t.Fatal("no response bytes")
	}
	return decodeResponse(t, out)
}

func TestOIDCAdmissionDelegatedAndAppOnly(t *testing.T) {
	iss, stub, audit, engAccPub := oidcHarness(t)

	// Delegated (human): preferred_username present — logged, never keyed.
	claims := stub.Claims("11111111-aaaa-bbbb-cccc-000000000001", "engineering")
	claims["preferred_username"] = "daan@example.com"
	token, err := stub.Token(claims)
	if err != nil {
		t.Fatalf("stub token: %v", err)
	}
	resp := respondWith(t, iss, token)
	if resp.Error != "" {
		t.Fatalf("refused: %s\naudit:\n%s", resp.Error, audit.String())
	}
	uc, err := jwt.DecodeUserClaims(resp.Jwt)
	if err != nil {
		t.Fatalf("issued JWT does not decode: %v", err)
	}
	if uc.Name != "11111111-aaaa-bbbb-cccc-000000000001" {
		t.Fatalf("subject keyed on %q, want the oid (FR-007)", uc.Name)
	}
	if uc.IssuerAccount != engAccPub {
		t.Fatalf("issuer account %q, want the team's binding %q", uc.IssuerAccount, engAccPub)
	}
	if !uc.HasEmptyPermissions() {
		t.Fatal("claims-path JWT carries its own permissions")
	}
	if uc.Expires == 0 {
		t.Fatal("claims-path JWT is unbounded")
	}
	for _, want := range []string{"lane=oidc", "team=engineering",
		"subject=11111111-aaaa-bbbb-cccc-000000000001", "display=daan@example.com"} {
		if !strings.Contains(audit.String(), want) {
			t.Fatalf("attribution %q missing from audit:\n%s", want, audit.String())
		}
	}

	// App-only (service principal): no preferred_username — still admitted,
	// display recorded as absent (FR-013).
	appOnly, err := stub.Token(stub.Claims("22222222-aaaa-bbbb-cccc-000000000002", "engineering"))
	if err != nil {
		t.Fatalf("app-only token: %v", err)
	}
	resp2 := respondWith(t, iss, appOnly)
	if resp2.Error != "" {
		t.Fatalf("app-only refused: %s", resp2.Error)
	}
	if !strings.Contains(audit.String(), "display=-") {
		t.Fatalf("app-only display not recorded as absent:\n%s", audit.String())
	}
}

func TestOIDCRefusalMatrix(t *testing.T) {
	iss, stub, audit, _ := oidcHarness(t)
	oid := "33333333-aaaa-bbbb-cccc-000000000003"

	expired := stub.Claims(oid, "engineering")
	expired["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	expired["nbf"] = expired["iat"]
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	wrongAud := stub.Claims(oid, "engineering")
	wrongAud["aud"] = "some-other-app"
	wrongIss := stub.Claims(oid, "engineering")
	wrongIss["iss"] = "https://evil.example/v2.0"

	rows := []struct {
		name   string
		mint   func() (string, error)
		reason string // must land in the audit, never on the wire
	}{
		{"wrong audience", func() (string, error) { return stub.Token(wrongAud) }, "audience"},
		{"expired", func() (string, error) { return stub.Token(expired) }, "expired"},
		{"bad signature", func() (string, error) { return stub.TokenBadKey(stub.Claims(oid, "engineering")) }, "oidc token rejected"},
		{"wrong issuer", func() (string, error) { return stub.Token(wrongIss) }, "different provider"},
		{"roles absent", func() (string, error) { return stub.Token(stub.Claims(oid)) }, "no roles claim"},
		{"no declared team", func() (string, error) { return stub.Token(stub.Claims(oid, "marketing")) }, "no declared team"},
		{"ambiguous teams", func() (string, error) { return stub.Token(stub.Claims(oid, "engineering", "platform")) }, "ambiguous"},
		{"alg HS256", func() (string, error) { return stub.TokenAlg("HS256", stub.Claims(oid, "engineering")) }, "oidc token rejected"},
		{"alg none", func() (string, error) { return stub.TokenAlg("none", stub.Claims(oid, "engineering")) }, "oidc token rejected"},
	}
	for _, row := range rows {
		token, err := row.mint()
		if err != nil {
			t.Fatalf("%s: mint: %v", row.name, err)
		}
		resp := respondWith(t, iss, token)
		if resp.Error == "" || resp.Jwt != "" {
			t.Fatalf("%s: admitted", row.name)
		}
		// Generic on the wire (D20): never the specific reason.
		if resp.Error != "credential rejected" && resp.Error != "identity not authorized" {
			t.Fatalf("%s: wire error leaks the reason: %q", row.name, resp.Error)
		}
		if !strings.Contains(audit.String(), row.reason) {
			t.Fatalf("%s: specific reason %q not in audit:\n%s", row.name, row.reason, audit.String())
		}
	}
}

func TestOIDCKeyInfrastructureFailsClosedAndRotates(t *testing.T) {
	iss, stub, _, _ := oidcHarness(t)
	oid := "44444444-aaaa-bbbb-cccc-000000000004"

	// JWKS down before any key was ever fetched: refusal, never admission.
	stub.SetJWKSDown(true)
	token, err := stub.Token(stub.Claims(oid, "engineering"))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if resp := respondWith(t, iss, token); resp.Error == "" {
		t.Fatal("admitted while the JWKS was unreachable")
	}
	// Endpoint restored: the same validator recovers without any restart.
	stub.SetJWKSDown(false)
	if resp := respondWith(t, iss, token); resp.Error != "" {
		t.Fatalf("refused after JWKS restored: %s", resp.Error)
	}

	// Provider key rotation: a token under the new key admits because the
	// verifier refetches on an unknown kid — no process restart (SC-004).
	if err := stub.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	rotated, err := stub.Token(stub.Claims(oid, "engineering"))
	if err != nil {
		t.Fatalf("rotated token: %v", err)
	}
	if resp := respondWith(t, iss, rotated); resp.Error != "" {
		t.Fatalf("refused after key rotation: %s", resp.Error)
	}
}

func TestOIDCDispatchGuards(t *testing.T) {
	// The plain harness has no OIDC lane: eyJ refuses early with the lane
	// reason — no token-store lookup is attempted (FR-005/US4).
	iss, _, token, _ := harness(t, "")
	fakeJWT := "eyJhbGciOiJSUzI1NiJ9.e30.sig"
	reqJWT, _, _ := request(t, fakeJWT)
	resp := decodeResponse(t, iss.respond([]byte(reqJWT), ""))
	if resp.Error == "" {
		t.Fatal("eyJ credential admitted with no OIDC lane configured")
	}

	// A credential of neither shape refuses.
	reqJWT2, _, _ := request(t, "credential-of-no-known-shape")
	if resp := decodeResponse(t, iss.respond([]byte(reqJWT2), "")); resp.Error == "" {
		t.Fatal("unknown credential shape admitted")
	}

	// The sit_ lane is untouched by dispatch: the harness token still admits.
	reqJWT3, _, _ := request(t, token)
	if resp := decodeResponse(t, iss.respond([]byte(reqJWT3), "")); resp.Error != "" {
		t.Fatalf("sit_ lane regressed: %s", resp.Error)
	}

	// The issuer's own AUTH signing key is infrastructure, never a team.
	oidcIss, stub, audit, _ := oidcHarness(t)
	tok, err := stub.Token(stub.Claims("55555555-aaaa-bbbb-cccc-000000000005", "auth/issuer"))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if resp := respondWith(t, oidcIss, tok); resp.Error == "" {
		t.Fatal("the AUTH signing key was resolved as a team")
	}
	if !strings.Contains(audit.String(), "no declared team") {
		t.Fatalf("auth-key role value not treated as undeclared:\n%s", audit.String())
	}
}
