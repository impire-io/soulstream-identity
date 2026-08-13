package client_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/internal/callout"
	"github.com/impire-io/soulstream-identity/internal/oidcstub"
	"github.com/impire-io/soulstream-identity/internal/service"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

// TestM4GateAgainstOperatorModeServer is auth callout's end-to-end proof
// [measured] — the M4 gate (../soul-hq/02-DESIGN/soulstream-identity/auth-callout.md): SoulIdentity as
// the callout issuer on a dedicated AUTH account (D21, xkey-sealed
// requests), a client holding only a sentinel creds file and an API token
// (D19), admitted with server-enforced scoped permissions and attributable
// in the audit log (D20/D22); the creds-file bypass verified natively with
// the issuer out of the path (D12); invalid and revoked tokens refused.
func TestM4GateAgainstOperatorModeServer(t *testing.T) {
	// --- The realm: operator, SYS, AUTH (external authorization + xkey),
	// APP (JetStream + a scoped signing key for issued users).
	opKP, _ := nkeys.CreateOperator()
	opPub, _ := opKP.PublicKey()
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()
	authKP, _ := nkeys.CreateAccount()
	authPub, _ := authKP.PublicKey()
	appKP, _ := nkeys.CreateAccount()
	appPub, _ := appKP.PublicKey()
	roleKP, _ := nkeys.CreateAccount()
	rolePub, _ := roleKP.PublicKey()
	roleSeed, _ := roleKP.Seed()
	// The AUTH signing key SoulIdentity holds: a signing key of AUTH, not
	// its master (D21 custody).
	authSKKP, _ := nkeys.CreateAccount()
	authSKPub, _ := authSKKP.PublicKey()
	authSKSeed, _ := authSKKP.Seed()
	// The callout xkey: requests sealed to the issuer (the D21 leg).
	calloutKP, _ := nkeys.CreateCurveKeys()
	calloutPub, _ := calloutKP.PublicKey()
	calloutSeed, _ := calloutKP.Seed()

	oc := jwt.NewOperatorClaims(opPub)
	oc.Name = "e2e-operator"
	opJWT, err := oc.Encode(opKP)
	if err != nil {
		t.Fatalf("operator jwt: %v", err)
	}
	sc := jwt.NewAccountClaims(sysPub)
	sc.Name = "SYS"
	sysJWT, err := sc.Encode(opKP)
	if err != nil {
		t.Fatalf("system account jwt: %v", err)
	}

	issuerUserKP, _ := nkeys.CreateUser()
	issuerUserPub, _ := issuerUserKP.PublicKey()
	authClaim := jwt.NewAccountClaims(authPub)
	authClaim.Name = "AUTH"
	authClaim.SigningKeys.Add(authSKPub)
	authClaim.EnableExternalAuthorization(issuerUserPub)
	authClaim.Authorization.AllowedAccounts.Add(appPub)
	authClaim.Authorization.XKey = calloutPub
	authJWT, err := authClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("auth account jwt: %v", err)
	}

	appClaim := jwt.NewAccountClaims(appPub)
	appClaim.Name = "APP"
	appClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	scope := jwt.NewUserScope()
	scope.Key = rolePub
	scope.Role = "external-user"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList{"demo.>"}},
			Sub: jwt.Permission{Allow: jwt.StringList{"demo.>", "_INBOX.>"}},
		},
	}
	appClaim.SigningKeys.AddScopedSigner(scope)
	appJWT, err := appClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("app account jwt: %v", err)
	}

	cfg := fmt.Sprintf(`
listen: 127.0.0.1:-1
operator: %s
system_account: %s
resolver: MEMORY
resolver_preload: {
  %s: %s,
  %s: %s,
  %s: %s,
}
jetstream { store_dir: %q }
`, opJWT, sysPub, sysPub, sysJWT, authPub, authJWT, appPub, appJWT, t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	opts, err := natsserver.ProcessConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("process config: %v", err)
	}
	opts.NoLog, opts.NoSigs = true, true
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}

	// Operator-issued bootstrap users: the service (APP, unrestricted), the
	// first admin (APP, own prefix), the issuer (AUTH, in auth_users).
	serviceCreds := issueUser(t, appKP, "service", nil)
	adminCreds := issueUser(t, appKP, "ops", &jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			"identity.status", "identity.xkey", "identity." + appPub + ".ops.>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
	})
	issuerJWT, err := jwt.NewUserClaims(issuerUserPub).Encode(authKP)
	if err != nil {
		t.Fatalf("issuer user jwt: %v", err)
	}
	issuerSeed, _ := issuerUserKP.Seed()
	issuerCredsBytes, err := jwt.FormatUserConfig(issuerJWT, issuerSeed)
	if err != nil {
		t.Fatalf("issuer creds: %v", err)
	}
	issuerCreds := filepath.Join(t.TempDir(), "issuer.creds")
	if err := os.WriteFile(issuerCreds, issuerCredsBytes, 0o600); err != nil {
		t.Fatalf("write issuer creds: %v", err)
	}

	// --- The service: vault + token store on APP's JetStream, the surface
	// on the APP connection, the issuer on the AUTH connection (D21). No
	// registry (D25): the token record names the identity, the role binding
	// authorizes it, and the operator's creds ARE the admin declaration.
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()

	ncService, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(serviceCreds))
	if err != nil {
		t.Fatalf("service connect: %v", err)
	}
	t.Cleanup(ncService.Close)
	js, err := jetstream.New(ncService)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	vaultKV, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "SOULIDENTITY_VAULT"})
	if err != nil {
		t.Fatalf("vault bucket: %v", err)
	}
	tokensKV, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "SOULIDENTITY_TOKENS"})
	if err != nil {
		t.Fatalf("token bucket: %v", err)
	}
	v, err := vault.New(vault.NewKVStore(vaultKV), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	store := callout.NewKVTokenStore(tokensKV)

	audit := &syncBuffer{}
	logger := newAuditLogger(audit)
	svc, err := service.New(v, string(surfaceSeed), logger,
		service.WithCallout(store, "auth/issuer", authPub))
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	if _, err := svc.Start(ncService); err != nil {
		t.Fatalf("service start: %v", err)
	}

	ncIssuer, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(issuerCreds))
	if err != nil {
		t.Fatalf("issuer connect: %v", err)
	}
	t.Cleanup(ncIssuer.Close)
	issuer, err := callout.NewIssuer(v, store, "auth/issuer", 2*time.Minute, string(calloutSeed), logger)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	if _, err := issuer.Start(ncIssuer); err != nil {
		t.Fatalf("issuer start: %v", err)
	}
	if err := ncIssuer.Flush(); err != nil {
		t.Fatalf("issuer flush: %v", err)
	}

	// --- Admin provisions over the sealed surface: both signing keys enter
	// the vault; a token and the sentinel come out.
	ncAdmin, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(adminCreds))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(ncAdmin.Close)
	admin := client.New(ncAdmin, appPub, "ops")
	if _, err := admin.ImportKey("acme", client.KindNATSAccountSigningKey, string(roleSeed), appPub, ""); err != nil {
		t.Fatalf("import role key: %v", err)
	}
	if _, err := admin.ImportKey("auth/issuer", client.KindNATSAccountSigningKey, string(authSKSeed), authPub, ""); err != nil {
		t.Fatalf("import auth key: %v", err)
	}
	created, err := admin.CreateToken(appPub, "daan-ext", "daan laptop", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	sentinel, err := admin.MintSentinel()
	if err != nil {
		t.Fatalf("mint sentinel: %v", err)
	}
	sentinelCreds := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(sentinelCreds, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatalf("write sentinel creds: %v", err)
	}

	// The bypass proof's baseline [measured]: every connection so far —
	// service, issuer, admin — was creds-file verified by the server with
	// the issuer out of the path: no callout decision in the audit yet.
	if s := audit.String(); strings.Contains(s, "callout ADMITTED") || strings.Contains(s, "callout REFUSED") {
		t.Fatalf("a bypass-lane connection went through callout:\n%s", s)
	}

	// --- The gate: an external client holding only the sentinel creds and
	// the API token, admitted with server-enforced scoped permissions.
	violations := make(chan error, 8)
	ncExt, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(created.Token),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			violations <- err
		}))
	if err != nil {
		t.Fatalf("external client connect: %v\naudit:\n%s", err, audit.String())
	}
	t.Cleanup(ncExt.Close)
	sub, err := ncExt.SubscribeSync("demo.ping")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := ncExt.Publish("demo.ping", []byte("pong")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := sub.NextMsg(5 * time.Second); err != nil {
		t.Fatalf("in-scope round-trip: %v", err)
	}
	if err := ncExt.Publish("forbidden.subject", []byte("x")); err != nil {
		t.Fatalf("out-of-scope publish: %v", err)
	}
	_ = ncExt.Flush()
	select {
	case verr := <-violations:
		if !strings.Contains(strings.ToLower(verr.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got %v", verr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("out-of-scope publish drew no permission violation")
	}

	// Attribution [measured]: the external identity, its label, and the
	// admitting decision are in the audit log.
	if s := audit.String(); !strings.Contains(s, "callout ADMITTED") ||
		!strings.Contains(s, "daan-ext") || !strings.Contains(s, "daan laptop") {
		t.Fatalf("admission not attributable in the audit log:\n%s", s)
	}

	// --- Refusals [measured]: invalid token, then revocation.
	if nc, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token("sit_"+strings.Repeat("00", 32))); err == nil {
		nc.Close()
		t.Fatal("invalid token admitted")
	}
	if err := admin.RevokeToken(created.Digest); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if nc, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(created.Token)); err == nil {
		nc.Close()
		t.Fatal("revoked token admitted on a fresh connect")
	}
	if !strings.Contains(audit.String(), "callout REFUSED") {
		t.Fatal("refusals not in the audit log")
	}
}

// TestEntraGateAgainstOperatorModeServer is the OIDC lane's end-to-end
// proof [measured] (specs/001-entra-oidc-backend, D23/D24): an external
// client holding the sentinel creds and a stub-issued Entra-shaped access
// token whose role value names a declared role, admitted through the sealed
// callout leg with server-enforced scope and full attribution; undeclared
// and ambiguous roles refused; the sit_ lane coexisting untouched; and the
// revocation bound demonstrated — a still-valid cached token re-admits
// after the TTL disconnect, a role-stripped fresh token refuses.
func TestEntraGateAgainstOperatorModeServer(t *testing.T) {
	// --- The realm: operator, SYS, AUTH (external authorization + xkey),
	// APP (the service's own account, JetStream), and TWO tenant accounts —
	// ENG and PLAT, each with its scoped signing key (SC-007's rig on the
	// D25 shape, nouns per D28: a role is an account signing key bound to
	// its account — the role IS the account, the tenant — and the token
	// lane resolves by that binding).
	opKP, _ := nkeys.CreateOperator()
	opPub, _ := opKP.PublicKey()
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()
	authKP, _ := nkeys.CreateAccount()
	authPub, _ := authKP.PublicKey()
	appKP, _ := nkeys.CreateAccount()
	appPub, _ := appKP.PublicKey()
	engAccKP, _ := nkeys.CreateAccount()
	engAccPub, _ := engAccKP.PublicKey()
	engSKKP, _ := nkeys.CreateAccount()
	engSKPub, _ := engSKKP.PublicKey()
	engSKSeed, _ := engSKKP.Seed()
	platAccKP, _ := nkeys.CreateAccount()
	platAccPub, _ := platAccKP.PublicKey()
	platSKKP, _ := nkeys.CreateAccount()
	platSKPub, _ := platSKKP.PublicKey()
	platSKSeed, _ := platSKKP.Seed()
	authSKKP, _ := nkeys.CreateAccount()
	authSKPub, _ := authSKKP.PublicKey()
	authSKSeed, _ := authSKKP.Seed()
	calloutKP, _ := nkeys.CreateCurveKeys()
	calloutPub, _ := calloutKP.PublicKey()
	calloutSeed, _ := calloutKP.Seed()

	oc := jwt.NewOperatorClaims(opPub)
	oc.Name = "entra-e2e-operator"
	opJWT, err := oc.Encode(opKP)
	if err != nil {
		t.Fatalf("operator jwt: %v", err)
	}
	sc := jwt.NewAccountClaims(sysPub)
	sc.Name = "SYS"
	sysJWT, err := sc.Encode(opKP)
	if err != nil {
		t.Fatalf("system account jwt: %v", err)
	}
	issuerUserKP, _ := nkeys.CreateUser()
	issuerUserPub, _ := issuerUserKP.PublicKey()
	authClaim := jwt.NewAccountClaims(authPub)
	authClaim.Name = "AUTH"
	authClaim.SigningKeys.Add(authSKPub)
	authClaim.EnableExternalAuthorization(issuerUserPub)
	authClaim.Authorization.AllowedAccounts.Add(engAccPub, platAccPub)
	authClaim.Authorization.XKey = calloutPub
	authJWT, err := authClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("auth account jwt: %v", err)
	}
	appClaim := jwt.NewAccountClaims(appPub)
	appClaim.Name = "APP"
	appClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	appJWT, err := appClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("app account jwt: %v", err)
	}
	engClaim := jwt.NewAccountClaims(engAccPub)
	engClaim.Name = "ENG"
	engScope := jwt.NewUserScope()
	engScope.Key = engSKPub
	engScope.Role = "engineering"
	engScope.Template = jwt.UserPermissionLimits{Permissions: jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"demo.>"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"demo.>", "_INBOX.>"}},
	}}
	engClaim.SigningKeys.AddScopedSigner(engScope)
	engJWT, err := engClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("eng account jwt: %v", err)
	}
	platClaim := jwt.NewAccountClaims(platAccPub)
	platClaim.Name = "PLAT"
	platScope := jwt.NewUserScope()
	platScope.Key = platSKPub
	platScope.Role = "platform"
	platScope.Template = jwt.UserPermissionLimits{Permissions: jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"ops.>"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"ops.>", "_INBOX.>"}},
	}}
	platClaim.SigningKeys.AddScopedSigner(platScope)
	platJWT, err := platClaim.Encode(opKP)
	if err != nil {
		t.Fatalf("plat account jwt: %v", err)
	}

	cfg := fmt.Sprintf(`
listen: 127.0.0.1:-1
operator: %s
system_account: %s
resolver: MEMORY
resolver_preload: {
  %s: %s,
  %s: %s,
  %s: %s,
  %s: %s,
  %s: %s,
}
jetstream { store_dir: %q }
`, opJWT, sysPub, sysPub, sysJWT, authPub, authJWT, appPub, appJWT,
		engAccPub, engJWT, platAccPub, platJWT, t.TempDir())
	cfgPath := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	opts, err := natsserver.ProcessConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("process config: %v", err)
	}
	opts.NoLog, opts.NoSigs = true, true
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}

	serviceCreds := issueUser(t, appKP, "service", nil)
	adminCreds := issueUser(t, appKP, "ops", &jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			"identity.status", "identity.xkey", "identity." + appPub + ".ops.>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
	})
	issuerJWT, err := jwt.NewUserClaims(issuerUserPub).Encode(authKP)
	if err != nil {
		t.Fatalf("issuer user jwt: %v", err)
	}
	issuerSeed, _ := issuerUserKP.Seed()
	issuerCredsBytes, err := jwt.FormatUserConfig(issuerJWT, issuerSeed)
	if err != nil {
		t.Fatalf("issuer creds: %v", err)
	}
	issuerCreds := filepath.Join(t.TempDir(), "issuer.creds")
	if err := os.WriteFile(issuerCreds, issuerCredsBytes, 0o600); err != nil {
		t.Fatalf("write issuer creds: %v", err)
	}

	// --- The service + issuer, with the OIDC lane against the local stub
	// (FR-011) and a short TTL so the revocation bound is observable. No
	// registry (D25): the role bindings and the token store carry every
	// declared fact.
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()

	ncService, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(serviceCreds))
	if err != nil {
		t.Fatalf("service connect: %v", err)
	}
	t.Cleanup(ncService.Close)
	js, err := jetstream.New(ncService)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	vaultKV, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "SOULIDENTITY_VAULT"})
	if err != nil {
		t.Fatalf("vault bucket: %v", err)
	}
	tokensKV, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "SOULIDENTITY_TOKENS"})
	if err != nil {
		t.Fatalf("token bucket: %v", err)
	}
	v, err := vault.New(vault.NewKVStore(vaultKV), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	store := callout.NewKVTokenStore(tokensKV)

	stub, err := oidcstub.New("soulstream-identity-e2e-app")
	if err != nil {
		t.Fatalf("oidc stub: %v", err)
	}
	t.Cleanup(stub.Close)
	oidcVal, err := callout.NewOIDCValidator(t.Context(), stub.Issuer(), stub.ClientID())
	if err != nil {
		t.Fatalf("oidc validator: %v", err)
	}

	audit := &syncBuffer{}
	logger := newAuditLogger(audit)
	svc, err := service.New(v, string(surfaceSeed), logger,
		service.WithCallout(store, "auth/issuer", authPub))
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	if _, err := svc.Start(ncService); err != nil {
		t.Fatalf("service start: %v", err)
	}
	ncIssuer, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(issuerCreds))
	if err != nil {
		t.Fatalf("issuer connect: %v", err)
	}
	t.Cleanup(ncIssuer.Close)
	const calloutTTL = 5 * time.Second // the revocation propagation bound
	issuer, err := callout.NewIssuer(v, store, "auth/issuer", calloutTTL,
		string(calloutSeed), logger, callout.WithOIDC(oidcVal))
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	if _, err := issuer.Start(ncIssuer); err != nil {
		t.Fatalf("issuer start: %v", err)
	}
	if err := ncIssuer.Flush(); err != nil {
		t.Fatalf("issuer flush: %v", err)
	}

	// --- Admin provisions: the two roles with their account bindings, the
	// AUTH key, one API token (coexistence), the sentinel. Note what is NOT
	// provisioned: nothing names the oid — zero per-person acts (SC-001).
	ncAdmin, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(adminCreds))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(ncAdmin.Close)
	admin := client.New(ncAdmin, appPub, "ops")
	if _, err := admin.ImportKey("engineering", client.KindNATSAccountSigningKey, string(engSKSeed), engAccPub, ""); err != nil {
		t.Fatalf("import engineering: %v", err)
	}
	if _, err := admin.ImportKey("platform", client.KindNATSAccountSigningKey, string(platSKSeed), platAccPub, ""); err != nil {
		t.Fatalf("import platform: %v", err)
	}
	if _, err := admin.ImportKey("auth/issuer", client.KindNATSAccountSigningKey, string(authSKSeed), authPub, ""); err != nil {
		t.Fatalf("import auth key: %v", err)
	}
	created, err := admin.CreateToken(engAccPub, "daan-ext", "daan laptop", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	sentinel, err := admin.MintSentinel()
	if err != nil {
		t.Fatalf("mint sentinel: %v", err)
	}
	sentinelCreds := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(sentinelCreds, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatalf("write sentinel creds: %v", err)
	}

	// --- Bar 1 [measured]: a delegated token naming one declared role
	// admits through the sealed leg with server-enforced scope.
	const oid = "aaaaaaaa-1111-2222-3333-bbbbbbbbcccc"
	claims := stub.Claims(oid, "engineering")
	claims["preferred_username"] = "daan@example.com"
	entraToken, err := stub.Token(claims)
	if err != nil {
		t.Fatalf("stub token: %v", err)
	}
	violations := make(chan error, 8)
	ncExt, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(entraToken),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			violations <- err
		}))
	if err != nil {
		t.Fatalf("entra client connect: %v\naudit:\n%s", err, audit.String())
	}
	t.Cleanup(ncExt.Close)
	sub, err := ncExt.SubscribeSync("demo.ping")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := ncExt.Publish("demo.ping", []byte("pong")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if _, err := sub.NextMsg(5 * time.Second); err != nil {
		t.Fatalf("in-scope round-trip: %v", err)
	}
	if err := ncExt.Publish("forbidden.subject", []byte("x")); err != nil {
		t.Fatalf("out-of-scope publish: %v", err)
	}
	_ = ncExt.Flush()
	select {
	case verr := <-violations:
		if !strings.Contains(strings.ToLower(verr.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got %v", verr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("out-of-scope publish drew no permission violation")
	}
	for _, want := range []string{"lane=oidc", "role=engineering", "subject=" + oid,
		"display=daan@example.com", "issuer=" + stub.Issuer()} {
		if !strings.Contains(audit.String(), want) {
			t.Fatalf("attribution %q missing from audit:\n%s", want, audit.String())
		}
	}

	// SC-007 [measured]: the declared state has zero per-person entries for
	// the oid — no vault key and no token record names it (and there is no
	// registry to hold one, D25).
	keys, err := admin.Keys()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	for _, k := range keys {
		if strings.Contains(k.Name, oid) {
			t.Fatalf("a per-person vault entry appeared for the oid: %+v", k)
		}
	}
	toks, err := admin.Tokens()
	if err != nil {
		t.Fatalf("tokens: %v", err)
	}
	for _, tk := range toks {
		if strings.Contains(tk.User, oid) {
			t.Fatalf("a per-person token record appeared for the oid: %+v", tk)
		}
	}

	// --- Refusals [measured]: an undeclared role, then ambiguity.
	unknownTok, err := stub.Token(stub.Claims(oid, "marketing"))
	if err != nil {
		t.Fatalf("stub token: %v", err)
	}
	if nc, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(unknownTok)); err == nil {
		nc.Close()
		t.Fatal("an undeclared role admitted")
	}
	ambiguousTok, err := stub.Token(stub.Claims(oid, "engineering", "platform"))
	if err != nil {
		t.Fatalf("stub token: %v", err)
	}
	if nc, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(ambiguousTok)); err == nil {
		nc.Close()
		t.Fatal("an ambiguous role set admitted")
	}
	for _, want := range []string{"no declared role", "ambiguous"} {
		if !strings.Contains(audit.String(), want) {
			t.Fatalf("refusal reason %q missing from audit:\n%s", want, audit.String())
		}
	}

	// --- Coexistence [measured]: the sit_ lane admits via its token record
	// and the role binding with the OIDC lane configured; both lanes share
	// the declared role set (D24, D25).
	ncTok, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(created.Token))
	if err != nil {
		t.Fatalf("api-token client with oidc configured: %v", err)
	}
	ncTok.Close()
	if !strings.Contains(audit.String(), "user=daan-ext") {
		t.Fatalf("token-lane admission missing from audit:\n%s", audit.String())
	}

	// --- The revocation bound [measured]: the TTL disconnects the admitted
	// connection; the still-valid cached token re-admits on reconnect; a
	// fresh role-stripped token refuses.
	reconnected := make(chan time.Time, 1)
	start := time.Now()
	revOID := "dddddddd-4444-5555-6666-eeeeeeeeffff"
	revTok, err := stub.Token(stub.Claims(revOID, "engineering"))
	if err != nil {
		t.Fatalf("stub token: %v", err)
	}
	ncRev, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(revTok),
		nats.ReconnectWait(200*time.Millisecond), nats.MaxReconnects(-1),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, _ error) {
			// the TTL disconnect ("authentication expired") is the point
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			select {
			case reconnected <- time.Now():
			default:
			}
		}))
	if err != nil {
		t.Fatalf("revocation client connect: %v", err)
	}
	t.Cleanup(ncRev.Close)
	select {
	case at := <-reconnected:
		t.Logf("revocation bound observed: disconnected and re-admitted %s after connect (ttl %s)",
			at.Sub(start).Round(time.Millisecond), calloutTTL)
	case <-time.After(calloutTTL + 10*time.Second):
		t.Fatal("no TTL disconnect/reconnect within the bound")
	}
	if n := strings.Count(audit.String(), "subject="+revOID); n < 2 {
		t.Fatalf("cached token did not re-admit after the TTL (admissions: %d)", n)
	}
	strippedTok, err := stub.Token(stub.Claims(revOID)) // role assignment removed
	if err != nil {
		t.Fatalf("stub token: %v", err)
	}
	if nc, err := nats.Connect(srv.ClientURL(),
		nats.UserCredentials(sentinelCreds), nats.Token(strippedTok)); err == nil {
		nc.Close()
		t.Fatal("a role-stripped fresh token admitted")
	}
	if !strings.Contains(audit.String(), "no roles claim") {
		t.Fatalf("role-stripped refusal missing from audit:\n%s", audit.String())
	}
}
