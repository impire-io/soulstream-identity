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

	"github.com/impire-io/soulidentity/client"
	"github.com/impire-io/soulidentity/internal/callout"
	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/service"
	"github.com/impire-io/soulidentity/internal/vault"
)

// TestM4GateAgainstOperatorModeServer is auth callout's end-to-end proof
// [measured] — the M4 gate (hq/02-DESIGN/auth-callout.md): SoulIdentity as
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
			"soulidentity.status", "soulidentity.xkey", "soulidentity." + appPub + ".ops.>",
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
	// on the APP connection, the issuer on the AUTH connection (D21).
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	for _, id := range []registry.Identity{
		{Account: appPub, User: "ops", Admin: true},
		{Account: appPub, User: "daan-ext", Role: "acme/role"},
	} {
		if err := reg.Put(id); err != nil {
			t.Fatalf("declare %s: %v", id.User, err)
		}
	}
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
	svc, err := service.New(v, reg, string(surfaceSeed), logger,
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
	issuer, err := callout.NewIssuer(v, reg, store, "auth/issuer", 2*time.Minute, string(calloutSeed), logger)
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
	if _, err := admin.ImportKey("acme/role", client.KindNATSAccountSigningKey, string(roleSeed), appPub); err != nil {
		t.Fatalf("import role key: %v", err)
	}
	if _, err := admin.ImportKey("auth/issuer", client.KindNATSAccountSigningKey, string(authSKSeed), authPub); err != nil {
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
