package client_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/embed"
)

// TestTenancyOpFamilyE2E is D47's acceptance criterion measured through
// the REAL op family (hq 02-DESIGN/soulstream-identity/platform-topology.md):
// a tenant born over the sealed accounts.create, a token issued for it
// over tokens.create, and a client holding only the sentinel and that
// token admitted into the tenant as a USABLE user — subscribing and
// publishing inside the persona scope, refused outside it — then
// suspend/resume through the same surface. Everything travels the
// public embed assembly and the public client; no internal machinery is
// driven directly.
func TestTenancyOpFamilyE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- The deployment: operator, SYS, AUTH (callout), SVC (service home).
	opKP, _ := nkeys.CreateOperator()
	opPub, _ := opKP.PublicKey()
	opSeed, _ := opKP.Seed()

	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()
	sysClaims := jwt.NewAccountClaims(sysPub)
	sysClaims.Name = "SYS"
	sysJWT, err := sysClaims.Encode(opKP)
	if err != nil {
		t.Fatal(err)
	}

	authKP, _ := nkeys.CreateAccount()
	authPub, _ := authKP.PublicKey()
	authSKKP, _ := nkeys.CreateAccount()
	authSKPub, _ := authSKKP.PublicKey()
	authSKSeed, _ := authSKKP.Seed()
	issuerUserKP, _ := nkeys.CreateUser()
	issuerUserPub, _ := issuerUserKP.PublicKey()
	issuerUserSeed, _ := issuerUserKP.Seed()
	authClaims := jwt.NewAccountClaims(authPub)
	authClaims.Name = "AUTH"
	authClaims.SigningKeys.Add(authSKPub)
	authClaims.EnableExternalAuthorization(issuerUserPub)
	// allowed_accounts starts EMPTY: creation must teach it each tenant.
	authJWT, err := authClaims.Encode(opKP)
	if err != nil {
		t.Fatal(err)
	}

	svcKP, _ := nkeys.CreateAccount()
	svcPub, _ := svcKP.PublicKey()
	svcClaims := jwt.NewAccountClaims(svcPub)
	svcClaims.Name = "SVC"
	svcClaims.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	svcJWT, err := svcClaims.Encode(opKP)
	if err != nil {
		t.Fatal(err)
	}

	res, err := natsserver.NewDirAccResolver(t.TempDir(), 1000, time.Minute, natsserver.NoDelete)
	if err != nil {
		t.Fatal(err)
	}
	for pub, j := range map[string]string{sysPub: sysJWT, authPub: authJWT, svcPub: svcJWT} {
		if err := res.Store(pub, j); err != nil {
			t.Fatal(err)
		}
	}
	oc := jwt.NewOperatorClaims(opPub)
	oc.Name = "e2e-op"
	oc.SystemAccount = sysPub
	opJWT, err := oc.Encode(opKP)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := jwt.DecodeOperatorClaims(opJWT)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host: "127.0.0.1", Port: -1,
		TrustedOperators: []*jwt.OperatorClaims{trusted},
		SystemAccount:    sysPub,
		AccountResolver:  res,
		JetStream:        true, StoreDir: t.TempDir(),
		NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}
	url := srv.ClientURL()

	mkUser := func(name string, acct nkeys.KeyPair) string {
		uk, _ := nkeys.CreateUser()
		upub, _ := uk.PublicKey()
		useed, _ := uk.Seed()
		uc := jwt.NewUserClaims(upub)
		uc.Name = name
		tok, err := uc.Encode(acct)
		if err != nil {
			t.Fatal(err)
		}
		creds, err := jwt.FormatUserConfig(tok, useed)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), name+".creds")
		if err := os.WriteFile(p, creds, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	svcConn, err := nats.Connect(url, nats.UserCredentials(mkUser("service", svcKP)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svcConn.Close)
	opsConn, err := nats.Connect(url, nats.UserCredentials(mkUser("ops", svcKP)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(opsConn.Close)
	sysConn, err := nats.Connect(url, nats.UserCredentials(mkUser("sys", sysKP)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sysConn.Close)
	issuerJWT, err := jwt.NewUserClaims(issuerUserPub).Encode(authKP)
	if err != nil {
		t.Fatal(err)
	}
	issuerCredsBytes, err := jwt.FormatUserConfig(issuerJWT, issuerUserSeed)
	if err != nil {
		t.Fatal(err)
	}
	issuerCreds := filepath.Join(t.TempDir(), "issuer.creds")
	if err := os.WriteFile(issuerCreds, issuerCredsBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	authConn, err := nats.Connect(url, nats.UserCredentials(issuerCreds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authConn.Close)

	// --- The plane, through the public assembly: callout + tenancy on.
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()
	done := make(chan error, 1)
	go func() {
		done <- embed.Run(ctx, embed.Options{
			Conn:        svcConn,
			CalloutConn: authConn,
			SystemConn:  sysConn,
			FirstKey:    string(firstSeed),
			SurfaceKey:  string(surfaceSeed),
			AuthAccount: authPub,
			CalloutTTL:  time.Minute,
		})
	}()
	t.Cleanup(func() { cancel(); <-done })

	admin := client.New(opsConn, svcPub, "ops")
	waitReady := func() {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := admin.Status(); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("service never became ready")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitReady()

	// Founding acts through the public client: the operator key (the
	// tenancy authority's pen) and the AUTH signing key (the issuer's).
	if _, err := admin.ImportKey("operator/root", "nats-operator-key", string(opSeed), "", ""); err != nil {
		t.Fatalf("import operator key: %v", err)
	}
	if _, err := admin.ImportKey("auth/issuer", "nats-account-signing-key", string(authSKSeed), authPub, ""); err != nil {
		t.Fatalf("import auth signing key: %v", err)
	}
	sentinel, err := admin.MintSentinel()
	if err != nil {
		t.Fatalf("mint sentinel: %v", err)
	}
	sentinelCreds := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(sentinelCreds, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatal(err)
	}

	// --- The op family: a tenant is born over the sealed surface.
	born := time.Now()
	rec, err := admin.AccountCreate("acme")
	if err != nil {
		t.Fatalf("accounts.create: %v", err)
	}
	if rec.Status != "active" || rec.Account == "" {
		t.Fatalf("record: %+v", rec)
	}

	// A token for a person in the tenant — tokens.create resolves the
	// signing key by the tenant's fresh vault binding.
	created, err := admin.CreateToken(rec.Account, "alice", "e2e", 0)
	if err != nil {
		t.Fatalf("tokens.create for the new tenant: %v", err)
	}

	// The gate: sentinel + token admits into the just-born tenant, USABLE.
	violations := make(chan error, 4)
	dialTenant := func() (*nats.Conn, error) {
		return nats.Connect(url,
			nats.UserCredentials(sentinelCreds), nats.Token(created.Token),
			nats.RetryOnFailedConnect(false), nats.MaxReconnects(0),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
				select {
				case violations <- e:
				default:
				}
			}))
	}
	nc, err := dialTenant()
	if err != nil {
		t.Fatalf("admission into the born tenant: %v", err)
	}
	sub, err := nc.SubscribeSync("SOULSTREAM.ping")
	if err != nil {
		t.Fatalf("scoped tenant user cannot subscribe (the inert defect): %v", err)
	}
	if err := nc.Publish("SOULSTREAM.ping", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("round trip in the born tenant: %v", err)
	}
	t.Logf("accounts.create -> usable token-lane admission in %v", time.Since(born))

	if err := nc.Publish("foreign.subject", []byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = nc.FlushTimeout(2 * time.Second)
	select {
	case e := <-violations:
		if e == nil || !strings.Contains(strings.ToLower(e.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation outside the scope, got: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publish outside the persona scope drew no violation")
	}
	nc.Close()

	// Resolution and listing answer through the same surface.
	got, err := admin.AccountResolve("acme")
	if err != nil || got.Account != rec.Account {
		t.Fatalf("resolve: %v %+v", err, got)
	}
	list, err := admin.Accounts()
	if err != nil || len(list) != 1 || list[0].Name != "acme" {
		t.Fatalf("list: %v %+v", err, list)
	}

	// Suspension refuses the tenant's next admission; resume restores it.
	if _, err := admin.AccountSuspend("acme"); err != nil {
		t.Fatal(err)
	}
	if ncSusp, err := dialTenant(); err == nil {
		ncSusp.Close()
		t.Fatal("suspended tenant admitted a connection")
	}
	if _, err := admin.AccountResume("acme"); err != nil {
		t.Fatal(err)
	}
	ncBack, err := dialTenant()
	if err != nil {
		t.Fatalf("resume did not restore admission: %v", err)
	}
	ncBack.Close()
}
