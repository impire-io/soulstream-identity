package accounts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

// TestAccountLifecycleLive is Bar 1/2 re-measured through the real
// engine and the local-operator authority (D35's acceptance): an
// account born at runtime on a real resolver with zero restarts, no
// usable half-account, suspension refusing the next connection, resume
// restoring it.
func TestAccountLifecycleLive(t *testing.T) {
	ctx := context.Background()

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

	// An AUTH account with callout enabled and an empty allowed_accounts:
	// the D47 coupling under test is that creation teaches it each tenant.
	authKP, _ := nkeys.CreateAccount()
	authPub, _ := authKP.PublicKey()
	issuerUserKP, _ := nkeys.CreateUser()
	issuerUserPub, _ := issuerUserKP.PublicKey()
	authClaims := jwt.NewAccountClaims(authPub)
	authClaims.Name = "AUTH"
	authClaims.EnableExternalAuthorization(issuerUserPub)
	authJWT, err := authClaims.Encode(opKP)
	if err != nil {
		t.Fatal(err)
	}

	res, err := natsserver.NewDirAccResolver(t.TempDir(), 1000, time.Minute, natsserver.NoDelete)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Store(sysPub, sysJWT); err != nil {
		t.Fatal(err)
	}
	if err := res.Store(authPub, authJWT); err != nil {
		t.Fatal(err)
	}
	oc := jwt.NewOperatorClaims(opPub)
	oc.Name = "op"
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
		NoLog:            true, NoSigs: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("server not ready")
	}
	defer srv.Shutdown()

	sysUserKP, _ := nkeys.CreateUser()
	sysUserPub, _ := sysUserKP.PublicKey()
	sysUserSeed, _ := sysUserKP.Seed()
	suc := jwt.NewUserClaims(sysUserPub)
	suc.Name = "sys"
	sysUserJWT, err := suc.Encode(sysKP)
	if err != nil {
		t.Fatal(err)
	}
	sysConn, err := nats.Connect(srv.ClientURL(), nats.UserJWTAndSeed(sysUserJWT, string(sysUserSeed)))
	if err != nil {
		t.Fatal(err)
	}
	defer sysConn.Close()

	// The operator key into the vault — custody first, authority second.
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Import("operator/root", vault.KindNATSOperatorKey, string(opSeed), "", ""); err != nil {
		t.Fatal(err)
	}
	engine, err := New(sealedstore.NewMemStore(), string(firstSeed),
		&LocalOperator{Vault: v, OperatorKeyName: "operator/root", Sys: sysConn,
			AuthAccount: authPub})
	if err != nil {
		t.Fatal(err)
	}

	// Bar 2's fail-closed half: before creation, nothing resolves.
	if _, err := engine.Resolve("acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pre-create resolve: %v", err)
	}

	// Bar 1: born at runtime — one act, no restart anywhere.
	born := time.Now()
	rec, signingSeed, err := engine.Create(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != Active || rec.PublicKey == "" || rec.SigningKey == "" {
		t.Fatalf("record: %+v", rec)
	}
	// A name reuse refuses: first-seen wins.
	if _, _, err := engine.Create(ctx, "acme"); !errors.Is(err, ErrExists) {
		t.Fatalf("reuse: %v", err)
	}

	// A principal in the new account connects THE WAY THE MINT SHAPES IT
	// (SetScoped, permission-less — D5) and completes a round trip inside
	// the persona scope. Before D47 this user was admitted but inert
	// (scoped user on a plain key: 0 subscriptions, 0 payload) — the
	// subscribe below is the assertion that kills that defect.
	skKP, err := nkeys.FromSeed([]byte(signingSeed))
	if err != nil {
		t.Fatal(err)
	}
	userKP, _ := nkeys.CreateUser()
	userPub, _ := userKP.PublicKey()
	userSeed, _ := userKP.Seed()
	uc := jwt.NewUserClaims(userPub)
	uc.Name = "alice"
	uc.IssuerAccount = rec.PublicKey
	uc.SetScoped(true)
	uc.Expires = time.Now().Add(15 * time.Minute).Unix()
	userJWT, err := uc.Encode(skKP)
	if err != nil {
		t.Fatal(err)
	}
	violations := make(chan error, 4)
	dial := func() (*nats.Conn, error) {
		return nats.Connect(srv.ClientURL(), nats.UserJWTAndSeed(userJWT, string(userSeed)),
			nats.RetryOnFailedConnect(false), nats.MaxReconnects(0),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) {
				select {
				case violations <- e:
				default:
				}
			}))
	}
	nc, err := dial()
	if err != nil {
		t.Fatalf("admission into the born account: %v", err)
	}
	sub, err := nc.SubscribeSync("SOULSTREAM.ping")
	if err != nil {
		t.Fatalf("scoped user cannot subscribe (the inert-tenant defect): %v", err)
	}
	if err := nc.Publish("SOULSTREAM.ping", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("round trip in the born account: %v", err)
	}
	t.Logf("store -> usable-admission round trip in %v", time.Since(born))

	// The template bounds the user: a publish outside the persona scope
	// draws a server-side permissions violation (never silence).
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
		t.Fatal("publish outside the persona scope drew no permissions violation — the template is not applied")
	}
	nc.Close()

	// The D47 coupling: AUTH's stored JWT now lists the tenant, so the
	// callout may place users into it (D21's explicit allowed_accounts).
	lookup, err := sysConn.Request(fmt.Sprintf("$SYS.REQ.ACCOUNT.%s.CLAIMS.LOOKUP", authPub), nil, 5*time.Second)
	if err != nil {
		t.Fatalf("auth lookup: %v", err)
	}
	authNow, err := jwt.DecodeAccountClaims(string(lookup.Data))
	if err != nil {
		t.Fatalf("auth decode: %v", err)
	}
	if !authNow.Authorization.AllowedAccounts.Contains(rec.PublicKey) {
		t.Fatalf("AUTH allowed_accounts did not learn the tenant: %v", authNow.Authorization.AllowedAccounts)
	}

	// Suspension refuses the next connection; the record and data stay.
	if _, err := engine.SetSuspended(ctx, "acme", true); err != nil {
		t.Fatal(err)
	}
	if ncSusp, err := dial(); err == nil {
		ncSusp.Close()
		t.Fatal("suspended account admitted a connection")
	}
	rec2, err := engine.Resolve("acme")
	if err != nil || rec2.Status != Suspended {
		t.Fatalf("suspended record: %v %+v", err, rec2)
	}

	// Resume restores admission.
	if _, err := engine.SetSuspended(ctx, "acme", false); err != nil {
		t.Fatal(err)
	}
	ncBack, err := dial()
	if err != nil {
		t.Fatalf("resume did not restore admission: %v", err)
	}
	ncBack.Close()
}
