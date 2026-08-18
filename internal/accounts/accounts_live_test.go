package accounts

import (
	"context"
	"errors"
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

	res, err := natsserver.NewDirAccResolver(t.TempDir(), 1000, time.Minute, natsserver.NoDelete)
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Store(sysPub, sysJWT); err != nil {
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
		&LocalOperator{Vault: v, OperatorKeyName: "operator/root", Sys: sysConn})
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

	// A principal in the new account connects and completes a round trip.
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
	userJWT, err := uc.Encode(skKP)
	if err != nil {
		t.Fatal(err)
	}
	dial := func() (*nats.Conn, error) {
		return nats.Connect(srv.ClientURL(), nats.UserJWTAndSeed(userJWT, string(userSeed)),
			nats.RetryOnFailedConnect(false), nats.MaxReconnects(0))
	}
	nc, err := dial()
	if err != nil {
		t.Fatalf("admission into the born account: %v", err)
	}
	sub, err := nc.SubscribeSync("ping")
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish("ping", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("round trip in the born account: %v", err)
	}
	nc.Close()
	t.Logf("store -> admitted round trip in %v", time.Since(born))

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
