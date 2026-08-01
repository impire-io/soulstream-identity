// The consumer-position gate for the embed seam (spec 002, US1): a full
// operator-mode ceremony stood up from nothing, the identity plane
// assembled through the public embed package, provisioning driven through
// the public client package — and not one internal/ import, which the
// module path makes a compile error rather than a review finding.
//
// The ceremony is the callout e2e's, re-expressed through pure
// server.Options (no config file) — the fourth consumer-position copy of
// its kind (research R4; soulnode's composition rig proved the shape).
package embedgate

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/client"
	"github.com/impire-io/soulidentity/embed"
)

// syncBuffer captures the plane's audit log for assertions.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// ceremony is everything the gate provisions before the plane runs.
type ceremony struct {
	url         string
	appPub      string
	authPub     string
	firstSeed   string
	surfaceSeed string
	calloutSeed string
	acmeSKSeed  string
	authSKSeed  string

	ncService *nats.Conn
	ncCallout *nats.Conn
	ncOps     *nats.Conn

	shutdown func()
}

// provision stands up the operator-mode server with auth callout and the
// bootstrap connections, entirely in code.
func provision(t *testing.T) *ceremony {
	t.Helper()

	// Keys: operator, SYS, AUTH (+signing key, issuer user, callout
	// xkey), APP (+scoped signing key), the two service curve seeds.
	opKP, _ := nkeys.CreateOperator()
	opPub, _ := opKP.PublicKey()
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()
	authKP, _ := nkeys.CreateAccount()
	authPub, _ := authKP.PublicKey()
	authSK, _ := nkeys.CreateAccount()
	authSKPub, _ := authSK.PublicKey()
	authSKSeed, _ := authSK.Seed()
	issuerUserKP, _ := nkeys.CreateUser()
	issuerUserPub, _ := issuerUserKP.PublicKey()
	issuerUserSeed, _ := issuerUserKP.Seed()
	calloutKP, _ := nkeys.CreateCurveKeys()
	calloutPub, _ := calloutKP.PublicKey()
	calloutSeed, _ := calloutKP.Seed()
	appKP, _ := nkeys.CreateAccount()
	appPub, _ := appKP.PublicKey()
	acmeSK, _ := nkeys.CreateAccount()
	acmeSKPub, _ := acmeSK.PublicKey()
	acmeSKSeed, _ := acmeSK.Seed()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()

	// Account JWTs, signed by the operator.
	sysClaims := jwt.NewAccountClaims(sysPub)
	sysClaims.Name = "SYS"
	sysJWT, err := sysClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("sys jwt: %v", err)
	}

	authClaims := jwt.NewAccountClaims(authPub)
	authClaims.Name = "AUTH"
	authClaims.SigningKeys.Add(authSKPub)
	authClaims.EnableExternalAuthorization(issuerUserPub)
	authClaims.Authorization.AllowedAccounts.Add(appPub)
	authClaims.Authorization.XKey = calloutPub
	authJWT, err := authClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("auth jwt: %v", err)
	}

	appClaims := jwt.NewAccountClaims(appPub)
	appClaims.Name = "APP"
	appClaims.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	scope := jwt.NewUserScope()
	scope.Key = acmeSKPub
	scope.Role = "external-user"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: []string{
				client.Segment + ".status",
				client.Segment + ".xkey",
				client.Segment + ".{{account-subject()}}.{{name()}}.sign.record",
				client.Segment + ".{{account-subject()}}.{{name()}}.keys.public",
				"$SYS.REQ.USER.INFO",
			}},
			Sub: jwt.Permission{Allow: []string{"_INBOX.>"}},
		},
	}
	appClaims.SigningKeys.AddScopedSigner(scope)
	appJWT, err := appClaims.Encode(opKP)
	if err != nil {
		t.Fatalf("app jwt: %v", err)
	}

	// The server: pure server.Options, memory resolver, JetStream.
	res := &natsserver.MemAccResolver{}
	for pub, token := range map[string]string{sysPub: sysJWT, authPub: authJWT, appPub: appJWT} {
		if err := res.Store(pub, token); err != nil {
			t.Fatalf("resolver store: %v", err)
		}
	}
	srv, err := natsserver.NewServer(&natsserver.Options{
		Host:            "127.0.0.1",
		Port:            -1,
		JetStream:       true,
		StoreDir:        t.TempDir(),
		TrustedKeys:     []string{opPub},
		SystemAccount:   sysPub,
		AccountResolver: res,
		NoLog:           true,
		NoSigs:          true,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		t.Fatal("server not ready")
	}

	// Bootstrap users: service + ops signed by the APP account key (the
	// creds bypass lane), the issuer user signed by the AUTH account key.
	userJWTSeed := func(name string, signer nkeys.KeyPair) (string, string) {
		ukp, _ := nkeys.CreateUser()
		upub, _ := ukp.PublicKey()
		useed, _ := ukp.Seed()
		uc := jwt.NewUserClaims(upub)
		uc.Name = name
		token, err := uc.Encode(signer)
		if err != nil {
			t.Fatalf("user %s: %v", name, err)
		}
		return token, string(useed)
	}
	serviceJWT, serviceSeed := userJWTSeed("service", appKP)
	opsJWT, opsSeed := userJWTSeed("ops", appKP)
	issuerClaims := jwt.NewUserClaims(issuerUserPub)
	issuerClaims.Name = "soulidentity-issuer"
	issuerJWT, err := issuerClaims.Encode(authKP)
	if err != nil {
		t.Fatalf("issuer user: %v", err)
	}

	connect := func(what, token, seed string) *nats.Conn {
		nc, err := nats.Connect(srv.ClientURL(), nats.UserJWTAndSeed(token, seed),
			nats.Name(what), nats.RetryOnFailedConnect(false), nats.MaxReconnects(0))
		if err != nil {
			t.Fatalf("%s connect: %v", what, err)
		}
		return nc
	}
	ncService := connect("service", serviceJWT, serviceSeed)
	ncCallout := connect("issuer", issuerJWT, string(issuerUserSeed))
	ncOps := connect("ops", opsJWT, opsSeed)

	c := &ceremony{
		url: srv.ClientURL(), appPub: appPub, authPub: authPub,
		firstSeed: string(firstSeed), surfaceSeed: string(surfaceSeed),
		calloutSeed: string(calloutSeed), acmeSKSeed: string(acmeSKSeed),
		authSKSeed: string(authSKSeed),
		ncService:  ncService, ncCallout: ncCallout, ncOps: ncOps,
		shutdown: func() {
			ncOps.Close()
			ncCallout.Close()
			ncService.Close()
			srv.Shutdown()
		},
	}
	t.Cleanup(c.shutdown)
	return c
}

// principal reads the server-asserted (persona, account) from the expanded
// sign.record grant — no client-claimed identity anywhere.
func principal(t *testing.T, nc *nats.Conn) (persona, account string) {
	t.Helper()
	msg, err := nc.Request("$SYS.REQ.USER.INFO", nil, 5*time.Second)
	if err != nil {
		t.Fatalf("USER.INFO: %v", err)
	}
	var info struct {
		Data struct {
			Permissions struct {
				Publish struct {
					Allow []string `json:"allow"`
				} `json:"publish"`
			} `json:"permissions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(msg.Data, &info); err != nil {
		t.Fatalf("USER.INFO decode: %v", err)
	}
	for _, subj := range info.Data.Permissions.Publish.Allow {
		parts := strings.Split(subj, ".")
		if len(parts) == 5 && parts[0] == client.Segment && parts[3] == "sign" && parts[4] == "record" {
			return parts[2], parts[1]
		}
	}
	t.Fatalf("no expanded sign.record grant in %v", info.Data.Permissions.Publish.Allow)
	return "", ""
}

// TestEmbedGate is the M4 admission shape through embed.Run: assemble the
// plane via the public seam, provision via the public client, then prove
// admission, invalid-token refusal, revoked-token refusal, and the drain
// on ctx end (spec 002 US1, scenarios 1–3).
func TestEmbedGate(t *testing.T) {
	c := provision(t)

	audit := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(audit, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- embed.Run(ctx, embed.Options{
			Conn:        c.ncService,
			CalloutConn: c.ncCallout,
			FirstKey:    c.firstSeed,
			SurfaceKey:  c.surfaceSeed,
			CalloutKey:  c.calloutSeed,
			AuthAccount: c.authPub,
			CalloutTTL:  2 * time.Minute,
			Logger:      logger,
		})
	}()

	// Readiness: the sealed surface answers status (scenario 1).
	ops := client.New(c.ncOps, c.appPub, "ops")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := ops.Status(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("service never served: %v (audit: %s)", err, audit.String())
		}
		select {
		case err := <-runErr:
			t.Fatalf("Run returned during startup: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Provisioning through the public client only: both signing keys into
	// the vault, one API token, the sentinel.
	if _, err := ops.ImportKey("acme", client.KindNATSAccountSigningKey, c.acmeSKSeed, c.appPub, ""); err != nil {
		t.Fatalf("import app signing key: %v", err)
	}
	if _, err := ops.ImportKey("auth/issuer", client.KindNATSAccountSigningKey, c.authSKSeed, c.authPub, ""); err != nil {
		t.Fatalf("import auth signing key: %v", err)
	}
	created, err := ops.CreateToken(c.appPub, "daan-ext", "embed gate", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	sentinel, err := ops.MintSentinel()
	if err != nil {
		t.Fatalf("mint sentinel: %v", err)
	}
	sentinelPath := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(sentinelPath, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	dial := func(token string) (*nats.Conn, error) {
		return nats.Connect(c.url,
			nats.UserCredentials(sentinelPath), nats.Token(token),
			nats.RetryOnFailedConnect(false), nats.MaxReconnects(0))
	}

	// Scenario 2a: the token lane admits, attributed by the server.
	nc, err := dial(created.Token)
	if err != nil {
		t.Fatalf("token lane refused: %v (audit: %s)", err, audit.String())
	}
	defer nc.Close()
	persona, account := principal(t, nc)
	if persona != "daan-ext" || account != c.appPub {
		t.Fatalf("principal = %s@%s, want daan-ext@%s", persona, account, c.appPub)
	}

	// Scenario 2b: an invalid token is refused, and the audit says so.
	if ncBad, err := dial("sit_" + strings.Repeat("00", 32)); err == nil {
		ncBad.Close()
		t.Fatal("invalid token admitted")
	}
	if !strings.Contains(audit.String(), "callout REFUSED") {
		t.Fatal("no 'callout REFUSED' in the audit after the invalid token")
	}

	// Scenario 2c: a revoked token is refused on the next connection.
	if err := ops.RevokeToken(created.Digest); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ncRevoked, err := dial(created.Token); err == nil {
		ncRevoked.Close()
		t.Fatal("revoked token admitted")
	}

	// Scenario 3: ctx ends → Run drains its subscriptions and returns;
	// the surface goes silent while the caller's connections stay open.
	cancel()
	select {
	case err := <-runErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	if !c.ncService.IsConnected() {
		t.Fatal("Run closed the caller's service connection")
	}
	if _, err := ops.Status(); err == nil {
		t.Fatal("surface still serving after drain")
	}
}
