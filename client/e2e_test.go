package client_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/client"
	"github.com/impire-io/soulidentity/internal/agent"
	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

// TestMintAndNonceOracleAgainstOperatorModeServer is the walking skeleton's
// end-to-end proof [measured]: a NATS server in operator mode (memory
// resolver), an account whose SCOPED signing key lives in the vault, a user
// JWT minted through the agent, and a connection whose nonce is signed by the
// agent — no seed ever present in this process. The scope's permissions are
// proven server-enforced: an out-of-scope publish draws a permission
// violation.
func TestMintAndNonceOracleAgainstOperatorModeServer(t *testing.T) {
	// --- The realm side: operator, system account, one account with a scoped
	// signing key allowing only e2e.> (plus inbox subscriptions).
	opKP, _ := nkeys.CreateOperator()
	opPub, _ := opKP.PublicKey()
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	askKP, _ := nkeys.CreateAccount()
	askPub, _ := askKP.PublicKey()
	askSeed, _ := askKP.Seed()

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
	ac := jwt.NewAccountClaims(accPub)
	ac.Name = "e2e-account"
	scope := jwt.NewUserScope()
	scope.Key = askPub
	scope.Role = "e2e-persona"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList{"e2e.>"}},
			Sub: jwt.Permission{Allow: jwt.StringList{"e2e.>", "_INBOX.>"}},
		},
	}
	ac.SigningKeys.AddScopedSigner(scope)
	accJWT, err := ac.Encode(opKP)
	if err != nil {
		t.Fatalf("account jwt: %v", err)
	}

	cfg := fmt.Sprintf(`
listen: 127.0.0.1:-1
operator: %s
system_account: %s
resolver: MEMORY
resolver_preload: {
  %s: %s,
  %s: %s,
}
`, opJWT, sysPub, sysPub, sysJWT, accPub, accJWT)
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

	// --- The agent side: vault + registry + agent on a real Unix socket.
	dataDir, err := os.MkdirTemp("", "si-e2e")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })
	v, err := vault.Open(filepath.Join(dataDir, "vault"))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	reg, err := registry.Open(filepath.Join(dataDir, "registry.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	socket := filepath.Join(dataDir, "agent.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- agent.Serve(ctx, socket, agent.New(v, reg, nil).Handler()) }()

	c := client.New(socket)
	waitFor(t, 5*time.Second, func() error {
		_, err := c.Status()
		return err
	})

	// Everything below goes through the agent API — the scoped signing key's
	// seed enters the vault and is never seen again.
	if _, err := c.ImportKey("e2e/persona-role", client.KindNATSAccountSigningKey, string(askSeed)); err != nil {
		t.Fatalf("import signing key: %v", err)
	}
	if err := c.PutIdentity(client.Identity{
		Account: accPub, User: "daan", Personas: []string{"daan"}, Role: "e2e/persona-role",
	}); err != nil {
		t.Fatalf("declare identity: %v", err)
	}

	// --- The proof: connect with agent-held credentials, roundtrip a message.
	violations := make(chan error, 8)
	nc, err := nats.Connect(srv.ClientURL(),
		c.NATSOption(accPub, "daan"),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			violations <- err
		}),
	)
	if err != nil {
		t.Fatalf("connect through the oracle: %v", err)
	}
	t.Cleanup(nc.Close)

	sub, err := nc.SubscribeSync("e2e.ping")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := nc.Publish("e2e.ping", []byte("pong")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("roundtrip: %v", err)
	}
	if string(msg.Data) != "pong" {
		t.Fatalf("roundtrip payload: %q", msg.Data)
	}

	// --- The scope is the policy, server-enforced: out-of-scope publish draws
	// a permission violation (the minted JWT carries no permissions of its own).
	if err := nc.Publish("forbidden.subject", []byte("nope")); err != nil {
		t.Fatalf("publish (violation goes async): %v", err)
	}
	_ = nc.Flush()
	select {
	case err := <-violations:
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("out-of-scope publish drew no permission violation — scope not enforced")
	}

	// The agent stayed healthy throughout.
	select {
	case err := <-serveErr:
		t.Fatalf("agent exited during the test: %v", err)
	default:
	}
}

func waitFor(t *testing.T, timeout time.Duration, fn func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for time.Now().Before(deadline) {
		if err = fn(); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not reached in %s: %v", timeout, err)
}
