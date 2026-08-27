package client_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/internal/service"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

// TestAgentScopeGate (spec 004 SC-001..003) is research 0126's capability
// rig reborn as a standing test: the canonical agent scope, installed as a
// scoped signer on a live operator-mode account, clamps a D28 tagged mint
// to exactly its declared subjects — the template is the whole policy,
// server-enforced. It also first-verifies the two server behaviors the
// capability-minting arc depends on: multi-value tag expansion (two tools
// through one credential) and the zero-matching-tag line drop (a tool-less
// mint still admits).
func TestAgentScopeGate(t *testing.T) {
	// --- The realm: operator, SYS, one account with JetStream and the
	// agent-role signing key under the exported template.
	opKP, _ := nkeys.CreateOperator()
	opPub, _ := opKP.PublicKey()
	sysKP, _ := nkeys.CreateAccount()
	sysPub, _ := sysKP.PublicKey()
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	agentKP, _ := nkeys.CreateAccount()
	agentPub, _ := agentKP.PublicKey()
	agentSeed, _ := agentKP.Seed()

	oc := jwt.NewOperatorClaims(opPub)
	oc.Name = "agentscope-operator"
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
	ac.Name = "agentscope-account"
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	scope := jwt.NewUserScope()
	scope.Key = agentPub
	scope.Role = client.AgentScopeRole
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList(client.AgentScopePubAllow(""))},
			Sub: jwt.Permission{Allow: jwt.StringList(client.AgentScopeSubAllow(""))},
		},
	}
	ac.SigningKeys.AddScopedSigner(scope)
	accJWT, err := ac.Encode(opKP)
	if err != nil {
		t.Fatalf("account jwt: %v", err)
	}

	storeDir := t.TempDir()
	cfg := fmt.Sprintf(`
listen: 127.0.0.1:-1
operator: %s
system_account: %s
resolver: MEMORY
resolver_preload: {
  %s: %s,
  %s: %s,
}
jetstream { store_dir: %q }
`, opJWT, sysPub, sysPub, sysJWT, accPub, accJWT, storeDir)
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

	// --- The service (vault on KV) and its operator-grade admin.
	serviceCreds := issueUser(t, accKP, "service", nil)
	adminCreds := issueUser(t, accKP, "ops", &jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			e2eRoot + ".status", e2eRoot + ".xkey", e2eRoot + "." + accPub + ".ops.>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
	})
	toolsCreds := issueUser(t, accKP, "tools", nil) // unrestricted: serves the tool subjects

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
	kv, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "SOULIDENTITY_VAULT"})
	if err != nil {
		t.Fatalf("kv bucket: %v", err)
	}
	v, err := vault.New(vault.NewKVStore(kv), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	audit := &syncBuffer{}
	svc, err := service.New(v, string(surfaceSeed), newAuditLogger(audit),
		service.WithPrefix(e2ePrefix))
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	if _, err := svc.Start(ncService); err != nil {
		t.Fatalf("service start: %v", err)
	}

	ncAdmin, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(adminCreds))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(ncAdmin.Close)
	admin := client.New(ncAdmin, accPub, "ops", client.WithPrefix(e2ePrefix))
	if _, err := admin.ImportKey("agent", client.KindNATSAccountSigningKey, string(agentSeed), accPub, ""); err != nil {
		t.Fatalf("import agent role key: %v", err)
	}

	// --- Three tool responders on one unrestricted connection; each counts
	// its deliveries so refusals below can prove zero.
	ncTools, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(toolsCreds))
	if err != nil {
		t.Fatalf("tools connect: %v", err)
	}
	t.Cleanup(ncTools.Close)
	var seenA, seenB, seenC int32
	serve := func(name string, seen *int32) {
		if _, err := ncTools.Subscribe("SOULSTREAM.SVC."+name, func(msg *nats.Msg) {
			atomic.AddInt32(seen, 1)
			_ = msg.Respond([]byte("answered by " + name))
		}); err != nil {
			t.Fatalf("serve %s: %v", name, err)
		}
	}
	serve("toola", &seenA)
	serve("toolb", &seenB)
	serve("toolc", &seenC)
	opsArrived := make(chan *nats.Msg, 4)
	if _, err := ncTools.ChanSubscribe("SOULSTREAM.TOPICS.OPS.t-ab12", opsArrived); err != nil {
		t.Fatalf("ops subscribe: %v", err)
	}
	if err := ncTools.Flush(); err != nil {
		t.Fatalf("tools flush: %v", err)
	}

	// --- The tagged mint: sprite, two tools, one topic (D28; the tag values
	// are exactly what workloads' MintTags renders).
	mintAndConnect := func(user string, tags []string) (*nats.Conn, chan error) {
		t.Helper()
		ukp, _ := nkeys.CreateUser()
		upub, _ := ukp.PublicKey()
		token, err := admin.MintEphemeral("agent", user, upub, time.Minute, tags)
		if err != nil {
			t.Fatalf("mint %s: %v", user, err)
		}
		seed, _ := ukp.Seed()
		credsBytes, err := jwt.FormatUserConfig(token, seed)
		if err != nil {
			t.Fatalf("render %s creds: %v", user, err)
		}
		path := filepath.Join(t.TempDir(), user+".creds")
		if err := os.WriteFile(path, credsBytes, 0o600); err != nil {
			t.Fatalf("write %s creds: %v", user, err)
		}
		violations := make(chan error, 8)
		nc, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(path),
			nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, e error) { violations <- e }))
		if err != nil {
			t.Fatalf("%s did not admit: %v", user, err)
		}
		t.Cleanup(nc.Close)
		return nc, violations
	}
	expectViolation := func(what string, violations chan error) {
		t.Helper()
		select {
		case e := <-violations:
			if !strings.Contains(strings.ToLower(e.Error()), "permission") {
				t.Fatalf("%s: expected a permissions violation, got: %v", what, e)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s was NOT denied by the server", what)
		}
	}

	nc, violations := mintAndConnect("sprite",
		[]string{"persona:sprite", "topic:t-ab12", "tool:toola", "tool:toolb"})

	// SC-001, positive arm — multi-tag expansion measured: BOTH tagged tools
	// answer through the one credential.
	for _, name := range []string{"toola", "toolb"} {
		resp, err := nc.Request("SOULSTREAM.SVC."+name, []byte("ping"), 3*time.Second)
		if err != nil {
			t.Fatalf("granted tool %s failed: %v", name, err)
		}
		if string(resp.Data) != "answered by "+name {
			t.Fatalf("tool %s answered %q", name, resp.Data)
		}
	}

	// SC-001, refusal arm: the third tool refuses server-side, zero
	// deliveries to its responder.
	if err := nc.Publish("SOULSTREAM.SVC.toolc", []byte("nope")); err != nil {
		t.Fatalf("toolc publish call: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	expectViolation("ungranted tool publish", violations)
	if n := atomic.LoadInt32(&seenC); n != 0 {
		t.Fatalf("ungranted responder received %d deliveries, want 0", n)
	}

	// SC-002: the tagged topic's op subject is open — the publish ARRIVES —
	// and any other topic refuses.
	if err := nc.Publish("SOULSTREAM.TOPICS.OPS.t-ab12", []byte("op")); err != nil {
		t.Fatalf("tagged topic publish call: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	select {
	case <-opsArrived:
	case <-time.After(3 * time.Second):
		t.Fatal("the tagged topic op never arrived")
	}
	if err := nc.Publish("SOULSTREAM.TOPICS.OPS.foreign-cd34", []byte("op")); err != nil {
		t.Fatalf("foreign topic publish call: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	expectViolation("foreign topic publish", violations)

	// The subscribe side: the minted user's own notify subject resolves via
	// {{name()}} — attribution and reachability from the same fact.
	if _, err := nc.SubscribeSync("SOULSTREAM.PERSONA.NOTIFY.sprite"); err != nil {
		t.Fatalf("own notify subscribe: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	select {
	case e := <-violations:
		t.Fatalf("own notify subscribe drew a violation: %v", e)
	case <-time.After(300 * time.Millisecond):
	}

	// SC-003 — the zero-tag line drop measured: a tool-less mint still
	// admits (the SVC template line drops instead of failing auth) and
	// reaches no tool subject.
	lone, loneViolations := mintAndConnect("lone", []string{"persona:lone", "topic:t-ab12"})
	if err := lone.Publish("SOULSTREAM.SVC.toola", []byte("nope")); err != nil {
		t.Fatalf("lone toola publish call: %v", err)
	}
	if err := lone.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	expectViolation("tool-less credential reaching a tool", loneViolations)
}
