// The D9 gate (../soul-hq/02-DESIGN/soulstream-identity/sealing-keys.md,
// D50–D53): a sealed topic materialises entirely through the custodian —
// the X25519 sealing seed never exists outside the vault, the epoch key is
// unwrapped ONCE PER EPOCH (never per message: D9's no-oracle line,
// measured here), and the whole ceremony is the F1 posture: PersonaSigner
// + PersonaUnwrapper constructed (both first touches), the endorsed public
// halves ensure-published by the consumer. Like the M2 gate, this module
// sits in the consumer position the cycle guard requires: PersonaUnwrapper
// satisfies soulstream's identity.Unwrapper structurally.
package e2e_test

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

	"github.com/impire-io/soulstream-core/identity"
	"github.com/impire-io/soulstream-core/realm"
	"github.com/impire-io/soulstream-core/registry"
	"github.com/impire-io/soulstream-core/topic"
)

// countingUnwrapper counts Unwrap calls — the structural seam makes the
// measurement free. It is the no-oracle proof: calls == epochs, never
// messages.
type countingUnwrapper struct {
	inner interface {
		PublicKey() string
		Unwrap([]byte) ([]byte, error)
	}
	calls int64
}

func (c *countingUnwrapper) PublicKey() string { return c.inner.PublicKey() }
func (c *countingUnwrapper) Unwrap(wrapped []byte) ([]byte, error) {
	atomic.AddInt64(&c.calls, 1)
	return c.inner.Unwrap(wrapped)
}

func TestD9GateSealedTopicMaterialisesThroughTheCustodian(t *testing.T) {
	// --- The realm: operator, SYS, one APP account whose scoped template
	// is the CANONICAL persona scope from the one exported source — which
	// is itself part of the proof: the template must carry the new
	// seal.unwrap tail (D52), or nothing below works.
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
	oc.Name = "d9-operator"
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
	ac.Name = "d9-app"
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	scope := jwt.NewUserScope()
	scope.Key = askPub
	scope.Role = "soulstream-user"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList(client.PersonaScopePubAllow(""))},
			Sub: jwt.Permission{Allow: jwt.StringList(client.PersonaScopeSubAllow(""))},
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
jetstream { store_dir: %q }
`, opJWT, sysPub, sysPub, sysJWT, accPub, accJWT, t.TempDir())
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

	// --- The service, its operator, and the realm provisioner.
	serviceCreds := issueUser(t, accKP, "service", nil)
	adminCreds := issueUser(t, accKP, "ops", &jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			client.Segment + ".status", client.Segment + ".xkey",
			client.Segment + "." + accPub + ".ops.>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
	})
	provisionerCreds := issueUser(t, accKP, "provisioner", nil)

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
	svc, err := service.New(v, string(surfaceSeed), nil)
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
	admin := client.New(ncAdmin, accPub, "ops")
	if _, err := admin.ImportKey("acme", client.KindNATSAccountSigningKey, string(askSeed), accPub, ""); err != nil {
		t.Fatalf("import role key: %v", err)
	}

	ncProv, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(provisionerCreds))
	if err != nil {
		t.Fatalf("provisioner connect: %v", err)
	}
	t.Cleanup(ncProv.Close)
	rcProv, err := realm.NewClient(t.Context(), ncProv, realm.Config{Realm: "proof"})
	if err != nil {
		t.Fatalf("provisioner realm client: %v", err)
	}
	t.Cleanup(func() { _ = rcProv.Close() })
	if _, err := rcProv.Provision(t.Context()); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// --- Two custodial members. The D53 ceremony per member: minted creds,
	// PersonaSigner (signing first touch), EnsureSigningKey, PersonaUnwrapper
	// (sealing first touch), EnsureSealingKey with the custodial signer as
	// endorser. No seed ever exists outside the vault.
	type member struct {
		si        *client.Client
		rc        *realm.Client
		signer    *client.PersonaSigner
		unwrapper *client.PersonaUnwrapper
	}
	newMember := func(persona string) *member {
		t.Helper()
		minted, err := admin.MintCreds(accPub, persona)
		if err != nil {
			t.Fatalf("mint %s: %v", persona, err)
		}
		credsPath := filepath.Join(t.TempDir(), persona+".creds")
		if err := os.WriteFile(credsPath, []byte(minted.Creds), 0o600); err != nil {
			t.Fatalf("write %s creds: %v", persona, err)
		}
		nc, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(credsPath))
		if err != nil {
			t.Fatalf("%s connect: %v", persona, err)
		}
		t.Cleanup(nc.Close)
		si := client.New(nc, accPub, persona)
		signer, err := si.PersonaSigner(persona)
		if err != nil {
			t.Fatalf("%s signer: %v", persona, err)
		}
		unwrapper, err := si.PersonaUnwrapper(persona)
		if err != nil {
			t.Fatalf("%s unwrapper: %v", persona, err)
		}
		rc, err := realm.NewClient(t.Context(), nc, realm.Config{
			Realm: "proof", Persona: persona, Signer: signer,
		})
		if err != nil {
			t.Fatalf("%s realm client: %v", persona, err)
		}
		t.Cleanup(func() { _ = rc.Close() })
		if err := registry.EnsureSigningKey(t.Context(), rc, signer); err != nil {
			t.Fatalf("%s ensure signing key: %v", persona, err)
		}
		if err := registry.EnsureSealingKey(t.Context(), rc, signer, unwrapper.PublicKey()); err != nil {
			t.Fatalf("%s ensure sealing key: %v", persona, err)
		}
		return &member{si: si, rc: rc, signer: signer, unwrapper: unwrapper}
	}
	daan := newMember("daan")
	architect := newMember("architect")

	// --- A sealed conversation across two epochs: two turns in epoch 1
	// (one mentioning @architect), a bump, one more in epoch 2 — three
	// sealed messages, two epochs.
	h, err := topic.StartSealedTopic(t.Context(), daan.rc, topic.StartSealedTopicInput{
		Name:          "the custody proof",
		SubjectMatter: "the seed never leaves the vault",
		Members:       []string{"daan", "architect"},
	})
	if err != nil {
		t.Fatalf("start sealed topic: %v", err)
	}
	if _, err := h.PostSealedTurn(t.Context(), "epoch one, message one — @architect read this"); err != nil {
		t.Fatalf("post 1: %v", err)
	}
	if _, err := h.PostSealedTurn(t.Context(), "epoch one, message two"); err != nil {
		t.Fatalf("post 2: %v", err)
	}
	if _, err := h.BumpEpoch(t.Context(), []string{"daan", "architect"}); err != nil {
		t.Fatalf("bump epoch: %v", err)
	}
	if _, err := h.PostSealedTurn(t.Context(), "epoch two, message three"); err != nil {
		t.Fatalf("post 3: %v", err)
	}

	// --- Negative control first: without an unwrapper the view is
	// structure only — the plaintext below is earned by the custodian.
	bare := topic.Open(rcProv, h.Path())
	bview, err := bare.Materialise(t.Context())
	if err != nil {
		t.Fatalf("materialise (no unwrapper): %v", err)
	}
	if !bview.Sealed || bview.Announcement == nil || bview.Announcement.Name != "" {
		t.Fatalf("structure-only view leaked: %+v", bview.Announcement)
	}
	for _, c := range bview.Contributions {
		if strings.Contains(c.Body, "message") {
			t.Fatalf("structure-only view leaked a body: %+v", c)
		}
	}

	// A foreign persona cannot even construct architect's unwrapper —
	// fail-fast at the constructor, not at first materialise.
	if _, err := daan.si.PersonaUnwrapper("architect"); err == nil ||
		!strings.Contains(err.Error(), "another principal") {
		t.Fatalf("foreign unwrapper construction: %v", err)
	}

	// --- The positive: architect materialises the whole conversation
	// through the counting custodian.
	counting := &countingUnwrapper{inner: architect.unwrapper}
	ha := topic.Open(architect.rc, h.Path())
	ha.UseSealing(counting)
	daanPub, err := architect.si.PersonaPublicKey("daan")
	if err != nil {
		t.Fatalf("directory read: %v", err)
	}
	archPub, err := architect.si.PersonaPublicKey("architect")
	if err != nil {
		t.Fatalf("directory read: %v", err)
	}
	ha.UseKeyring(&identity.Keyring{Keys: map[string][]string{
		"daan": {daanPub}, "architect": {archPub},
	}})
	view, err := ha.Materialise(t.Context())
	if err != nil {
		t.Fatalf("materialise through the custodian: %v", err)
	}
	if !view.Sealed || view.Epoch != 2 {
		t.Fatalf("sealed/epoch = %v/%d, want true/2", view.Sealed, view.Epoch)
	}
	if view.Announcement == nil || view.Announcement.Name != "the custody proof" {
		t.Fatalf("announcement name not unsealed: %+v", view.Announcement)
	}
	if len(view.Contributions) != 3 {
		t.Fatalf("contributions = %d, want 3", len(view.Contributions))
	}
	for i, c := range view.Contributions {
		if !strings.Contains(c.Body, "message") {
			t.Fatalf("contribution %d not unsealed: %+v", i, c)
		}
		if c.Sig != topic.SigVerified {
			t.Fatalf("contribution %d signature = %s, want verified", i, c.Sig)
		}
	}

	// The no-oracle measurement (D9, D51): one unwrap per EPOCH — two —
	// against three sealed messages. A per-message custodian would read 3+.
	if got := atomic.LoadInt64(&counting.calls); got != 2 {
		t.Fatalf("unwrap calls = %d for 3 messages in 2 epochs — want exactly 2 (one per epoch)", got)
	}

	// --- The notify path: the sealed mention body (arbitrary length, the
	// second call shape of the one op) opens through the custodian — which
	// also proves the vault's key derivation is byte-compatible with core's
	// WrapForSealingKey targets.
	notes, err := topic.FetchInbox(t.Context(), architect.rc, "architect", 0, nil)
	if err != nil || len(notes) != 1 {
		t.Fatalf("inbox = %d notes (%v), want 1", len(notes), err)
	}
	if notes[0].SealedBody == "" {
		t.Fatalf("the mention body must travel sealed: %+v", notes[0])
	}
	opened, err := notes[0].Unseal(architect.unwrapper)
	if err != nil || opened.Topic != h.Path() || opened.Author != "daan" {
		t.Fatalf("unsealed notification = %+v (%v)", opened, err)
	}
	// A body sealed to architect must not open for daan — the custodian
	// enforces ownership, not the caller's honesty.
	if _, err := notes[0].Unseal(daan.unwrapper); err == nil {
		t.Fatal("a body sealed to architect opened for daan")
	}

	// --- Article I, closed: the directory serves public halves only, and
	// they are exactly the custodians' — one key, one home, never a seed.
	sealPub, err := architect.si.SealingPublicKey("daan")
	if err != nil || sealPub != daan.unwrapper.PublicKey() {
		t.Fatalf("directory sealing key %q != custodian %q (%v)", sealPub, daan.unwrapper.PublicKey(), err)
	}
}
