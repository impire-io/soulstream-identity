package client_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
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
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/client"
	"github.com/impire-io/soulidentity/internal/service"
	"github.com/impire-io/soulidentity/internal/vault"
)

// The M3 e2e runs under a shared ecosystem prefix (D14 as amended, journey
// 0011): the scope templates, the observer, and every client carry it — the
// M4 e2e covers the bare default.
const (
	e2ePrefix = "prod.soulstream"
	e2eRoot   = e2ePrefix + "." + client.Segment
)

// TestM3GateAgainstOperatorModeServer is the NATS-native rebuild's end-to-end
// proof [measured] — the M3 gate (hq/02-DESIGN/nats-surface.md, acceptance
// criteria), re-proven on the D25 shape (no registry; the ACL gates the op
// tail, the bindings gate the data): a NATS server in operator mode with
// JetStream, the service on its sealed surface, a scoped signing key whose
// template pins each user to its own prefix AND to the user ops only
// (D15/D25), and five measured proofs:
//
//  1. signing with a persona key the caller does not own is refused and
//     logged (the owner binding, D6 as amended);
//  2. a request body on the wire is ciphertext to an account-privileged
//     observer;
//  3. the vault's KV bucket holds ciphertext only at rest, shown against a
//     plaintext positive control;
//  4. a caller on another identity's prefix is refused by the server and
//     never reaches the service;
//  5. a represented user publishing a management op on its OWN prefix is
//     refused by the server and never reaches the service — the D25 op-tail
//     gate, zero service decisions.
func TestM3GateAgainstOperatorModeServer(t *testing.T) {
	// --- The realm: operator, SYS, one account with JetStream and a scoped
	// signing key template that pins users to their own prefix and to the
	// user ops (D15, D25).
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
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	// The represented-user scope: own prefix AND the user ops only — the
	// op-tail half of D25's ACL gate. Management op subjects are simply not
	// in the template.
	scope := jwt.NewUserScope()
	scope.Key = askPub
	scope.Role = "soulidentity-user"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList{
				e2eRoot + ".status", e2eRoot + ".xkey",
				e2eRoot + ".{{account-subject()}}.{{name()}}.sign.record",
				e2eRoot + ".{{account-subject()}}.{{name()}}.keys.public",
			}},
			Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
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

	// Operator-issued users (the pre-service bootstrap): the service itself
	// (unrestricted in its account), the first admin, and a privileged
	// observer that can read the service's whole subject space.
	serviceCreds := issueUser(t, accKP, "service", nil)
	adminCreds := issueUser(t, accKP, "ops", &jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			e2eRoot + ".status", e2eRoot + ".xkey", e2eRoot + "." + accPub + ".ops.>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
	})
	observerCreds := issueUser(t, accKP, "observer", &jwt.Permissions{
		Sub: jwt.Permission{Allow: jwt.StringList{e2eRoot + ".>"}},
	})

	// --- The service: vault on the KV backend, both xkeys deployment-
	// supplied (D13/D17). No registry: the operator's creds ARE the admin
	// declaration — their permission template grants the op space (D25).
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
	if err := v.Verify(); err != nil {
		t.Fatalf("vault verify: %v", err)
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

	// --- The operator provisions through the sealed surface: the team (the
	// scoped signing key, bound to its account — D24) and daan's persona key
	// (bound to its owner — D6 as amended) enter the vault and are never
	// seen again; daan's creds leave through the loud escape (D7). The key
	// imports ARE the declarations: no registry row exists anywhere.
	ncAdmin, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(adminCreds))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(ncAdmin.Close)
	admin := client.New(ncAdmin, accPub, "ops", client.WithPrefix(e2ePrefix))
	if _, err := admin.Status(); err != nil {
		t.Fatalf("status: %v", err)
	}
	if _, err := admin.ImportKey("acme", client.KindNATSAccountSigningKey, string(askSeed), accPub, ""); err != nil {
		t.Fatalf("import signing key: %v", err)
	}
	_, personaPriv, _ := ed25519.GenerateKey(nil)
	personaSeed := base64.StdEncoding.EncodeToString(personaPriv.Seed())
	personaEntry, err := admin.ImportKey(client.PersonaKeyName("daan"), client.KindPersonaSigningKey, personaSeed, accPub, "daan")
	if err != nil {
		t.Fatalf("import persona key: %v", err)
	}
	// A second persona, owned by ops — proof 1's foil: daan must not be able
	// to sign with it.
	_, opsPriv, _ := ed25519.GenerateKey(nil)
	opsSeed := base64.StdEncoding.EncodeToString(opsPriv.Seed())
	if _, err := admin.ImportKey(client.PersonaKeyName("ops"), client.KindPersonaSigningKey, opsSeed, accPub, "ops"); err != nil {
		t.Fatalf("import ops persona key: %v", err)
	}
	minted, err := admin.MintCreds(accPub, "daan")
	if err != nil {
		t.Fatalf("mint creds: %v", err)
	}
	daanCreds := filepath.Join(t.TempDir(), "daan.creds")
	if err := os.WriteFile(daanCreds, []byte(minted.Creds), 0o600); err != nil {
		t.Fatalf("write creds: %v", err)
	}

	// --- daan connects with the minted scoped JWT; the template expanded to
	// exactly daan's prefix, server-side.
	violations := make(chan error, 8)
	ncDaan, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(daanCreds),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			violations <- err
		}))
	if err != nil {
		t.Fatalf("daan connect: %v", err)
	}
	t.Cleanup(ncDaan.Close)
	daan := client.New(ncDaan, accPub, "daan", client.WithPrefix(e2ePrefix))

	// Proof 2 setup: the observer captures daan's request off the wire.
	ncObserver, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(observerCreds))
	if err != nil {
		t.Fatalf("observer connect: %v", err)
	}
	t.Cleanup(ncObserver.Close)
	captured := make(chan *nats.Msg, 8)
	if _, err := ncObserver.ChanSubscribe(e2eRoot+"."+accPub+".daan.>", captured); err != nil {
		t.Fatalf("observer subscribe: %v", err)
	}
	if err := ncObserver.Flush(); err != nil {
		t.Fatalf("observer flush: %v", err)
	}

	// The authorized flow, through the Signer seam's shape (soulstream M2's
	// wiring point): the bound signer resolves its public key over
	// keys.public and signs over sign.record.
	signer, err := daan.PersonaSigner("daan")
	if err != nil {
		t.Fatalf("persona signer: %v", err)
	}
	if signer.PublicKey() != personaEntry.PublicKey {
		t.Fatalf("signer public key %q, want %q", signer.PublicKey(), personaEntry.PublicKey)
	}
	canonical := []byte("canonical-record-bytes")
	sig, err := signer.Sign(canonical)
	if err != nil {
		t.Fatalf("owner signing refused: %v", err)
	}
	personaPub, _ := base64.StdEncoding.DecodeString(personaEntry.PublicKey)
	rawSig, _ := base64.StdEncoding.DecodeString(sig)
	if !ed25519.Verify(ed25519.PublicKey(personaPub), canonical, rawSig) {
		t.Fatal("signature does not verify against the persona key")
	}

	// --- Proof 1 [measured]: signing with a persona the caller does not own
	// — a key that exists, bound to ops — is refused and logged; a missing
	// key refuses identically.
	if _, err := daan.SignRecord("ops", canonical); err == nil ||
		!strings.Contains(err.Error(), "no persona key") {
		t.Fatalf("non-owner signing must refuse, got: %v", err)
	}
	if _, err := daan.SignRecord("ghost", canonical); err == nil ||
		!strings.Contains(err.Error(), "no persona key") {
		t.Fatalf("missing-key signing must refuse identically, got: %v", err)
	}
	if !strings.Contains(audit.String(), "no persona key") {
		t.Fatal("the owner-binding refusal is not in the audit log")
	}

	// --- Proof 2 [measured]: the captured request is ciphertext — the sealed
	// envelope shape, with no trace of the plaintext body.
	select {
	case msg := <-captured:
		var env struct {
			XKey string `json:"xkey"`
			Data []byte `json:"data"`
		}
		if err := json.Unmarshal(msg.Data, &env); err != nil || env.XKey == "" || len(env.Data) == 0 {
			t.Fatalf("captured request is not a sealed envelope: %s", msg.Data)
		}
		if bytes.Contains(msg.Data, []byte("canonical")) ||
			bytes.Contains(msg.Data, []byte(base64.StdEncoding.EncodeToString(canonical))) {
			t.Fatal("captured request leaks the plaintext body")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("observer captured nothing")
	}

	// --- Proof 4 [measured]: another identity's prefix is refused by the
	// server itself — the request times out and never reaches the service.
	auditBefore := audit.String()
	imposter := client.New(ncDaan, accPub, "ops",
		client.WithPrefix(e2ePrefix), client.WithTimeout(1500*time.Millisecond))
	if _, err := imposter.Keys(); err == nil {
		t.Fatal("daan reached ops's prefix")
	}
	select {
	case err := <-violations:
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cross-prefix publish drew no permission violation")
	}
	if diff := strings.TrimPrefix(audit.String(), auditBefore); strings.Contains(diff, "keys.list") {
		t.Fatalf("the cross-prefix request reached the service: %s", diff)
	}

	// --- Proof 5 [measured]: the op-tail gate (D25). daan publishes a
	// management op on his OWN prefix; the scope template does not grant the
	// op subject, so the server refuses the publish and the service records
	// zero decisions — the admin boundary with no admin flag anywhere.
	auditBefore = audit.String()
	ownPrefixAdmin := client.New(ncDaan, accPub, "daan",
		client.WithPrefix(e2ePrefix), client.WithTimeout(1500*time.Millisecond))
	if _, err := ownPrefixAdmin.Keys(); err == nil {
		t.Fatal("a represented user reached keys.list on its own prefix")
	}
	select {
	case err := <-violations:
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatalf("expected a permissions violation, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("own-prefix management op drew no permission violation")
	}
	if diff := strings.TrimPrefix(audit.String(), auditBefore); strings.Contains(diff, "keys.list") {
		t.Fatalf("the op-tail-refused request reached the service: %s", diff)
	}

	// --- Proof 3 [measured]: the vault's stream holds ciphertext only at
	// rest, proven against a plaintext positive control in another bucket.
	ctrl, err := js.CreateOrUpdateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: "CONTROL"})
	if err != nil {
		t.Fatalf("control bucket: %v", err)
	}
	if _, err := ctrl.Put(t.Context(), "leak-test", []byte(string(askSeed))); err != nil {
		t.Fatalf("control put: %v", err)
	}
	ncService.Close()
	ncAdmin.Close()
	ncDaan.Close()
	ncObserver.Close()
	srv.Shutdown()
	srv.WaitForShutdown()

	store := readTree(t, storeDir)
	if !bytes.Contains(store, askSeed) {
		t.Fatal("positive control failed: the plaintext control seed is not findable in the store")
	}
	vaultStore := readTree(t, filepath.Join(storeDir, "jetstream", accPub, "streams", "KV_SOULIDENTITY_VAULT"))
	for name, secret := range map[string][]byte{
		"signing key seed": askSeed,
		"persona seed":     []byte(personaSeed),
		"record shape":     []byte(`"secret"`),
	} {
		if bytes.Contains(vaultStore, secret) {
			t.Fatalf("the vault stream holds a plaintext %s at rest", name)
		}
	}
}

// issueUser is the operator-side bootstrap: an account-signed user JWT (with
// explicit permissions unless nil = unrestricted) rendered to a creds file.
func issueUser(t *testing.T, accKP nkeys.KeyPair, name string, perms *jwt.Permissions) string {
	t.Helper()
	ukp, _ := nkeys.CreateUser()
	uPub, _ := ukp.PublicKey()
	uc := jwt.NewUserClaims(uPub)
	uc.Name = name
	if perms != nil {
		uc.Permissions = *perms
	}
	token, err := uc.Encode(accKP)
	if err != nil {
		t.Fatalf("issue %s: %v", name, err)
	}
	seed, _ := ukp.Seed()
	creds, err := jwt.FormatUserConfig(token, seed)
	if err != nil {
		t.Fatalf("creds %s: %v", name, err)
	}
	path := filepath.Join(t.TempDir(), name+".creds")
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatalf("write creds %s: %v", name, err)
	}
	return path
}

// readTree concatenates every file under dir for byte-level leak checks.
func readTree(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		buf.Write(data)
		return nil
	})
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	return buf.Bytes()
}

// syncBuffer is a mutex-guarded buffer: the service logs from NATS callback
// goroutines while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newAuditLogger(w *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, nil))
}
