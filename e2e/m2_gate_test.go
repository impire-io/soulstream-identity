// The M2 cross-service gate (../soul-hq/03-IMPLEMENTATION/ROADMAP.md, milestone 2):
// a Soulstream record signed through the running SoulIdentity service
// verifies in a real realm [measured]. This module sits in the consumer
// position the cycle guard requires — it imports BOTH soulstream-identity and
// soulstream and wires soulstream's identity.Signer seam to
// soulstream-identity's PersonaSigner, which satisfies it structurally (neither
// core module imports the other).
package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/impire-io/soulstream-core/topic"
)

// TestM2GateRecordSignedThroughTheServiceVerifiesInTheRealm runs the whole
// consumer story on one operator-mode server:
//
//   - daan is EPHEMERAL: no per-user provisioning act exists anywhere —
//     the IAM-shaped acts are per-team (the role key; a team is the
//     account, the tenant — D28) and per-connection
//     (the minted credential); daan's persona key MATERIALIZES inside the
//     vault on first touch, owner-bound to the server-proven principal
//     (D26);
//   - daan holds ONE minted scoped credential whose template carries both
//     subject spaces — the SoulIdentity user ops and the Soulstream realm
//     (the shape the remote MCP node's per-user connections need);
//   - daan's realm client signs every op through client.PersonaSigner —
//     the process never holds the seed, which never existed outside the
//     vault at all;
//   - the reader builds its keyring FROM THE IDENTITY PLANE (keys.public,
//     the directory read — the vault that custodies the keys is the key
//     directory; there is no published per-user profile store) and sees
//     every op SigVerified — after first seeing unknown-key without a
//     keyring, the negative control that shows the verdict is earned, not
//     defaulted.
func TestM2GateRecordSignedThroughTheServiceVerifiesInTheRealm(t *testing.T) {
	// --- The realm: operator, SYS, one APP account with JetStream and a
	// scoped signing key template spanning both subject spaces.
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
	oc.Name = "m2-operator"
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
	ac.Name = "m2-app"
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	// The represented-user scope: the SoulIdentity user ops on the own
	// prefix (D25's op-tail gate — no management op is grantable here) plus
	// the Soulstream realm's subject space.
	scope := jwt.NewUserScope()
	scope.Key = askPub
	scope.Role = "soulstream-user"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList{
				client.Segment + ".status", client.Segment + ".xkey",
				client.Segment + ".{{account-subject()}}.{{name()}}.sign.record",
				client.Segment + ".{{account-subject()}}.{{name()}}.keys.public",
				"SOULSTREAM.>", "$JS.API.>", "$KV.>", "$O.>",
			}},
			Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>", "SOULSTREAM.>"}},
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

	// Operator-issued bootstrap users: the service, the operator (full op
	// space on its own prefix), and the reader (unrestricted — it also
	// provisions the realm artefacts).
	serviceCreds := issueUser(t, accKP, "service", nil)
	adminCreds := issueUser(t, accKP, "ops", &jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			client.Segment + ".status", client.Segment + ".xkey",
			client.Segment + "." + accPub + ".ops.>",
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{"_INBOX.>"}},
	})
	readerCreds := issueUser(t, accKP, "reader", nil)

	// --- The SoulIdentity service: vault on KV, both xkeys deployment-
	// supplied; no registry anywhere (D25).
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

	// --- The operator's acts are per-TEAM and per-CONNECTION only: the
	// role key bound to its account (the team, D28), and daan's minted
	// credential through the loud escape. Nothing names daan's persona —
	// no import, no profile, no row. Users are ephemeral (D26).
	ncAdmin, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(adminCreds))
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	t.Cleanup(ncAdmin.Close)
	admin := client.New(ncAdmin, accPub, "ops")
	if _, err := admin.ImportKey("acme", client.KindNATSAccountSigningKey, string(askSeed), accPub, ""); err != nil {
		t.Fatalf("import role key: %v", err)
	}
	minted, err := admin.MintCreds(accPub, "daan")
	if err != nil {
		t.Fatalf("mint creds: %v", err)
	}
	daanCreds := filepath.Join(t.TempDir(), "daan.creds")
	if err := os.WriteFile(daanCreds, []byte(minted.Creds), 0o600); err != nil {
		t.Fatalf("write creds: %v", err)
	}

	// --- The consumer wiring (M2): ONE connection for daan; the
	// SoulIdentity client and the Soulstream realm client share it. The
	// PersonaSigner satisfies soulstream's identity.Signer structurally,
	// and constructing it is daan's FIRST TOUCH: the persona key
	// materializes inside the vault at this call, owner-bound (D26) — the
	// seed has never existed anywhere else.
	ncDaan, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(daanCreds))
	if err != nil {
		t.Fatalf("daan connect: %v", err)
	}
	t.Cleanup(ncDaan.Close)
	si := client.New(ncDaan, accPub, "daan")
	signer, err := si.PersonaSigner("daan")
	if err != nil {
		t.Fatalf("persona signer: %v", err)
	}

	// The reader provisions the realm artefacts (streams, inbox, object
	// store, persona directory) before anyone publishes.
	ncReader, err := nats.Connect(srv.ClientURL(), nats.UserCredentials(readerCreds))
	if err != nil {
		t.Fatalf("reader connect: %v", err)
	}
	rcReader, err := realm.NewClient(t.Context(), ncReader, realm.Config{Realm: "proof"})
	if err != nil {
		t.Fatalf("reader realm client: %v", err)
	}
	t.Cleanup(func() { _ = rcReader.Close() })
	if _, err := rcReader.Provision(t.Context()); err != nil {
		t.Fatalf("provision: %v", err)
	}

	rcDaan, err := realm.NewClient(t.Context(), ncDaan, realm.Config{
		Realm: "proof", Persona: "daan", Signer: signer,
	})
	if err != nil {
		t.Fatalf("daan realm client: %v", err)
	}
	t.Cleanup(func() { _ = rcDaan.Close() })

	// Deliberately absent here: any author-side trust act. daan publishes
	// NO profile — there is no persona registry anywhere; the identity
	// plane is the key directory (D26) and the reader queries it below.

	// --- Publish through the seam: the announce, the baseline, and one
	// turn — every op signed by the vault, round-tripping the sealed
	// surface on daan's own prefix.
	h, err := topic.StartTopic(t.Context(), rcDaan, topic.StartTopicInput{
		Name: "m2-gate", SubjectMatter: "the cross-service proof",
	})
	if err != nil {
		t.Fatalf("start topic: %v", err)
	}
	if _, err := h.PostTurn(t.Context(), "signed through the vault; the seed never left it"); err != nil {
		t.Fatalf("post turn: %v", err)
	}

	// --- The reader verifies. Negative control first: with no keyring the
	// signed ops read unknown-key — the verified verdict below is earned.
	hr := topic.Open(rcReader, h.Path())
	bare, err := hr.Materialise(t.Context())
	if err != nil {
		t.Fatalf("materialise (no keyring): %v", err)
	}
	if bare.Announcement == nil || bare.Announcement.Sig != topic.SigUnknownKey {
		t.Fatalf("without a keyring the announcement must read unknown-key, got %+v", bare.Announcement)
	}

	// The trust path: the reader asks the IDENTITY PLANE for the author's
	// public key — the vault that custodies the keys is the key directory
	// (D26); no profile store, no out-of-band handoff. The keyring is
	// soulstream's, built from soulstream-identity's answer: the two systems
	// meeting exactly at the seam.
	authorPub, err := client.New(ncReader, accPub, "reader").PersonaPublicKey("daan")
	if err != nil {
		t.Fatalf("directory read: %v", err)
	}
	kr := &identity.Keyring{Keys: map[string][]string{"daan": {authorPub}}}
	hr.UseKeyring(kr)

	mt, err := hr.Materialise(t.Context())
	if err != nil {
		t.Fatalf("materialise: %v", err)
	}
	if mt.Announcement == nil || mt.Announcement.Sig != topic.SigVerified {
		t.Fatalf("announcement not verified: %+v", mt.Announcement)
	}
	if len(mt.Contributions) == 0 {
		t.Fatal("no contributions materialised")
	}
	for i, c := range mt.Contributions {
		if c.Sig != topic.SigVerified {
			t.Fatalf("contribution %d (%s) not verified: sig=%s", i, c.Type, c.Sig)
		}
	}

	// The chain closes: the key the reader trusted from the identity plane
	// is exactly the key the signer materialized — one key, one home.
	if signer.PublicKey() == "" || authorPub != signer.PublicKey() {
		t.Fatalf("directory key %q != signer key %q", authorPub, signer.PublicKey())
	}
}

// issueUser is the operator-side bootstrap: an account-signed user JWT
// (explicit permissions unless nil = unrestricted) rendered to a creds file.
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
