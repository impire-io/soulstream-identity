package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/nkeys"
)

func accountPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	return pub
}

func newRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := Open(filepath.Join(t.TempDir(), "registry.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return r
}

func TestPutGetListAllowed(t *testing.T) {
	r := newRegistry(t)
	acc := accountPub(t)

	id := Identity{Account: acc, User: "daan", Personas: []string{"daan", "smith"}, Role: "acme/role"}
	if err := r.Put(id); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := r.Get(acc, "daan")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.Role != "acme/role" || len(got.Personas) != 2 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Redeclaration replaces: the newest declaration wins.
	id.Personas = []string{"daan"}
	if err := r.Put(id); err != nil {
		t.Fatalf("re-Put: %v", err)
	}
	all, err := r.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 1 || len(all[0].Personas) != 1 {
		t.Fatalf("replace failed: %+v", all)
	}

	ok, err = r.AllowedPersona(acc, "daan", "daan")
	if err != nil || !ok {
		t.Fatalf("AllowedPersona(daan): ok=%v err=%v", ok, err)
	}
	ok, err = r.AllowedPersona(acc, "daan", "smith")
	if err != nil || ok {
		t.Fatalf("revoked persona still allowed: ok=%v err=%v", ok, err)
	}
	// An unregistered identity is allowed nothing.
	ok, err = r.AllowedPersona(acc, "ghost", "daan")
	if err != nil || ok {
		t.Fatalf("unregistered identity allowed: ok=%v err=%v", ok, err)
	}
}

func TestValidateRefusesBadShapes(t *testing.T) {
	r := newRegistry(t)
	if err := r.Put(Identity{Account: "not-a-key", User: "daan"}); err == nil {
		t.Fatal("bad account accepted")
	}
	if err := r.Put(Identity{Account: accountPub(t), User: ""}); err == nil {
		t.Fatal("empty user accepted")
	}
	if err := r.Put(Identity{Account: accountPub(t), User: "with space"}); err == nil {
		t.Fatal("user with whitespace accepted")
	}
	// User names ride NATS subjects: separators and wildcards are refused.
	for _, bad := range []string{"a.b", "a*", "a>", "a/b"} {
		if err := r.Put(Identity{Account: accountPub(t), User: bad}); err == nil {
			t.Fatalf("user %q accepted", bad)
		}
	}
}

func TestAdminFlagRoundTrips(t *testing.T) {
	r := newRegistry(t)
	acc := accountPub(t)
	if err := r.Put(Identity{Account: acc, User: "ops", Admin: true}); err != nil {
		t.Fatalf("Put admin: %v", err)
	}
	got, ok, err := r.Get(acc, "ops")
	if err != nil || !ok || !got.Admin {
		t.Fatalf("admin lost in roundtrip: ok=%v err=%v %+v", ok, err, got)
	}
}

func TestStrictDecodeFailsLoudly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, []byte(`{"identities":[],"kind":"legacy"}`), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := r.List(); err == nil {
		t.Fatal("unknown field decoded silently")
	}
}
