package secrets

import (
	"bytes"
	"errors"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
)

func testService(t *testing.T) (*Service, *sealedstore.MemStore) {
	t.Helper()
	kp, _ := nkeys.CreateCurveKeys()
	seed, _ := kp.Seed()
	mem := sealedstore.NewMemStore()
	s, err := New(mem, string(seed))
	if err != nil {
		t.Fatal(err)
	}
	return s, mem
}

// TestCRUDAndCAS: the D2 discipline — a conditional write on a stale
// revision loses loudly; the winner's revision is the line.
func TestCRUDAndCAS(t *testing.T) {
	s, _ := testService(t)
	rev, err := s.Put("daan", "github/webhook", []byte("hunter2"), 0)
	if err != nil || rev == 0 {
		t.Fatalf("create: %v rev=%d", err, rev)
	}
	if _, err := s.Put("daan", "github/webhook", []byte("again"), 0); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("re-create: want CAS conflict, got %v", err)
	}
	got, gotRev, err := s.Get("daan", "github/webhook")
	if err != nil || !bytes.Equal(got, []byte("hunter2")) || gotRev != rev {
		t.Fatalf("get: %v %q rev=%d", err, got, gotRev)
	}
	rev2, err := s.Put("daan", "github/webhook", []byte("rotated"), rev)
	if err != nil || rev2 <= rev {
		t.Fatalf("conditional update: %v", err)
	}
	if _, err := s.Put("daan", "github/webhook", []byte("stale"), rev); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale write: want CAS conflict, got %v", err)
	}
	if err := s.Delete("daan", "github/webhook"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, _, err := s.Get("daan", "github/webhook"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: want not-found, got %v", err)
	}
	if err := s.Delete("daan", "github/webhook"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("re-delete: want not-found, got %v", err)
	}
}

// TestPersonaTreesAreStructural (D3/D4): the same path in two personas
// names two secrets; a list never crosses trees.
func TestPersonaTreesAreStructural(t *testing.T) {
	s, _ := testService(t)
	if _, err := s.Put("daan", "api/token", []byte("daans"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("scribe", "api/token", []byte("scribes"), 0); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Get("scribe", "api/token")
	if err != nil || string(got) != "scribes" {
		t.Fatalf("scribe's tree: %v %q", err, got)
	}
	paths, err := s.List("daan")
	if err != nil || len(paths) != 1 || paths[0] != "api/token" {
		t.Fatalf("daan's list: %v %v", err, paths)
	}
}

// TestPathRefusals: reach is structural — a path that could escape the
// scheme refuses before any storage touch.
func TestPathRefusals(t *testing.T) {
	s, _ := testService(t)
	for _, bad := range []string{"", "/", "a//b", "../up", ".hidden", "a/" + string(make([]byte, 70)), "a/b/c/d/e/f/g/h/i"} {
		if _, err := s.Put("daan", bad, []byte("x"), 0); !errors.Is(err, ErrBadPath) {
			t.Errorf("path %q: want ErrBadPath, got %v", bad, err)
		}
	}
}

// TestAtRestPositiveControl (the D13 idiom): the secret greps from the
// plaintext and NOT from the sealed bytes.
func TestAtRestPositiveControl(t *testing.T) {
	s, mem := testService(t)
	secret := []byte("rt-secret-value-cleartext")
	if _, err := s.Put("daan", "the/secret", secret, 0); err != nil {
		t.Fatal(err)
	}
	sealed := mem.SealedBytes("secret/daan/the/secret")
	if len(sealed) == 0 {
		t.Fatal("nothing at rest")
	}
	if bytes.Contains(sealed, secret) {
		t.Fatal("secret rests in cleartext")
	}
	// Positive control: the same grep finds it in a plaintext encoding.
	if !bytes.Contains([]byte(`{"value":"rt-secret-value-cleartext"}`), secret) {
		t.Fatal("positive control broken — the grep itself is wrong")
	}
}
