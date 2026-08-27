package vault

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"
)

func sealingVault(t *testing.T, store Store) *Vault {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := New(store, string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	return v
}

func wrapTo(t *testing.T, publicB64 string, plain []byte) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(publicB64)
	if err != nil || len(raw) != 32 {
		t.Fatalf("sealing public key %q is not 32 raw base64 bytes", publicB64)
	}
	var pub [32]byte
	copy(pub[:], raw)
	wrapped, err := box.SealAnonymous(nil, plain, &pub, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return wrapped
}

// TestSealingKeyRoundTrip (spec 005 FR-001): generate → wrap to the derived
// public half → unwrap inside the vault, for the 32-byte epoch-key shape and
// an arbitrary-length notify shape.
func TestSealingKeyRoundTrip(t *testing.T) {
	v := sealingVault(t, NewMemStore())
	acc, _ := nkeys.CreateAccount()
	accPub, _ := acc.PublicKey()
	e, err := v.GenerateSealingKey("sealing/daan", accPub, "daan")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if e.Kind != KindPersonaSealingKey || e.Account != accPub || e.User != "daan" {
		t.Fatalf("entry %+v", e)
	}

	for _, plain := range [][]byte{
		[]byte("0123456789abcdef0123456789abcdef"), // 32 bytes — the epoch-key shape
		[]byte(`{"topic":"t-ab12","body":"a sealed notify body of arbitrary length"}`),
	} {
		got, err := v.Unwrap("sealing/daan", wrapTo(t, e.PublicKey, plain))
		if err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		if string(got) != string(plain) {
			t.Fatalf("round trip changed the plaintext")
		}
	}

	// Idempotent first touch: the same owner gets the same key back.
	again, err := v.GenerateSealingKey("sealing/daan", accPub, "daan")
	if err != nil || again.PublicKey != e.PublicKey {
		t.Fatalf("get-or-generate not idempotent: %v %+v", err, again)
	}
}

// TestSealingKeyRefusals: wrong-key unwrap fails; kind mismatches refuse in
// both directions; bindings required; names immutable; foreign owner refused.
func TestSealingKeyRefusals(t *testing.T) {
	v := sealingVault(t, NewMemStore())
	acc, _ := nkeys.CreateAccount()
	accPub, _ := acc.PublicKey()
	a, _ := v.GenerateSealingKey("sealing/a", accPub, "a")
	if _, err := v.GenerateSealingKey("sealing/b", accPub, "b"); err != nil {
		t.Fatalf("generate b: %v", err)
	}

	// A box sealed to a is not openable by b.
	if _, err := v.Unwrap("sealing/b", wrapTo(t, a.PublicKey, []byte("secret"))); err == nil ||
		!strings.Contains(err.Error(), "not sealed to this key") {
		t.Fatalf("cross-key unwrap: %v", err)
	}
	// Kind mismatch, both directions.
	if _, err := v.SignRecord("sealing/a", []byte("c")); err == nil {
		t.Fatal("SignRecord accepted a sealing key")
	}
	if _, err := v.GeneratePersonaKey("persona/p", accPub, "p"); err != nil {
		t.Fatalf("persona: %v", err)
	}
	if _, err := v.Unwrap("persona/p", []byte("x")); err == nil {
		t.Fatal("Unwrap accepted a signing key")
	}
	// Binding required.
	if _, err := v.Import("sealing/loose", KindPersonaSealingKey,
		base64.StdEncoding.EncodeToString(make([]byte, 32)), "", ""); err == nil {
		t.Fatal("unbound sealing import accepted")
	}
	// Immutable.
	if _, err := v.Import("sealing/a", KindPersonaSealingKey,
		base64.StdEncoding.EncodeToString(make([]byte, 32)), accPub, "a"); err == nil {
		t.Fatal("overwrite accepted")
	}
	// Foreign owner refused on generate.
	if _, err := v.GenerateSealingKey("sealing/a", accPub, "impostor"); err == nil {
		t.Fatal("foreign-owner generate accepted")
	}
}

// racingStore misses its first Get so a generate races a concurrent winner:
// Get says absent, Create says exists — the re-Get must return the winner.
type racingStore struct {
	*MemStore
	misses int
}

func (s *racingStore) Get(name string) ([]byte, error) {
	if s.misses > 0 {
		s.misses--
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return s.MemStore.Get(name)
}

// TestSealingKeyFirstTouchRace (spec 005 edge case): the cross-instance
// first-touch race resolves to the winner's entry, never a spurious refusal.
func TestSealingKeyFirstTouchRace(t *testing.T) {
	mem := NewMemStore()
	acc, _ := nkeys.CreateAccount()
	accPub, _ := acc.PublicKey()

	winner := sealingVault(t, mem)
	// Note: both vaults must share the first key to read each other's
	// records — reuse the winner's vault for the racer over a missing Get.
	won, err := winner.GenerateSealingKey("sealing/daan", accPub, "daan")
	if err != nil {
		t.Fatalf("winner: %v", err)
	}
	racer := &Vault{store: &racingStore{MemStore: mem, misses: 1}, first: winner.first, firstPub: winner.firstPub}
	got, err := racer.GenerateSealingKey("sealing/daan", accPub, "daan")
	if err != nil {
		t.Fatalf("racer refused: %v", err)
	}
	if got.PublicKey != won.PublicKey {
		t.Fatal("racer did not return the winner's key")
	}
}
