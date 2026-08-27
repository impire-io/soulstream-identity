package service

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/impire-io/soulstream-identity/internal/vault"
)

func wrapToB64(t *testing.T, publicB64 string, plain []byte) []byte {
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

// TestSealUnwrapOwnKeyMaterializesAndOpens (spec 005 FR-002): the caller's
// own sealing key materializes on first touch through keys.public, and
// seal.unwrap releases the artifact — for the epoch-key shape and the
// arbitrary-length notify shape through the same one op (D51).
func TestSealUnwrapOwnKeyMaterializesAndOpens(t *testing.T) {
	s, _, accPub := harness(t)

	// First touch through the directory door (D52).
	var entry vault.Entry
	if err := call(t, s, accPub, "daan", "keys.public",
		map[string]string{"key": "sealing/daan"}, &entry); err != nil {
		t.Fatalf("keys.public: %v", err)
	}
	if entry.Kind != vault.KindPersonaSealingKey || entry.User != "daan" {
		t.Fatalf("entry %+v", entry)
	}

	for _, plain := range [][]byte{
		[]byte("0123456789abcdef0123456789abcdef"),
		[]byte("a sealed notify body, longer than an epoch key by some margin"),
	} {
		var out sealUnwrapResponse
		if err := call(t, s, accPub, "daan", "seal.unwrap", map[string]any{
			"key": "sealing/daan", "wrapped": wrapToB64(t, entry.PublicKey, plain),
		}, &out); err != nil {
			t.Fatalf("seal.unwrap: %v", err)
		}
		if string(out.Secret) != string(plain) || out.PublicKey != entry.PublicKey {
			t.Fatal("unwrap round trip changed the artifact")
		}
	}

	// Absent own key on a fresh persona: materializes, then fails honestly —
	// the wrap predates the key's birth (spec 005 edge case).
	if err := call(t, s, accPub, "fresh", "seal.unwrap", map[string]any{
		"key": "sealing/fresh", "wrapped": wrapToB64(t, entry.PublicKey, []byte("x")),
	}, nil); err == nil || !strings.Contains(err.Error(), "not sealed to this key") {
		t.Fatalf("fresh-key unwrap: %v", err)
	}
}

// TestSealUnwrapRefusals (spec 005 FR-002): foreign keys refuse identically
// whether they exist or not — the refusal must not probe the vault.
func TestSealUnwrapRefusals(t *testing.T) {
	s, _, accPub := harness(t)
	if err := call(t, s, accPub, "owner", "keys.public",
		map[string]string{"key": "sealing/owner"}, nil); err != nil {
		t.Fatalf("materialize owner: %v", err)
	}

	existing := call(t, s, accPub, "daan", "seal.unwrap",
		map[string]any{"key": "sealing/owner", "wrapped": []byte("x")}, nil)
	absent := call(t, s, accPub, "daan", "seal.unwrap",
		map[string]any{"key": "sealing/ghost", "wrapped": []byte("x")}, nil)
	if existing == nil || absent == nil {
		t.Fatal("foreign unwrap was not refused")
	}
	want := `has no sealing key`
	if !strings.Contains(existing.Error(), want) || !strings.Contains(absent.Error(), want) {
		t.Fatalf("refusals differ or mis-name: existing=%v absent=%v", existing, absent)
	}
	if strings.Replace(existing.Error(), "sealing/owner", "sealing/ghost", 1) != absent.Error() {
		t.Fatalf("refusals must be identical up to the name: %v vs %v", existing, absent)
	}

	// The persona grammar refuses non-sealing names on the op.
	if err := call(t, s, accPub, "daan", "seal.unwrap",
		map[string]any{"key": "persona/daan", "wrapped": []byte("x")}, nil); err == nil ||
		!strings.Contains(err.Error(), "sealing keys are named") {
		t.Fatalf("grammar refusal: %v", err)
	}
}

// TestSealingDirectoryRead (D52): any authenticated caller reads any
// persona's sealing public half; the public form carries no secret field.
func TestSealingDirectoryRead(t *testing.T) {
	s, _, accPub := harness(t)
	var own vault.Entry
	if err := call(t, s, accPub, "owner", "keys.public",
		map[string]string{"key": "sealing/owner"}, &own); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	var read vault.Entry
	if err := call(t, s, accPub, "reader", "keys.public",
		map[string]string{"key": "sealing/owner"}, &read); err != nil {
		t.Fatalf("directory read: %v", err)
	}
	if read.PublicKey != own.PublicKey || read.Kind != vault.KindPersonaSealingKey {
		t.Fatalf("directory read %+v", read)
	}
	// A missing foreign sealing key is a plain not-found on the open read.
	if err := call(t, s, accPub, "reader", "keys.public",
		map[string]string{"key": "sealing/nobody"}, nil); err == nil ||
		!strings.Contains(err.Error(), "no sealing key") {
		t.Fatalf("missing directory read: %v", err)
	}
}
