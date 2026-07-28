package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/nats-io/nkeys"
)

func newVault(t *testing.T) *Vault {
	t.Helper()
	v, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return v
}

func accountSeed(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return string(seed)
}

func personaSeed(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), pub
}

func TestImportRefusesOverwriteAndBadSeeds(t *testing.T) {
	v := newVault(t)
	seed := accountSeed(t)

	if _, err := v.Import("acme/role", KindNATSAccountSigningKey, seed); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := v.Import("acme/role", KindNATSAccountSigningKey, seed); !errors.Is(err, ErrExists) {
		t.Fatalf("re-import should be ErrExists, got %v", err)
	}
	// A user seed is not an account signing key.
	ukp, _ := nkeys.CreateUser()
	useed, _ := ukp.Seed()
	if _, err := v.Import("wrong-kind", KindNATSAccountSigningKey, string(useed)); err == nil {
		t.Fatal("user seed accepted as account signing key")
	}
	if _, err := v.Import("bad-persona", KindPersonaSigningKey, "not-base64!"); err == nil {
		t.Fatal("garbage accepted as persona seed")
	}
	if _, err := v.Import("../escape", KindNATSAccountSigningKey, seed); err == nil {
		t.Fatal("path-escaping name accepted")
	}
}

func TestSignNonceVerifiesAgainstPublicKey(t *testing.T) {
	v := newVault(t)
	entry, err := v.Import("acme/role", KindNATSAccountSigningKey, accountSeed(t))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	nonce := []byte("server-nonce-1234")
	sig, err := v.SignNonce("acme/role", nonce)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}
	pub, err := nkeys.FromPublicKey(entry.PublicKey)
	if err != nil {
		t.Fatalf("public keypair: %v", err)
	}
	if err := pub.Verify(nonce, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}

func TestSignRecordMatchesEd25519AndRefusesWrongKind(t *testing.T) {
	v := newVault(t)
	seed, pub := personaSeed(t)
	if _, err := v.Import("persona/daan", KindPersonaSigningKey, seed); err != nil {
		t.Fatalf("import persona: %v", err)
	}
	canonical := []byte(`{"v":1,"id":"x"}`)
	sigB64, err := v.SignRecord("persona/daan", canonical)
	if err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("signature does not verify")
	}
	// Kinds do not cross: a persona key cannot sign nonces, an nkey cannot
	// sign records.
	if _, err := v.SignNonce("persona/daan", []byte("n")); err == nil {
		t.Fatal("persona key signed a nonce")
	}
	if _, err := v.Import("acme/role", KindNATSAccountSigningKey, accountSeed(t)); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := v.SignRecord("acme/role", canonical); err == nil {
		t.Fatal("nkey signed a record")
	}
}

func TestGenerateUserKeyIsIdempotent(t *testing.T) {
	v := newVault(t)
	a, err := v.GenerateUserKey("user/ACC/daan")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := v.GenerateUserKey("user/ACC/daan")
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if a.PublicKey != b.PublicKey {
		t.Fatalf("user key changed across calls: %s != %s", a.PublicKey, b.PublicKey)
	}
	if !nkeys.IsValidPublicUserKey(a.PublicKey) {
		t.Fatalf("not a user public key: %s", a.PublicKey)
	}
}

func TestListAndGetNeverExposeSecrets(t *testing.T) {
	v := newVault(t)
	if _, err := v.Import("acme/role", KindNATSAccountSigningKey, accountSeed(t)); err != nil {
		t.Fatalf("import: %v", err)
	}
	entries, err := v.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "acme/role" {
		t.Fatalf("unexpected listing: %+v", entries)
	}
	if _, err := v.Get("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing should be ErrNotFound, got %v", err)
	}
}
