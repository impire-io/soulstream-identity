package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
)

func newTestVault(t *testing.T) (*Vault, *MemStore) {
	t.Helper()
	kp, err := nkeys.CreateCurveKeys()
	if err != nil {
		t.Fatalf("curve keys: %v", err)
	}
	seed, _ := kp.Seed()
	store := NewMemStore()
	v, err := New(store, string(seed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	return v, store
}

func userSeed(t *testing.T) string {
	t.Helper()
	kp, _ := nkeys.CreateUser()
	seed, _ := kp.Seed()
	return string(seed)
}

func accountPub(t *testing.T) string {
	t.Helper()
	kp, _ := nkeys.CreateAccount()
	pub, _ := kp.PublicKey()
	return pub
}

func personaSeed(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	return base64.StdEncoding.EncodeToString(priv.Seed())
}

func TestNewRejectsNonCurveSeed(t *testing.T) {
	if _, err := New(NewMemStore(), userSeed(t)); err == nil {
		t.Fatal("a user seed must not open a vault")
	}
	if _, err := New(nil, ""); err == nil {
		t.Fatal("a nil store must be refused")
	}
}

func TestImportGetListRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	seed := userSeed(t)
	e, err := v.Import("user/acc/daan", KindNATSUserKey, seed, "", "")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !nkeys.IsValidPublicUserKey(e.PublicKey) {
		t.Fatalf("entry public key %q is not a user key", e.PublicKey)
	}
	got, err := v.Get("user/acc/daan")
	if err != nil || got != e {
		t.Fatalf("get: %v, %+v != %+v", err, got, e)
	}
	list, err := v.List()
	if err != nil || len(list) != 1 || list[0] != e {
		t.Fatalf("list: %v, %+v", err, list)
	}
}

func TestImportRefusesOverwrite(t *testing.T) {
	v, _ := newTestVault(t)
	if _, err := v.Import("k", KindNATSUserKey, userSeed(t), "", ""); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if _, err := v.Import("k", KindNATSUserKey, userSeed(t), "", ""); !errors.Is(err, ErrExists) {
		t.Fatalf("second import: want ErrExists, got %v", err)
	}
}

func TestStoreHoldsCiphertextOnly(t *testing.T) {
	v, store := newTestVault(t)
	seed := userSeed(t)
	if _, err := v.Import("k", KindNATSUserKey, seed, "", ""); err != nil {
		t.Fatalf("import: %v", err)
	}
	sealed, err := store.Get("k")
	if err != nil {
		t.Fatalf("raw get: %v", err)
	}
	if bytes.Contains(sealed, []byte(seed)) {
		t.Fatal("the stored bytes contain the plaintext seed")
	}
	if bytes.Contains(sealed, []byte(`"secret"`)) {
		t.Fatal("the stored bytes contain the plaintext record shape")
	}
}

func TestVerifyFailsFastOnWrongFirstKey(t *testing.T) {
	v, store := newTestVault(t)
	if err := v.Verify(); err != nil {
		t.Fatalf("an empty store must verify: %v", err)
	}
	if _, err := v.Import("k", KindNATSUserKey, userSeed(t), "", ""); err != nil {
		t.Fatalf("import: %v", err)
	}
	if err := v.Verify(); err != nil {
		t.Fatalf("the right key must verify: %v", err)
	}
	otherKP, _ := nkeys.CreateCurveKeys()
	otherSeed, _ := otherKP.Seed()
	other, err := New(store, string(otherSeed))
	if err != nil {
		t.Fatalf("second vault: %v", err)
	}
	if err := other.Verify(); err == nil {
		t.Fatal("a wrong first key over a populated store must refuse to verify")
	}
}

func TestGenerateUserKeyIsIdempotent(t *testing.T) {
	v, _ := newTestVault(t)
	a, err := v.GenerateUserKey("user/acc/daan")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := v.GenerateUserKey("user/acc/daan")
	if err != nil || a != b {
		t.Fatalf("regenerate: %v, %+v != %+v", err, b, a)
	}
	if _, err := v.Import("clash", KindPersonaSigningKey,
		base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)), accountPub(t), "daan"); err != nil {
		t.Fatalf("persona import: %v", err)
	}
	if _, err := v.GenerateUserKey("clash"); err == nil {
		t.Fatal("generate over a non-user key must refuse")
	}
}

func TestSignRecordVerifies(t *testing.T) {
	v, _ := newTestVault(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	e, err := v.Import("persona/daan", KindPersonaSigningKey, seed, accountPub(t), "daan")
	if err != nil {
		t.Fatalf("import persona: %v", err)
	}
	canonical := []byte("canonical-bytes")
	sig, err := v.SignRecord("persona/daan", canonical)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub, _ := base64.StdEncoding.DecodeString(e.PublicKey)
	raw, _ := base64.StdEncoding.DecodeString(sig)
	if !ed25519.Verify(ed25519.PublicKey(pub), canonical, raw) {
		t.Fatal("signature does not verify")
	}
	if _, err := v.SignRecord("missing", canonical); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key: want ErrNotFound, got %v", err)
	}
	if _, err := v.GenerateUserKey("user/acc/daan"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := v.SignRecord("user/acc/daan", canonical); err == nil {
		t.Fatal("record signing with a non-persona key must refuse")
	}
}

func TestExportSeedReturnsTheSecret(t *testing.T) {
	v, _ := newTestVault(t)
	seed := userSeed(t)
	if _, err := v.Import("k", KindNATSUserKey, seed, "", ""); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := v.ExportSeed("k")
	if err != nil || got != seed {
		t.Fatalf("export: %v, %q", err, got)
	}
}

func TestNameGrammar(t *testing.T) {
	v, _ := newTestVault(t)
	for _, bad := range []string{"", "../etc", "a//b", "a/./b", "sp ace", "sub>", "star*"} {
		if _, err := v.Import(bad, KindNATSUserKey, userSeed(t), "", ""); err == nil {
			t.Fatalf("name %q must be refused", bad)
		}
	}
	if err := checkName("user/acc/daan.v2_x-1"); err != nil {
		t.Fatalf("legal name refused: %v", err)
	}
}

func TestKindValidation(t *testing.T) {
	v, _ := newTestVault(t)
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	if _, err := v.Import("k", KindNATSAccountSigningKey, userSeed(t), accPub, ""); err == nil ||
		!strings.Contains(err.Error(), "not an account key") {
		t.Fatalf("user seed as account key: %v", err)
	}
	if _, err := v.Import("k", Kind("mystery"), "x", "", ""); err == nil {
		t.Fatal("unknown kind must be refused")
	}
}

func TestAccountBindingOnSigningKeys(t *testing.T) {
	v, _ := newTestVault(t)
	signKP, _ := nkeys.CreateAccount()
	signSeed, _ := signKP.Seed()
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()

	// An account signing key without its binding is refused (D24: the key
	// name is the team name; the binding completes the team object).
	if _, err := v.Import("engineering", KindNATSAccountSigningKey, string(signSeed), "", ""); err == nil {
		t.Fatal("an account signing key without its account binding must be refused")
	}
	if _, err := v.Import("engineering", KindNATSAccountSigningKey, string(signSeed), "not-a-key", ""); err == nil {
		t.Fatal("an invalid account binding must be refused")
	}
	if _, err := v.Import("engineering", KindNATSAccountSigningKey, string(signSeed), accPub, "daan"); err == nil {
		t.Fatal("an account signing key with a user binding must be refused")
	}
	e, err := v.Import("engineering", KindNATSAccountSigningKey, string(signSeed), accPub, "")
	if err != nil {
		t.Fatalf("import with binding: %v", err)
	}
	if e.Account != accPub {
		t.Fatalf("entry account %q, want %q", e.Account, accPub)
	}
	got, err := v.Get("engineering")
	if err != nil || got.Account != accPub {
		t.Fatalf("binding lost on read: %v, %+v", err, got)
	}

	// No other kind carries a binding.
	if _, err := v.Import("u", KindNATSUserKey, userSeed(t), accPub, ""); err == nil {
		t.Fatal("a user key with an account binding must be refused")
	}
	if _, err := v.Import("u", KindNATSUserKey, userSeed(t), "", "daan"); err == nil {
		t.Fatal("a user key with a user binding must be refused")
	}
}

func TestOwnerBindingOnPersonaKeys(t *testing.T) {
	v, _ := newTestVault(t)
	accPub := accountPub(t)

	// A persona key without its owner is refused (D6 as amended, D25).
	if _, err := v.Import("persona/daan", KindPersonaSigningKey, personaSeed(t), "", ""); err == nil {
		t.Fatal("a persona key without its owner binding must be refused")
	}
	if _, err := v.Import("persona/daan", KindPersonaSigningKey, personaSeed(t), accPub, ""); err == nil {
		t.Fatal("a persona key without an owner user must be refused")
	}
	if _, err := v.Import("persona/daan", KindPersonaSigningKey, personaSeed(t), "not-a-key", "daan"); err == nil {
		t.Fatal("an invalid owner account must be refused")
	}
	e, err := v.Import("persona/daan", KindPersonaSigningKey, personaSeed(t), accPub, "daan")
	if err != nil {
		t.Fatalf("import with owner: %v", err)
	}
	if e.Account != accPub || e.User != "daan" {
		t.Fatalf("owner binding %q/%q, want %q/daan", e.Account, e.User, accPub)
	}
	got, err := v.Get("persona/daan")
	if err != nil || got.Account != accPub || got.User != "daan" {
		t.Fatalf("owner lost on read: %v, %+v", err, got)
	}
}

func TestGeneratePersonaKeyMaterializesOwnerBound(t *testing.T) {
	v, _ := newTestVault(t)
	accPub := accountPub(t)

	a, err := v.GeneratePersonaKey("persona/daan", accPub, "daan")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if a.Kind != KindPersonaSigningKey || a.Account != accPub || a.User != "daan" || a.PublicKey == "" {
		t.Fatalf("materialized entry: %+v", a)
	}
	// Idempotent for the same owner: the key is stable across touches.
	b, err := v.GeneratePersonaKey("persona/daan", accPub, "daan")
	if err != nil || b != a {
		t.Fatalf("regenerate: %v, %+v != %+v", err, b, a)
	}
	// Another owner cannot take the name — first owner wins (D26's cost).
	if _, err := v.GeneratePersonaKey("persona/daan", accountPub(t), "daan"); err == nil {
		t.Fatal("a second owner materialized over an existing persona key")
	}
	// A name held by another kind refuses.
	if _, err := v.Import("stray", KindNATSUserKey, userSeed(t), "", ""); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, err := v.GeneratePersonaKey("stray", accPub, "daan"); err == nil {
		t.Fatal("materialized over a non-persona key")
	}
}

func TestTeamForAccountResolvesByBinding(t *testing.T) {
	v, _ := newTestVault(t)
	accPub := accountPub(t)

	// No team bound: refused.
	if _, err := v.TeamForAccount(accPub); err == nil {
		t.Fatal("an account with no bound team must refuse")
	}

	signKP, _ := nkeys.CreateAccount()
	signSeed, _ := signKP.Seed()
	if _, err := v.Import("engineering", KindNATSAccountSigningKey, string(signSeed), accPub, ""); err != nil {
		t.Fatalf("import team: %v", err)
	}
	e, err := v.TeamForAccount(accPub)
	if err != nil || e.Name != "engineering" {
		t.Fatalf("resolve: %v, %+v", err, e)
	}

	// A second key bound to the same account: ambiguous, refused (the D5
	// amendment's reversal condition watches exactly this refusal).
	sign2KP, _ := nkeys.CreateAccount()
	sign2Seed, _ := sign2KP.Seed()
	if _, err := v.Import("engineering-2", KindNATSAccountSigningKey, string(sign2Seed), accPub, ""); err != nil {
		t.Fatalf("import second team: %v", err)
	}
	if _, err := v.TeamForAccount(accPub); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("two bound teams must refuse as ambiguous, got %v", err)
	}
}
