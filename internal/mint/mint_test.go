package mint

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

// harness: a vault holding one account signing key and a registry with one
// identity whose role names it.
func harness(t *testing.T) (*vault.Vault, *registry.Registry, string, string) {
	t.Helper()
	dir := t.TempDir()
	v, err := vault.Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	reg, err := registry.Open(filepath.Join(dir, "registry.json"))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	askKP, _ := nkeys.CreateAccount() // signing keys are account-typed nkeys
	askSeed, _ := askKP.Seed()
	askEntry, err := v.Import("acme/persona-role", vault.KindNATSAccountSigningKey, string(askSeed))
	if err != nil {
		t.Fatalf("import signing key: %v", err)
	}

	id := registry.Identity{Account: accPub, User: "daan", Personas: []string{"daan"}, Role: "acme/persona-role"}
	if err := reg.Put(id); err != nil {
		t.Fatalf("register identity: %v", err)
	}
	return v, reg, accPub, askEntry.PublicKey
}

func TestMintIssuesScopedUserJWT(t *testing.T) {
	v, reg, accPub, askPub := harness(t)

	res, err := Mint(v, reg, accPub, "daan")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(res.JWT)
	if err != nil {
		t.Fatalf("minted JWT does not decode: %v", err)
	}
	if uc.Subject != res.UserPublicKey || !nkeys.IsValidPublicUserKey(uc.Subject) {
		t.Fatalf("subject %q is not the returned user key %q", uc.Subject, res.UserPublicKey)
	}
	if uc.Issuer != askPub {
		t.Fatalf("issuer %q is not the signing key %q", uc.Issuer, askPub)
	}
	if uc.IssuerAccount != accPub {
		t.Fatalf("issuer_account %q is not the account %q (membership is declared at mint)", uc.IssuerAccount, accPub)
	}
	if !uc.HasEmptyPermissions() {
		t.Fatal("minted JWT carries its own permissions — the scope must be the whole policy")
	}

	// A second mint reuses the vaulted user key: same subject, stable identity.
	res2, err := Mint(v, reg, accPub, "daan")
	if err != nil {
		t.Fatalf("re-Mint: %v", err)
	}
	if res2.UserPublicKey != res.UserPublicKey {
		t.Fatalf("user key changed across mints: %s != %s", res2.UserPublicKey, res.UserPublicKey)
	}
}

func TestMintRefusals(t *testing.T) {
	v, reg, accPub, _ := harness(t)

	if _, err := Mint(v, reg, accPub, "ghost"); err == nil {
		t.Fatal("minted for an unregistered identity")
	}
	// A role naming a user key (not an account signing key) is refused.
	if _, err := v.GenerateUserKey("stray-user-key"); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := reg.Put(registry.Identity{Account: accPub, User: "misroled", Role: "stray-user-key"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := Mint(v, reg, accPub, "misroled"); err == nil {
		t.Fatal("minted with a user key as role")
	}
	// No role at all: refused with guidance.
	if err := reg.Put(registry.Identity{Account: accPub, User: "roleless"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := Mint(v, reg, accPub, "roleless"); err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("roleless mint error should name the role, got %v", err)
	}
}

func TestExportCredsIsACompleteCredsFile(t *testing.T) {
	v, reg, accPub, _ := harness(t)
	res, err := Mint(v, reg, accPub, "daan")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	creds, err := ExportCreds(v, accPub, "daan", res.JWT)
	if err != nil {
		t.Fatalf("ExportCreds: %v", err)
	}
	// The creds file must carry both the JWT and the seed — that is exactly
	// why it is the custody escape.
	if !strings.Contains(creds, res.JWT) {
		t.Fatal("creds file lacks the JWT")
	}
	if !strings.Contains(creds, "-----BEGIN USER NKEY SEED-----") {
		t.Fatal("creds file lacks the seed block")
	}
}
