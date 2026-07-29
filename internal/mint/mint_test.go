package mint

import (
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/vault"
)

// harness: a vault holding one team — an account signing key bound to its
// account (D24) — the authorize source of every mint path (D25).
func harness(t *testing.T) (*vault.Vault, string, string) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}

	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	askKP, _ := nkeys.CreateAccount() // signing keys are account-typed nkeys
	askSeed, _ := askKP.Seed()
	askEntry, err := v.Import("acme", vault.KindNATSAccountSigningKey, string(askSeed), accPub, "")
	if err != nil {
		t.Fatalf("import signing key: %v", err)
	}
	return v, accPub, askEntry.PublicKey
}

func TestMintIssuesScopedUserJWT(t *testing.T) {
	v, accPub, askPub := harness(t)

	res, err := Mint(v, accPub, "daan")
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
	res2, err := Mint(v, accPub, "daan")
	if err != nil {
		t.Fatalf("re-Mint: %v", err)
	}
	if res2.UserPublicKey != res.UserPublicKey {
		t.Fatalf("user key changed across mints: %s != %s", res2.UserPublicKey, res.UserPublicKey)
	}
}

func TestMintRefusals(t *testing.T) {
	v, accPub, _ := harness(t)

	// An account no team is bound to: refused (D25 — the binding is the
	// authorize source; there is nothing else to consult).
	strayKP, _ := nkeys.CreateAccount()
	strayPub, _ := strayKP.PublicKey()
	if _, err := Mint(v, strayPub, "daan"); err == nil {
		t.Fatal("minted for an account with no bound team")
	}

	// A second team bound to the same account: ambiguous, refused (the D5
	// amendment's reversal condition watches this refusal).
	ask2KP, _ := nkeys.CreateAccount()
	ask2Seed, _ := ask2KP.Seed()
	if _, err := v.Import("acme-2", vault.KindNATSAccountSigningKey, string(ask2Seed), accPub, ""); err != nil {
		t.Fatalf("import second team: %v", err)
	}
	if _, err := Mint(v, accPub, "daan"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("two bound teams must refuse as ambiguous, got %v", err)
	}
}

func TestMintForKeyIssuesEphemeralScopedJWT(t *testing.T) {
	v, accPub, askPub := harness(t)
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()

	token, err := ForKey(v, accPub, "daan", upub, time.Minute)
	if err != nil {
		t.Fatalf("MintForKey: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(token)
	if err != nil {
		t.Fatalf("ephemeral JWT does not decode: %v", err)
	}
	if uc.Subject != upub {
		t.Fatalf("subject %q is not the provided key %q", uc.Subject, upub)
	}
	if uc.Issuer != askPub || uc.IssuerAccount != accPub {
		t.Fatalf("issuer chain wrong: %q / %q", uc.Issuer, uc.IssuerAccount)
	}
	if !uc.HasEmptyPermissions() {
		t.Fatal("ephemeral JWT carries its own permissions — the scope must be the whole policy")
	}
	if uc.Expires == 0 || time.Unix(uc.Expires, 0).Before(time.Now()) {
		t.Fatalf("ephemeral JWT must expire in the future, got %d", uc.Expires)
	}

	if _, err := ForKey(v, accPub, "daan", "not-a-key", time.Minute); err == nil {
		t.Fatal("bad public key accepted")
	}
	if _, err := ForKey(v, accPub, "daan", upub, 0); err == nil {
		t.Fatal("zero ttl accepted — an unbounded ephemeral credential")
	}
	strayKP, _ := nkeys.CreateAccount()
	strayPub, _ := strayKP.PublicKey()
	if _, err := ForKey(v, strayPub, "daan", upub, time.Minute); err == nil {
		t.Fatal("minted for an account with no bound team")
	}
}

func TestExportCredsIsACompleteCredsFile(t *testing.T) {
	v, accPub, _ := harness(t)
	res, err := Mint(v, accPub, "daan")
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
