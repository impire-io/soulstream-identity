// Package mint issues NATS user JWTs from account signing keys held in the
// vault. The user key is generated inside the vault on first mint and reused
// after; permissions are left to the signing key's scope, so the server — not
// the minter — decides what the user may do (../soul-hq/02-DESIGN/soulidentity/agent.md D4, D5).
package mint

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/vault"
)

// UserKeyName is the vault name of the generated user key for a principal.
func UserKeyName(account, user string) string {
	return "user/" + account + "/" + user
}

// Result is a successful mint: the JWT and the user key it names.
type Result struct {
	JWT           string `json:"jwt"`
	UserPublicKey string `json:"user_public_key"`
}

// roleKey resolves the signing key for account by its D24 binding — the
// authorize step of the binding-resolved mint paths (D25, D5 as amended):
// the account's one declared role. A multi-role account refuses here and
// is reachable only by role name (D28).
func roleKey(v *vault.Vault, account string) (nkeys.KeyPair, error) {
	e, err := v.RoleForAccount(account)
	if err != nil {
		return nil, fmt.Errorf("mint: %w", err)
	}
	return v.KeyPair(e.Name)
}

// claims builds the scoped user claims every mint path shares: the JWT
// carries no permissions of its own; the signing key's scope in the account
// JWT is the whole policy (D5), enforced by the server. A mis-bound role key
// yields a JWT the server rejects at connection time; that is the verifier
// of record (D3).
func claims(userPub, account, user string) *jwt.UserClaims {
	uc := jwt.NewUserClaims(userPub)
	uc.Name = user
	uc.IssuerAccount = account // membership is declared (D2)
	uc.SetScoped(true)
	return uc
}

// Mint issues a durable user JWT for (account, user) — an operator act
// (provisioning, ACL-gated per D25) — with the user key generated inside
// the vault and reused across mints.
func Mint(v *vault.Vault, account, user string) (Result, error) {
	kp, err := roleKey(v, account)
	if err != nil {
		return Result{}, err
	}
	uk, err := v.GenerateUserKey(UserKeyName(account, user))
	if err != nil {
		return Result{}, err
	}
	token, err := claims(uk.PublicKey, account, user).Encode(kp)
	if err != nil {
		return Result{}, fmt.Errorf("mint: encode user JWT for %s/%s: %w", account, user, err)
	}
	return Result{JWT: token, UserPublicKey: uk.PublicKey}, nil
}

// ForKey issues an ephemeral scoped user JWT for a caller-provided user
// public key — the auth-callout path (../soul-hq/02-DESIGN/soulidentity/auth-callout.md D20),
// where the key is server-assigned and no vault key exists or is created.
// The authorize stage is the target account's role binding (D22 as
// amended, D25); ttl bounds the credential and is the revocation
// propagation bound (D22).
func ForKey(v *vault.Vault, account, user, userPub string, ttl time.Duration) (string, error) {
	kp, err := roleKey(v, account)
	if err != nil {
		return "", err
	}
	return ephemeral(kp, account, user, userPub, ttl, nil)
}

// ForRole issues an ephemeral scoped user JWT for a named role — role
// selection by declared configuration (D28): the role name resolves directly
// to its vault signing key and the account binding recorded at import — no
// registry row, no mapping store. The claims-derived callout lane (D24) and
// the mint.ephemeral op both end here; only the by-name paths reach a
// multi-role account, the binding-resolved paths keep refusing it as
// ambiguous (D5 as amended). subject names the minted user (the stable oid
// on the claims lane, D27) and tags ride into the user claims for the
// scoped template to resolve. Returns the bound account beside the token so
// the caller can attribute the mint in full.
func ForRole(v *vault.Vault, role, subject, userPub string, ttl time.Duration, tags []string) (string, string, error) {
	e, err := v.Get(role)
	if err != nil {
		return "", "", fmt.Errorf("mint: no declared role %q: %w", role, err)
	}
	if e.Kind != vault.KindNATSAccountSigningKey {
		return "", "", fmt.Errorf("mint: role %q is %q, want %q", role, e.Kind, vault.KindNATSAccountSigningKey)
	}
	if e.Account == "" {
		return "", "", fmt.Errorf("mint: role %q has no account binding — reimport it with its account", role)
	}
	kp, err := v.KeyPair(role)
	if err != nil {
		return "", "", err
	}
	token, err := ephemeral(kp, e.Account, subject, userPub, ttl, tags)
	if err != nil {
		return "", "", err
	}
	return token, e.Account, nil
}

// ephemeral is the shared mint tail (D20): scoped, permission-less,
// TTL-bounded claims for the caller-provided key, signed by the resolved
// signing key. Both authorize sources (account binding, declared role) end
// here. Tags are inert on their own — only a scoped template that derives
// subjects from them gives them meaning (D28) — and follow NATS tag
// semantics on encode (lowercased, trimmed, deduplicated).
func ephemeral(kp nkeys.KeyPair, account, name, userPub string, ttl time.Duration, tags []string) (string, error) {
	if !nkeys.IsValidPublicUserKey(userPub) {
		return "", fmt.Errorf("mint: %q is not a user public key", userPub)
	}
	if ttl <= 0 {
		return "", errors.New("mint: an ephemeral mint needs a positive ttl")
	}
	uc := claims(userPub, account, name)
	uc.Expires = time.Now().Add(ttl).Unix()
	for _, tag := range tags {
		if strings.TrimSpace(tag) == "" {
			return "", errors.New("mint: a tag must be non-empty")
		}
	}
	uc.Tags.Add(tags...)
	token, err := uc.Encode(kp)
	if err != nil {
		return "", fmt.Errorf("mint: encode ephemeral JWT for %s/%s: %w", account, name, err)
	}
	return token, nil
}

// ExportCreds renders a creds file (JWT + user seed) for external tools. This
// is the explicit custody escape (D7): the seed leaves the vault here and
// nowhere else. Callers present it as exactly that.
func ExportCreds(v *vault.Vault, account, user, token string) (string, error) {
	if token == "" {
		return "", errors.New("mint: creds export needs the minted JWT")
	}
	seed, err := v.ExportSeed(UserKeyName(account, user))
	if err != nil {
		return "", err
	}
	creds, err := jwt.FormatUserConfig(token, []byte(seed))
	if err != nil {
		return "", fmt.Errorf("mint: format creds: %w", err)
	}
	return string(creds), nil
}
