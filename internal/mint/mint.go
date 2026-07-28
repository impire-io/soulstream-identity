// Package mint issues NATS user JWTs from account signing keys held in the
// vault. The user key is generated inside the vault on first mint and reused
// after; permissions are left to the signing key's scope, so the server — not
// the minter — decides what the user may do (hq/02-DESIGN/agent.md D4, D5).
package mint

import (
	"errors"
	"fmt"

	"github.com/nats-io/jwt/v2"

	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

// UserKeyName is the vault name of the generated user key for an identity.
func UserKeyName(account, user string) string {
	return "user/" + account + "/" + user
}

// Result is a successful mint: the JWT and the user key it names.
type Result struct {
	JWT           string `json:"jwt"`
	UserPublicKey string `json:"user_public_key"`
}

// Mint issues a user JWT for the registered identity (account, user), signed
// by the identity's role key. The claims carry issuer_account (membership is
// declared, D2) and are scoped — permissions come from the signing key's
// scope in the account JWT, enforced by the server. A mis-bound role key
// yields a JWT the server rejects at connection time; that is the verifier of
// record (D3).
func Mint(v *vault.Vault, reg *registry.Registry, account, user string) (Result, error) {
	id, ok, err := reg.Get(account, user)
	if err != nil {
		return Result{}, err
	}
	if !ok {
		return Result{}, fmt.Errorf("mint: identity %s/%s is not registered", account, user)
	}
	if id.Role == "" {
		return Result{}, fmt.Errorf("mint: identity %s/%s has no role — register it with the vault name of an account signing key", account, user)
	}
	role, err := v.Get(id.Role)
	if err != nil {
		return Result{}, fmt.Errorf("mint: role of %s/%s: %w", account, user, err)
	}
	if role.Kind != vault.KindNATSAccountSigningKey {
		return Result{}, fmt.Errorf("mint: role key %s is %q, want %q", id.Role, role.Kind, vault.KindNATSAccountSigningKey)
	}

	uk, err := v.GenerateUserKey(UserKeyName(account, user))
	if err != nil {
		return Result{}, err
	}

	uc := jwt.NewUserClaims(uk.PublicKey)
	uc.Name = user
	uc.IssuerAccount = account
	// Scoped: the user JWT carries no permissions of its own; the signing
	// key's scope in the account JWT is the whole policy.
	uc.SetScoped(true)

	kp, err := v.KeyPair(id.Role)
	if err != nil {
		return Result{}, err
	}
	token, err := uc.Encode(kp)
	if err != nil {
		return Result{}, fmt.Errorf("mint: encode user JWT for %s/%s: %w", account, user, err)
	}
	return Result{JWT: token, UserPublicKey: uk.PublicKey}, nil
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
