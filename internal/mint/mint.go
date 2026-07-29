// Package mint issues NATS user JWTs from account signing keys held in the
// vault. The user key is generated inside the vault on first mint and reused
// after; permissions are left to the signing key's scope, so the server — not
// the minter — decides what the user may do (hq/02-DESIGN/agent.md D4, D5).
package mint

import (
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

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

// teamKey resolves the signing key for account by its D24 binding — the
// authorize step of every mint path since the registry dissolved (D25,
// D5 as amended): the team the account binds to is the only role there is.
func teamKey(v *vault.Vault, account string) (nkeys.KeyPair, error) {
	e, err := v.TeamForAccount(account)
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
	kp, err := teamKey(v, account)
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
// public key — the auth-callout path (hq/02-DESIGN/auth-callout.md D20),
// where the key is server-assigned and no vault key exists or is created.
// The authorize stage is the target account's team binding (D22 as
// amended, D25); ttl bounds the credential and is the revocation
// propagation bound (D22).
func ForKey(v *vault.Vault, account, user, userPub string, ttl time.Duration) (string, error) {
	kp, err := teamKey(v, account)
	if err != nil {
		return "", err
	}
	return ephemeral(kp, account, user, userPub, ttl)
}

// ForTeam issues an ephemeral scoped user JWT for the claims-derived lane
// (D24): the team name resolves directly to its vault signing key and the
// account binding recorded at import — no registry row, no mapping store.
// subject names the external identity (the stable oid) for attribution.
func ForTeam(v *vault.Vault, team, subject, userPub string, ttl time.Duration) (string, error) {
	e, err := v.Get(team)
	if err != nil {
		return "", fmt.Errorf("mint: no declared team %q: %w", team, err)
	}
	if e.Kind != vault.KindNATSAccountSigningKey {
		return "", fmt.Errorf("mint: team %q is %q, want %q", team, e.Kind, vault.KindNATSAccountSigningKey)
	}
	if e.Account == "" {
		return "", fmt.Errorf("mint: team %q has no account binding — reimport it with its account", team)
	}
	kp, err := v.KeyPair(team)
	if err != nil {
		return "", err
	}
	return ephemeral(kp, e.Account, subject, userPub, ttl)
}

// ephemeral is the shared mint tail (D20): scoped, permission-less,
// TTL-bounded claims for the server-assigned key, signed by the resolved
// signing key. Both authorize sources (registry row, declared team) end here.
func ephemeral(kp nkeys.KeyPair, account, name, userPub string, ttl time.Duration) (string, error) {
	if !nkeys.IsValidPublicUserKey(userPub) {
		return "", fmt.Errorf("mint: %q is not a user public key", userPub)
	}
	if ttl <= 0 {
		return "", errors.New("mint: an ephemeral mint needs a positive ttl")
	}
	uc := claims(userPub, account, name)
	uc.Expires = time.Now().Add(ttl).Unix()
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
