// The local-operator authority (A8's self-hosted arm): the operator
// signing key lives in the vault and never leaves it; account JWTs are
// signed in-process and landed on the server's resolver through the
// system-account connection — the one act. Suspension rebuilds the SAME
// complete artifact with connections refused: deterministic from the
// record, no per-account state held here.
//
// D47 (hq 02-DESIGN/soulstream-identity/platform-topology.md) amended
// what "complete" means, twice — both halves measured in the topology
// research: the tenant signing key is a SCOPED signer carrying the
// persona template (a plain key leaves every SetScoped mint admitted
// but inert: 0 subscriptions, 0 payload), and creation amends the AUTH
// account's allowed_accounts so the callout may place users into the
// new tenant (D21's explicit list, never `*`).

package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

// claimsUpdateSubject is the resolver push: the account JWT, operator-
// signed, as the request body; the server stores or refuses.
const claimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"

// claimsLookupSubject is the resolver read: the stored account JWT for
// one account, raw in the reply — the read half of the D47 AUTH amend
// (lookup, modify, re-land; the custodian is the only writer).
const claimsLookupSubject = "$SYS.REQ.ACCOUNT.%s.CLAIMS.LOOKUP"

// LocalOperator signs with the vault-held operator key and pushes over
// the system-account connection.
type LocalOperator struct {
	// Vault holds the operator key under OperatorKeyName.
	Vault *vault.Vault
	// OperatorKeyName is the vault name of the SO… seed.
	OperatorKeyName string
	// Sys is the system-account connection the pushes ride.
	Sys *nats.Conn
	// Timeout bounds one push. Zero means 5s.
	Timeout time.Duration

	// AuthAccount is the AUTH account public key (A…) whose
	// allowed_accounts learns each created tenant (D47). Empty skips the
	// coupling — a deployment running no callout has no admission list
	// to maintain, and says so by leaving this unset.
	AuthAccount string

	// ScopePub and ScopeSub are the persona template rendered onto the
	// tenant's scoped signing key (D47). Nil defaults to the canonical
	// persona scope at the bare prefix (client.PersonaScope*Allow) —
	// the embed seam passes the deployment's prefix-rendered lists.
	ScopePub []string
	ScopeSub []string
}

func (l *LocalOperator) timeout() time.Duration {
	if l.Timeout > 0 {
		return l.Timeout
	}
	return 5 * time.Second
}

func (l *LocalOperator) scopePub() []string {
	if l.ScopePub != nil {
		return l.ScopePub
	}
	return client.PersonaScopePubAllow("")
}

func (l *LocalOperator) scopeSub() []string {
	if l.ScopeSub != nil {
		return l.ScopeSub
	}
	return client.PersonaScopeSubAllow("")
}

// buildJWT encodes the COMPLETE account artifact: identity, name, the
// signing key as a SCOPED signer carrying the persona template (D47 —
// every mint issues SetScoped users, and a scoped user on a plain key
// is admitted but inert), unlimited JetStream, and the suspension state
// as the connection limit. Determinism is the suspend/resume contract:
// the scope re-renders identically from the record and configuration.
func (l *LocalOperator) buildJWT(accountPub, name, signingPub string, suspended bool) (string, error) {
	opKP, err := l.Vault.KeyPair(l.OperatorKeyName)
	if err != nil {
		return "", fmt.Errorf("accounts: operator key: %w", err)
	}
	ac := jwt.NewAccountClaims(accountPub)
	ac.Name = name
	scope := jwt.NewUserScope()
	scope.Key = signingPub
	scope.Role = "soulstream-user"
	scope.Template = jwt.UserPermissionLimits{
		Permissions: jwt.Permissions{
			Pub: jwt.Permission{Allow: jwt.StringList(l.scopePub())},
			Sub: jwt.Permission{Allow: jwt.StringList(l.scopeSub())},
		},
	}
	ac.SigningKeys.AddScopedSigner(scope)
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	if suspended {
		ac.Limits.Conn = 0
	} else {
		ac.Limits.Conn = -1
	}
	token, err := ac.Encode(opKP)
	if err != nil {
		return "", fmt.Errorf("accounts: encode account jwt: %w", err)
	}
	return token, nil
}

// amendAuthAllowed is the D47 coupling: the AUTH account's stored JWT is
// looked up from the resolver, the tenant enters allowed_accounts, and
// the artifact re-lands complete — the same one-act discipline as the
// tenant push. Idempotent: an already-listed tenant re-lands nothing.
func (l *LocalOperator) amendAuthAllowed(ctx context.Context, tenantPub string) error {
	msg, err := l.Sys.RequestWithContext(ctx, fmt.Sprintf(claimsLookupSubject, l.AuthAccount), nil)
	if err != nil {
		return fmt.Errorf("auth lookup: %w", err)
	}
	if len(msg.Data) == 0 {
		return errors.New("auth lookup: resolver returned no AUTH account JWT")
	}
	ac, err := jwt.DecodeAccountClaims(string(msg.Data))
	if err != nil {
		return fmt.Errorf("auth decode: %w", err)
	}
	if ac.Authorization.AllowedAccounts.Contains(tenantPub) {
		return nil
	}
	ac.Authorization.AllowedAccounts.Add(tenantPub)
	opKP, err := l.Vault.KeyPair(l.OperatorKeyName)
	if err != nil {
		return fmt.Errorf("operator key: %w", err)
	}
	token, err := ac.Encode(opKP)
	if err != nil {
		return fmt.Errorf("auth re-encode: %w", err)
	}
	return l.push(ctx, token)
}

func (l *LocalOperator) push(ctx context.Context, token string) error {
	msg, err := l.Sys.RequestWithContext(ctx, claimsUpdateSubject, []byte(token))
	if err != nil {
		return fmt.Errorf("accounts: resolver push: %w", err)
	}
	// The resolver answers a JSON envelope; an error inside is a refusal.
	var resp struct {
		Error *struct {
			Description string `json:"description"`
		} `json:"error"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err == nil && resp.Error != nil {
		return fmt.Errorf("accounts: resolver refused: %s", resp.Error.Description)
	}
	return nil
}

// CreateAccount implements Authority: generate, build complete, land as
// one act — then teach AUTH the new tenant (D47). Tenant first, AUTH
// second: a probe between the acts draws an authorization violation
// (fail closed), never a usable half-tenant. The signing key seed goes
// back to the engine's caller for vault custody; nothing here retains it.
func (l *LocalOperator) CreateAccount(ctx context.Context, name string) (string, string, string, error) {
	acctKP, err := nkeys.CreateAccount()
	if err != nil {
		return "", "", "", err
	}
	acctPub, _ := acctKP.PublicKey()
	skKP, err := nkeys.CreateAccount()
	if err != nil {
		return "", "", "", err
	}
	skPub, _ := skKP.PublicKey()
	skSeed, _ := skKP.Seed()

	token, err := l.buildJWT(acctPub, name, skPub, false)
	if err != nil {
		return "", "", "", err
	}
	pctx, cancel := context.WithTimeout(ctx, l.timeout())
	defer cancel()
	if err := l.push(pctx, token); err != nil {
		return "", "", "", err
	}
	if l.AuthAccount != "" {
		actx, acancel := context.WithTimeout(ctx, l.timeout())
		defer acancel()
		if err := l.amendAuthAllowed(actx, acctPub); err != nil {
			// The tenant landed; admission has not. Loud and specific —
			// the callout will refuse this tenant until AUTH re-lands.
			return "", "", "", fmt.Errorf("accounts: tenant %s landed but AUTH did not learn it (allowed_accounts unamended): %w", name, err)
		}
	}
	return acctPub, skPub, string(skSeed), nil
}

// SetSuspended implements Authority: re-land the complete artifact with
// the connection limit flipped.
func (l *LocalOperator) SetSuspended(ctx context.Context, rec Record, suspended bool) error {
	token, err := l.buildJWT(rec.PublicKey, rec.Name, rec.SigningKey, suspended)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, l.timeout())
	defer cancel()
	return l.push(pctx, token)
}
