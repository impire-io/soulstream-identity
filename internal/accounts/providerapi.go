// The provider-API authority (A8's hosted arm, D35's second backend):
// the deployment does NOT hold the operator key — a hosting provider
// custodies it and exposes an API. Account birth is then two API calls
// (the account, then its programmatic signing-key group whose seed
// returns exactly once) and suspension is an account update that drops
// the connection limit to zero — the same observable the local arm
// produces by re-landing its JWT.
//
// Custody is unchanged by the seam: the signing-key seed the API
// returns once goes straight to the engine's caller, which imports it
// into the vault; nothing here retains it, and the operator key is
// never ours to hold.

package accounts

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/synadia-io/control-plane-sdk-go/syncp"

	"github.com/impire-io/soulstream-identity/client"
)

// The control plane is a lossy channel: a just-created account's next
// call can answer 500 while the platform settles (measured 2026-08-19
// on the DEV system — the same class the product's founding driver
// already retries, hq episode 0099). Retry 5xx with a short backoff;
// a 4xx is an answer and is never retried.
const cpAttempts = 4

var cpBackoffBase = 2 * time.Second

func is5xx(resp *http.Response) bool { return resp != nil && resp.StatusCode >= 500 }

func cpRetry(ctx context.Context, what string, f func() (*http.Response, error)) error {
	for attempt := 1; ; attempt++ {
		resp, err := f()
		if err == nil {
			return nil
		}
		if !is5xx(resp) || attempt == cpAttempts {
			return fmt.Errorf("accounts: %s: %w", what, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("accounts: %s: %w", what, ctx.Err())
		case <-time.After(time.Duration(attempt) * cpBackoffBase):
		}
	}
}

// ProviderAPI drives a Synadia Cloud system's control plane.
type ProviderAPI struct {
	// Client is the control-plane client (token-authenticated).
	Client *syncp.APIClient
	// SystemID is the Cloud system accounts are born into.
	SystemID string
	// GroupName is the programmatic signing-key group created per
	// account — the role the realm's users are minted against.
	// Default "soulstream-user".
	GroupName string
	// Log receives progress lines. Optional.
	Log func(format string, args ...any)

	// AuthAccount is the AUTH account public key (A…) whose
	// allowed_accounts learns each created tenant (D47 — parity with
	// the local arm). Empty skips the coupling: no callout half, no
	// admission list to maintain.
	AuthAccount string

	// ScopePub and ScopeSub are the persona template rendered onto the
	// tenant's signing-key group as its scope (D47 — without it the
	// group is plain and every SetScoped mint is admitted but inert).
	// Nil defaults to the canonical persona scope at the bare prefix.
	ScopePub []string
	ScopeSub []string
}

func (p *ProviderAPI) scopePub() []string {
	if p.ScopePub != nil {
		return p.ScopePub
	}
	return client.PersonaScopePubAllow("")
}

func (p *ProviderAPI) scopeSub() []string {
	if p.ScopeSub != nil {
		return p.ScopeSub
	}
	return client.PersonaScopeSubAllow("")
}

func (p *ProviderAPI) groupName() string {
	if p.GroupName != "" {
		return p.GroupName
	}
	return "soulstream-user"
}

func (p *ProviderAPI) logf(format string, args ...any) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

// accountByName finds an account in the system by name.
func (p *ProviderAPI) accountByName(ctx context.Context, name string) (*syncp.AccountViewResponse, error) {
	accounts, _, err := p.Client.SystemAPI.ListAccounts(ctx, p.SystemID).Execute()
	if err != nil {
		return nil, fmt.Errorf("accounts: list accounts: %w", err)
	}
	for i, a := range accounts.Items {
		if strings.EqualFold(a.Name, name) {
			return &accounts.Items[i], nil
		}
	}
	return nil, nil
}

// CreateAccount implements Authority: the account, then its
// programmatic signing-key group — complete before anything names it,
// exactly as the local arm builds its JWT whole before landing it.
func (p *ProviderAPI) CreateAccount(ctx context.Context, name string) (string, string, string, error) {
	if existing, err := p.accountByName(ctx, name); err != nil {
		return "", "", "", err
	} else if existing != nil {
		// The engine's own store already refuses a name it knows; a name
		// the provider knows and we do not is a collision worth naming.
		return "", "", "", fmt.Errorf("%w: %s exists at the provider", ErrExists, name)
	}
	var created *syncp.AccountViewResponse
	if err := cpRetry(ctx, "create account "+name, func() (*http.Response, error) {
		c, resp, err := p.Client.SystemAPI.CreateAccount(ctx, p.SystemID).
			AccountCreateRequest(syncp.AccountCreateRequest{Name: name}).Execute()
		created = c
		return resp, err
	}); err != nil {
		return "", "", "", err
	}
	p.logf("created account %q (id %s)", name, created.Id)

	var group *syncp.SigningKeyGroupCreateResponse
	if err := cpRetry(ctx, "create signing-key group for "+name, func() (*http.Response, error) {
		g, resp, err := p.Client.AccountAPI.CreateAccountSkGroup(ctx, created.Id).
			SigningKeyGroupCreateRequest(syncp.SigningKeyGroupCreateRequest{
				Name: p.groupName(), Programmatic: true,
				// D47: the group carries the persona template as its
				// scope — a plain group leaves every SetScoped mint
				// admitted but inert (0 subscriptions, 0 payload).
				Scope: &syncp.UserPermissionLimits{
					Permissions: syncp.Permissions{
						Pub: &syncp.Permission{Allow: p.scopePub()},
						Sub: &syncp.Permission{Allow: p.scopeSub()},
					},
				},
			}).Execute()
		group = g
		return resp, err
	}); err != nil {
		return "", "", "", err
	}
	if group == nil || group.Seed == nil || *group.Seed == "" {
		return "", "", "", fmt.Errorf("accounts: signing-key group for %s returned no seed — nothing to custody", name)
	}
	// The group's public half is derived, not returned: the platform
	// hands back the seed exactly once and never again.
	kp, err := nkeys.FromSeed([]byte(*group.Seed))
	if err != nil {
		return "", "", "", fmt.Errorf("accounts: signing-key seed for %s is unreadable: %w", name, err)
	}
	signingPub, err := kp.PublicKey()
	if err != nil {
		return "", "", "", fmt.Errorf("accounts: signing-key public half for %s: %w", name, err)
	}
	// The seed leaves this scope for the vault immediately.
	acctPub := deref(created.AccountPublicKey)

	// D47's coupling, provider-side: AUTH learns the tenant. Tenant
	// first, AUTH second — the between-acts window fails closed.
	if p.AuthAccount != "" {
		if err := p.amendAuthAllowed(ctx, acctPub); err != nil {
			return "", "", "", fmt.Errorf("accounts: tenant %s landed but AUTH did not learn it (allowed_accounts unamended): %w", name, err)
		}
	}
	return acctPub, signingPub, *group.Seed, nil
}

// accountByPublicKey finds an account in the system by its public key.
func (p *ProviderAPI) accountByPublicKey(ctx context.Context, pub string) (*syncp.AccountViewResponse, error) {
	accounts, _, err := p.Client.SystemAPI.ListAccounts(ctx, p.SystemID).Execute()
	if err != nil {
		return nil, fmt.Errorf("accounts: list accounts: %w", err)
	}
	for i, a := range accounts.Items {
		if deref(a.AccountPublicKey) == pub {
			return &accounts.Items[i], nil
		}
	}
	return nil, nil
}

// amendAuthAllowed is the provider-side D47 coupling: read the AUTH
// account's whole authorization object from its JWT settings, union
// the tenant into allowed_accounts, and write the object back —
// idempotent, the custodian the only writer.
func (p *ProviderAPI) amendAuthAllowed(ctx context.Context, tenantPub string) error {
	auth, err := p.accountByPublicKey(ctx, p.AuthAccount)
	if err != nil {
		return err
	}
	if auth == nil {
		return fmt.Errorf("%w: AUTH account %s at the provider", ErrNotFound, p.AuthAccount)
	}
	// The list view can omit jwt_settings; fetch the account whole.
	var view *syncp.AccountViewResponse
	if err := cpRetry(ctx, "get AUTH account", func() (*http.Response, error) {
		v, resp, err := p.Client.AccountAPI.GetAccount(ctx, auth.Id).Execute()
		view = v
		return resp, err
	}); err != nil {
		return err
	}
	var authz *syncp.ExternalAuthorization
	if view != nil && view.JwtSettings != nil {
		authz = view.JwtSettings.Authorization
	}
	// The JWT rule (nats-io/jwt): external authorization cannot have
	// accounts without users. An AUTH with no auth_users is not a
	// callout account and no allowed_accounts write on it can ever be
	// valid — the control plane answers 400.
	if authz == nil || len(authz.AuthUsers) == 0 {
		return fmt.Errorf("accounts: AUTH %s has no auth_users — not a callout account, allowed_accounts cannot be set on it", p.AuthAccount)
	}
	for _, a := range authz.AllowedAccounts {
		if a == tenantPub {
			return nil
		}
	}
	allowed := append(append([]string{}, authz.AllowedAccounts...), tenantPub)
	// The whole authorization object is written back — auth_users and
	// xkey carried forward — so the write stays valid whether the
	// control plane merges the patch per field or replaces the object.
	patch := syncp.AccountJWTSettingsPatch{
		Authorization: &syncp.Nullable[syncp.ExternalAuthorizationPatch]{
			Val: syncp.ExternalAuthorizationPatch{
				AllowedAccounts: allowed,
				AuthUsers:       authz.AuthUsers,
				Xkey:            authz.Xkey,
			}, ZeroIsValid: true,
		},
	}
	if err := cpRetry(ctx, "amend AUTH allowed_accounts", func() (*http.Response, error) {
		_, resp, err := p.Client.AccountAPI.UpdateAccount(ctx, auth.Id).
			AccountUpdateRequest(syncp.AccountUpdateRequest{JwtSettings: &patch}).Execute()
		return resp, err
	}); err != nil {
		return err
	}
	p.logf("AUTH %s allowed_accounts += %s", p.AuthAccount, tenantPub)
	return nil
}

// SetSuspended implements Authority: drop the account's connection
// limit to zero (or restore it), the provider-side twin of the local
// arm's re-landed JWT.
func (p *ProviderAPI) SetSuspended(ctx context.Context, rec Record, suspended bool) error {
	acct, err := p.accountByName(ctx, rec.Name)
	if err != nil {
		return err
	}
	if acct == nil {
		return fmt.Errorf("%w: %s at the provider", ErrNotFound, rec.Name)
	}
	var conn int64 = -1
	if suspended {
		conn = 0
	}
	patch := syncp.AccountJWTSettingsPatch{
		Limits: &syncp.Nullable[syncp.OperatorLimitsPatch]{
			Val: syncp.OperatorLimitsPatch{Conn: &conn}, ZeroIsValid: true,
		},
	}
	if err := cpRetry(ctx, fmt.Sprintf("set suspended=%v on %s", suspended, rec.Name),
		func() (*http.Response, error) {
			_, resp, err := p.Client.AccountAPI.UpdateAccount(ctx, acct.Id).
				AccountUpdateRequest(syncp.AccountUpdateRequest{JwtSettings: &patch}).Execute()
			return resp, err
		}); err != nil {
		return err
	}
	p.logf("account %q suspended=%v", rec.Name, suspended)
	return nil
}

// Delete removes an account at the provider — not part of the
// Authority contract (D35 has no delete: suspension keeps the data),
// exported for the measurement rigs that must clean up after
// themselves.
func (p *ProviderAPI) Delete(ctx context.Context, name string) error {
	acct, err := p.accountByName(ctx, name)
	if err != nil || acct == nil {
		return err
	}
	if err := cpRetry(ctx, "delete "+name, func() (*http.Response, error) {
		return p.Client.AccountAPI.DeleteAccount(ctx, acct.Id).Execute()
	}); err != nil {
		return err
	}
	p.logf("deleted account %q", name)
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
