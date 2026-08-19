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
	return deref(created.AccountPublicKey), signingPub, *group.Seed, nil
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
