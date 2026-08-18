// The accounts ops (tenancy.md D35): tenancy on the management surface,
// operator-gated by the permission template like every management op
// (D25). Creation completes the composition: the new account's signing
// key goes straight into the vault BOUND to the new account (the D24
// team binding), so the existing mint path serves the new tenant the
// moment the op returns — and the seed appears in no reply, ever.

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/impire-io/soulstream-identity/internal/accounts"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

type accountCreateRequest struct {
	Name string `json:"name"`
}

type accountResponse struct {
	Name      string `json:"name"`
	Account   string `json:"account"` // the public key
	Status    string `json:"status"`
	CreatedAt string `json:"created_at,omitempty"`
}

type accountNameRequest struct {
	Name string `json:"name"`
}

type accountsListResponse struct {
	Accounts []accountResponse `json:"accounts"`
}

func (s *Service) requireAccounts() error {
	if s.accounts == nil {
		return errors.New("service: this deployment runs no account authority")
	}
	return nil
}

func accountView(r accounts.Record) accountResponse {
	return accountResponse{Name: r.Name, Account: r.PublicKey, Status: string(r.Status), CreatedAt: r.CreatedAt}
}

func (s *Service) dispatchAccounts(account, user, op string, body []byte) (any, error) {
	if err := s.requireAccounts(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch op {
	case "accounts.create":
		var req accountCreateRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		rec, signingSeed, err := s.accounts.Create(ctx, req.Name)
		if err != nil {
			return nil, err
		}
		// The signing key into the vault, bound to the new account — the
		// tenant is mintable immediately; the seed dies with this scope.
		if _, err := s.vault.Import("team/"+req.Name, vault.KindNATSAccountSigningKey, signingSeed, rec.PublicKey, ""); err != nil {
			return nil, fmt.Errorf("service: account %s landed but its signing key did not reach the vault: %w", req.Name, err)
		}
		s.allow(account, user, op, "name", req.Name, "account", rec.PublicKey)
		return accountView(rec), nil

	case "accounts.resolve":
		var req accountNameRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		rec, err := s.accounts.Resolve(req.Name)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op, "name", req.Name)
		return accountView(rec), nil

	case "accounts.list":
		recs, err := s.accounts.List()
		if err != nil {
			return nil, err
		}
		out := accountsListResponse{}
		for _, r := range recs {
			out.Accounts = append(out.Accounts, accountView(r))
		}
		s.allow(account, user, op)
		return out, nil

	case "accounts.suspend", "accounts.resume":
		var req accountNameRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		rec, err := s.accounts.SetSuspended(ctx, req.Name, op == "accounts.suspend")
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op, "name", req.Name, "status", string(rec.Status))
		return accountView(rec), nil

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}
