// The grants ops (../soul-hq/02-DESIGN/soulstream-identity/grants.md
// D30–D34): outbound credentials brokered on the principal-scoped surface.
// The persona in every op is the server-proven caller — reachability is the
// deployment's permission template on the op tail (D25), so the only grants
// a caller can ever touch are its own; the broker makes zero identity
// decisions. On-behalf-of (D33) binds the delegation's actor to the same
// server-proven principal, and every decision audits both personas.

package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/impire-io/soulstream-identity/internal/grants"
)

type grantLinkStartRequest struct {
	Resource string `json:"resource"`
}

type grantLinkStartResponse struct {
	AuthorizeURL string `json:"authorize_url"`
	LinkID       string `json:"link_id"`
}

type grantLinkCompleteRequest struct {
	LinkID string `json:"link_id"`
	Code   string `json:"code"`
}

type grantAccessRequest struct {
	Resource   string `json:"resource"`
	OnBehalfOf string `json:"on_behalf_of,omitempty"`
	// Delegation payload and signature (base64), required with
	// OnBehalfOf: the subject's persona key signed the payload (D33).
	DelegationPayload string `json:"delegation_payload,omitempty"`
	DelegationSig     string `json:"delegation_sig,omitempty"`
	// SubjectToken is lane 3's input (D34): the caller's own bearer,
	// presented for exchange, never retained. Required for exchange
	// resources, refused elsewhere.
	SubjectToken string `json:"subject_token,omitempty"`
}

// grantAccessResponse carries the derived short-lived token — the only
// credential class this surface may return (D32).
type grantAccessResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

type grantsListResponse struct {
	Grants []grants.GrantInfo `json:"grants"`
}

type grantRevokeRequest struct {
	Resource string `json:"resource"`
}

// requireGrants gates the ops that only exist on a grants-enabled service.
func (s *Service) requireGrants() error {
	if s.grants == nil {
		return errors.New("service: this deployment declares no grant resources")
	}
	return nil
}

func (s *Service) dispatchGrants(account, user, op string, body []byte) (any, error) {
	if err := s.requireGrants(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch op {
	case "grants.link.start":
		var req grantLinkStartRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		authorizeURL, linkID, err := s.grants.LinkStart(user, req.Resource)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op, "resource", req.Resource, "link_id", linkID)
		return grantLinkStartResponse{AuthorizeURL: authorizeURL, LinkID: linkID}, nil

	case "grants.link.complete":
		var req grantLinkCompleteRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if err := s.grants.LinkComplete(ctx, user, req.LinkID, req.Code); err != nil {
			return nil, err
		}
		s.allow(account, user, op, "link_id", req.LinkID)
		return struct{}{}, nil

	case "grants.access":
		var req grantAccessRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		var ts grants.TokenSet
		var err error
		if s.grants.ResourceIsExchange(req.Resource) {
			// Lane 3: the caller's own token, exchanged, nothing
			// custodied. On-behalf has no meaning here — there is no
			// custody to redeem for a subject.
			if req.OnBehalfOf != "" {
				return nil, errors.New("service: exchange resources serve the caller's own token only")
			}
			ts, err = s.grants.AccessExchange(ctx, req.Resource, req.SubjectToken)
			if err != nil {
				return nil, err
			}
			s.allow(account, user, op, "resource", req.Resource, "lane", "exchange")
			resp := grantAccessResponse{AccessToken: ts.AccessToken}
			if !ts.ExpiresAt.IsZero() {
				resp.ExpiresAt = ts.ExpiresAt.UTC().Format(time.RFC3339)
			}
			return resp, nil
		}
		if req.OnBehalfOf != "" {
			// The caller (actor) is the server-proven principal; the
			// decision — either way — audits both personas (D33).
			ts, err = s.grants.AccessOnBehalf(ctx, user, req.OnBehalfOf, req.Resource,
				req.DelegationPayload, req.DelegationSig)
			if err != nil {
				s.log.Warn("on-behalf access REFUSED", "op", op,
					"account", account, "caller", user,
					"subject", req.OnBehalfOf, "resource", req.Resource, "reason", err.Error())
				return nil, err
			}
			s.allow(account, user, op, "subject", req.OnBehalfOf, "resource", req.Resource)
		} else {
			ts, err = s.grants.Access(ctx, user, req.Resource)
			if err != nil {
				return nil, err
			}
			s.allow(account, user, op, "resource", req.Resource)
		}
		resp := grantAccessResponse{AccessToken: ts.AccessToken}
		if !ts.ExpiresAt.IsZero() {
			resp.ExpiresAt = ts.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return resp, nil

	case "grants.list":
		infos, err := s.grants.List(user)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op)
		return grantsListResponse{Grants: infos}, nil

	case "grants.revoke":
		var req grantRevokeRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if err := s.grants.Revoke(ctx, user, req.Resource); err != nil {
			return nil, err
		}
		s.log.Info("grant REVOKED (custody deleted, upstream best-effort)", "op", op,
			"account", account, "user", user, "resource", req.Resource)
		return struct{}{}, nil

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}
