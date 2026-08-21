// The resources ops (../soul-hq/02-DESIGN/soulstream-identity/external-tools.md
// D40): the tool catalog's custody half becomes runtime state. Management
// ops like guardrail.load — the permission template decides who reaches the
// tail, the guardrail evaluates each call like any other (nothing here is
// exempt), and the client secret goes into sealed custody and never into a
// reply or a log line.

package service

import (
	"errors"
	"fmt"

	"github.com/impire-io/soulstream-identity/internal/grants"
)

// resourceAddRequest is the full declaration — the one place the secret
// crosses the (sealed) wire, inbound only.
type resourceAddRequest struct {
	Name             string   `json:"name"`
	AuthURL          string   `json:"auth_url,omitempty"`
	TokenURL         string   `json:"token_url,omitempty"`
	RevokeURL        string   `json:"revoke_url,omitempty"`
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	RedirectURI      string   `json:"redirect_uri,omitempty"`
	ExchangeTokenURL string   `json:"exchange_token_url,omitempty"`
	ExchangeAudience string   `json:"exchange_audience,omitempty"`
}

type resourceRemoveRequest struct {
	Name string `json:"name"`
}

type resourceListResponse struct {
	Resources []grants.ResourceInfo `json:"resources"`
}

func (s *Service) dispatchResources(account, user, op string, body []byte) (any, error) {
	if s.grants == nil {
		return nil, errors.New("service: this deployment runs no grants broker")
	}
	switch op {
	case "resources.add":
		var req resourceAddRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if err := s.grants.AddResource(grants.Resource{
			Name: req.Name, AuthURL: req.AuthURL, TokenURL: req.TokenURL,
			RevokeURL: req.RevokeURL, ClientID: req.ClientID,
			ClientSecret: req.ClientSecret, Scopes: req.Scopes,
			RedirectURI: req.RedirectURI, ExchangeTokenURL: req.ExchangeTokenURL,
			ExchangeAudience: req.ExchangeAudience,
		}); err != nil {
			return nil, err
		}
		// The audit names the resource, never its secret.
		s.allow(account, user, op, "resource", req.Name)
		return struct{}{}, nil

	case "resources.remove":
		var req resourceRemoveRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if err := s.grants.RemoveResource(req.Name); err != nil {
			return nil, err
		}
		s.allow(account, user, op, "resource", req.Name)
		return struct{}{}, nil

	case "resources.list":
		return resourceListResponse{Resources: s.grants.Resources()}, nil

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}
