// The callout-management ops (hq/02-DESIGN/auth-callout.md D21/D22): API
// tokens issued and revoked over the sealed surface, and the sentinel minted
// from the AUTH signing key the vault holds. All operator ops — the
// deployment's permission template gates who reaches them (D25).

package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/callout"
)

type tokenCreateRequest struct {
	Account    string `json:"account"`
	User       string `json:"user"`
	Label      string `json:"label,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

// tokenCreateResponse carries the plaintext exactly once — at issuance; the
// store keeps only the digest (D22).
type tokenCreateResponse struct {
	Token  string `json:"token"`
	Digest string `json:"digest"`
}

type tokensResponse struct {
	Tokens []callout.TokenEntry `json:"tokens"`
}

type tokenRevokeRequest struct {
	Digest string `json:"digest"`
}

type sentinelResponse struct {
	JWT   string `json:"jwt"`
	Creds string `json:"creds"`
}

// requireCallout gates the ops that only exist on a callout-enabled service.
func (s *Service) requireCallout() error {
	if s.tokens == nil || s.authKeyName == "" || s.authAccount == "" {
		return errors.New("service: this deployment has no callout configuration (token store + auth key + auth account)")
	}
	return nil
}

func (s *Service) dispatchCallout(account, user, op string, body []byte) (any, error) {
	if err := s.requireCallout(); err != nil {
		return nil, err
	}
	switch op {
	case "tokens.create":
		var req tokenCreateRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		// A token for an account no role is bound to would only ever be
		// refused at callout time; refuse the mistake at issuance (D25).
		if _, err := s.vault.RoleForAccount(req.Account); err != nil {
			return nil, err
		}
		if req.User == "" {
			return nil, errors.New("service: a token names its user")
		}
		token, digest, err := callout.NewToken()
		if err != nil {
			return nil, err
		}
		rec := callout.Record{Account: req.Account, User: req.User, Label: req.Label}
		if req.TTLSeconds > 0 {
			rec.Expires = time.Now().Add(time.Duration(req.TTLSeconds) * time.Second).UTC().Format(time.RFC3339)
		}
		if err := s.tokens.Create(digest, rec); err != nil {
			return nil, err
		}
		s.log.Info("token ISSUED (plaintext returned once)", "op", op,
			"account", account, "user", user,
			"target_account", req.Account, "target_user", req.User,
			"label", req.Label, "digest", digest, "expires", rec.Expires)
		return tokenCreateResponse{Token: token, Digest: digest}, nil

	case "tokens.list":
		entries, err := s.tokens.Entries()
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op)
		return tokensResponse{Tokens: entries}, nil

	case "tokens.revoke":
		var req tokenRevokeRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if req.Digest == "" {
			return nil, errors.New("service: revoke needs the token digest")
		}
		if err := s.tokens.Delete(req.Digest); err != nil {
			return nil, err
		}
		s.log.Info("token REVOKED (open connections end at JWT expiry)", "op", op,
			"account", account, "user", user, "digest", req.Digest)
		return struct{}{}, nil

	case "sentinel.mint":
		ukp, err := nkeys.CreateUser()
		if err != nil {
			return nil, fmt.Errorf("service: sentinel key: %w", err)
		}
		upub, err := ukp.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("service: sentinel key: %w", err)
		}
		uc := jwt.NewUserClaims(upub)
		uc.Name = "sentinel"
		// Bearer + deny-all: distributable by design — the JWT admits only
		// as far as the callout, and is dead weight without it (D19).
		uc.BearerToken = true
		uc.Pub.Deny.Add(">")
		uc.Sub.Deny.Add(">")
		// Signed by a signing key, the sentinel must name its account or
		// the server refuses it before callout fires [measured, e2e].
		uc.IssuerAccount = s.authAccount
		authKP, err := s.vault.KeyPair(s.authKeyName)
		if err != nil {
			return nil, fmt.Errorf("service: AUTH signing key %s: %w", s.authKeyName, err)
		}
		token, err := uc.Encode(authKP)
		if err != nil {
			return nil, fmt.Errorf("service: encode sentinel: %w", err)
		}
		seed, err := ukp.Seed()
		if err != nil {
			return nil, fmt.Errorf("service: sentinel seed: %w", err)
		}
		creds, err := jwt.FormatUserConfig(token, seed)
		if err != nil {
			return nil, fmt.Errorf("service: render sentinel creds: %w", err)
		}
		s.log.Info("sentinel minted (public artifact: bearer, deny-all)", "op", op,
			"account", account, "user", user, "sentinel_key", upub)
		return sentinelResponse{JWT: token, Creds: string(creds)}, nil

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}
