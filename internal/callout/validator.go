// Validator: D22's authn-backend seam made concrete (D23). A presented
// credential proves a subject; authorization stays in the issuer (registry
// row for the token lane, declared team for the claims lane) and mint is
// shared. The seam exists because the design names its backends — API
// tokens and Entra/OIDC — not as a plugin point for later.

package callout

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Lane names the credential family a subject arrived through — audit
// vocabulary, fixed by the contract (specs/001-entra-oidc-backend).
type Lane string

const (
	// LaneToken is the sit_ API-token lane (registry-declared membership).
	LaneToken Lane = "token"
	// LaneOIDC is the eyJ external-JWT lane (claims-derived membership, D24).
	LaneOIDC Lane = "oidc"
)

// ExternalSubject is stage-1 output (D22): who the credential names,
// carrying what the authorize stage needs. Fields are lane-specific; Lane
// tags which half is meaningful.
type ExternalSubject struct {
	Lane Lane

	// Token lane: the principal the token record names.
	Account string
	User    string
	Label   string

	// OIDC lane: the validated external subject.
	OID     string
	Display string // preferred_username — audit legibility only, never keyed
	Issuer  string
	Roles   []string
}

// Validator proves a presented credential names a subject (D23). It decides
// nothing about authorization — policy never lives in the credential store
// (D22).
type Validator interface {
	Validate(credential string) (ExternalSubject, error)
}

// APITokenValidator is the sit_ lane: an unsalted SHA-256 digest lookup in
// the token store (D22's stage 1 for API tokens).
type APITokenValidator struct {
	tokens Store
}

// NewAPITokenValidator wraps the token store as a Validator.
func NewAPITokenValidator(tokens Store) *APITokenValidator {
	return &APITokenValidator{tokens: tokens}
}

// Validate resolves the token record; authorization (the registry row) is
// the caller's stage.
func (a *APITokenValidator) Validate(credential string) (ExternalSubject, error) {
	rec, err := Validate(a.tokens, credential)
	if err != nil {
		return ExternalSubject{}, err
	}
	return ExternalSubject{Lane: LaneToken, Account: rec.Account, User: rec.User, Label: rec.Label}, nil
}

// OIDCValidator is the eyJ lane: an external JWT verified against one
// pinned issuer and audience via OIDC discovery + JWKS (D23). Discovery
// runs at construction and fails closed; verification refetches the key
// set on an unknown kid, so provider key rotation needs no restart.
type OIDCValidator struct {
	issuer   string
	audience string
	verifier *oidc.IDTokenVerifier
}

// NewOIDCValidator discovers the issuer and pins the verifier to it: exact
// issuer match, the audience, and RS256 only (alg downgrades refuse).
func NewOIDCValidator(ctx context.Context, issuer, audience string) (*OIDCValidator, error) {
	if issuer == "" || audience == "" {
		return nil, errors.New("callout: the oidc lane needs both issuer and audience")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("callout: oidc discovery for %s: %w", issuer, err)
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID:             audience,
		SupportedSigningAlgs: []string{oidc.RS256},
	})
	return &OIDCValidator{issuer: issuer, audience: audience, verifier: verifier}, nil
}

// Validate verifies signature, issuer, audience, and validity window, then
// extracts the claims the authorize stage needs. The stable oid keys the
// subject; preferred_username is carried for the audit only.
func (o *OIDCValidator) Validate(credential string) (ExternalSubject, error) {
	tok, err := o.verifier.Verify(context.Background(), credential)
	if err != nil {
		return ExternalSubject{}, fmt.Errorf("oidc token rejected: %w", err)
	}
	var c struct {
		OID     string   `json:"oid"`
		Roles   []string `json:"roles"`
		Display string   `json:"preferred_username"`
	}
	if err := tok.Claims(&c); err != nil {
		return ExternalSubject{}, fmt.Errorf("oidc claims unreadable: %w", err)
	}
	if c.OID == "" {
		return ExternalSubject{}, errors.New("oidc token carries no oid")
	}
	return ExternalSubject{Lane: LaneOIDC, OID: c.OID, Display: c.Display, Issuer: tok.Issuer, Roles: c.Roles}, nil
}
