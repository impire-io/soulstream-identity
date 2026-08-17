// Package grants is the outbound-credentials broker
// (../soul-hq/02-DESIGN/soulstream-identity/grants.md D30–D34): per-persona
// OAuth grants custodied in their own sealed CAS store, redeemed at call
// time for the derived short-lived access token — the refresh token never
// crosses any wire and never rests unsealed (D32). The key vault is not
// touched: its records are immutable by design; rotation lives here, in a
// second custody domain (D31).
package grants

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
)

var (
	// ErrNotFound is the one refusal for absent grants — identical whether
	// the resource exists or not, so refusals cannot probe custody.
	ErrNotFound = errors.New("grants: no grant for this persona and resource")
	// ErrCASConflict reports a losing compare-and-swap write.
	ErrCASConflict = errors.New("grants: record changed underneath the update")
	// ErrLinkInvalid covers expired, spent, or unknown link ceremonies.
	ErrLinkInvalid = errors.New("grants: link ceremony is unknown, spent, or expired")
	// ErrDelegationInvalid covers absent, unverifiable, expired, or
	// out-of-bounds delegations (D33).
	ErrDelegationInvalid = errors.New("grants: delegation missing, unverifiable, expired, or out of bounds")
	// ErrActorMismatch refuses a delegation presented by anyone but its
	// actor — checked against the server-proven caller, never a claim.
	ErrActorMismatch = errors.New("grants: caller is not the delegation's actor")
)

// Resource is a deployment-declared remote system (D34 lane 2): value-only,
// no per-user configuration anywhere (D26's spirit).
type Resource struct {
	Name         string   `json:"name"`
	AuthURL      string   `json:"auth_url"`
	TokenURL     string   `json:"token_url"`
	RevokeURL    string   `json:"revoke_url,omitempty"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	RedirectURI  string   `json:"redirect_uri"`
}

// Validate refuses an unusable declaration by name.
func (r Resource) Validate() error {
	switch {
	case r.Name == "":
		return errors.New("grants: a resource needs a name")
	case r.AuthURL == "" || r.TokenURL == "":
		return fmt.Errorf("grants: resource %s needs auth_url and token_url", r.Name)
	case r.ClientID == "" || r.RedirectURI == "":
		return fmt.Errorf("grants: resource %s needs client_id and redirect_uri", r.Name)
	}
	return nil
}

// grantRecord is what rests sealed in the store: the custodied secret and
// its provenance. It never crosses the service surface.
type grantRecord struct {
	RefreshToken string   `json:"refresh_token"`
	Scopes       []string `json:"scopes,omitempty"`
	LinkedAt     string   `json:"linked_at"`
}

// linkRecord is one in-flight ceremony: single-use, expiring.
type linkRecord struct {
	Resource string `json:"resource"`
	Verifier string `json:"verifier"`
	Expires  string `json:"expires"`
}

// TokenSet is what a provider redemption yields. AccessToken is the derived
// artifact D32 allows out; RefreshToken stays in custody.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// Provider redeems codes and refresh tokens at a resource's AS. The HTTP
// implementation lives in provider.go; tests substitute rotation fakes.
type Provider interface {
	Exchange(ctx context.Context, res Resource, code, verifier string) (TokenSet, error)
	Redeem(ctx context.Context, res Resource, refreshToken string) (TokenSet, error)
	Revoke(ctx context.Context, res Resource, refreshToken string) error
}

// GrantInfo is the public form grants.list returns — provenance, no secret.
type GrantInfo struct {
	Resource string   `json:"resource"`
	Scopes   []string `json:"scopes,omitempty"`
	LinkedAt string   `json:"linked_at"`
}

// Delegation is D33's bounded on-behalf proof, signed by the subject's
// persona key (the D26 directory is the trust root; no new anchor exists).
type Delegation struct {
	Subject   string   `json:"subject"`
	Actor     string   `json:"actor"`
	Resources []string `json:"resources"`
	Scopes    []string `json:"scopes,omitempty"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
}

// SubjectKeyResolver returns the subject persona's public key (base64 raw
// Ed25519, the directory encoding). The broker side supplies the vault read.
type SubjectKeyResolver func(subject string) (string, error)

// Broker is the custody engine behind the grants.* ops.
type Broker struct {
	store      *sealedStore
	resources  map[string]Resource
	provider   Provider
	subjectKey SubjectKeyResolver
	now        func() time.Time
}

// New builds a broker over a CAS store sealed with the deployment's first
// key (the same seed the vault seals with — one custody root, two domains).
func New(store Store, firstKeySeed string, resources []Resource, provider Provider, subjectKey SubjectKeyResolver) (*Broker, error) {
	kp, err := nkeys.FromCurveSeed([]byte(strings.TrimSpace(firstKeySeed)))
	if err != nil {
		return nil, fmt.Errorf("grants: first key is not a curve (SX…) seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("grants: first key public half: %w", err)
	}
	m := make(map[string]Resource, len(resources))
	for _, r := range resources {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if _, dup := m[r.Name]; dup {
			return nil, fmt.Errorf("grants: resource %s declared twice", r.Name)
		}
		m[r.Name] = r
	}
	return &Broker{
		store:      &sealedStore{store: store, first: kp, firstPub: pub},
		resources:  m,
		provider:   provider,
		subjectKey: subjectKey,
		now:        time.Now,
	}, nil
}

func grantName(persona, resource string) string { return "grant/" + persona + "/" + resource }
func linkName(persona, id string) string        { return "link/" + persona + "/" + id }

// LinkStart begins the consent ceremony: PKCE S256, the verifier custodied
// sealed, the authorize URL returned for the persona's own browser.
func (b *Broker) LinkStart(persona, resource string) (authorizeURL, linkID string, err error) {
	res, ok := b.resources[resource]
	if !ok {
		return "", "", fmt.Errorf("grants: unknown resource %q", resource)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("grants: entropy: %w", err)
	}
	linkID = hex.EncodeToString(raw[:16])
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))

	rec := linkRecord{
		Resource: resource,
		Verifier: verifier,
		Expires:  b.now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
	}
	if _, err := b.store.put(linkName(persona, linkID), rec, 0); err != nil {
		return "", "", err
	}

	u, err := url.Parse(res.AuthURL)
	if err != nil {
		return "", "", fmt.Errorf("grants: resource %s auth_url: %w", resource, err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", res.ClientID)
	q.Set("redirect_uri", res.RedirectURI)
	q.Set("state", linkID)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:]))
	q.Set("code_challenge_method", "S256")
	if len(res.Scopes) > 0 {
		q.Set("scope", strings.Join(res.Scopes, " "))
	}
	u.RawQuery = q.Encode()
	return u.String(), linkID, nil
}

// LinkComplete redeems the ceremony's code and begins custody. The link
// record is spent first — a ceremony redeems at most once.
func (b *Broker) LinkComplete(ctx context.Context, persona, linkID, code string) error {
	var rec linkRecord
	if _, err := b.store.get(linkName(persona, linkID), &rec); err != nil {
		return ErrLinkInvalid
	}
	// Spend before redeeming: a crash after this point costs a re-link,
	// never a double custody line (the same honesty as D31's write order).
	if err := b.store.delete(linkName(persona, linkID)); err != nil {
		return ErrLinkInvalid
	}
	if exp, err := time.Parse(time.RFC3339, rec.Expires); err != nil || b.now().After(exp) {
		return ErrLinkInvalid
	}
	res := b.resources[rec.Resource]
	tok, err := b.provider.Exchange(ctx, res, code, rec.Verifier)
	if err != nil {
		return fmt.Errorf("grants: code redemption for %s: %w", rec.Resource, err)
	}
	if tok.RefreshToken == "" {
		return fmt.Errorf("grants: %s returned no refresh token — request offline scope in the declaration", rec.Resource)
	}
	g := grantRecord{
		RefreshToken: tok.RefreshToken,
		Scopes:       res.Scopes,
		LinkedAt:     b.now().UTC().Format(time.RFC3339),
	}
	// Re-linking replaces the line: read any existing revision and write
	// over it under CAS.
	var existing grantRecord
	rev, err := b.store.get(grantName(persona, rec.Resource), &existing)
	if err != nil {
		rev = 0
	}
	if _, err := b.store.put(grantName(persona, rec.Resource), g, rev); err != nil {
		return err
	}
	return nil
}

// Access redeems the persona's grant and CAS-persists the rotated successor
// BEFORE returning the derived access token (D31's measured discipline).
// A CAS loser serves its still-valid token and writes nothing.
func (b *Broker) Access(ctx context.Context, persona, resource string) (TokenSet, error) {
	if _, ok := b.resources[resource]; !ok {
		return TokenSet{}, ErrNotFound
	}
	res := b.resources[resource]
	// One contender wins each rotation round; the rest retry against the
	// successor. Contention is bounded by time, not a fixed round count.
	deadline := b.now().Add(5 * time.Second)
	for b.now().Before(deadline) {
		var g grantRecord
		rev, err := b.store.get(grantName(persona, resource), &g)
		if err != nil {
			return TokenSet{}, ErrNotFound
		}
		tok, err := b.provider.Redeem(ctx, res, g.RefreshToken)
		if err != nil {
			// A concurrent winner may hold the rotation we just lost —
			// its CAS write of the successor may still be in flight, so
			// poll briefly for the revision to move before concluding the
			// line itself is dead.
			if b.waitForRotation(ctx, grantName(persona, resource), rev) {
				continue
			}
			return TokenSet{}, fmt.Errorf("grants: redemption for %s: %w", resource, err)
		}
		if tok.RefreshToken != "" && tok.RefreshToken != g.RefreshToken {
			g.RefreshToken = tok.RefreshToken
			if _, err := b.store.put(grantName(persona, resource), g, rev); err != nil {
				if errors.Is(err, ErrCASConflict) {
					return tok, nil // the winner's successor is the line
				}
				return TokenSet{}, err
			}
		}
		return tok, nil
	}
	return TokenSet{}, fmt.Errorf("grants: access for %s: contention retries exhausted", resource)
}

// waitForRotation polls a grant record for a revision moving past seen —
// the sign a concurrent redeemer's successor landed. Bounded and short: the
// winner's CAS write follows its redemption immediately.
func (b *Broker) waitForRotation(ctx context.Context, name string, seen uint64) bool {
	deadline := b.now().Add(500 * time.Millisecond)
	for b.now().Before(deadline) {
		var cur grantRecord
		curRev, err := b.store.get(name, &cur)
		if err != nil {
			return false // deleted underneath us — not a rotation
		}
		if curRev != seen {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}

// AccessOnBehalf is D33's gate. caller is the server-proven principal of
// the connection — the op layer passes the subject-token user, never
// anything the request body claims.
func (b *Broker) AccessOnBehalf(ctx context.Context, caller, subject, resource, payloadB64, sigB64 string) (TokenSet, error) {
	if payloadB64 == "" || sigB64 == "" {
		return TokenSet{}, fmt.Errorf("%w: no delegation presented", ErrDelegationInvalid)
	}
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: payload is not base64", ErrDelegationInvalid)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: signature is not base64", ErrDelegationInvalid)
	}
	var d Delegation
	if err := json.Unmarshal(payload, &d); err != nil {
		return TokenSet{}, fmt.Errorf("%w: payload is unreadable", ErrDelegationInvalid)
	}
	if d.Subject != subject {
		return TokenSet{}, fmt.Errorf("%w: delegation names subject %q", ErrDelegationInvalid, d.Subject)
	}
	if d.Actor != caller {
		return TokenSet{}, ErrActorMismatch
	}
	exp, err := time.Parse(time.RFC3339, d.ExpiresAt)
	if err != nil || b.now().After(exp) {
		return TokenSet{}, fmt.Errorf("%w: expired", ErrDelegationInvalid)
	}
	if !slices.Contains(d.Resources, resource) {
		return TokenSet{}, fmt.Errorf("%w: resource %s not delegated", ErrDelegationInvalid, resource)
	}
	pubB64, err := b.subjectKey(subject)
	if err != nil {
		return TokenSet{}, fmt.Errorf("%w: subject has no persona key", ErrDelegationInvalid)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return TokenSet{}, fmt.Errorf("%w: subject key is unreadable", ErrDelegationInvalid)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return TokenSet{}, fmt.Errorf("%w: signature does not verify", ErrDelegationInvalid)
	}
	return b.Access(ctx, subject, resource)
}

// List returns the persona's grants, public form only.
func (b *Broker) List(persona string) ([]GrantInfo, error) {
	names, err := b.store.names()
	if err != nil {
		return nil, err
	}
	prefix := "grant/" + persona + "/"
	var out []GrantInfo
	for _, n := range names {
		res, ok := strings.CutPrefix(n, prefix)
		if !ok {
			continue
		}
		var g grantRecord
		if _, err := b.store.get(n, &g); err != nil {
			return nil, err
		}
		out = append(out, GrantInfo{Resource: res, Scopes: g.Scopes, LinkedAt: g.LinkedAt})
	}
	return out, nil
}

// Revoke deletes custody and best-effort revokes upstream (RFC 7009). The
// deletion is the decision; the upstream call may fail without undoing it.
func (b *Broker) Revoke(ctx context.Context, persona, resource string) error {
	var g grantRecord
	if _, err := b.store.get(grantName(persona, resource), &g); err != nil {
		return ErrNotFound
	}
	if err := b.store.delete(grantName(persona, resource)); err != nil {
		return err
	}
	if res, ok := b.resources[resource]; ok && res.RevokeURL != "" {
		_ = b.provider.Revoke(ctx, res, g.RefreshToken)
	}
	return nil
}
