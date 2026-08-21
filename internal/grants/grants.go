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
	"sync"
	"time"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
)

var (
	// ErrNotFound is the one refusal for absent grants — identical whether
	// the resource exists or not, so refusals cannot probe custody.
	ErrNotFound = errors.New("grants: no grant for this persona and resource")
	// ErrCASConflict reports a losing compare-and-swap write (the shared
	// custody-domain error, so store returns match by errors.Is).
	ErrCASConflict = sealedstore.ErrCASConflict
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
	AuthURL      string   `json:"auth_url,omitempty"`
	TokenURL     string   `json:"token_url,omitempty"`
	RevokeURL    string   `json:"revoke_url,omitempty"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	RedirectURI  string   `json:"redirect_uri,omitempty"`
	// Lane 3 (D34): an exchange-capable IdP. Both set = the resource is
	// served by RFC 8693 exchange of the caller's own token — no linking
	// ceremony, no custody, nothing at rest.
	ExchangeTokenURL string `json:"exchange_token_url,omitempty"`
	ExchangeAudience string `json:"exchange_audience,omitempty"`
}

// IsExchange reports whether the resource rides lane 3.
func (r Resource) IsExchange() bool { return r.ExchangeTokenURL != "" }

// Validate refuses an unusable declaration by name.
func (r Resource) Validate() error {
	if r.Name == "" {
		return errors.New("grants: a resource needs a name")
	}
	if (r.ExchangeTokenURL == "") != (r.ExchangeAudience == "") {
		return fmt.Errorf("grants: resource %s: exchange needs both exchange_token_url and exchange_audience", r.Name)
	}
	if r.IsExchange() {
		if r.ClientID == "" {
			return fmt.Errorf("grants: resource %s needs client_id", r.Name)
		}
		return nil
	}
	switch {
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
	// ExchangeToken is lane 3 (D34): RFC 8693 against an
	// exchange-capable IdP — the caller's own token in, a derived
	// audience-scoped token out, nothing custodied.
	ExchangeToken(ctx context.Context, res Resource, subjectToken string) (TokenSet, error)
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

// Broker is the custody engine behind the grants.* ops. The catalog it
// serves is mutable at runtime (D40): the statically declared list and the
// store-held entries merge under one lock, and every ceremony path reads
// through it.
type Broker struct {
	store      *sealedstore.Sealed
	provider   Provider
	subjectKey SubjectKeyResolver
	now        func() time.Time

	mu        sync.RWMutex
	resources map[string]Resource
	// static names the resources declared in configuration — the
	// operator's explicit hand, not editable through the op: that change
	// belongs where the declaration lives.
	static map[string]bool
}

// New builds a broker over a CAS store sealed with the deployment's first
// key (the same seed the vault seals with — one custody root, two domains).
// The starting catalog is the declared list merged with whatever resource
// records the store holds (D40); a name both declared and stored is
// refused loudly — remove one.
func New(store Store, firstKeySeed string, resources []Resource, provider Provider, subjectKey SubjectKeyResolver) (*Broker, error) {
	sealed, err := sealedstore.NewSealed(store, strings.TrimSpace(firstKeySeed))
	if err != nil {
		return nil, fmt.Errorf("grants: %w", err)
	}
	m := make(map[string]Resource, len(resources))
	static := make(map[string]bool, len(resources))
	for _, r := range resources {
		if err := r.Validate(); err != nil {
			return nil, err
		}
		if _, dup := m[r.Name]; dup {
			return nil, fmt.Errorf("grants: resource %s declared twice", r.Name)
		}
		m[r.Name] = r
		static[r.Name] = true
	}
	b := &Broker{
		store:      sealed,
		resources:  m,
		static:     static,
		provider:   provider,
		subjectKey: subjectKey,
		now:        time.Now,
	}
	if err := b.loadStoredResources(); err != nil {
		return nil, err
	}
	return b, nil
}

func grantName(persona, resource string) string { return "grant/" + persona + "/" + resource }
func linkName(persona, id string) string        { return "link/" + persona + "/" + id }
func storedResourceName(name string) string     { return "resource/" + name }

// resourceRecord is what rests sealed for a runtime-added resource: the
// whole declaration, secret beside its public half — one record, never a
// partial description (D39's own anti-split-brain rule, applied at rest).
type resourceRecord struct {
	Resource  Resource `json:"resource"`
	UpdatedAt string   `json:"updated_at"`
}

// loadStoredResources merges the store-held catalog beside the declared one.
func (b *Broker) loadStoredResources() error {
	names, err := b.store.Names()
	if err != nil {
		return fmt.Errorf("grants: list stored resources: %w", err)
	}
	for _, name := range names {
		short, ok := strings.CutPrefix(name, "resource/")
		if !ok {
			continue
		}
		var rec resourceRecord
		if _, err := b.store.Get(name, &rec); err != nil {
			return fmt.Errorf("grants: read stored resource %s: %w", short, err)
		}
		if b.static[short] {
			return fmt.Errorf("grants: resource %s is both declared in configuration and stored — remove one", short)
		}
		b.resources[short] = rec.Resource
	}
	return nil
}

// resource is the one locked read every ceremony path goes through.
func (b *Broker) resource(name string) (Resource, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r, ok := b.resources[name]
	return r, ok
}

// AddResource makes a resource usable at runtime (D40): validated exactly
// like a declared one, persisted whole and sealed, live on return — no
// restart anywhere. Re-adding a runtime resource replaces it; a statically
// declared name refuses, by name.
func (b *Broker) AddResource(r Resource) error {
	if err := r.Validate(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.static[r.Name] {
		return fmt.Errorf("grants: resource %s is declared in configuration — change it there", r.Name)
	}
	// The read is only for the revision: absent reads write as a create.
	var prior resourceRecord
	rev, err := b.store.Get(storedResourceName(r.Name), &prior)
	if err != nil {
		rev = 0
	}
	rec := resourceRecord{Resource: r, UpdatedAt: b.now().UTC().Format(time.RFC3339)}
	if _, err := b.store.Put(storedResourceName(r.Name), rec, rev); err != nil {
		return fmt.Errorf("grants: store resource %s: %w", r.Name, err)
	}
	b.resources[r.Name] = r
	return nil
}

// RemoveResource retires a runtime resource: the next ceremony refuses by
// the uniform not-found. Standing grants keep their custody — revoking is
// each persona's own act, never a side effect of catalog editing. Removing
// what is absent already happened; a declared resource refuses, by name.
func (b *Broker) RemoveResource(name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.static[name] {
		return fmt.Errorf("grants: resource %s is declared in configuration — change it there", name)
	}
	if _, ok := b.resources[name]; !ok {
		return nil
	}
	if err := b.store.Delete(storedResourceName(name)); err != nil {
		return fmt.Errorf("grants: delete resource %s: %w", name, err)
	}
	delete(b.resources, name)
	return nil
}

// ResourceInfo is one catalog entry's public half — what resources.list
// serves. The client secret has no public form anywhere.
type ResourceInfo struct {
	Name             string   `json:"name"`
	AuthURL          string   `json:"auth_url,omitempty"`
	TokenURL         string   `json:"token_url,omitempty"`
	RevokeURL        string   `json:"revoke_url,omitempty"`
	ClientID         string   `json:"client_id"`
	Scopes           []string `json:"scopes,omitempty"`
	RedirectURI      string   `json:"redirect_uri,omitempty"`
	ExchangeTokenURL string   `json:"exchange_token_url,omitempty"`
	ExchangeAudience string   `json:"exchange_audience,omitempty"`
	// Declared says the entry came from configuration rather than the op.
	Declared bool `json:"declared,omitempty"`
}

// Resources lists the catalog's public halves, sorted by name.
func (b *Broker) Resources() []ResourceInfo {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]ResourceInfo, 0, len(b.resources))
	for name, r := range b.resources {
		out = append(out, ResourceInfo{
			Name: r.Name, AuthURL: r.AuthURL, TokenURL: r.TokenURL,
			RevokeURL: r.RevokeURL, ClientID: r.ClientID, Scopes: r.Scopes,
			RedirectURI: r.RedirectURI, ExchangeTokenURL: r.ExchangeTokenURL,
			ExchangeAudience: r.ExchangeAudience, Declared: b.static[name],
		})
	}
	slices.SortFunc(out, func(a, z ResourceInfo) int { return strings.Compare(a.Name, z.Name) })
	return out
}

// ResourceIsExchange reports whether a declared resource rides lane 3.
// Unknown resources answer false; the access path's uniform not-found
// refusal stays the only signal.
func (b *Broker) ResourceIsExchange(resource string) bool {
	res, ok := b.resource(resource)
	return ok && res.IsExchange()
}

// AccessExchange is lane 3's workhorse (D34): the caller's OWN token —
// presented, never retained — exchanged at the declared IdP for a token
// scoped to the resource's audience. No linking, no custody, nothing at
// rest; the derived token is the only thing that moves.
func (b *Broker) AccessExchange(ctx context.Context, resource, subjectToken string) (TokenSet, error) {
	res, ok := b.resource(resource)
	if !ok || !res.IsExchange() {
		return TokenSet{}, ErrNotFound
	}
	if strings.TrimSpace(subjectToken) == "" {
		return TokenSet{}, fmt.Errorf("grants: exchange resource %s needs the caller's subject token", resource)
	}
	return b.provider.ExchangeToken(ctx, res, subjectToken)
}

// LinkStart begins the consent ceremony: PKCE S256, the verifier custodied
// sealed, the authorize URL returned for the persona's own browser.
func (b *Broker) LinkStart(persona, resource string) (authorizeURL, linkID string, err error) {
	res, ok := b.resource(resource)
	if !ok {
		return "", "", fmt.Errorf("grants: unknown resource %q", resource)
	}
	if res.IsExchange() {
		return "", "", fmt.Errorf("grants: resource %s rides token exchange — nothing to link", resource)
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
	if _, err := b.store.Put(linkName(persona, linkID), rec, 0); err != nil {
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
	if _, err := b.store.Get(linkName(persona, linkID), &rec); err != nil {
		return ErrLinkInvalid
	}
	// Spend before redeeming: a crash after this point costs a re-link,
	// never a double custody line (the same honesty as D31's write order).
	if err := b.store.Delete(linkName(persona, linkID)); err != nil {
		return ErrLinkInvalid
	}
	if exp, err := time.Parse(time.RFC3339, rec.Expires); err != nil || b.now().After(exp) {
		return ErrLinkInvalid
	}
	// The resource may have been retired between start and complete —
	// runtime catalogs make that a real window, answered by name.
	res, ok := b.resource(rec.Resource)
	if !ok {
		return fmt.Errorf("grants: resource %s was retired while this link was underway", rec.Resource)
	}
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
	rev, err := b.store.Get(grantName(persona, rec.Resource), &existing)
	if err != nil {
		rev = 0
	}
	if _, err := b.store.Put(grantName(persona, rec.Resource), g, rev); err != nil {
		return err
	}
	return nil
}

// Access redeems the persona's grant and CAS-persists the rotated successor
// BEFORE returning the derived access token (D31's measured discipline).
// A CAS loser serves its still-valid token and writes nothing.
func (b *Broker) Access(ctx context.Context, persona, resource string) (TokenSet, error) {
	res, ok := b.resource(resource)
	if !ok {
		return TokenSet{}, ErrNotFound
	}
	// One contender wins each rotation round; the rest retry against the
	// successor. Contention is bounded by time, not a fixed round count.
	deadline := b.now().Add(5 * time.Second)
	for b.now().Before(deadline) {
		var g grantRecord
		rev, err := b.store.Get(grantName(persona, resource), &g)
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
			if _, err := b.store.Put(grantName(persona, resource), g, rev); err != nil {
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
		curRev, err := b.store.Get(name, &cur)
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
	iss, err := time.Parse(time.RFC3339, d.IssuedAt)
	if err != nil || b.now().Before(iss) {
		return TokenSet{}, fmt.Errorf("%w: not yet valid", ErrDelegationInvalid)
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
	names, err := b.store.Names()
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
		if _, err := b.store.Get(n, &g); err != nil {
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
	if _, err := b.store.Get(grantName(persona, resource), &g); err != nil {
		return ErrNotFound
	}
	if err := b.store.Delete(grantName(persona, resource)); err != nil {
		return err
	}
	if res, ok := b.resource(resource); ok && res.RevokeURL != "" {
		_ = b.provider.Revoke(ctx, res, g.RefreshToken)
	}
	return nil
}
