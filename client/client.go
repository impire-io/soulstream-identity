// Package client talks to a SoulIdentity service over NATS request/reply with
// xkey-sealed payloads (hq/02-DESIGN/nats-surface.md D16). The caller's NATS
// connection is the authentication: requests ride the caller's own subject
// prefix, which the server only lets the rightful principal publish to (D15).
//
// The types here mirror the service's JSON wire contract; this package is the
// contract's canonical consumer-side definition.
package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// Segment is the service's fixed token in the subject space; the full root
// is <prefix>.<Segment>, where the prefix is the deployment's shared
// ecosystem namespace, empty by default (D14 as amended, journey 0011).
const Segment = "soulidentity"

// Key is a vault entry as the service shows it: never the secret. The
// binding fields are the authorization source (D25): for an account signing
// key, Account is the account it signs for — the team's binding (D24); for
// a persona signing key, (Account, User) is the owner principal that may
// sign with it; both empty for user keys.
type Key struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
	Account   string `json:"account,omitempty"`
	User      string `json:"user,omitempty"`
}

// Vault key kinds (the service's vocabulary).
const (
	KindNATSAccountSigningKey = "nats-account-signing-key"
	KindNATSUserKey           = "nats-user-key"
	KindPersonaSigningKey     = "persona-signing-key"
)

// MintResult is a minted user JWT; Creds is present only when the custody
// escape was explicitly requested.
type MintResult struct {
	JWT           string `json:"jwt"`
	UserPublicKey string `json:"user_public_key"`
	Creds         string `json:"creds,omitempty"`
}

// Client is a SoulIdentity service client bound to the principal its
// connection authenticates as. The zero value is not usable; New.
type Client struct {
	nc      *nats.Conn
	account string
	user    string
	timeout time.Duration
	root    string // <prefix>.<Segment>; must match the service's deployment

	mu         sync.Mutex
	servicePub string // pinned via WithServiceXKey or learned by discovery
}

// Option configures a Client.
type Option func(*Client)

// WithServiceXKey pins the service's surface public key out of band instead
// of trusting discovery over the broker (hq/02-DESIGN/nats-surface.md D16).
func WithServiceXKey(pub string) Option {
	return func(c *Client) { c.servicePub = pub }
}

// WithTimeout overrides the per-request timeout (default 10s).
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.timeout = d }
}

// WithPrefix targets a service deployed under a shared ecosystem prefix —
// the same prefix the service was started with; a mismatch surfaces as
// request timeouts, not errors.
func WithPrefix(prefix string) Option {
	return func(c *Client) {
		c.root = Segment
		if prefix != "" {
			c.root = prefix + "." + Segment
		}
	}
}

// New returns a client speaking as (account, user) — the same principal nc is
// authenticated as; the server refuses the subject prefix otherwise.
func New(nc *nats.Conn, account, user string, opts ...Option) *Client {
	c := &Client{nc: nc, account: account, user: user, timeout: 10 * time.Second, root: Segment}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// envelope is the sealed transport shape (D16); encoding/json carries Data as
// base64.
type envelope struct {
	XKey string `json:"xkey"`
	Data []byte `json:"data"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// serviceXKey returns the service's surface public key, discovering it once.
func (c *Client) serviceXKey() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.servicePub != "" {
		return c.servicePub, nil
	}
	msg, err := c.nc.Request(c.root+".xkey", nil, c.timeout)
	if err != nil {
		return "", fmt.Errorf("soulidentity: service discovery: %w", err)
	}
	var x struct {
		XKey string `json:"xkey"`
	}
	if err := json.Unmarshal(msg.Data, &x); err != nil || x.XKey == "" {
		return "", errors.New("soulidentity: service discovery returned no xkey")
	}
	c.servicePub = x.XKey
	return c.servicePub, nil
}

// call performs one sealed round-trip on the client's own subject prefix.
func (c *Client) call(op string, in, out any) error {
	servicePub, err := c.serviceXKey()
	if err != nil {
		return err
	}
	eph, err := nkeys.CreateCurveKeys()
	if err != nil {
		return fmt.Errorf("soulidentity: ephemeral key: %w", err)
	}
	ephPub, err := eph.PublicKey()
	if err != nil {
		return fmt.Errorf("soulidentity: ephemeral key: %w", err)
	}
	plain, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("soulidentity: encode request: %w", err)
	}
	sealed, err := eph.Seal(plain, servicePub)
	if err != nil {
		return fmt.Errorf("soulidentity: seal request: %w", err)
	}
	req, err := json.Marshal(envelope{XKey: ephPub, Data: sealed})
	if err != nil {
		return fmt.Errorf("soulidentity: encode envelope: %w", err)
	}

	subject := strings.Join([]string{c.root, c.account, c.user, op}, ".")
	msg, err := c.nc.Request(subject, req, c.timeout)
	if err != nil {
		return fmt.Errorf("soulidentity: %s: %w", op, err)
	}

	var env envelope
	if uerr := json.Unmarshal(msg.Data, &env); uerr != nil || len(env.Data) == 0 {
		// Not an envelope: a plaintext refusal from before the secure channel.
		var er errorResponse
		if json.Unmarshal(msg.Data, &er) == nil && er.Error != "" {
			return fmt.Errorf("soulidentity: %s", er.Error)
		}
		return fmt.Errorf("soulidentity: %s: unreadable reply", op)
	}
	// Replies are opened against the pinned/discovered service key — a reply
	// sealed by anything else does not open.
	opened, err := eph.Open(env.Data, servicePub)
	if err != nil {
		return fmt.Errorf("soulidentity: %s: reply cannot be unsealed: %w", op, err)
	}
	var er errorResponse
	if json.Unmarshal(opened, &er) == nil && er.Error != "" {
		return fmt.Errorf("soulidentity: %s", er.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(opened, out); err != nil {
		return fmt.Errorf("soulidentity: decode response: %w", err)
	}
	return nil
}

// Status returns the service's version, doubling as a liveness probe. It is
// one of the two open (unsealed) ops.
func (c *Client) Status() (string, error) {
	msg, err := c.nc.Request(c.root+".status", nil, c.timeout)
	if err != nil {
		return "", fmt.Errorf("soulidentity: status: %w", err)
	}
	var out struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(msg.Data, &out); err != nil {
		return "", fmt.Errorf("soulidentity: decode status: %w", err)
	}
	return out.Version, nil
}

// ImportKey stores a secret in the vault (write-only; the response carries
// the public key). Existing names are refused. account and user are the
// binding (D25): an account signing key requires account — the account it
// signs for (the key name is the team name, D24); a persona signing key
// requires both — its owner; other kinds refuse either. An operator op —
// the deployment's permission template gates who reaches it.
func (c *Client) ImportKey(name, kind, secret, account, user string) (Key, error) {
	var out Key
	err := c.call("keys.import", map[string]string{
		"name": name, "kind": kind, "secret": secret, "account": account, "user": user,
	}, &out)
	return out, err
}

// Keys lists the vault (public form). An operator op.
func (c *Client) Keys() ([]Key, error) {
	var out struct {
		Keys []Key `json:"keys"`
	}
	err := c.call("keys.list", struct{}{}, &out)
	return out.Keys, err
}

// PersonaKeyName is the vault name of a persona's signing key; the key's
// owner binding is what sign.record and keys.public are enforced against
// (D6 as amended, D25).
func PersonaKeyName(persona string) string {
	return "persona/" + persona
}

// SignRecord signs canonical record bytes as persona, returning the base64
// signature string Soulstream-Sig carries. The service enforces the persona
// key's owner binding against this client's principal (D6 as amended).
func (c *Client) SignRecord(persona string, canonical []byte) (string, error) {
	var out struct {
		Sig       string `json:"sig"`
		PublicKey string `json:"public_key"`
	}
	err := c.call("sign.record", map[string]string{
		"key": PersonaKeyName(persona), "canonical": base64.StdEncoding.EncodeToString(canonical),
	}, &out)
	return out.Sig, err
}

// PersonaPublicKey returns any persona's public key (base64 raw Ed25519,
// the encoding soulstream pins and keyrings use) — the directory read
// (D26): the vault that custodies the keys is the realm's key directory,
// and readers build verification keyrings from it; no published per-user
// profile store exists. The caller's own persona key materializes on
// first touch.
func (c *Client) PersonaPublicKey(persona string) (string, error) {
	var out Key
	err := c.call("keys.public", map[string]string{"key": PersonaKeyName(persona)}, &out)
	return out.PublicKey, err
}

// PersonaSigner is the persona bound to a signing capability: the shape of
// soulstream's identity.Signer seam (PublicKey() string; Sign(canonical
// []byte) (string, error)), satisfied structurally — this package imports
// nothing of soulstream and soulstream nothing of it; a consumer wires the
// two (the cycle guard, ROADMAP M2). Safe for concurrent use: every Sign is
// an independent sealed round-trip; deadlines are the Client's per-request
// timeout, owned here as the seam requires.
type PersonaSigner struct {
	c       *Client
	persona string
	pub     string
}

// PersonaSigner binds persona to its signer, resolving the public key once
// through keys.public. The client principal's own persona key materializes
// in the vault on this first touch (D26) — no provisioning act preceded
// it. Construction fails when the persona key is owned by another
// principal (D6 as amended), so a mis-wired signer fails fast, not at
// first publish.
func (c *Client) PersonaSigner(persona string) (*PersonaSigner, error) {
	var out Key
	if err := c.call("keys.public", map[string]string{"key": PersonaKeyName(persona)}, &out); err != nil {
		return nil, err
	}
	if out.PublicKey == "" {
		return nil, errors.New("soulidentity: keys.public returned no public key")
	}
	if out.Account != c.account || out.User != c.user {
		return nil, fmt.Errorf("soulidentity: persona %q is owned by another principal — this client signs only with its own key", persona)
	}
	return &PersonaSigner{c: c, persona: persona, pub: out.PublicKey}, nil
}

// PublicKey returns the persona's public key — the persona this signer
// signs as.
func (s *PersonaSigner) PublicKey() string { return s.pub }

// Sign signs canonical bytes as the persona. It never returns ("", nil):
// an empty signature is a signing failure (the seam's contract — the
// canonical form spells "unsigned" as an omitted sig).
func (s *PersonaSigner) Sign(canonical []byte) (string, error) {
	sig, err := s.c.SignRecord(s.persona, canonical)
	if err != nil {
		return "", err
	}
	if sig == "" {
		return "", errors.New("soulidentity: service returned an empty signature")
	}
	return sig, nil
}

// Mint issues a durable user JWT for (account, user) — an operator op:
// issuing durable credentials is provisioning (D25).
func (c *Client) Mint(account, user string) (MintResult, error) {
	var out MintResult
	err := c.call("mint", map[string]any{
		"account": account, "user": user,
	}, &out)
	return out, err
}

// MintCreds is the explicit custody escape (hq/02-DESIGN/agent.md D7): mint plus a creds
// file whose seed leaves the vault. For self-custody onboarding and external
// tools; the service logs it loudly.
func (c *Client) MintCreds(account, user string) (MintResult, error) {
	var out MintResult
	err := c.call("mint", map[string]any{
		"account": account, "user": user, "export_creds": true,
	}, &out)
	if err == nil && out.Creds == "" {
		return out, errors.New("soulidentity: service did not return creds")
	}
	return out, err
}

// UserKeyName is the vault name of a principal's minted user key.
func UserKeyName(account, user string) string {
	return "user/" + account + "/" + user
}

// TokenEntry is a stored API token as the service shows it: the digest
// handle and the declared principal — never the plaintext.
type TokenEntry struct {
	Digest  string `json:"digest"`
	Account string `json:"account"`
	User    string `json:"user"`
	Label   string `json:"label,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// TokenResult is a freshly issued API token. The plaintext appears here and
// nowhere else — the service stores only the digest.
type TokenResult struct {
	Token  string `json:"token"`
	Digest string `json:"digest"`
}

// SentinelResult is a minted sentinel: a bearer, deny-all user JWT (and its
// creds rendering) — public by design (hq/02-DESIGN/auth-callout.md D19).
type SentinelResult struct {
	JWT   string `json:"jwt"`
	Creds string `json:"creds"`
}

// CreateToken issues an API token for a principal; ttl of zero
// means no expiry. An operator op (D25).
func (c *Client) CreateToken(account, user, label string, ttl time.Duration) (TokenResult, error) {
	var out TokenResult
	err := c.call("tokens.create", map[string]any{
		"account": account, "user": user, "label": label,
		"ttl_seconds": int64(ttl / time.Second),
	}, &out)
	return out, err
}

// Tokens lists the stored API tokens (digests and principals, never
// plaintext). An operator op (D25).
func (c *Client) Tokens() ([]TokenEntry, error) {
	var out struct {
		Tokens []TokenEntry `json:"tokens"`
	}
	err := c.call("tokens.list", struct{}{}, &out)
	return out.Tokens, err
}

// RevokeToken deletes a token by its digest handle: the next connection
// attempt is refused; open connections end at their JWT's expiry. An
// operator op (D25).
func (c *Client) RevokeToken(digest string) error {
	return c.call("tokens.revoke", map[string]string{"digest": digest}, nil)
}

// MintSentinel mints the deployment's sentinel credential. An operator op
// (D25).
func (c *Client) MintSentinel() (SentinelResult, error) {
	var out SentinelResult
	err := c.call("sentinel.mint", struct{}{}, &out)
	return out, err
}
