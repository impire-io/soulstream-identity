// Package client talks to a SoulIdentity agent over its Unix socket and wires
// the agent's oracles into consumers — most importantly nats.go's credential
// callbacks, so a NATS connection authenticates with a key that never leaves
// the vault (DESIGN.md D1).
//
// The types here mirror the agent's JSON wire contract; this package is the
// contract's canonical consumer-side definition.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
)

// Key is a vault entry as the agent shows it: never the secret.
type Key struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
}

// Vault key kinds (the agent's vocabulary).
const (
	KindNATSAccountSigningKey = "nats-account-signing-key"
	KindNATSUserKey           = "nats-user-key"
	KindPersonaSigningKey     = "persona-signing-key"
)

// Identity is one registered identity, keyed by (Account, User).
type Identity struct {
	Account  string   `json:"account"`
	User     string   `json:"user"`
	Personas []string `json:"personas,omitempty"`
	Role     string   `json:"role,omitempty"`
}

// MintResult is a minted user JWT; Creds is present only when the custody
// escape was explicitly requested.
type MintResult struct {
	JWT           string `json:"jwt"`
	UserPublicKey string `json:"user_public_key"`
	Creds         string `json:"creds,omitempty"`
}

// DefaultSocket is the agent's default socket path
// (<user-config-dir>/soulidentity/agent.sock).
func DefaultSocket() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join("soulidentity", "agent.sock")
	}
	return filepath.Join(dir, "soulidentity", "agent.sock")
}

// Client is a SoulIdentity agent client. The zero value is not usable; New.
type Client struct {
	socket string
	hc     *http.Client
}

// New returns a client for the agent at socket ("" means DefaultSocket).
func New(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket()
	}
	return &Client{
		socket: socket,
		hc: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
			Timeout: 10 * time.Second,
		},
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

// call performs one JSON round-trip. The host "agent" is a placeholder — the
// transport dials the socket regardless.
func (c *Client) call(method, path string, in, out any) error {
	var body *bytes.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("soulidentity: encode request: %w", err)
		}
		body = bytes.NewReader(data)
	} else {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, "http://agent"+path, body)
	if err != nil {
		return fmt.Errorf("soulidentity: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("soulidentity: agent at %s unreachable: %w", c.socket, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		var er errorResponse
		if json.NewDecoder(resp.Body).Decode(&er) == nil && er.Error != "" {
			return fmt.Errorf("soulidentity: %s", er.Error)
		}
		return fmt.Errorf("soulidentity: agent returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("soulidentity: decode response: %w", err)
	}
	return nil
}

// Status returns the agent's version, doubling as a liveness probe.
func (c *Client) Status() (string, error) {
	var out struct {
		Version string `json:"version"`
	}
	if err := c.call(http.MethodGet, "/v1/status", nil, &out); err != nil {
		return "", err
	}
	return out.Version, nil
}

// ImportKey stores a secret in the vault (write-only; the response carries the
// public key). Existing names are refused.
func (c *Client) ImportKey(name, kind, secret string) (Key, error) {
	var out Key
	err := c.call(http.MethodPost, "/v1/keys", map[string]string{
		"name": name, "kind": kind, "secret": secret,
	}, &out)
	return out, err
}

// Keys lists the vault (public form).
func (c *Client) Keys() ([]Key, error) {
	var out struct {
		Keys []Key `json:"keys"`
	}
	err := c.call(http.MethodGet, "/v1/keys", nil, &out)
	return out.Keys, err
}

// PutIdentity declares an identity (create-or-replace).
func (c *Client) PutIdentity(id Identity) error {
	return c.call(http.MethodPost, "/v1/identities", id, nil)
}

// Identities lists the registry.
func (c *Client) Identities() ([]Identity, error) {
	var out struct {
		Identities []Identity `json:"identities"`
	}
	err := c.call(http.MethodGet, "/v1/identities", nil, &out)
	return out.Identities, err
}

// SignNonce signs a NATS connection nonce with the named vault key, returning
// raw signature bytes — the shape nats.go's signature callback wants.
func (c *Client) SignNonce(key string, nonce []byte) ([]byte, error) {
	var out struct {
		Sig string `json:"sig"`
	}
	if err := c.call(http.MethodPost, "/v1/sign/nonce", map[string]string{
		"key": key, "nonce": base64.StdEncoding.EncodeToString(nonce),
	}, &out); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(out.Sig)
	if err != nil {
		return nil, fmt.Errorf("soulidentity: agent returned invalid signature: %w", err)
	}
	return sig, nil
}

// SignRecord signs canonical record bytes with the named persona key,
// returning the base64 signature string Soulstream-Sig carries.
func (c *Client) SignRecord(key string, canonical []byte) (string, error) {
	var out struct {
		Sig string `json:"sig"`
	}
	err := c.call(http.MethodPost, "/v1/sign/record", map[string]string{
		"key": key, "canonical": base64.StdEncoding.EncodeToString(canonical),
	}, &out)
	return out.Sig, err
}

// Mint issues a user JWT for the registered identity. The user key lives in
// the vault; connecting uses NATSOption, no creds file.
func (c *Client) Mint(account, user string) (MintResult, error) {
	var out MintResult
	err := c.call(http.MethodPost, "/v1/mint", map[string]any{
		"account": account, "user": user,
	}, &out)
	return out, err
}

// MintCreds is the explicit custody escape (DESIGN.md D7): mint plus a creds
// file whose seed leaves the vault. For external tools only.
func (c *Client) MintCreds(account, user string) (MintResult, error) {
	var out MintResult
	err := c.call(http.MethodPost, "/v1/mint", map[string]any{
		"account": account, "user": user, "export_creds": true,
	}, &out)
	if err == nil && out.Creds == "" {
		return out, errors.New("soulidentity: agent did not return creds")
	}
	return out, err
}

// UserKeyName is the vault name of an identity's minted user key.
func UserKeyName(account, user string) string {
	return "user/" + account + "/" + user
}

// NATSOption returns a nats.Option authenticating as (account, user) entirely
// through the agent: the JWT callback mints (idempotently reusing the vaulted
// user key), the signature callback signs the server's nonce in the vault.
// No key material ever reaches this process.
func (c *Client) NATSOption(account, user string) nats.Option {
	key := UserKeyName(account, user)
	return nats.UserJWT(
		func() (string, error) {
			res, err := c.Mint(account, user)
			if err != nil {
				return "", err
			}
			return res.JWT, nil
		},
		func(nonce []byte) ([]byte, error) {
			return c.SignNonce(key, nonce)
		},
	)
}
