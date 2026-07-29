// Package oidcstub is a test-only local OIDC issuer: discovery + JWKS over
// an httptest server, RS256-signing tokens with Entra-v2.0-shaped claims.
// It exists so the unit suite (internal/callout) and the operator-mode e2e
// (client) measure the OIDC lane against one issuer behavior
// (specs/001-entra-oidc-backend/research.md R5). No production code may
// import it.
package oidcstub

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// Stub serves /.well-known/openid-configuration and a JWKS endpoint, and
// mints RS256 tokens under its active key. Rotate swaps the active key (the
// JWKS serves only the new one — a verifier must refetch on unknown kid);
// SetJWKSDown simulates a key-infrastructure outage; badKey never appears
// in the JWKS.
type Stub struct {
	srv      *httptest.Server
	clientID string
	tenantID string

	mu       sync.Mutex
	active   *rsa.PrivateKey
	kid      string
	serial   int
	jwksDown bool
	badKey   *rsa.PrivateKey
}

// New starts the stub. clientID becomes the default token audience (the
// app registration's client ID in Entra terms).
func New(clientID string) (*Stub, error) {
	active, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidcstub: generate key: %w", err)
	}
	bad, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("oidcstub: generate bad key: %w", err)
	}
	s := &Stub{clientID: clientID, tenantID: "00000000-1111-2222-3333-444444444444",
		active: active, kid: "stub-key-1", serial: 1, badKey: bad}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/keys", s.jwks)
	s.srv = httptest.NewServer(mux)
	return s, nil
}

// Issuer returns the stub's issuer URL (also the discovery base).
func (s *Stub) Issuer() string { return s.srv.URL }

// ClientID returns the default audience.
func (s *Stub) ClientID() string { return s.clientID }

// Close shuts the stub down.
func (s *Stub) Close() { s.srv.Close() }

// Rotate replaces the active signing key under a fresh kid; the JWKS serves
// only the new key from now on.
func (s *Stub) Rotate() error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("oidcstub: rotate: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial++
	s.active, s.kid = key, fmt.Sprintf("stub-key-%d", s.serial)
	return nil
}

// SetJWKSDown makes the JWKS endpoint answer 503 (or restores it).
func (s *Stub) SetJWKSDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwksDown = down
}

func (s *Stub) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.srv.URL,
		"jwks_uri":                              s.srv.URL + "/keys",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"subject_types_supported":               []string{"pairwise"},
	})
}

func (s *Stub) jwks(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	down, key, kid := s.jwksDown, s.active, s.kid
	s.mu.Unlock()
	if down {
		http.Error(w, "jwks unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": b64url(key.N.Bytes()),
		"e": b64url(big.NewInt(int64(key.E)).Bytes()),
	}}})
}

// Claims returns the Entra-v2.0-shaped defaults for one subject holding
// roles; tests override or delete entries before minting (a nil value
// deletes the claim).
func (s *Stub) Claims(oid string, roles ...string) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": s.srv.URL,
		"aud": s.clientID,
		"ver": "2.0",
		"tid": s.tenantID,
		"oid": oid,
		"sub": "pairwise-" + oid,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if len(roles) > 0 {
		c["roles"] = roles
	}
	return c
}

// Token mints an RS256 token under the active key from the claim set.
func (s *Stub) Token(claims map[string]any) (string, error) {
	s.mu.Lock()
	key, kid := s.active, s.kid
	s.mu.Unlock()
	return signRS256(key, kid, claims)
}

// TokenBadKey mints an RS256 token under a key the JWKS never serves.
func (s *Stub) TokenBadKey(claims map[string]any) (string, error) {
	return signRS256(s.badKey, "never-published", claims)
}

// TokenAlg mints a token under an arbitrary alg for downgrade rows:
// "none" (empty signature) or "HS256" (HMAC over a static secret).
func (s *Stub) TokenAlg(alg string, claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": alg}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64url(h) + "." + b64url(p)
	switch alg {
	case "none":
		return signing + ".", nil
	case "HS256":
		mac := sha256.Sum256([]byte(signing + "|static-test-secret"))
		return signing + "." + b64url(mac[:]), nil
	default:
		return "", fmt.Errorf("oidcstub: unsupported alg %q", alg)
	}
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	h, err := json.Marshal(map[string]any{"typ": "JWT", "alg": "RS256", "kid": kid})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64url(h) + "." + b64url(p)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("oidcstub: sign: %w", err)
	}
	return signing + "." + b64url(sig), nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
