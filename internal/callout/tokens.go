// Package callout is SoulIdentity as the NATS auth-callout issuer
// (../soul-hq/02-DESIGN/soulidentity/auth-callout.md): the front door through which external
// external subjects are represented inside NATS (D12's second lane). The token store
// here is the credential store half of D22 — records name a principal and
// carry no policy; policy stays in the registry.
package callout

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TokenPrefix marks SoulIdentity-issued API tokens.
const TokenPrefix = "sit_"

// Record is the token store's whole schema (D22): the declared principal and
// bookkeeping — deliberately no permission, persona, or role field. Its
// appearance would fire D22's reversal condition.
type Record struct {
	Account string `json:"account"`
	User    string `json:"user"`
	Label   string `json:"label,omitempty"`
	Expires string `json:"expires,omitempty"` // RFC 3339; empty = no expiry
}

// TokenEntry is a stored record with its digest handle (the revocation key).
type TokenEntry struct {
	Digest string `json:"digest"`
	Record
}

// Store is the token store seam: digest-keyed records. NATS KV is the real
// backend; MemTokenStore serves tests.
type Store interface {
	Create(digest string, rec Record) error
	Get(digest string) (Record, bool, error)
	Delete(digest string) error
	Entries() ([]TokenEntry, error)
}

// Digest is the one hashing rule: unsalted SHA-256, honest only because
// tokens are generated high-entropy (256-bit) — explicitly not a password
// scheme (journey 0009).
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewToken mints a fresh high-entropy API token. The plaintext exists only
// in the return value — callers show it once and store the digest.
func NewToken() (token, digest string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("callout: token entropy: %w", err)
	}
	token = TokenPrefix + hex.EncodeToString(raw)
	return token, Digest(token), nil
}

// Validate resolves a presented token against the store: digest lookup plus
// the record's own expiry. It returns the declared principal — authorization
// against the registry is the caller's next step (D22 keeps the stages
// separate).
func Validate(s Store, token string) (Record, error) {
	if token == "" {
		return Record{}, errors.New("callout: no token presented")
	}
	rec, ok, err := s.Get(Digest(token))
	if err != nil {
		return Record{}, err
	}
	if !ok {
		return Record{}, errors.New("callout: unknown token")
	}
	if rec.Expires != "" {
		exp, err := time.Parse(time.RFC3339, rec.Expires)
		if err != nil {
			return Record{}, fmt.Errorf("callout: token record has an unreadable expiry: %w", err)
		}
		if time.Now().After(exp) {
			return Record{}, errors.New("callout: token expired")
		}
	}
	return rec, nil
}

// MemTokenStore is an in-memory Store for tests.
type MemTokenStore struct {
	mu sync.Mutex
	m  map[string]Record
}

// NewMemTokenStore returns an empty MemTokenStore.
func NewMemTokenStore() *MemTokenStore {
	return &MemTokenStore{m: map[string]Record{}}
}

// Create implements Store.
func (s *MemTokenStore) Create(digest string, rec Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[digest]; ok {
		return errors.New("callout: token already exists")
	}
	s.m[digest] = rec
	return nil
}

// Get implements Store.
func (s *MemTokenStore) Get(digest string) (Record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[digest]
	return rec, ok, nil
}

// Delete implements Store.
func (s *MemTokenStore) Delete(digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, digest)
	return nil
}

// Entries implements Store.
func (s *MemTokenStore) Entries() ([]TokenEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TokenEntry, 0, len(s.m))
	for digest, rec := range s.m {
		out = append(out, TokenEntry{Digest: digest, Record: rec})
	}
	return out, nil
}

// marshalRecord / unmarshalRecord are the KV value codec, shared so the KV
// backend and tests agree on bytes.
func marshalRecord(rec Record) ([]byte, error) {
	return json.Marshal(rec)
}

func unmarshalRecord(data []byte) (Record, error) {
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return Record{}, fmt.Errorf("callout: corrupt token record: %w", err)
	}
	return rec, nil
}
