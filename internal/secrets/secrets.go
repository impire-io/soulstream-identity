// Package secrets is the custodian's general secret store (D36 — hq
// 02-DESIGN/soulstream-identity/tenancy.md): the third custody domain
// on the sealed CAS pattern. Every path lives under the calling
// persona's own tree by construction — the same path in two personas
// names two secrets, and no caller can name a path outside its reach:
// the op layer passes the server-proven principal, never a claim.
package secrets

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
)

var (
	// ErrNotFound is the one absent-secret refusal — identical whether
	// the path ever existed, so refusals cannot probe the tree.
	ErrNotFound = errors.New("secrets: no such secret")
	// ErrCASConflict reports a losing conditional write (D2).
	ErrCASConflict = sealedstore.ErrCASConflict
	// ErrBadPath refuses a path outside the naming scheme.
	ErrBadPath = errors.New("secrets: path must be 1-8 segments of [A-Za-z0-9._-], joined by '/'")
)

var segmentRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// record is what rests sealed: the secret and its provenance.
type record struct {
	Value     []byte `json:"value"`
	UpdatedAt string `json:"updated_at"`
}

// Service custodies per-persona secrets over a sealed CAS store.
type Service struct {
	store *sealedstore.Sealed
}

// New builds the service over a CAS store sealed with the deployment's
// first key — one custody root, its own domain and bucket.
func New(store sealedstore.Store, firstKeySeed string) (*Service, error) {
	sealed, err := sealedstore.NewSealed(store, strings.TrimSpace(firstKeySeed))
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	return &Service{store: sealed}, nil
}

// CheckPath refuses paths outside the scheme before any storage touch.
func CheckPath(path string) error {
	segments := strings.Split(path, "/")
	if len(segments) < 1 || len(segments) > 8 {
		return ErrBadPath
	}
	for _, seg := range segments {
		if !segmentRe.MatchString(seg) {
			return ErrBadPath
		}
	}
	return nil
}

func name(persona, path string) string { return "secret/" + persona + "/" + path }

// Put writes the persona's secret at path iff the stored revision equals
// expectedRev (0 = create; the path must not exist). Returns the new
// revision — the caller's handle for its next conditional write (D2).
func (s *Service) Put(persona, path string, value []byte, expectedRev uint64) (uint64, error) {
	if err := CheckPath(path); err != nil {
		return 0, err
	}
	rec := record{Value: value, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	rev, err := s.store.Put(name(persona, path), rec, expectedRev)
	if err != nil {
		if errors.Is(err, sealedstore.ErrCASConflict) {
			return 0, fmt.Errorf("%w: %s", ErrCASConflict, path)
		}
		return 0, err
	}
	return rev, nil
}

// Get returns the persona's secret at path and its revision.
func (s *Service) Get(persona, path string) ([]byte, uint64, error) {
	if err := CheckPath(path); err != nil {
		return nil, 0, err
	}
	var rec record
	rev, err := s.store.Get(name(persona, path), &rec)
	if err != nil {
		if errors.Is(err, sealedstore.ErrNotFound) {
			return nil, 0, fmt.Errorf("%w: %s", ErrNotFound, path)
		}
		return nil, 0, err
	}
	return rec.Value, rev, nil
}

// List returns the persona's secret paths — its own tree, nothing else,
// by construction of the name prefix.
func (s *Service) List(persona string) ([]string, error) {
	names, err := s.store.Names()
	if err != nil {
		return nil, err
	}
	prefix := "secret/" + persona + "/"
	var out []string
	for _, n := range names {
		if p, ok := strings.CutPrefix(n, prefix); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// Delete removes the persona's secret at path; absent refuses.
func (s *Service) Delete(persona, path string) error {
	if err := CheckPath(path); err != nil {
		return err
	}
	var rec record
	if _, err := s.store.Get(name(persona, path), &rec); err != nil {
		return fmt.Errorf("%w: %s", ErrNotFound, path)
	}
	return s.store.Delete(name(persona, path))
}
