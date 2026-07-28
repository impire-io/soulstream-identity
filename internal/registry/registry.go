// Package registry is the identity ledger: which (account, user) exists, which
// personas it may act as, and which vault role mints its credentials.
// Identities are declared, never inferred (hq/02-DESIGN/agent.md D2); the act-as list is
// the runtime shadow of Soulstream's operated_by claim (D6).
package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nats-io/nkeys"
)

// Identity is one registered identity, keyed by (Account, User).
type Identity struct {
	// Account is the NATS account public key ("A…") the user belongs to.
	// Membership is declared here; the minted JWT's issuer_account carries it.
	Account string `json:"account"`
	// User is the identity's name within the account.
	User string `json:"user"`
	// Personas this identity may act as (sign records for). Soulstream-level
	// policy — transport permissions live NATS-side in the role's scope (D5).
	Personas []string `json:"personas,omitempty"`
	// Role names the vault key (an account signing key, ideally scoped) that
	// mints this identity's user JWTs.
	Role string `json:"role,omitempty"`
}

// Validate checks the shape: a real account public key, a sane user name.
func (id Identity) Validate() error {
	if !nkeys.IsValidPublicAccountKey(id.Account) {
		return fmt.Errorf("registry: %q is not a NATS account public key", id.Account)
	}
	if id.User == "" || len(id.User) > 128 {
		return errors.New("registry: user is required (max 128 chars)")
	}
	if strings.ContainsAny(id.User, " \t\r\n/") {
		return fmt.Errorf("registry: user %q must not contain whitespace or '/'", id.User)
	}
	for _, p := range id.Personas {
		if strings.TrimSpace(p) == "" {
			return errors.New("registry: empty persona in act-as list")
		}
	}
	return nil
}

// Registry is a strict-decoded JSON file of identities. Single-writer by
// design: the agent owns it.
type Registry struct {
	path string
}

// Open uses path as the registry file; a missing file is an empty registry.
func Open(path string) (*Registry, error) {
	if path == "" {
		return nil, errors.New("registry: a file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("registry: create dir: %w", err)
	}
	return &Registry{path: path}, nil
}

type document struct {
	Identities []Identity `json:"identities"`
}

func (r *Registry) load() (document, error) {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return document{}, nil
		}
		return document{}, fmt.Errorf("registry: read %s: %w", r.path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return document{}, fmt.Errorf("registry: %s is invalid: %w", r.path, err)
	}
	return doc, nil
}

func (r *Registry) save(doc document) error {
	slices.SortFunc(doc.Identities, func(a, b Identity) int {
		if c := strings.Compare(a.Account, b.Account); c != 0 {
			return c
		}
		return strings.Compare(a.User, b.User)
	})
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: encode: %w", err)
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("registry: write: %w", err)
	}
	if err := os.Rename(tmp, r.path); err != nil {
		return fmt.Errorf("registry: commit: %w", err)
	}
	return nil
}

// Put declares an identity, replacing any existing (account, user) entry —
// declaration is idempotent and the newest declaration wins.
func (r *Registry) Put(id Identity) error {
	if err := id.Validate(); err != nil {
		return err
	}
	doc, err := r.load()
	if err != nil {
		return err
	}
	doc.Identities = slices.DeleteFunc(doc.Identities, func(e Identity) bool {
		return e.Account == id.Account && e.User == id.User
	})
	doc.Identities = append(doc.Identities, id)
	return r.save(doc)
}

// Get returns one identity; absence is (zero, false, nil), never an error.
func (r *Registry) Get(account, user string) (Identity, bool, error) {
	doc, err := r.load()
	if err != nil {
		return Identity{}, false, err
	}
	for _, id := range doc.Identities {
		if id.Account == account && id.User == user {
			return id, true, nil
		}
	}
	return Identity{}, false, nil
}

// List returns every identity, sorted by (account, user).
func (r *Registry) List() ([]Identity, error) {
	doc, err := r.load()
	if err != nil {
		return nil, err
	}
	return doc.Identities, nil
}

// AllowedPersona reports whether (account, user) may act as persona.
// An unregistered identity is allowed nothing.
func (r *Registry) AllowedPersona(account, user, persona string) (bool, error) {
	id, ok, err := r.Get(account, user)
	if err != nil || !ok {
		return false, err
	}
	return slices.Contains(id.Personas, persona), nil
}
