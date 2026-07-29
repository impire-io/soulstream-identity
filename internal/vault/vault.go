// Package vault is the service's keystore: named secrets sealed at rest,
// signatures out, seeds never. Records are sealed to the deployment-supplied
// first key (hq/02-DESIGN/agent.md D13) before they reach the storage backend
// (D10) — the backend only ever holds ciphertext. The API surface above this
// package exposes public keys and signing operations only; the sole exception
// is ExportSeed, the explicit custody escape used by credential export (D7).
package vault

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/nats-io/nkeys"
)

// Kind names what a vault entry is and thus how it signs.
type Kind string

const (
	// KindNATSAccountSigningKey is an account (signing) nkey seed ("SA…"): mints
	// user JWTs. Scoped signing keys are the recommended shape (hq/02-DESIGN/agent.md D5).
	KindNATSAccountSigningKey Kind = "nats-account-signing-key"
	// KindNATSUserKey is a user nkey seed ("SU…"): the minted identities' keys.
	KindNATSUserKey Kind = "nats-user-key"
	// KindPersonaSigningKey is a Soulstream persona's Ed25519 seed (base64,
	// 32 bytes — the `soulstream key init` file format): signs canonical records.
	KindPersonaSigningKey Kind = "persona-signing-key"
)

// Entry is a vault key as the API shows it: never the secret. The binding
// fields are the authorization source (hq/02-DESIGN/nats-surface.md D25):
// for an account signing key, Account is the account identity it signs for —
// the team object's binding (hq/02-DESIGN/auth-callout.md D24); for a
// persona signing key, (Account, User) is the owner identity that may sign
// with it (hq/02-DESIGN/agent.md D6 as amended); both empty for user keys.
type Entry struct {
	Name      string `json:"name"`
	Kind      Kind   `json:"kind"`
	PublicKey string `json:"public_key"`
	Account   string `json:"account,omitempty"`
	User      string `json:"user,omitempty"`
}

// Sentinel errors; the service maps them to wire errors.
var (
	ErrExists   = errors.New("vault: key already exists (keys are immutable; import under a new name)")
	ErrNotFound = errors.New("vault: no such key")
)

// Store is the storage backend seam (hq/02-DESIGN/agent.md D10): it moves
// opaque sealed bytes and never sees plaintext. NATS KV is the initial
// backend; MemStore serves tests.
type Store interface {
	// Create stores sealed under name, refusing an existing name (ErrExists).
	Create(name string, sealed []byte) error
	// Get returns the sealed bytes for name (ErrNotFound when absent).
	Get(name string) ([]byte, error)
	// Names lists every stored name.
	Names() ([]string, error)
}

// stored is the record shape sealed into the backend. Secret is the seed in
// its kind's native encoding. Account binds an account signing key to the
// account identity it signs for (D24); (Account, User) binds a persona
// signing key to its owner (D6 as amended, D25); both empty for user keys.
type stored struct {
	Kind      Kind   `json:"kind"`
	Secret    string `json:"secret"`
	PublicKey string `json:"public_key"`
	Account   string `json:"account,omitempty"`
	User      string `json:"user,omitempty"`
}

// Vault seals records to the first key and hands the backend ciphertext only.
// Single-writer by design: the service is the one process holding the key.
type Vault struct {
	store    Store
	first    nkeys.KeyPair
	firstPub string
}

// New opens a vault over store, unsealing with the deployment-supplied first
// key ("SX…" curve seed — hq/02-DESIGN/agent.md D13).
func New(store Store, firstKeySeed string) (*Vault, error) {
	if store == nil {
		return nil, errors.New("vault: a store is required")
	}
	kp, err := nkeys.FromCurveSeed([]byte(strings.TrimSpace(firstKeySeed)))
	if err != nil {
		return nil, fmt.Errorf("vault: first key is not a curve (SX…) seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("vault: first key public half: %w", err)
	}
	return &Vault{store: store, first: kp, firstPub: pub}, nil
}

// Verify fails fast when the store already holds records the first key cannot
// open — a mis-supplied seed must not double-seal a vault (hq/02-DESIGN/nats-surface.md).
func (v *Vault) Verify() error {
	names, err := v.store.Names()
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return nil
	}
	if _, err := v.load(names[0]); err != nil {
		return fmt.Errorf("vault: store holds records this first key cannot open (probe %s): %w", names[0], err)
	}
	return nil
}

// checkName enforces the vault's name grammar: path-like ("user/<acc>/<daan>"),
// each segment [A-Za-z0-9._-]+, no escapes. Names are backend keys, so the
// grammar is the security boundary.
func checkName(name string) error {
	if name == "" {
		return errors.New("vault: key name is required")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("vault: invalid key name %q", name)
		}
		for _, r := range seg {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
				r == '.', r == '_', r == '-':
			default:
				return fmt.Errorf("vault: invalid key name %q (segment %q)", name, seg)
			}
		}
	}
	return nil
}

// derive validates a secret for its kind and returns the public key.
func derive(kind Kind, secret string) (string, error) {
	switch kind {
	case KindNATSAccountSigningKey, KindNATSUserKey:
		kp, err := nkeys.FromSeed([]byte(secret))
		if err != nil {
			return "", fmt.Errorf("vault: not an nkey seed: %w", err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			return "", fmt.Errorf("vault: derive public key: %w", err)
		}
		if kind == KindNATSAccountSigningKey && !nkeys.IsValidPublicAccountKey(pub) {
			return "", fmt.Errorf("vault: seed is not an account key (public key %s…)", pub[:2])
		}
		if kind == KindNATSUserKey && !nkeys.IsValidPublicUserKey(pub) {
			return "", fmt.Errorf("vault: seed is not a user key (public key %s…)", pub[:2])
		}
		return pub, nil
	case KindPersonaSigningKey:
		raw, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("vault: persona seed is not base64: %w", err)
		}
		if len(raw) != ed25519.SeedSize {
			return "", fmt.Errorf("vault: persona seed decodes to %d bytes, want %d", len(raw), ed25519.SeedSize)
		}
		pub := ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey)
		return base64.StdEncoding.EncodeToString(pub), nil
	default:
		return "", fmt.Errorf("vault: unknown key kind %q", kind)
	}
}

// Import stores a secret under name. Existing names are refused, never
// overwritten — a changed key is indistinguishable from a substitution.
// The binding completes the key (D25): an account signing key requires
// account — the identity it signs for (the key name is the team name,
// D24); a persona signing key requires (account, user) — the owner that
// may sign with it (D6 as amended); a user key refuses both.
func (v *Vault) Import(name string, kind Kind, secret, account, user string) (Entry, error) {
	if err := checkName(name); err != nil {
		return Entry{}, err
	}
	switch kind {
	case KindNATSAccountSigningKey:
		if !nkeys.IsValidPublicAccountKey(account) {
			return Entry{}, fmt.Errorf("vault: an account signing key needs its account binding (a public account key, got %q)", account)
		}
		if user != "" {
			return Entry{}, fmt.Errorf("vault: an account signing key binds to an account, not a user (got user %q)", user)
		}
	case KindPersonaSigningKey:
		if !nkeys.IsValidPublicAccountKey(account) || user == "" {
			return Entry{}, fmt.Errorf("vault: a persona key needs its owner binding (a public account key and a user name)")
		}
	default:
		if account != "" || user != "" {
			return Entry{}, fmt.Errorf("vault: %q keys carry no binding", kind)
		}
	}
	pub, err := derive(kind, secret)
	if err != nil {
		return Entry{}, err
	}
	plain, err := json.Marshal(stored{Kind: kind, Secret: secret, PublicKey: pub, Account: account, User: user})
	if err != nil {
		return Entry{}, fmt.Errorf("vault: encode key: %w", err)
	}
	sealed, err := v.first.Seal(plain, v.firstPub)
	if err != nil {
		return Entry{}, fmt.Errorf("vault: seal key %s: %w", name, err)
	}
	if err := v.store.Create(name, sealed); err != nil {
		return Entry{}, err
	}
	return Entry{Name: name, Kind: kind, PublicKey: pub, Account: account, User: user}, nil
}

// GenerateUserKey creates a NATS user key inside the vault, or returns the
// existing entry when name is already present (mint reuses user keys). The
// seed never leaves except through ExportSeed.
func (v *Vault) GenerateUserKey(name string) (Entry, error) {
	if e, err := v.Get(name); err == nil {
		if e.Kind != KindNATSUserKey {
			return Entry{}, fmt.Errorf("vault: %s exists with kind %q, want %q", name, e.Kind, KindNATSUserKey)
		}
		return e, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Entry{}, err
	}
	kp, err := nkeys.CreateUser()
	if err != nil {
		return Entry{}, fmt.Errorf("vault: generate user key: %w", err)
	}
	seed, err := kp.Seed()
	if err != nil {
		return Entry{}, fmt.Errorf("vault: read generated seed: %w", err)
	}
	return v.Import(name, KindNATSUserKey, string(seed), "", "")
}

func (v *Vault) load(name string) (stored, error) {
	if err := checkName(name); err != nil {
		return stored{}, err
	}
	sealed, err := v.store.Get(name)
	if err != nil {
		return stored{}, err
	}
	plain, err := v.first.Open(sealed, v.firstPub)
	if err != nil {
		return stored{}, fmt.Errorf("vault: key %s cannot be unsealed: %w", name, err)
	}
	var s stored
	if err := json.Unmarshal(plain, &s); err != nil {
		return stored{}, fmt.Errorf("vault: key %s is unreadable: %w", name, err)
	}
	return s, nil
}

// Get returns one entry (public form).
func (v *Vault) Get(name string) (Entry, error) {
	s, err := v.load(name)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Name: name, Kind: s.Kind, PublicKey: s.PublicKey, Account: s.Account, User: s.User}, nil
}

// List returns every entry (public form), sorted by name.
func (v *Vault) List() ([]Entry, error) {
	names, err := v.store.Names()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	out := make([]Entry, 0, len(names))
	for _, name := range names {
		e, err := v.Get(name)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// TeamForAccount resolves the team that signs for account: the one account
// signing key whose binding names it (D24, resolved per D25 — every mint
// path authorizes against this). None declared refuses; more than one
// refuses as ambiguous, because import order must never decide which key
// signs (the D5 amendment's reversal condition watches this refusal).
func (v *Vault) TeamForAccount(account string) (Entry, error) {
	entries, err := v.List()
	if err != nil {
		return Entry{}, err
	}
	var teams []Entry
	for _, e := range entries {
		if e.Kind == KindNATSAccountSigningKey && e.Account == account {
			teams = append(teams, e)
		}
	}
	switch len(teams) {
	case 0:
		return Entry{}, fmt.Errorf("vault: no team is bound to account %s", account)
	case 1:
		return teams[0], nil
	default:
		names := make([]string, len(teams))
		for i, e := range teams {
			names[i] = e.Name
		}
		return Entry{}, fmt.Errorf("vault: %d teams are bound to account %s (%s) — ambiguous", len(teams), account, strings.Join(names, ", "))
	}
}

// SignRecord signs canonical record bytes with a persona key, returning the
// base64 signature string Soulstream's Soulstream-Sig header carries.
func (v *Vault) SignRecord(name string, canonical []byte) (string, error) {
	s, err := v.load(name)
	if err != nil {
		return "", err
	}
	if s.Kind != KindPersonaSigningKey {
		return "", fmt.Errorf("vault: %s is %q — record signing needs a persona key", name, s.Kind)
	}
	raw, err := base64.StdEncoding.DecodeString(s.Secret)
	if err != nil {
		return "", fmt.Errorf("vault: key %s is unreadable: %w", name, err)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(raw), canonical)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// KeyPair hands the in-process keypair to the minter. It is deliberately not
// reachable over the service API: the process boundary is the custody boundary.
func (v *Vault) KeyPair(name string) (nkeys.KeyPair, error) {
	s, err := v.load(name)
	if err != nil {
		return nil, err
	}
	if s.Kind != KindNATSAccountSigningKey && s.Kind != KindNATSUserKey {
		return nil, fmt.Errorf("vault: %s is %q — not an nkey", name, s.Kind)
	}
	kp, err := nkeys.FromSeed([]byte(s.Secret))
	if err != nil {
		return nil, fmt.Errorf("vault: key %s is unreadable: %w", name, err)
	}
	return kp, nil
}

// ExportSeed returns the raw secret: THE custody escape (hq/02-DESIGN/agent.md D7), used
// only by explicit credential export. Callers surface the export loudly.
func (v *Vault) ExportSeed(name string) (string, error) {
	s, err := v.load(name)
	if err != nil {
		return "", err
	}
	return s.Secret, nil
}

// MemStore is an in-memory Store for tests and ephemeral use; it holds the
// same sealed bytes a real backend would.
type MemStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{m: map[string][]byte{}}
}

// Create implements Store.
func (s *MemStore) Create(name string, sealed []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; ok {
		return fmt.Errorf("%w: %s", ErrExists, name)
	}
	s.m[name] = append([]byte(nil), sealed...)
	return nil
}

// Get implements Store.
func (s *MemStore) Get(name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sealed, ok := s.m[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return append([]byte(nil), sealed...), nil
}

// Names implements Store.
func (s *MemStore) Names() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.m))
	for name := range s.m {
		names = append(names, name)
	}
	return names, nil
}
