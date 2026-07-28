// Package vault is the agent's keystore: named secrets on disk, signatures out,
// seeds never. Every secret lives in its own 0600 file under a 0700 directory;
// the API surface above this package exposes public keys and signing operations
// only — the sole exception is ExportSeed, the explicit custody escape used by
// credential export (hq/02-DESIGN/agent.md D7).
package vault

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"
)

// Kind names what a vault entry is and thus how it signs.
type Kind string

const (
	// KindNATSAccountSigningKey is an account (signing) nkey seed ("SA…"): mints
	// user JWTs. Scoped signing keys are the recommended shape (hq/02-DESIGN/agent.md D5).
	KindNATSAccountSigningKey Kind = "nats-account-signing-key"
	// KindNATSUserKey is a user nkey seed ("SU…"): signs NATS connection nonces.
	KindNATSUserKey Kind = "nats-user-key"
	// KindPersonaSigningKey is a Soulstream persona's Ed25519 seed (base64,
	// 32 bytes — the `soulstream key init` file format): signs canonical records.
	KindPersonaSigningKey Kind = "persona-signing-key"
)

// Entry is a vault key as the API shows it: never the secret.
type Entry struct {
	Name      string `json:"name"`
	Kind      Kind   `json:"kind"`
	PublicKey string `json:"public_key"`
}

// Sentinel errors; the agent maps them to HTTP statuses.
var (
	ErrExists   = errors.New("vault: key already exists (keys are immutable; import under a new name)")
	ErrNotFound = errors.New("vault: no such key")
)

// stored is the on-disk form. Secret is the seed in its kind's native encoding.
type stored struct {
	Kind      Kind   `json:"kind"`
	Secret    string `json:"secret"`
	PublicKey string `json:"public_key"`
}

// Vault is a directory of secret files. It is not safe for concurrent writers
// across processes; the agent is the single writer by design.
type Vault struct {
	dir string
}

// Open creates (0700) or opens the vault directory.
func Open(dir string) (*Vault, error) {
	if dir == "" {
		return nil, errors.New("vault: a directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("vault: create %s: %w", dir, err)
	}
	return &Vault{dir: dir}, nil
}

// checkName enforces the vault's name grammar: path-like ("user/<acc>/<daan>"),
// each segment [A-Za-z0-9._-]+, no escapes. Names are file paths, so the
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

func (v *Vault) file(name string) string {
	return filepath.Join(v.dir, filepath.FromSlash(name)+".json")
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
func (v *Vault) Import(name string, kind Kind, secret string) (Entry, error) {
	if err := checkName(name); err != nil {
		return Entry{}, err
	}
	pub, err := derive(kind, secret)
	if err != nil {
		return Entry{}, err
	}
	data, err := json.Marshal(stored{Kind: kind, Secret: secret, PublicKey: pub})
	if err != nil {
		return Entry{}, fmt.Errorf("vault: encode key: %w", err)
	}
	path := v.file(name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Entry{}, fmt.Errorf("vault: create key dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return Entry{}, fmt.Errorf("%w: %s", ErrExists, name)
		}
		return Entry{}, fmt.Errorf("vault: store key %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(data); err != nil {
		return Entry{}, fmt.Errorf("vault: store key %s: %w", name, err)
	}
	return Entry{Name: name, Kind: kind, PublicKey: pub}, nil
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
	return v.Import(name, KindNATSUserKey, string(seed))
}

func (v *Vault) load(name string) (stored, error) {
	if err := checkName(name); err != nil {
		return stored{}, err
	}
	data, err := os.ReadFile(v.file(name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return stored{}, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return stored{}, fmt.Errorf("vault: read key %s: %w", name, err)
	}
	var s stored
	if err := json.Unmarshal(data, &s); err != nil {
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
	return Entry{Name: name, Kind: s.Kind, PublicKey: s.PublicKey}, nil
}

// List returns every entry (public form), sorted by name.
func (v *Vault) List() ([]Entry, error) {
	var out []Entry
	err := filepath.WalkDir(v.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		rel, rerr := filepath.Rel(v.dir, path)
		if rerr != nil {
			return rerr
		}
		name := strings.TrimSuffix(filepath.ToSlash(rel), ".json")
		e, gerr := v.Get(name)
		if gerr != nil {
			return gerr
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SignNonce signs a NATS connection nonce with an nkey entry (challenge-
// response authentication; hq/02-DESIGN/agent.md D1). Returns the raw signature bytes the
// nats client protocol expects.
func (v *Vault) SignNonce(name string, nonce []byte) ([]byte, error) {
	s, err := v.load(name)
	if err != nil {
		return nil, err
	}
	if s.Kind != KindNATSAccountSigningKey && s.Kind != KindNATSUserKey {
		return nil, fmt.Errorf("vault: %s is %q — nonce signing needs an nkey", name, s.Kind)
	}
	kp, err := nkeys.FromSeed([]byte(s.Secret))
	if err != nil {
		return nil, fmt.Errorf("vault: key %s is unreadable: %w", name, err)
	}
	sig, err := kp.Sign(nonce)
	if err != nil {
		return nil, fmt.Errorf("vault: sign nonce with %s: %w", name, err)
	}
	return sig, nil
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
// reachable over the agent API: the process boundary is the custody boundary.
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
