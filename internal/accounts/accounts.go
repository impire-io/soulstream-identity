// Package accounts is the tenancy engine (D35 — hq
// 02-DESIGN/soulstream-identity/tenancy.md): accounts born, suspended,
// resumed, and resolved at runtime, behind a pluggable authority. The
// ordering rule is the measured one: the account artifact is built
// COMPLETE and landed as one act — no observable intermediate state
// (Bars 1 and 2). Names bind first-seen; a reuse refuses. The name→key
// mapping is display/resolution-layer: verification never depends on it
// (A10 puts the key itself in the record).
package accounts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
)

var (
	// ErrExists refuses a name reuse: first-seen wins, forever.
	ErrExists = errors.New("accounts: name already bound (names bind first-seen)")
	// ErrNotFound is the one absent-account refusal.
	ErrNotFound = errors.New("accounts: no such account")
	// ErrBadName refuses names outside the scheme.
	ErrBadName = errors.New("accounts: name must match [a-z0-9][a-z0-9-]{0,62}")
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Status is an account's lifecycle state.
type Status string

// The lifecycle states. Suspension keeps the data; resume reverses it.
const (
	Active    Status = "active"
	Suspended Status = "suspended"
)

// Record is the resolution entry: name → cryptographic identity, plus
// what the authority needs to rebuild the account artifact
// deterministically (suspend/resume re-land the COMPLETE artifact).
type Record struct {
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	SigningKey string `json:"signing_key"` // the account's signing key public half
	Status     Status `json:"status"`
	CreatedAt  string `json:"created_at"`
}

// Authority is where account-creating power lives (A7's seam, A8's two
// arms): the local operator key, or a hosting provider's control plane.
type Authority interface {
	// CreateAccount builds the account COMPLETE — identity, signing key,
	// limits — and lands it as one act. It returns the account public
	// key, the signing key public half, and the signing key SEED — which
	// the caller imports into the vault and never returns to anyone.
	CreateAccount(ctx context.Context, name string) (accountPub, signingPub, signingSeed string, err error)
	// SetSuspended re-lands the account artifact with connections
	// refused (true) or restored (false).
	SetSuspended(ctx context.Context, rec Record, suspended bool) error
}

// Engine drives the lifecycle over a sealed record store.
type Engine struct {
	store     *sealedstore.Sealed
	authority Authority
	now       func() time.Time
}

// New builds the engine over its own sealed domain.
func New(store sealedstore.Store, firstKeySeed string, authority Authority) (*Engine, error) {
	sealed, err := sealedstore.NewSealed(store, strings.TrimSpace(firstKeySeed))
	if err != nil {
		return nil, fmt.Errorf("accounts: %w", err)
	}
	return &Engine{store: sealed, authority: authority, now: time.Now}, nil
}

func recName(name string) string { return "account/" + name }

// Create births the account: name reserved first-seen (a racing create
// loses on the store's CAS), the authority lands the complete artifact,
// the mapping records it. The signing key seed goes to the CALLER (the
// ops layer imports it into the vault, bound to the new account, so the
// existing mint path serves the new tenant immediately) — it is never
// part of any reply.
func (e *Engine) Create(ctx context.Context, name string) (Record, string, error) {
	if !nameRe.MatchString(name) {
		return Record{}, "", ErrBadName
	}
	var existing Record
	if _, err := e.store.Get(recName(name), &existing); err == nil {
		return Record{}, "", fmt.Errorf("%w: %s", ErrExists, name)
	}
	accountPub, signingPub, signingSeed, err := e.authority.CreateAccount(ctx, name)
	if err != nil {
		return Record{}, "", err
	}
	rec := Record{
		Name: name, PublicKey: accountPub, SigningKey: signingPub,
		Status: Active, CreatedAt: e.now().UTC().Format(time.RFC3339),
	}
	if _, err := e.store.Put(recName(name), rec, 0); err != nil {
		// The substrate act landed; the mapping lost a race or a write.
		// Loud, honest, and recoverable by resolve-by-key — never silent.
		return Record{}, "", fmt.Errorf("accounts: account %s landed but its mapping did not: %w", name, err)
	}
	return rec, signingSeed, nil
}

// Resolve answers name → record.
func (e *Engine) Resolve(name string) (Record, error) {
	var rec Record
	if _, err := e.store.Get(recName(name), &rec); err != nil {
		return Record{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return rec, nil
}

// List returns every record.
func (e *Engine) List() ([]Record, error) {
	names, err := e.store.Names()
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, n := range names {
		if !strings.HasPrefix(n, "account/") {
			continue
		}
		var rec Record
		if _, err := e.store.Get(n, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}

// SetSuspended flips the account's standing: suspended refuses new
// connections at the substrate; resume restores them. Data untouched.
func (e *Engine) SetSuspended(ctx context.Context, name string, suspended bool) (Record, error) {
	var rec Record
	rev, err := e.store.Get(recName(name), &rec)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err := e.authority.SetSuspended(ctx, rec, suspended); err != nil {
		return Record{}, err
	}
	if suspended {
		rec.Status = Suspended
	} else {
		rec.Status = Active
	}
	if _, err := e.store.Put(recName(name), rec, rev); err != nil {
		return Record{}, err
	}
	return rec, nil
}
