// Package tickets is the deferral's custody (D42 — hq
// 02-DESIGN/soulstream-identity/approvals.md): a guardrail defer stops
// being a stateless refusal and becomes a durable, TTL-bounded ticket with
// witnessed transitions. Sealed CAS like every custody domain; the ticket
// deliberately carries the invocation's NAME (the hash) and never its
// arguments — the same privacy line the approval artifact holds (D38).
//
// Two clocks, deliberately distinct: the ticket TTL here is the human's
// window; the approval TTL (minutes, in-memory, D38 unchanged) is the
// retry's window and starts at the yes. Expiry is a first-class, recorded
// outcome — a pending ticket past its window is written expired the moment
// any read observes it, never silently dropped.
package tickets

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
)

// State is where a ticket stands.
type State string

const (
	// Pending awaits a human.
	Pending State = "pending"
	// Approved carries the human's yes; the retry's presentation converts
	// it to spent. A plane restart may drop the in-memory approval while
	// the ticket stays approved — re-presenting closes that gap.
	Approved State = "approved"
	// Spent is an executed approval: the loop closed.
	Spent State = "spent"
	// Denied is the human's no.
	Denied State = "denied"
	// Expired is the clock's no — recorded, never silent.
	Expired State = "expired"
)

// Ticket is one deferred invocation as custody describes it. No arguments
// anywhere: the invocation id names them without carrying them.
type Ticket struct {
	InvocationID string `json:"invocation_id"`
	// Principal is the originator, account/user — whose retry this is,
	// and the only caller (beside the management lane) status serves.
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Rule      string `json:"rule"`
	State     State  `json:"state"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	// ResolvedBy and ResolvedAt name the hand and the moment of the
	// terminal transition (approved/denied), or the observed expiry.
	ResolvedBy string `json:"resolved_by,omitempty"`
	ResolvedAt string `json:"resolved_at,omitempty"`
}

// ErrNotFound is the one absent-ticket refusal.
var ErrNotFound = errors.New("tickets: no such ticket")

func name(id string) string { return "ticket/" + id }

// Store custodies tickets over a sealed CAS store.
type Store struct {
	store *sealedstore.Sealed
	ttl   time.Duration
	now   func() time.Time
}

// New builds the store. ttl is the ticket's human-window (D42).
func New(store sealedstore.Store, firstKeySeed string, ttl time.Duration) (*Store, error) {
	sealed, err := sealedstore.NewSealed(store, strings.TrimSpace(firstKeySeed))
	if err != nil {
		return nil, fmt.Errorf("tickets: %w", err)
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &Store{store: sealed, ttl: ttl, now: time.Now}, nil
}

// TTL is the configured human-window.
func (s *Store) TTL() time.Duration { return s.ttl }

// Ensure opens (or re-opens) the pending ticket for one deferred
// invocation. An existing live pending or approved ticket stands — a
// retry does not reset the human's clock. A terminal ticket (spent,
// denied, expired) re-opens pending: the originator asked again, so the
// window does too.
func (s *Store) Ensure(id, principal, action, rule string) (Ticket, error) {
	now := s.now().UTC()
	var t Ticket
	rev, err := s.store.Get(name(id), &t)
	if err == nil {
		t = s.expireOnTouch(t, rev)
		if t.State == Pending || t.State == Approved {
			return t, nil
		}
	} else {
		rev = 0
	}
	t = Ticket{
		InvocationID: id, Principal: principal, Action: action, Rule: rule,
		State:     Pending,
		CreatedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(s.ttl).Format(time.RFC3339),
	}
	if _, err := s.store.Put(name(id), t, rev); err != nil {
		return Ticket{}, fmt.Errorf("tickets: open %s: %w", id, err)
	}
	return t, nil
}

// Get reads one ticket, writing the expiry transition if this read is the
// one that observes it.
func (s *Store) Get(id string) (Ticket, error) {
	var t Ticket
	rev, err := s.store.Get(name(id), &t)
	if err != nil {
		return Ticket{}, ErrNotFound
	}
	return s.expireOnTouch(t, rev), nil
}

// expireOnTouch writes pending→expired when the window has passed —
// best-effort on the write (a losing race means someone else recorded a
// transition; the re-read tells the truth).
func (s *Store) expireOnTouch(t Ticket, rev uint64) Ticket {
	if t.State != Pending {
		return t
	}
	exp, err := time.Parse(time.RFC3339, t.ExpiresAt)
	if err != nil || s.now().Before(exp) {
		return t
	}
	t.State = Expired
	t.ResolvedAt = s.now().UTC().Format(time.RFC3339)
	if _, werr := s.store.Put(name(t.InvocationID), t, rev); werr != nil {
		var current Ticket
		if _, gerr := s.store.Get(name(t.InvocationID), &current); gerr == nil {
			return current
		}
	}
	return t
}

// resolve moves a live pending ticket to a terminal state, by name.
func (s *Store) resolve(id string, to State, by string) (Ticket, error) {
	var t Ticket
	rev, err := s.store.Get(name(id), &t)
	if err != nil {
		return Ticket{}, ErrNotFound
	}
	t = s.expireOnTouch(t, rev)
	switch {
	case to == Spent && t.State == Approved:
		// the one transition that starts from approved
	case t.State == Pending:
	default:
		return Ticket{}, fmt.Errorf("tickets: ticket %s is %s", id, t.State)
	}
	t.State = to
	t.ResolvedBy = by
	t.ResolvedAt = s.now().UTC().Format(time.RFC3339)
	if _, err := s.store.Put(name(id), t, rev); err != nil {
		return Ticket{}, fmt.Errorf("tickets: %s %s: %w", to, id, err)
	}
	return t, nil
}

// Approve records the human's yes on a live pending ticket.
func (s *Store) Approve(id, by string) (Ticket, error) { return s.resolve(id, Approved, by) }

// Deny records the human's no on a live pending ticket.
func (s *Store) Deny(id, by string) (Ticket, error) { return s.resolve(id, Denied, by) }

// Spend records the executed conversion on an approved ticket.
func (s *Store) Spend(id string) (Ticket, error) { return s.resolve(id, Spent, "") }

// Pending lists the tickets awaiting a decision, expiring on touch.
func (s *Store) Pending() ([]Ticket, error) {
	names, err := s.store.Names()
	if err != nil {
		return nil, fmt.Errorf("tickets: list: %w", err)
	}
	var out []Ticket
	for _, n := range names {
		id, ok := strings.CutPrefix(n, "ticket/")
		if !ok {
			continue
		}
		t, err := s.Get(id)
		if err != nil {
			continue
		}
		if t.State == Pending {
			out = append(out, t)
		}
	}
	return out, nil
}
