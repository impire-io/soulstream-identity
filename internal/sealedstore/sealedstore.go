// Package sealedstore is the custody-domain storage pattern (D31, made
// the fixture by D36): sealed bytes with compare-and-swap, envelope
// encryption above the backend seam exactly as in the vault — backends
// move ciphertext only. Each custody domain (grants, secrets) gets its
// own bucket over this one shape.
package sealedstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

var (
	// ErrNotFound is the one absent-record refusal — identical whatever
	// was asked for, so refusals cannot probe custody.
	ErrNotFound = errors.New("sealedstore: no such record")
	// ErrCASConflict reports a losing compare-and-swap write.
	ErrCASConflict = errors.New("sealedstore: record changed underneath the update")
)

// Store is the backend seam: sealed bytes, revisioned.
type Store interface {
	// Get returns the sealed bytes and their revision.
	Get(name string) (sealed []byte, rev uint64, err error)
	// Put writes iff the stored revision equals expectedRev (0 = create;
	// the name must not exist). Returns the new revision, or
	// ErrCASConflict.
	Put(name string, sealed []byte, expectedRev uint64) (uint64, error)
	Delete(name string) error
	Names() ([]string, error)
}

// Sealed seals/opens JSON records around a Store — one custody root
// (the deployment's first key), any number of domains.
type Sealed struct {
	store    Store
	first    nkeys.KeyPair
	firstPub string
}

// NewSealed wraps a Store with envelope sealing under the first key
// (an SX… curve seed).
func NewSealed(store Store, firstKeySeed string) (*Sealed, error) {
	kp, err := nkeys.FromCurveSeed([]byte(firstKeySeed))
	if err != nil {
		return nil, fmt.Errorf("sealedstore: first key is not a curve (SX…) seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("sealedstore: first key public half: %w", err)
	}
	return &Sealed{store: store, first: kp, firstPub: pub}, nil
}

// Get unseals the named record into out and returns its revision.
func (s *Sealed) Get(name string, out any) (uint64, error) {
	sealed, rev, err := s.store.Get(name)
	if err != nil {
		return 0, err
	}
	plain, err := s.first.Open(sealed, s.firstPub)
	if err != nil {
		return 0, fmt.Errorf("sealedstore: record %s cannot be unsealed: %w", name, err)
	}
	if err := json.Unmarshal(plain, out); err != nil {
		return 0, fmt.Errorf("sealedstore: record %s is unreadable: %w", name, err)
	}
	return rev, nil
}

// Put seals rec and writes it under CAS.
func (s *Sealed) Put(name string, rec any, expectedRev uint64) (uint64, error) {
	plain, err := json.Marshal(rec)
	if err != nil {
		return 0, fmt.Errorf("sealedstore: encode record: %w", err)
	}
	sealed, err := s.first.Seal(plain, s.firstPub)
	if err != nil {
		return 0, fmt.Errorf("sealedstore: seal record %s: %w", name, err)
	}
	return s.store.Put(name, sealed, expectedRev)
}

// Delete removes the named record.
func (s *Sealed) Delete(name string) error { return s.store.Delete(name) }

// Names lists every record name in the domain.
func (s *Sealed) Names() ([]string, error) { return s.store.Names() }

// KVStore adapts a JetStream KV bucket: Create for revision 0,
// Update(rev) otherwise — JetStream's own CAS. Delete purges: secrets
// leave no tombstone history.
type KVStore struct {
	kv      jetstream.KeyValue
	timeout time.Duration
}

// NewKVStore wraps an existing bucket handle.
func NewKVStore(kv jetstream.KeyValue) *KVStore {
	return &KVStore{kv: kv, timeout: 10 * time.Second}
}

func (s *KVStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

// Get implements Store.
func (s *KVStore) Get(name string) ([]byte, uint64, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	entry, err := s.kv.Get(ctx, name)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, 0, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return nil, 0, fmt.Errorf("sealedstore: kv get %s: %w", name, err)
	}
	return entry.Value(), entry.Revision(), nil
}

// Put implements Store.
func (s *KVStore) Put(name string, sealed []byte, expectedRev uint64) (uint64, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	if expectedRev == 0 {
		rev, err := s.kv.Create(ctx, name, sealed)
		if err != nil {
			if errors.Is(err, jetstream.ErrKeyExists) {
				return 0, fmt.Errorf("%w: %s", ErrCASConflict, name)
			}
			return 0, fmt.Errorf("sealedstore: kv create %s: %w", name, err)
		}
		return rev, nil
	}
	rev, err := s.kv.Update(ctx, name, sealed, expectedRev)
	if err != nil {
		var apiErr *jetstream.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode == jetstream.JSErrCodeStreamWrongLastSequence {
			return 0, fmt.Errorf("%w: %s", ErrCASConflict, name)
		}
		return 0, fmt.Errorf("sealedstore: kv update %s: %w", name, err)
	}
	return rev, nil
}

// Delete implements Store.
func (s *KVStore) Delete(name string) error {
	ctx, cancel := s.ctx()
	defer cancel()
	if err := s.kv.Purge(ctx, name); err != nil {
		return fmt.Errorf("sealedstore: kv delete %s: %w", name, err)
	}
	return nil
}

// Names implements Store.
func (s *KVStore) Names() ([]string, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	names, err := s.kv.Keys(ctx)
	if err != nil {
		if errors.Is(err, jetstream.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("sealedstore: kv list: %w", err)
	}
	return names, nil
}

// MemStore is the in-memory Store for tests: same sealed bytes, same CAS.
type MemStore struct {
	mu   sync.Mutex
	m    map[string][]byte
	revs map[string]uint64
	next uint64
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore {
	return &MemStore{m: map[string][]byte{}, revs: map[string]uint64{}}
}

// Get implements Store.
func (s *MemStore) Get(name string) ([]byte, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sealed, ok := s.m[name]
	if !ok {
		return nil, 0, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return sealed, s.revs[name], nil
}

// Put implements Store.
func (s *MemStore) Put(name string, sealed []byte, expectedRev uint64) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, exists := s.revs[name]
	switch {
	case !exists && expectedRev != 0:
		return 0, fmt.Errorf("%w: %s", ErrCASConflict, name)
	case exists && cur != expectedRev:
		return 0, fmt.Errorf("%w: %s", ErrCASConflict, name)
	}
	s.next++
	s.m[name] = sealed
	s.revs[name] = s.next
	return s.next, nil
}

// Delete implements Store.
func (s *MemStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[name]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	delete(s.m, name)
	delete(s.revs, name)
	return nil
}

// Names implements Store.
func (s *MemStore) Names() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.m))
	for n := range s.m {
		names = append(names, n)
	}
	return names, nil
}

// SealedBytes exposes a record's raw stored bytes — for at-rest
// positive-control tests only (the D13 idiom: prove ciphertext by grep).
func (s *MemStore) SealedBytes(name string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[name]
}
