// The NATS KV backend: the vault's initial store (hq/02-DESIGN/agent.md D10).
// It moves sealed bytes only — envelope encryption happens above this seam, so
// broker disks, replicas, and backups never hold a plaintext seed.

package vault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// KVStore adapts a JetStream KV bucket to the Store seam. Vault names are
// valid KV keys as-is: the KV key grammar is a superset of the name grammar.
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

// Create implements Store: KV's own create-only write keeps keys immutable.
func (s *KVStore) Create(name string, sealed []byte) error {
	ctx, cancel := s.ctx()
	defer cancel()
	if _, err := s.kv.Create(ctx, name, sealed); err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			return fmt.Errorf("%w: %s", ErrExists, name)
		}
		return fmt.Errorf("vault: kv create %s: %w", name, err)
	}
	return nil
}

// Get implements Store.
func (s *KVStore) Get(name string) ([]byte, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	entry, err := s.kv.Get(ctx, name)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return nil, fmt.Errorf("vault: kv get %s: %w", name, err)
	}
	return entry.Value(), nil
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
		return nil, fmt.Errorf("vault: kv list: %w", err)
	}
	return names, nil
}
