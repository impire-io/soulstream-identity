// The NATS KV backend of the token store: digest keys, principal-only values
// (D22) — plaintext tokens never reach this bucket.

package callout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// KVTokenStore adapts a JetStream KV bucket to the token Store seam.
type KVTokenStore struct {
	kv      jetstream.KeyValue
	timeout time.Duration
}

// NewKVTokenStore wraps an existing bucket handle.
func NewKVTokenStore(kv jetstream.KeyValue) *KVTokenStore {
	return &KVTokenStore{kv: kv, timeout: 10 * time.Second}
}

func (s *KVTokenStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

// Create implements Store.
func (s *KVTokenStore) Create(digest string, rec Record) error {
	data, err := marshalRecord(rec)
	if err != nil {
		return err
	}
	ctx, cancel := s.ctx()
	defer cancel()
	if _, err := s.kv.Create(ctx, digest, data); err != nil {
		if errors.Is(err, jetstream.ErrKeyExists) {
			return errors.New("callout: token already exists")
		}
		return fmt.Errorf("callout: kv create: %w", err)
	}
	return nil
}

// Get implements Store.
func (s *KVTokenStore) Get(digest string) (Record, bool, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	entry, err := s.kv.Get(ctx, digest)
	if err != nil {
		if errors.Is(err, jetstream.ErrKeyNotFound) {
			return Record{}, false, nil
		}
		return Record{}, false, fmt.Errorf("callout: kv get: %w", err)
	}
	rec, err := unmarshalRecord(entry.Value())
	if err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

// Delete implements Store. KV Purge removes the value and its history — a
// revoked digest leaves no record behind.
func (s *KVTokenStore) Delete(digest string) error {
	ctx, cancel := s.ctx()
	defer cancel()
	if err := s.kv.Purge(ctx, digest); err != nil {
		return fmt.Errorf("callout: kv purge: %w", err)
	}
	return nil
}

// Entries implements Store.
func (s *KVTokenStore) Entries() ([]TokenEntry, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	keys, err := s.kv.Keys(ctx)
	if err != nil {
		if errors.Is(err, jetstream.ErrNoKeysFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("callout: kv list: %w", err)
	}
	out := make([]TokenEntry, 0, len(keys))
	for _, digest := range keys {
		rec, ok, err := s.Get(digest)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, TokenEntry{Digest: digest, Record: rec})
		}
	}
	return out, nil
}
