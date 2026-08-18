// The grants custody store (D31) rides the shared custody-domain
// pattern (internal/sealedstore, extracted when D36 gave it a second
// consumer): sealed bytes with compare-and-swap — the one property the
// key vault's immutable store refuses and rotation demands.

package grants

import (
	"github.com/impire-io/soulstream-identity/internal/sealedstore"
)

// Store is the backend seam: sealed bytes, revisioned.
type Store = sealedstore.Store

// KVStore adapts a JetStream KV bucket (JetStream's own CAS).
type KVStore = sealedstore.KVStore

// MemStore is the in-memory Store for tests.
type MemStore = sealedstore.MemStore

// NewKVStore wraps an existing bucket handle.
var NewKVStore = sealedstore.NewKVStore

// NewMemStore returns an empty MemStore.
var NewMemStore = sealedstore.NewMemStore
