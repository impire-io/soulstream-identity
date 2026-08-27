# Tasks: Sealing custody — the D9 custodian

**Input**: spec.md, plan.md in this directory.

- [x] T001 Vault: `KindPersonaSealingKey`, X25519 derive case, binding rule,
      `GenerateSealingKey` (ErrExists re-Get), `Unwrap` (kind-checked,
      never (nil,nil)); x/crypto direct; unit suite (FR-001, SC-002).
- [x] T002 Service: `SealingKeyPrefix`, `seal.unwrap` dispatch,
      `ownedSealingKey`/`sealingKeyPublic`, `keys.public` grammar routing,
      audit with wrapped_len; unit suite (FR-002, SC-002).
- [x] T003 Client: `SealingKeyName`, `SealingPublicKey`, `PersonaUnwrapper`,
      kind const; scope.go `seal.unwrap` tail (FR-003, FR-004).
- [x] T004 e2e: core pins → v0.14.0-rc.1 (both modules);
      `d9_gate_test.go` — plaintext through the custodian, negatives,
      unwrap-count == epochs, notify path, Article-I control (SC-001).
- [x] T005 `make fmt && make test && make lint` green, none skipped.
