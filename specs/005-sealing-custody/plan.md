# Implementation Plan: Sealing custody — the D9 custodian

**Branch**: `005-sealing-custody` | **Date**: 2026-08-27 | **Spec**: [spec.md](spec.md)

## Summary

The vault grows the sealing-key kind (X25519, first-touch, owner-bound,
in-vault `box.OpenAnonymous`); the service grows `seal.unwrap` and the
`sealing/` directory grammar on `keys.public`; the client grows
`PersonaUnwrapper` mirroring `PersonaSigner`; the persona scope template
grows one tail. The consumer-position e2e proves a sealed topic
materialising entirely through the custodian, with the unwrap-count
measurement pinning D9's no-oracle claim.

## Constitution Check

- **I Custody Without Possession — PASS**: the seed never leaves the
  vault (no export sibling); the released epoch key is a shared group
  secret, an artifact (the D32 parallel); every unwrap audited.
- **II The seam, not a silo — PASS**: core's `Unwrapper` is satisfied
  structurally; no import either direction; consumers wire (D53).
- **III Decided-then-built — PASS**: D50–D53 in sealing-keys.md; the
  mechanism fixed and measured by core's spec 021.
- **D25 — PASS**: authorization is the op tail (one new tail in the one
  exported template) plus the owner binding.

## Project Structure

```text
specs/005-sealing-custody/   # spec.md, plan.md, tasks.md
internal/vault/vault.go      # kind, derive case, Import binding,
                             #   GenerateSealingKey, Unwrap
internal/service/service.go  # SealingKeyPrefix, seal.unwrap, grammar
                             #   routing, ownedSealingKey/sealingKeyPublic
client/client.go             # SealingKeyName, SealingPublicKey,
                             #   PersonaUnwrapper, KindPersonaSealingKey
client/scope.go              # + seal.unwrap tail
e2e/d9_gate_test.go          # NEW: the D9 gate (core pin → v0.14.0-rc.1)
```

## Complexity Tracking

No violations. Rotation/batching/product wiring are the design's [O]s.
