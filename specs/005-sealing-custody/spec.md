# Feature Specification: Sealing custody — the D9 custodian

**Feature Branch**: `005-sealing-custody`
**Created**: 2026-08-27
**Status**: Draft
**Input**: soul-hq design [`sealing-keys.md`](../../../soul-hq/02-DESIGN/soulstream-identity/sealing-keys.md) (D50–D53, realizing D9) against soulstream-core's shipped `Unwrapper` seam (core `specs/021-sealed-topics`, which hands the custodian to this repo). The vault grows the X25519 sealing-key kind with first-touch materialization; the surface grows exactly one op (`seal.unwrap`) and one directory grammar (`keys.public` on `sealing/<persona>`); the client grows `PersonaUnwrapper`, the line-for-line mirror of `PersonaSigner` that satisfies core's seam structurally.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A sealed topic materialises through the custodian (Priority: P1)

A persona whose sealing seed lives only in the vault reads a sealed topic: `PersonaUnwrapper` construction materializes the key (first touch), the consumer publishes the endorsed public half (`EnsureSealingKey`, F1 posture), and materialise unwraps one epoch key per epoch through `seal.unwrap` — full plaintext, seed never anywhere but the vault.

**Independent Test**: the consumer-position e2e (`e2e/d9_gate_test.go`) — the M2 gate's beat-for-beat sibling over a sealed topic.

**Acceptance Scenarios**:

1. **Given** two personas with custodial signers and unwrappers, **When** one starts a sealed topic with both as members, posts, and rotates an epoch, **Then** the other materialises full plaintext through `UseSealing(unwrapper)`.
2. **Given** the same topic read with no unwrapper, **Then** the view is structure-only; **Given** a wrong persona's unwrapper cannot be constructed (foreign-owner refusal), the sealed view stays closed to it.
3. **Given** a counting unwrapper, **Then** unwrap calls equal the number of epochs, never the number of messages (D9's no-oracle line, measured).

---

### User Story 2 - Custody without possession, unchanged (Priority: P1)

No op returns sealing seed material, ever; the released epoch key is a shared group secret (an artifact), sealed in transit inside the xkey envelope.

**Acceptance Scenarios**:

1. **Given** the whole gate run, **Then** no wire response carries a seed (no op exists that returns one; `keys.public` entries carry the public form only).
2. **Given** `seal.unwrap` on a key the caller does not own, **Then** the refusal is identical whether the key exists or not (no vault probing).
3. **Given** `Notification.Unseal` through the custodian, **Then** the arbitrary-length path works (and proves byte-compatibility with core's `WrapForSealingKey`).

---

### Edge Cases

- Absent OWN key at `seal.unwrap`: materializes, then the unwrap fails honestly ("not sealed to this key") — the wrap predates the key's birth; the fresh public half is what the next wrap targets (D50).
- Cross-instance first-touch race: `GenerateSealingKey` re-Gets on `ErrExists` and returns the winner's entry when kind+owner match.
- Output length is the CALLER's concern (core folds a wrong-size epoch key as a warning); the op enforces none (D51 — one op serves both shapes).
- Pre-existing accounts lack the `seal.unwrap` tail until their template re-renders (D52's ops note); guardrail default-deny deployments must admit the new op.
- Never `(nil, nil)`: vault, service, and client each refuse an empty result.

## Requirements *(mandatory)*

- **FR-001**: Vault: `KindPersonaSealingKey` ("persona-sealing-key"), seed = base64 of 32 raw X25519 bytes, public = base64 X25519 (byte-compatible with core's `SealingKeyFromSeed`); owner binding as persona keys; `GenerateSealingKey` first-touch (get-or-generate, `ErrExists` re-Get); `Unwrap(name, wrapped)` = in-vault `box.OpenAnonymous`, kind-checked, never `(nil, nil)`. No export sibling.
- **FR-002**: Service: `seal.unwrap` op — strict decode, `ownedSealingKey` act-as gate (own-name first touch, no-probe foreign refusal), audit with `wrapped_len` and never the bytes; `keys.public` routes the `sealing/` grammar (own = first touch, foreign = open read).
- **FR-003**: Client: `SealingKeyName`, `SealingPublicKey`, `PersonaUnwrapper` (constructor = one `keys.public`, fail-fast foreign-owner; `PublicKey() string`; `Unwrap([]byte) ([]byte, error)`) — core's `identity.Unwrapper`, satisfied structurally, doc stating the D53 ensure-publication pairing.
- **FR-004**: `client.PersonaScopePubAllow` grows exactly one tail: `seal.unwrap` (D52; one-source fan-out reaches embed/providerapi/localoperator).
- **FR-005**: The e2e modules pin core at v0.14.0-rc.1 (the tag carrying sealed topics); re-pin at the core release.

## Success Criteria *(mandatory)*

- **SC-001**: The D9 gate e2e passes in `make test`: full plaintext through the custodian, structure-only and foreign-owner negatives, unwrap-count == epochs, notify path, zero seed material on the wire [measured].
- **SC-002**: Unit suites cover the vault kind (derive round trip, wrong-key failure, kind-mismatch both directions, binding refusals, immutability, race re-Get) and the service ops (first touch, no-probe refusals, both grammars).
- **SC-003**: Full gate green (`make fmt && make test && make lint`, e2e modules included); existing gates unchanged.

## Assumptions

- Rotation, batch unwrap, and product wiring are the design's named [O]s — deliberately out of this slice.
- `golang.org/x/crypto` promotes from indirect to direct (the vault's box/curve25519 use).
