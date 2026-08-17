# Implementation Plan: The Grants Broker

**Branch**: `003-grants-broker` | **Spec**: [spec.md](spec.md)
**Design**: `soul-hq/02-DESIGN/soulstream-identity/grants.md` (D30–D34)

## Constitution Check

- **Article I (custody without possession)**: the refresh token never
  crosses the wire and never rests unsealed; the only returns are derived,
  expiring access tokens — D32 draws the line explicitly, and there is no
  grants export op. The at-rest positive-control test enforces it.
- **Article II (no second verifier)**: isolation is the server's
  publish-permission enforcement on the op tail (D15/D25); the broker makes
  zero identity decisions. Delegation verification keys on the D26
  directory — no new trust root.
- **Article III (no new machinery)**: the op family rides the existing
  dispatch, envelope, and audit; custody reuses the first key and the KV
  idiom, adding only the CAS the vault deliberately refuses (its own
  numbered decision, D31).

## Structure

| Piece | Where | Why there |
|---|---|---|
| Custody + broker core | `internal/grants/` (grants.go, store.go, provider.go) | pure logic + its own sealed CAS store seam; NATS-free unit tests |
| Op family | `internal/service/ops_grants.go` | the ops_tokens.go pattern: own wire types, own capability check |
| Consumer surface | `client/grants.go` | wire mirror in the same change (repo rule); MintDelegation composes sign.record |
| Operator surface | `embed/embed.go` (+ daemon flags) | one assembly, two entrypoints (D29) |

## Decisions taken at plan time

- The Store seam returns revisions and takes expectedRev — JetStream KV
  `Create`/`Update(rev)` is the CAS; MemStore mirrors it for tests.
- Access contention is bounded by time (5s), not round count: one
  contender wins each rotation round; losers poll briefly for the
  winner's successor before retrying (the redeem→CAS-write gap is real
  and measured — the rig caught it as a 3-attempt starvation).
- The link ceremony is spent *before* code redemption: a crash costs a
  re-link, never a doubled custody line.
- `LinkComplete` requires a refresh token in the response: an
  access-only grant would silently become a dead line at first expiry —
  refused at linking with the scope hint in the error.
- Delegation minting is client-side (`MintDelegation` = compose + one
  `sign.record` round-trip); the service only verifies. Standing-consent
  enforcement at mint time belongs to the minting surface (shell/wrapper)
  per D33 — deliberately out of this feature.
