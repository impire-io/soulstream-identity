# Implementation Plan: The Embed Seam

**Branch**: `002-embed-seam` | **Date**: 2026-08-01 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-embed-seam/spec.md`

## Summary

Lift the daemon's serve assembly out of `cmdServe` into a public `embed`
package: `Run(ctx context.Context, o Options) error` assembles vault →
sealed service surface → (optional) callout issuer against caller-supplied
`*nats.Conn`s, enforces the daemon's construction-time invariants (vault
verification, prefix validation, callout both-halves, OIDC
both-or-neither), serves until ctx ends, then drains its subscriptions.
`cmd/soulidentity serve` becomes the first consumer — one assembly, two
entrypoints. The no-`internal/` claim is proven by a compiler-enforced
consumer-position gate: a new never-published test module whose path sits
*outside* this repo's namespace runs the M4 admission shape (admit /
refuse / revoke) through `embed.Run` on an embedded operator-mode server.

## Technical Context

**Language/Version**: Go 1.26.2
**Primary Dependencies**: `nats.go v1.52.0` (+ `jetstream`), `jwt/v2 v2.8.2`, `nkeys v0.4.16` — all already direct deps; no new dependency
**Storage**: NATS JetStream KV (existing `SOULIDENTITY_VAULT` / `SOULIDENTITY_TOKENS` buckets; unchanged)
**Testing**: `go test` via `make check`; existing e2e suites unchanged (US2); new consumer-position gate module for US1
**Target Platform**: any Go platform (library surface)
**Project Type**: library — a new public package on an existing module, plus a cmd refactor
**Performance Goals**: n/a — assembly only, no hot path touched
**Constraints**: no `internal/` type crosses the public boundary (D29); no new provisioning API (constitution I); daemon behavior byte-compatible where tested (flags, env, log lines, e2e gates)
**Scale/Scope**: 1 new public package (~150 LOC), `cmdServe` slimmed to flag/env parsing + connection ownership, 1 new test module (~250 LOC ceremony + scenario), Makefile wiring

## Constitution Check

*GATE: evaluated against `hq/00-GENESIS/constitution.md` v1.3.1 (projection
in `.specify/memory/constitution.md`).*

- **I. Custody Without Possession — PASS.** The seam moves no key
  material: seeds stay deployment-supplied strings (D13 as amended), no
  new API returns secrets, no provisioning or key-mutation surface is
  added (FR-006); in-process key material stays inside `internal/vault`.
- **II. The Server Is the Verifier of Record — PASS.** Assembly only; no
  new enforcement path. Admission/refusal behavior is the existing
  issuer's, re-hosted.
- **III. Smallest Viable Implementation — PASS.** One package, value-only
  options, no speculative injection points (no custom store/validator
  hooks — D29's reversal condition explicitly gates that door). The
  concrete consumer is named and blocked today (soulnode).
- **IV. Documentation Is a First-Class Citizen — PASS.** D29 landed in
  `hq/02-DESIGN/agent.md` with the spec; package doc, contract, and
  quickstart ship with the change; the journey episode lands with the
  merge.
- **Working Agreement — PASS.** Load-bearing claims in the artifacts carry
  evidence tags; the consumer findings this feature answers are measured
  (soulnode's topic journal, soulstream's remote-mcp-node journal).

Post-Phase-1 re-check: no new violations introduced by the design below.

## Project Structure

### Documentation (this feature)

```text
specs/002-embed-seam/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/
│   └── embed.md         # The public Go API contract
├── checklists/
│   └── requirements.md  # Spec quality checklist (done)
└── tasks.md             # Phase 2 output (/speckit-tasks — not this command)
```

### Source Code (repository root)

```text
embed/
└── embed.go             # NEW public package: Options, Run (the cmdServe lift)

cmd/soulidentity/
└── main.go              # cmdServe slims to flags/env + conn ownership → embed.Run

e2e/embedgate/           # NEW test module, path OUTSIDE the repo namespace
├── go.mod               # module soulidentity.invalid/embedgate (never published)
├── go.sum
└── gate_test.go         # operator-mode ceremony + M4 admission shape via embed.Run

Makefile                 # tidy/test/lint gain the embedgate module (same pattern as e2e/)
```

**Structure Decision**: single module gains one public package; the
compiler-proof gate is a separate nested test module in `e2e/embedgate/`,
mirroring the established consumer-position pattern of `e2e/` (Makefile
`cd`-wired, never tagged, replace-directed at the working tree).

## Complexity Tracking

No constitution violations to justify. One deliberate duplication,
recorded: the embedgate module carries its own operator-mode ceremony
(~200 lines) because test helpers cannot cross module boundaries and the
three existing e2e suites already accept exactly this duplication as the
consumer-position cost (see research.md R4).
