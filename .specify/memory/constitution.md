<!--
Sync Impact Report
- Version change: unfilled template → 1.2.0 (projection of hq/00-GENESIS/constitution.md v1.2.0)
- Modified principles: all template placeholders filled from the authoritative hq constitution
- Added sections: Core Principles I–IV; The Working Agreement (Anti-Drift);
  Technology Constraints; Development Workflow & Quality Gates; Governance
- Removed sections: none
- Templates requiring updates:
  - ✅ .specify/templates/plan-template.md — Constitution Check gate reads this file at plan time; no edit needed
  - ✅ .specify/templates/spec-template.md — generic; no constitution-dependent sections
  - ✅ .specify/templates/tasks-template.md — generic; note: its "Tests are OPTIONAL" default is
    overridden by the quality gates below (tests are mandatory in this project)
- Follow-up TODOs: none
-->

# SoulIdentity Constitution (speckit projection)

> **This file is a projection, not a source.** The authoritative constitution
> is [`hq/00-GENESIS/constitution.md`](../../hq/00-GENESIS/constitution.md)
> (v1.2.0), held together with `hq/00-GENESIS/vision.md` and
> `hq/00-GENESIS/how-we-work.md`. On any conflict, hq wins. Amend there
> first; re-project here in the same change.

## Core Principles

### I. Custody Without Possession

Secrets live in the vault and answer requests; they are never handed out.

- No API surface may return a seed, private key, or any material sufficient
  to sign without the vault — public keys, signatures, and minted tokens
  only.
- Every exception is a named custody escape (today: credential export),
  always explicit in the request, always loud in the audit log, never a side
  effect.
- Every signing operation is attributable and logged.
- In-process access to key material stays inside the vault package; the
  process boundary is the custody boundary.

**Rationale**: Custody-without-possession is the one property that
distinguishes SoulIdentity from a directory of seed files; lose it anywhere
and the project has no reason to exist.

### II. The Server Is the Verifier of Record

The NATS server enforces; SoulIdentity decides only what is genuinely its
own.

- Transport permissions live NATS-side (scoped signing keys, callout-issued
  JWTs), enforced by the server on every connection. SoulIdentity MUST NOT
  build a parallel enforcement path duplicating what the server checks.
- SoulIdentity's own policy surface is exactly: which identity exists, which
  personas it may act as, which role mints for it — declared in the registry
  or derived from validated claims in the presented credential (D2).
- Validations the server will repeat are diagnostics — warn-level
  conveniences, never gates.

**Rationale**: Two sources of truth drift. The NATS decentralized auth model
already carries membership, permissions, and rejection of bad bindings;
duplicating any of it would eventually contradict it.

### III. Smallest Viable Implementation

- Every change MUST be the smallest implementation that satisfies its need;
  anything not required by a concrete consumer is cut or deferred.
- Speculative generality is prohibited: no configuration options,
  abstraction layers, or plugin points added "for later". The
  storage-backend and authn-backend seams exist because the design names
  their concrete future backends; nothing else gets a seam in advance.
- Growth is new modes and backends on the same vault + registry, never new
  machinery beside them.
- Scope creep is a review blocker, not a style concern.

**Rationale**: An identity component earns trust by being small enough to
audit.

### IV. Documentation Is a First-Class Citizen

- Every concept is explained plainly — an everyday analogy before technical
  detail; plain words beat invented terms.
- The design docs record every load-bearing decision with a D-number and its
  reasoning; code comments cite the D-numbers.
- Docs ship in the same change as the behavior they describe; stale
  documentation is a bug with the same severity as a failing test.

**Rationale**: A security-adjacent tool that cannot be explained simply will
be misused, and misuse of an identity agent is a security failure.

## The Working Agreement (Anti-Drift)

Applies to every load-bearing decision — a custody-boundary change, an
enforcement-mode change, a scope call, or a public claim.

1. **Teach-back as a gate.** No load-bearing direction decision is recorded
   until the maintainer can restate the argument in his own words.
2. **Claims carry their evidence class.** `[measured]` (a test, a
   demonstrated NATS behavior), `[mechanism-argument]` (a reasoned case from
   how NATS or the agent works), or `[judgment]`. Only measured closes a
   debate.
3. **Decisions record their reversal condition** when made, phrased as an
   observable reading — never retrofitted.
4. **Adversarial pass on direction changes.** For decisions changing the
   custody boundary or an enforcement mode, the other side is argued at full
   strength before the decision.

## Technology Constraints

- **Language**: Go; official NATS libraries only (`nkeys`, `jwt/v2`,
  `nats.go`, embedded `nats-server` for tests).
- **Secrets at rest**: the vault rides NATS KV with xkey envelope encryption
  — only ciphertext is ever stored; the unwrapping xkey and the service's
  own NATS creds are the only local secrets.
- **Transport**: NATS is the only transport — request/reply with xkey-sealed
  payloads, the caller authenticated by its own NATS identity. No socket, no
  TCP listener. A presented creds file bypasses SoulIdentity (self-custody);
  an external token arrives through auth callout.
- **Dependencies**: an identity agent is judged by its audit surface — keep
  the dependency tree small enough to read.

## Development Workflow & Quality Gates

- Feature work runs the speckit loop — `/speckit-specify` →
  `/speckit-clarify` → `/speckit-plan` → `/speckit-tasks` →
  `/speckit-implement` — on numbered feature branches with artifacts under
  `specs/`. Research-grade unknowns carry pre-registered pass/fail bars as
  spec acceptance criteria; evidence classes and reversal conditions ride
  the resulting design amendments.
- The hq duties are unchanged by speckit and land in the same merge as the
  behavior: design docs propagated (`hq/02-DESIGN/`, D-numbered), ROADMAP
  updated, and a numbered journey episode in `hq/04-JOURNEY/` (the journey
  duty). `internal/hqlint` enforces the structure as part of `go test`.
- Gate before every commit and any "done": `make check` (fmt, tidy, build,
  test, lint) — all green, nothing skipped. Tests are NOT optional,
  regardless of any template default; `make test` includes the hq
  structural lint and the operator-mode end-to-end proof.
- Sign every commit. Never commit `.claude/settings.local.json`.

## Governance

- `hq/00-GENESIS/` is authoritative; this file exists so speckit's
  Constitution Check gates against the real rules. **On conflict, hq wins.**
- **Amendments**: amend `hq/00-GENESIS/constitution.md` first (version bump
  + journey episode per its governance), then re-project here in the same
  change.
- **Versioning**: this file mirrors the hq constitution's version; it never
  versions independently.

**Version**: 1.2.0 | **Ratified**: 2026-07-28 | **Last Amended**: 2026-07-28
