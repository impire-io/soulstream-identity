# SoulIdentity Constitution

Decisions are held against this file and [`vision.md`](vision.md) — see the
decision test in [`README.md`](README.md).

## Core Principles

### I. Custody Without Possession

Secrets live in the vault and answer requests; they are never handed out.

- No API surface may return a seed, private key, or any material sufficient to
  sign without the vault. The API returns public keys, signatures, and minted
  tokens — nothing else.
- Every exception is a named custody escape (today: credential export), always
  explicit in the request, always loud in the audit log, never a side effect.
- Every signing operation is attributable and logged. An oracle whose use
  cannot be audited is possession with extra steps.
- In-process access to key material stays inside the vault package; the
  process boundary is the custody boundary.

**Rationale**: The agent exists because shared infrastructure holding raw keys
turns node compromise into identity theft. Custody-without-possession is the
one property that distinguishes SoulIdentity from a directory of seed files;
lose it anywhere and the project has no reason to exist.

### II. The Server Is the Verifier of Record

The NATS server enforces; SoulIdentity decides only what is genuinely its own.

- Transport permissions live NATS-side — in scoped signing keys (mint mode) or
  callout-issued JWTs (callout mode) — and are enforced by the server on every
  connection. SoulIdentity MUST NOT build a parallel enforcement path that
  duplicates what the server already checks.
- SoulIdentity's own policy surface is exactly: which identity exists, which
  personas it may act as, which role mints for it — whether declared in the
  registry or derived from validated claims in the presented credential
  (D2). Act-as policy is ours; pub/sub permissions are not.
- Validations the server will repeat (e.g. signing-key ↔ account binding) are
  diagnostics — warn-level conveniences, never gates. A mis-bound key fails
  closed at the server; that is the design, not a gap.

**Rationale**: Two sources of truth drift. The NATS decentralized auth model
already carries membership (issuer_account), permissions (scopes), and
rejection of bad bindings; duplicating any of it would eventually contradict
it. Aligning with the native model is also what keeps both enforcement modes
— minted and callout — coherent on one registry.

### III. Smallest Viable Implementation

- Every change MUST be the smallest implementation that satisfies its need.
  Anything not required by a concrete consumer is cut or deferred.
- Speculative generality is prohibited: no configuration options, abstraction
  layers, or plugin points added "for later". The storage-backend seam and the
  authn-backend seam exist because the design names their concrete future
  backends; nothing else gets a seam in advance.
- Growth is new modes and backends on the same vault + registry, never new
  machinery beside them. If an addition doesn't survive the founding bet's
  list staying short, it becomes a backend or it goes nowhere.
- Scope creep is a review blocker, not a style concern.

**Rationale**: An identity component earns trust by being small enough to
audit. Every optional feature grows the surface an operator must believe in.

### IV. Documentation Is a First-Class Citizen

- Every concept is explained plainly — an everyday analogy before technical
  detail (the project's custody analogy is one: like an ssh-agent, it signs
  instead of handing out keys). Plain words beat invented terms.
- The design doc records every load-bearing decision with a D-number and its
  reasoning, so future changes argue against the real reasons.
- Docs ship in the same change as the behavior they describe; stale
  documentation is a bug with the same severity as a failing test.

**Rationale**: A security-adjacent tool that cannot be explained simply will
be misused, and misuse of an identity agent is a security failure, not a UX
failure.

## The Working Agreement (Anti-Drift)

Adopted from the Soulstream working agreement (soulstream journey 0002) at
genesis — recorded in journey
[0001](../04-JOURNEY/0001-genesis-and-the-walking-skeleton.md). It guards the
same failure mode: a fluent counterpart steering the maintainer on a
load-bearing call he cannot independently check in the moment. Applies to
every load-bearing decision — a custody-boundary change, an enforcement-mode
change, a scope call, or a public claim.

1. **Teach-back as a gate.** No load-bearing direction decision is recorded
   until the maintainer can restate the argument for it in his own words.
2. **Claims carry their evidence class.** **[measured]** (a test, a
   demonstrated NATS behavior), **[mechanism-argument]** (a reasoned case from
   how NATS or the agent works), or **[judgment]**. Only measured closes a
   debate.
3. **Decisions record the reversal condition,** written when the decision is
   made, phrased as an observable reading.
4. **Adversarial pass on direction changes.** For decisions that change the
   custody boundary or an enforcement mode, the other side is argued at full
   strength before the decision.

## Technology Constraints

- **Language**: Go, matching the ecosystem; official NATS libraries only
  (`nkeys`, `jwt/v2`, `nats.go`, embedded `nats-server` for tests).
- **Secrets at rest**: the vault's initial backend is NATS KV with xkey
  envelope encryption at rest — only ciphertext is ever stored; the
  milestone-1 file keystore (0600 files under 0700 directories) is
  transitional and retires with the NATS-native rebuild. Encryption at rest
  relocates the root secret, it does not eliminate it: the unwrapping xkey
  and the service's own NATS creds are the only local secrets, and the
  first-key story is decided by research before the backend lands. Further
  backends arrive through the storage seam.
- **Transport**: NATS is the only transport — request/reply with xkey-sealed
  payloads (end-to-end encrypted), the caller authenticated by its own NATS
  identity. There is no socket and no TCP listener. The pre-connection
  moment belongs to the connection ladder, not to a local surface: a client
  presenting a creds file connects to NATS directly and bypasses
  SoulIdentity (self-custody); a client presenting an external token arrives
  through auth callout. Auth-callout configuration is where that line is
  drawn and enforced.
- **Dependencies**: an identity agent is judged by its audit surface — keep
  the dependency tree small enough to read.

## Development Workflow & Quality Gates

- Research (open questions that precede a design) runs the `hq/01-RESEARCH/`
  lifecycle — see [`how-we-work.md`](how-we-work.md). Implementation follows
  the design docs and the roadmap's milestone gates.
- Before merge, everything MUST be green: `make check` (fmt, tidy, build,
  test, lint) — all tests pass (none skipped), the hq structural lint
  (`internal/hqlint`) included.
- Every landed milestone, concluded research topic, or load-bearing decision
  gets a numbered episode in `hq/04-JOURNEY/` in the same change (the journey
  duty).
- Commits are signed. `.claude/settings.local.json` is never committed.

## Governance

- This constitution supersedes all other practices for SoulIdentity. On
  conflict with README or any other document, the constitution wins.
- **Amendments**: made by editing this file, with a version bump and a journey
  episode recording the why and the reversal condition.
- **Versioning policy** (semantic): MAJOR — removing or redefining a
  principle; MINOR — a new principle or section, or materially expanded
  guidance; PATCH — clarifications.

**Version**: 1.2.0 | **Ratified**: 2026-07-28 | **Last Amended**: 2026-07-28

*Amendment history:*
- *1.2.0 (2026-07-28)* — the connection ladder (journey
  [0003](../04-JOURNEY/0003-nats-only-and-the-connection-ladder.md)):
  NATS becomes the *only* transport — the Unix socket is dropped entirely
  (superseding 1.1.0's bootstrap-mode role hours after it was written). The
  pre-connection moment is answered by the ladder instead: a presented creds
  file bypasses SoulIdentity (self-custody, server-verified natively); an
  external token arrives through auth callout, with the line drawn in
  callout config (D12). NATS KV + xkey envelope is promoted from named-next
  to the vault's *initial* backend (the file keystore is transitional), and
  Principle II's policy-surface bullet is clarified to admit validated
  claims in the presented credential as a policy source beside the declared
  registry (D2 amended). Principles I–IV otherwise unchanged (MINOR).
- *1.1.0 (2026-07-28)* — the identity-plane re-centering (journey
  [0002](../04-JOURNEY/0002-the-identity-plane-re-centering.md)): mission
  redefined in `vision.md` from "a local ssh-agent for personas" to the
  representation of identity for humans and agents, delivered as a NATS
  service with xkey-sealed E2E request/reply. Technology Constraints
  redefined accordingly — NATS becomes the primary transport (the planned
  TCP-plus-tokens listener is dropped; the Unix socket demotes to the
  bootstrap/laptop mode) and NATS KV with xkey envelope encryption is named
  the next storage backend. Principles I–IV unchanged (MINOR).
- *1.0.0 (2026-07-28)* — initial ratification (Principles I–IV + the working
  agreement), adopted at genesis with the hq structure (journey
  [0001](../04-JOURNEY/0001-genesis-and-the-walking-skeleton.md)).
