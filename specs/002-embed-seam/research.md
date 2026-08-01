# Research — 002-embed-seam

No NEEDS CLARIFICATION markers existed; the decisions below close the
plan-time choices the spec deferred.

## R1 — The package is `embed`, as D29 names it

- **Decision**: `github.com/impire-io/soulidentity/embed`, package `embed`.
- **Rationale**: D29 names it; "embed" states the operator-surface intent
  (who *hosts* the plane) against `client/` (who *calls* it). The known
  cost — Go's stdlib `embed` package shares the name, so a consumer file
  using both aliases one import (`siembed "…/soulidentity/embed"`) — is
  cosmetic and local to the consumer.
- **Alternatives considered**: `serve` (verb-shaped, and collides
  conceptually with the CLI subcommand it doesn't equal — the package
  doesn't parse flags or own connections); `plane` (invented term,
  constitution IV prefers plain words); a root-package `soulidentity.Run`
  (would make every future public helper root-level by gravity — too big a
  door for one seam).

## R2 — Ownership: the embedder owns connections, Run owns subscriptions

- **Decision**: `Run` never dials, closes, or drains the `*nats.Conn`s it
  is handed. On ctx end it drains what it created — the service and issuer
  subscriptions — and returns. The daemon keeps exactly its current
  behavior by draining its own connections *after* `Run` returns (it owns
  them; it dialed them).
- **Rationale**: mirrors the spec's assumption ("connection ownership
  stays with the embedder") and today's `cmdServe` split, where
  `sub.Drain()` precedes the connection drains. An embedder like soulnode
  shares connections across planes; a package that closed them would be
  unusable.
- **Alternatives considered**: Run drains connections too (breaks shared
  conns); an explicit `Close()` handle instead of ctx (more surface, same
  power — ctx is how the daemon already ends, constitution III).

## R3 — The gate module's path sits outside the namespace, so the compiler is the reviewer

- **Decision**: the consumer-position proof lives in `e2e/embedgate/`,
  module `soulidentity.invalid/embedgate` — a path outside
  `github.com/impire-io/soulidentity`, so a `internal/` import is a
  *compile error*, not a review finding. `.invalid` is the RFC-reserved
  never-resolves TLD: the module states its never-published nature in its
  own name. Wired into `make tidy/test/lint` exactly like `e2e/`.
- **Rationale**: the ecosystem has now twice ridden the module-namespace
  dodge to reach `internal/` (remote-mcp-node, soulnode's rig — both
  [measured] in their journals); a proof module *inside* the namespace
  (like `e2e/`, which could legally import `internal/` and simply
  doesn't) proves the claim by convention only. SC-001's zero-internal
  claim deserves the compiler.
- **Alternatives considered**: extend `e2e/` with the gate (in-namespace —
  convention-proof only); relocate `e2e/` itself outside the namespace
  (scope creep on a landed pattern); grep-based lint (weaker than the
  toolchain, one more custom check to maintain).

## R4 — The gate carries its own ceremony; duplication is accepted and bounded

- **Decision**: `gate_test.go` builds its own operator-mode server +
  callout ceremony (~200 lines: operator/SYS/AUTH/APP accounts, scoped
  signing key, xkeys, buckets, bootstrap creds), then assembles the plane
  through `embed.Run` and drives admit / refuse / revoke.
- **Rationale**: test helpers cannot cross module boundaries, and the
  repo already accepts exactly this cost three times (`client/`'s two
  e2es and `e2e/`'s gate each carry the ceremony). soulnode's rig is the
  fourth proof the ceremony is mechanical [measured, its provision.go].
  Promoting a shared ceremony helper into public surface would be
  speculative generality (constitution III) — no consumer asked for it.
- **Alternatives considered**: export a `natstest`-style public helper
  (new public surface nobody requested; D29's reversal condition governs
  the day someone does); making embedgate depend on soulnode's rig
  (inverts the dependency direction across repos).

## R5 — Misconfiguration error wording moves to the package; flag naming stays in the cmd

- **Decision**: `embed` validates and errors in its own vocabulary
  ("callout: AuthAccount required when a callout connection is supplied");
  `cmdServe` maps flag/env names where it adds information. The e2e
  suites assert behavior, not error prose — no gate depends on the old
  wording.
- **Rationale**: the package cannot know flag names; the daemon cannot
  leave misconfig unexplained. US2's "unchanged" contract is flags, env,
  log lines, lifecycle, and gates — checked against the suites, which do
  not pin these strings.

## R6 — The serving log lines move into `embed`

- **Decision**: "service serving" (root, bucket, version) and "callout
  issuer serving" (subject, token bucket, ttl, sealed_requests, oidc) are
  emitted by `Run`, same keys and text as today.
- **Rationale**: the diagnostic value ("this line is where a prefix
  mismatch is diagnosed" — cmdServe's own comment) belongs to every
  embedder, not just the daemon; US2 keeps the daemon's log surface
  intact by construction.
