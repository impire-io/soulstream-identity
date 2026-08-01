# Feature Specification: The Embed Seam

**Feature Branch**: `002-embed-seam`
**Created**: 2026-08-01
**Status**: Implemented (landed 2026-08-01 — journey 0018)
**Input**: User description: "The embed seam (D29): a public `embed` package that lifts the daemon's serve assembly behind `Run(ctx context.Context, o Options) error` so a consumer process can host the identity plane — service, optional callout issuer, vault — in-process against `*nats.Conn`s it already holds, with no `internal/` imports. Options are value-only; no internal type crosses the boundary; custody unchanged (D13); `client/` remains the consumer surface while `embed/` is the operator surface; provisioning stays on the wire through `client/`. `cmd/soulidentity serve` becomes the first consumer of `embed`. Acceptance: the operator-mode callout e2e shape passes with the plane assembled through `embed.Run`, driven from a consumer-position module with zero internal/ imports."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A distribution hosts the identity plane in its own process (Priority: P1)

An operator building a bundled deployment (soulnode is the named consumer)
holds live NATS connections to an embedded server and wants the identity
plane — the sealed service surface, and when callout connections are
supplied, the callout issuer — running inside the same process, assembled
entirely through the module's public surface. Today that operator must
either supervise the `soulidentity` binary as a child process or name their
module under this repo's path to reach `internal/` — both recorded as
findings by consumers (soulstream's remote-mcp-node experiment, soulnode's
composition rig).

**Why this priority**: This is the feature. M2 is "consumers wire in", and
the second consumer is blocked on exactly this seam; without it, a
single-process distribution violates its own no-`internal/`-reaches rule
or ships a namespace dodge to production.

**Independent Test**: From a consumer-position test module whose import
path is *outside* this repo's namespace, assemble the plane with the public
package against an embedded operator-mode server and run the M4 admission
shape: token-lane admission with correct attribution, invalid-token
refusal, revoked-token refusal.

**Acceptance Scenarios**:

1. **Given** a running operator-mode server and a service-account
   connection, **When** the operator calls the public entrypoint with
   value-only options (bucket names, the seeds, no callout connection),
   **Then** the sealed service surface serves (`status` answers) and no
   `internal/` import exists in the calling code.
2. **Given** the same, plus a callout-account connection and the callout
   options, **When** the operator calls the entrypoint, **Then** the
   issuer serves: a sentinel + valid API token connection is admitted with
   the persona attributed by the server, and an invalid or revoked token
   is refused with the refusal in the audit log.
3. **Given** a running assembly, **When** the operator's context ends,
   **Then** the plane drains and stops without leaking subscriptions —
   the same shutdown the daemon performs.

---

### User Story 2 - The daemon serves through the same assembly (Priority: P2)

An operator running the standalone `soulidentity serve` daemon gets exactly
the behavior they had before: same flags, same environment variables, same
log lines, same lifecycle. Internally the command now assembles the plane
through the public seam, so the daemon and every embedding consumer share
one assembly and cannot drift.

**Why this priority**: One assembly, two entrypoints is the drift guard —
but it is only refactoring value until the seam itself (US1) exists.

**Independent Test**: The existing e2e suites (M3 sealed surface, M4
callout, M2 cross-service gate) pass unchanged against the reworked
`serve`.

**Acceptance Scenarios**:

1. **Given** the documented `serve` invocation (env seeds, flags,
   callout creds), **When** the daemon starts, **Then** every existing e2e
   gate passes without modification to the tests.
2. **Given** a mis-supplied first key, **When** the daemon starts, **Then**
   it fails fast with the same vault-verification refusal as today (never
   double-seals).

---

### Edge Cases

- Callout options supplied without a callout connection (or the reverse):
  the entrypoint refuses at construction with an error naming the missing
  half — never a silently-disabled issuer.
- OIDC issuer supplied without audience (or the reverse): refused at
  construction, mirroring the daemon's existing both-or-neither rule.
- Context cancelled during startup: whatever was started is drained;
  no goroutine or subscription survives.
- The service connection closes underneath the assembly: the plane
  surfaces the failure to its logger; reconnection policy belongs to the
  connection's owner (the embedder), not the plane.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The module MUST expose a public package that assembles and
  runs the identity plane (vault, sealed service surface, optional callout
  issuer) against caller-supplied NATS connections, blocking until the
  caller's context ends, then draining.
- **FR-002**: The public options MUST be value-only — connections, bucket
  names, seed strings, key names, account key, TTL, prefix, OIDC
  issuer/audience, logger — and MUST NOT expose any type from `internal/`.
- **FR-003**: The assembly MUST enforce the daemon's existing invariants at
  construction: vault verification before serving (fail fast on a wrong
  first key), prefix validation, the callout both-halves rule, and the
  OIDC both-or-neither rule.
- **FR-004**: The callout issuer MUST be enabled exactly when a callout
  connection is supplied, with the same admission, refusal, revocation,
  and audit behavior the daemon exhibits.
- **FR-005**: `cmd/soulidentity serve` MUST assemble the plane through the
  public package — one assembly, two entrypoints — with its flag and
  environment contract unchanged.
- **FR-006**: The public package MUST NOT add any provisioning or
  key-mutation API; mutation stays on the sealed wire surface through
  `client/` (the existing custody model, D7/D13/D25, unchanged).
- **FR-007**: A consumer module outside this repo's namespace MUST be able
  to compile and run the full assembly with zero `internal/` imports —
  proven in-repo by a consumer-position test.

### Key Entities

- **The assembly options**: the value-only description of a deployment —
  which connections carry the service and the callout, which buckets hold
  vault and tokens, which seeds seal what, which account issues admitted
  users.
- **The running plane**: the assembled service + optional issuer bound to
  their connections, alive from call until context end, draining on the
  way out.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A consumer-position module with zero `internal/` imports
  assembles the plane and passes the M4 admission shape — valid token
  admitted with server-asserted attribution, invalid token refused,
  revoked token refused, refusals present in the audit — against an
  operator-mode server.
- **SC-002**: Every existing e2e gate (M3 sealed surface, M4 callout, M2
  cross-service) passes unchanged with the daemon serving through the
  seam.
- **SC-003**: The namespace dodge disappears from the ecosystem's forward
  path: the named consumer (soulnode) can delete its module-path
  workaround for the serve assembly, keeping public imports only.
- **SC-004**: The full quality gate (`make check`) stays green, no test
  skipped.

## Assumptions

- The seam's shape follows the daemon's existing `cmdServe` wiring —
  no new capability, no behavior change, assembly only.
- Connection ownership stays with the embedder: the plane never dials,
  reconnects, or closes the connections it is handed (the daemon keeps
  owning its own dials via its flags).
- The three seed strings remain deployment-supplied configuration (D13 as
  amended); the seam neither generates nor persists key material.
- `client/` remains the only consumer surface; this feature adds the
  operator surface without touching the wire protocol.
- Naming of the public package (`embed` vs another name) is a plan-time
  decision; the spec requires only that it is public and value-only.
