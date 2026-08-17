# Feature Specification: The Grants Broker (outbound identity)

**Feature Branch**: `003-grants-broker`
**Created**: 2026-08-17
**Status**: In progress (first slice started overnight at the operator's 2026-08-17 direction; unmerged, morning review pending)
**Input**: Design `soul-hq/02-DESIGN/soulstream-identity/grants.md` (D30–D34), graduated from research topic `outbound-identity-grants` (hq episode 0104, Bars 1–3 measured on the real fold, identity plane, and remote node).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A persona's outbound call carries its own remote credential (Priority: P1)

A persona (human through the shell, agent through its wrapper) needs a
short-lived access token for a remote system — a third-party API or a
remote MCP server — and must only ever be able to obtain *its own*: the
grants surface serves `grants.access` on the caller's principal-scoped
subject, custody holds the rotating refresh token in a sealed store the
caller never sees, and another persona's request for the same grant dies
at the server as a publish permission violation, never reaching the
broker.

**Why this priority**: This is the feature — the inversion that removes
credentials from agent/MCP-client config. Everything else composes on it.

**Independent Test**: Against an operator-mode server with the
represented-user scope template carrying the grants op tail: persona A
(grant seeded) obtains a live token twice across a provider-side
rotation; persona B publishing to A's grants subject times out and the
broker's audit shows A's subject served exactly once; `grants.revoke`
deletes custody and the next access refuses.

**Acceptance Scenarios**:

1. **Given** a linked grant for persona A and a provider that rotates
   refresh tokens, **When** A calls `grants.access` repeatedly and
   concurrently, **Then** every call yields a live access token, the
   rotated successor is CAS-persisted, and no interleaving loses the
   grant line (the stored token remains redeemable).
2. **Given** the same deployment, **When** persona B publishes to A's
   grants subject, **Then** the server refuses the publish and the
   broker never receives the request.
3. **Given** a linked grant, **When** A calls `grants.revoke`, **Then**
   custody is deleted, upstream revocation is attempted best-effort,
   and the next `grants.access` refuses with grant-not-found.
4. **Given** any `grants.*` op, **Then** exactly one audit entry names
   the server-proven principal, the op, the resource, and the decision.

---

### User Story 2 - Linking: the consent ceremony seeds custody (Priority: P2)

A persona links a remote account once: `grants.link.start` returns the
authorization URL for the deployment-declared resource (authorization-
code + PKCE), the person consents in their own browser, and
`grants.link.complete` redeems the code and begins custody. The refresh
token is never returned to any caller, in either direction, ever.

**Independent Test**: Against a local stand-in AS (the rig idiom):
`link.start` → scripted consent → `link.complete` → `grants.access`
serves; the refresh token appears in no reply and nowhere at rest
unsealed (positive-control grep, the D13 idiom).

**Acceptance Scenarios**:

1. **Given** a declared resource, **When** A calls `link.start`, **Then**
   the reply carries the authorize URL (PKCE S256) and a link id; the
   PKCE verifier is stored sealed, never returned.
2. **Given** a completed browser consent, **When** A calls
   `link.complete` with the code, **Then** the grant is custodied sealed
   and `grants.list` shows the resource for A (and only for A).
3. **Given** a link id that expired or was already used, **Then**
   `link.complete` refuses.

---

### User Story 3 - An agent acts on behalf of a persona, provably (Priority: P3)

An agent calling `grants.access` with `on_behalf_of` must present a
delegation — subject-signed, bounded to resources/scopes/TTL — and the
broker honors it only when the *server-proven caller* is the
delegation's actor. A stolen, validly-signed delegation presented from
any other connection refuses as an actor mismatch. Every on-behalf
decision audits both personas.

**Independent Test**: The Bar 3 matrix on the wire: valid delegation on
the actor's own subject serves the subject's token; absent, expired,
stolen (wrong caller), and out-of-bounds-resource each refuse with the
refusal audited naming both personas.

**Acceptance Scenarios**:

1. **Given** a delegation signed by subject S naming actor T for
   resource R, **When** T calls `grants.access{resource: R,
   on_behalf_of: S, delegation}` on T's own subject, **Then** S's grant
   is redeemed and the audit names S and T.
2. **Given** the same delegation, **When** any caller other than T
   presents it, **Then** the call refuses as an actor mismatch.
3. **Given** an expired delegation or a resource outside the
   delegation's bounds, **Then** the call refuses, audited.

---

### Edge Cases

- A caller with no grant for the named resource: grant-not-found, no
  probe surface (identical refusal whether the resource exists or not).
- Provider refuses the stored refresh token (line lost upstream): the
  access refuses with the provider's failure classed as redemption
  failure; custody is not deleted (re-linking is the persona's act).
- Concurrent redeem races: the CAS loser serves its still-valid access
  token and writes nothing (D31's measured discipline).
- Delegation verification when the subject has no persona key in the
  vault: refuses — the subject-signed home requires the D26 directory.
- `link.complete` crash between code redemption and custody write: the
  code is spent, no grant exists; the ceremony restarts (honest, small
  window — same class as D31's redeem/CAS window).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The service MUST serve a `grants.*` op family on the
  principal-scoped subject space (D14/D15/D16/D25 unchanged): `access`,
  `link.start`, `link.complete`, `list`, `revoke`.
- **FR-002**: Grants MUST live in their own sealed KV bucket (default
  `SOULIDENTITY_GRANTS`), records sealed to the first key, with CAS
  update semantics; the key vault's immutable store is not touched.
- **FR-003**: `grants.access` MUST redeem at the provider, CAS-persist
  the rotated successor before returning, and return only the derived
  short-lived access token; the refresh token MUST NOT appear in any
  reply, request, or unsealed record (D32).
- **FR-004**: `on_behalf_of` MUST require a delegation verified against
  the subject's persona public key from the vault (D26 directory),
  live, actor == server-proven caller, subject == `on_behalf_of`,
  resource within bounds; every on-behalf decision MUST audit both
  personas (D33).
- **FR-005**: Resources are declared deployment configuration (value-
  only: name, endpoints, client registration, scopes, redirect URI) on
  the embed options and the daemon; no per-user configuration exists.
- **FR-006**: `grants.revoke` MUST delete custody, attempt RFC 7009
  upstream best-effort, and refuse subsequent access.
- **FR-007**: The client package MUST mirror the wire types in the same
  change (the repo's standing rule).
- **FR-008**: There is NO export operation for grant material — the
  design adds no analogue of `ExportSeed`.

### Key Entities

- **Grant**: (persona, resource) → sealed {refresh token, scopes,
  linked-at}, CAS revision.
- **Link state**: (persona, link id) → sealed {resource, PKCE verifier,
  expiry}, single-use.
- **Delegation**: {subject, actor, resources, scopes, issued/expires} +
  the subject's persona-key signature, presented per call, never stored.
- **Resource declaration**: value-only provider description.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: US1's independent test passes against an operator-mode
  server: isolation is server-enforced (delivery-log proof), rotation
  survives ≥3 redemptions and a concurrent double-refresh under
  `-race`, revocation refuses.
- **SC-002**: US2's ceremony passes against the stand-in AS with the
  refresh token nowhere on the wire and nowhere unsealed at rest.
- **SC-003**: US3's matrix passes: 1 allowed path, 4 refusal classes,
  every on-behalf decision audited naming both personas.
- **SC-004**: `make check` green, no test skipped.
- **SC-005** (closes the research residue): one real provider (GitHub
  or Google) completes link → rotation → revoke — a human-in-the-loop
  runbook step, not a gate test.

## Assumptions

- The subject-signed delegation's *minting* (and any standing-consent
  enforcement at mint time) lives with the minting side (shell/wrapper,
  per D33); this feature verifies presented delegations only.
- Outbound HTTP (authorize-URL construction, code/refresh redemption,
  RFC 7009) is new surface in this repo, confined to the grants
  provider client; discovery is per-resource configuration, not a new
  trust decision.
- The fold's token-lifetime knob and RFC 8693 exchange are the fold's
  roadmap (episode 0104 calls them due); lane 3 (exchange backend) is
  a later slice behind that landing.
