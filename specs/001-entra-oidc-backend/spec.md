# Feature Specification: Entra ID as a Second Callout Credential Backend

**Feature Branch**: `001-entra-oidc-backend`
**Created**: 2026-07-29
**Status**: Draft
**Input**: User description: "Microsoft Entra ID as a second credential backend for the NATS auth-callout issuer — the Entra/OIDC lane deferred by design decision D22, with authorization from the token's app-role claim; no rule table, no precedence, no per-user entries."

## Clarifications

### Session 2026-07-29

- Q: Where is the role catalog declared? → A: There is no catalog. The name
  of the role is the name of the team: the role value in the token resolves
  directly to the team SoulIdentity already declares — the team's signing
  authority and its account binding. Declaring a team is the existing
  operator act; no separate mapping store exists.
- Q: Which Entra token classes are admitted? → A: Both delegated (human
  sign-in) and app-only (client-credentials daemon / service principal);
  the audit distinguishes them by subject.
- Q: Revocation-bound stance? → A: Accepted as stated — token lifetime plus
  one callout TTL; no maximum-token-age knob. The tenant's token-lifetime
  policy is the lever if the bound must shrink.
- Q: Custody acceptance (directory-controlled membership)? → A: Resolved by
  role == team: the tenant controls who is on a team; SoulIdentity's guard
  is that a team of that name must be declared. A role value naming no
  declared team is inert — the tenant cannot invent teams.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Corporate identity connects without pre-provisioning (Priority: P1)

An engineer (or an agent acting for them) whose organization uses Microsoft
Entra ID connects to the Soulstream ecosystem using their corporate sign-in.
Their tenant administrator has assigned them an application role named after
their team; they present the resulting access token (alongside the public
sentinel credentials) and are admitted with exactly the team's permissions —
no SoulIdentity API token was created for them, and no per-person record
exists in SoulIdentity.

**Why this priority**: This is the feature. It removes the per-person
provisioning step (token creation + registry row) for every member of an
Entra-managed organization, which is the main cost of onboarding at any scale.

**Independent Test**: On the test rig (a real broker with callout enabled and
a stand-in identity provider), a token whose role value names one declared
team admits the holder; the connection can do what the team allows, cannot do
anything else, and the audit log names the external identity, its team, and
where it connected from.

**Acceptance Scenarios**:

1. **Given** a valid access token for SoulIdentity's own app registration
   carrying exactly one role value that names a declared team, **When** the
   holder connects through the callout lane, **Then** the connection is
   admitted with the team's permissions enforced by the server, and the audit
   records issuer, stable subject identifier, team, and client host.
2. **Given** the same admitted connection, **When** it attempts an operation
   outside the team's permissions, **Then** the server itself denies it.
3. **Given** an admitted claims-path connection, **When** its identity is
   inspected anywhere in SoulIdentity, **Then** it carries no admin capability
   and no personas — those are never derived from claims.

---

### User Story 2 - Operator declares the team; the tenant decides who is on it (Priority: P2)

There is no mapping catalog. The name of the role is the name of the team:
a role value in the token resolves directly to the team SoulIdentity already
declares — the team's signing authority, bound to the account it admits
into. Declaring a team is the existing operator act; the Entra tenant
administrator — without touching SoulIdentity — controls who is on each
team. Neither side can do the other's job: a role value naming no declared
team admits no one, and no team declaration names a person.

**Why this priority**: The governance split is what makes the feature safe to
operate: SoulIdentity keeps deciding which teams exist and what they may do,
the directory keeps deciding who is on them, and neither store contains
per-user mapping rules. Both credential lanes converge on the same team
objects — the registry row names a team for API-token identities exactly as
the role claim names one here.

**Independent Test**: Inspect the complete declared state for a two-account,
two-team deployment: it contains zero per-user entries, zero
ordering-sensitive rules, and no mapping store of any kind. Present a token
whose role value names no declared team: refused.

**Acceptance Scenarios**:

1. **Given** a token carrying a role value that names no declared team,
   **When** its holder connects, **Then** the connection is refused with a
   generic wire error and a specific audit reason.
2. **Given** a token carrying two role values that both name declared teams,
   **When** its holder connects, **Then** the connection is refused as
   ambiguous (order of claims must never decide authorization).

---

### User Story 3 - Access ends when the directory says so (Priority: P2)

A tenant administrator removes a person's role assignment. That person's
access ends within a stated, bounded time — and the bound is honest: it is
the lifetime of the access token they already hold plus one callout interval,
which is longer than the API-token lane's revocation bound.

**Why this priority**: Revocation is the other half of admission; an identity
lane without a stated revocation bound cannot be trusted in operation.

**Independent Test**: On the rig, admit a connection, then strip the role at
the stand-in provider. The connection is disconnected at the callout interval;
a freshly issued role-less token is refused on reconnect; the previously
issued (still unexpired) token re-admits until it expires — demonstrating the
stated bound exactly.

**Acceptance Scenarios**:

1. **Given** an admitted claims-path connection, **When** the callout interval
   elapses, **Then** the server disconnects it and readmission requires
   passing validation and authorization again.
2. **Given** a subject whose role was removed at the provider, **When** they
   reconnect with a freshly issued token, **Then** they are refused.

---

### User Story 4 - Existing API-token clients are untouched (Priority: P3)

Every client already connecting with a SoulIdentity API token continues to
work exactly as before, whether or not the Entra lane is configured. The two
lanes are disjoint for membership: API tokens are checked against the token
store and registry; Entra tokens against the validator and the declared
teams; neither consults the other's membership source. Both resolve
permissions through the same team objects.

**Why this priority**: The feature must be a pure addition; regressing the
shipped M4 lane would be worse than not landing this at all.

**Independent Test**: The existing end-to-end admission proof for API tokens
passes unchanged on a deployment with the Entra lane configured; an
Entra-shaped credential presented to a deployment *without* the Entra lane
configured is refused early.

**Acceptance Scenarios**:

1. **Given** a deployment with both lanes configured, **When** an API-token
   client connects, **Then** it is admitted via the token store exactly as
   before.
2. **Given** a deployment with no Entra lane configured, **When** a client
   presents an Entra-shaped credential, **Then** it is refused without any
   token-store lookup being attempted.

---

### Edge Cases

- Identity provider's key-publication endpoint unreachable, or token signed
  by a key the service does not know: refuse (never admit on stale trust);
  after the provider rotates keys, a token under the new key must admit
  without restarting the service.
- Token altered in transit / signed by the wrong authority / expired / issued
  for a different application / issued by a non-allow-listed issuer: refused.
- Token valid but carrying no role claim at all: refused.
- Token presented with a symmetric or absent signature algorithm
  (downgrade attempt): refused.
- A role value naming no declared team is inert: granting a role in the
  tenant only ever grants a team SoulIdentity has declared — the tenant
  cannot invent teams, and exact name match is the guard.
- Refusals never leak the specific reason on the wire; the reason is recorded
  in the audit log only.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The callout issuer MUST accept an Entra-issued access token as
  a credential on the existing validate → authorize → mint pipeline, as a
  second lane beside the API-token lane.
- **FR-002**: Validation MUST verify, before any authorization: the token's
  issuer against a pinned allow-list, its audience against SoulIdentity's own
  application identity, its signature against keys published by the issuer
  (fetched via standard discovery), and its validity window.
- **FR-003**: Authorization MUST come from the token's application-role
  claim, where the role value IS the team name: it resolves directly to the
  declared team — the team's signing authority bound to its account. Exact
  name match only — no mapping catalog, no rule table, no precedence, no
  per-user entries.
- **FR-004**: A token whose role values name zero declared teams MUST be
  refused; a token whose role values name more than one declared team MUST
  be refused as ambiguous.
- **FR-005**: The two credential lanes MUST be disjoint for membership: API
  tokens are resolved against the token store and registry; Entra tokens
  against the validator and the declared teams; neither lane consults the
  other's membership source, and no cross-lookup or precedence between them
  exists. Both lanes resolve permissions through the same team objects.
- **FR-006**: Admin capability and personas MUST NOT be derivable from
  claims: every claims-path admission carries no admin capability and no
  personas. A person needing either gets a declared registry identity (the
  API-token lane).
- **FR-007**: The stable subject identifier (`oid`) MUST key the admitted
  identity and the audit trail; human-readable names from the token are
  logged for legibility but never used as keys.
- **FR-008**: Every admission and refusal MUST be attributable in the audit
  log (issuer, subject, role, client host on admission; specific reason on
  refusal); wire-level errors MUST stay generic.
- **FR-009**: The lane MUST fail closed in every degraded state: key
  endpoint unreachable, unknown signing key, lane not configured, malformed
  token — refusal, never admission. Key rotation at the provider MUST be
  absorbed without a service restart.
- **FR-010**: Issued connection credentials MUST remain TTL-bounded exactly
  as in the API-token lane; the revocation bound for the Entra lane (access
  token lifetime + one TTL) MUST be stated in the design documentation.
- **FR-011**: The measured acceptance proof MUST run against a local
  stand-in identity provider on the operator-mode end-to-end rig; behavior
  against a real Entra tenant is covered by a documented manual runbook and
  is never part of the automated test gate.
- **FR-012**: Unit tests mirroring the existing issuer tests and an
  end-to-end sibling of the existing M4 gate proof are explicitly part of
  this feature's scope, as are the hq landing duties (design amendment,
  roadmap update, journey episode) in the same merge.
- **FR-013**: The Entra lane MUST admit both delegated (human sign-in) and
  app-only (client-credentials / daemon) tokens; the audit distinguishes
  them by subject — a person's `oid` vs a service principal's `oid`.
- **FR-014**: The revocation bound is accepted as stated — access-token
  lifetime plus one callout TTL — with no maximum-token-age knob; the
  tenant's token-lifetime policy is the lever if the bound must shrink. The
  bound MUST be stated plainly in the design documentation.
- **FR-015**: No mapping store exists to declare: a team is declared by the
  existing operator act that establishes its signing authority and account
  binding. A role value naming no declared team MUST refuse; the set of
  declared teams is the complete authorization surface of the lane.

### Key Entities

- **External access token**: the credential presented by the connecting
  client; issued by the tenant's identity provider for SoulIdentity's own
  application registration; carries issuer, audience, validity window,
  stable subject identifier, and application-role values. Never stored by
  SoulIdentity.
- **Team**: the named unit of authorization both lanes converge on — a
  signing authority bound to one account, declared by the operator. The
  registry row names a team for API-token identities; the token's role value
  names one here. A team declaration contains no members, no ordering, no
  conditions: membership lives in the registry (token lane) or the directory
  (Entra lane).
- **External subject**: the admitted identity, keyed by the provider's stable
  object identifier; appears in the audit trail; holds no admin capability
  and no personas.
- **Issued connection credential**: the TTL-bounded, server-scoped credential
  minted on admission — identical in shape and custody to the API-token
  lane's (the mint stage is unchanged).
- **Sentinel**: the existing public deny-all bearer credential that routes an
  external client into the callout lane (unchanged by this feature).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A person granted a cataloged role in the directory can connect
  with zero per-person provisioning acts in SoulIdentity (no token minted,
  no registry row created) — measured on the rig as: assignment at the
  provider is the only act between "cannot connect" and "connects".
- **SC-002**: 100% of the refusal matrix refuses: wrong audience, expired,
  bad signature, non-allow-listed issuer, absent role claim, role naming no
  declared team, ambiguous roles, signature-algorithm downgrade — eight of
  eight, each with a generic wire error and a specific audit reason.
- **SC-003**: Admission carries full attribution: for every admitted
  connection the audit log names issuer, stable subject, team, and client
  host — verified for 100% of admissions on the rig.
- **SC-004**: Key-infrastructure failure never admits: with the provider's
  key endpoint unreachable or serving unknown keys, zero admissions occur;
  after key rotation, admission resumes without a service restart.
- **SC-005**: Revocation honors its stated bound: a stripped role stops
  admitting fresh tokens immediately and stops re-admitting cached tokens
  within token lifetime + one callout interval, demonstrated with the actual
  timings on the rig.
- **SC-006**: The existing API-token lane shows zero behavioral change with
  the Entra lane configured — the shipped M4 end-to-end proof passes
  unchanged.
- **SC-007**: The complete declared state for a two-account, two-team
  deployment contains zero per-user entries, zero ordering-sensitive rules,
  and no mapping store of any kind.

## Assumptions

- Single-tenant use: the issuer allow-list pins one tenant's issuer;
  multi-tenant admission is out of scope for this feature.
- The tenant issues v2.0-format access tokens for SoulIdentity's app
  registration (the app opts into the v2.0 token format; the v1.0 issuer
  format will not match and is out of scope).
- The tenant enables "assignment required" on the application so unassigned
  users are refused at the provider before a token exists (defense in depth;
  SoulIdentity's catalog match is the enforced guard regardless).
- The connecting client obtains and refreshes its own Entra tokens (standard
  sign-in tooling); SoulIdentity never performs the interactive login and
  never becomes an identity provider (per the project vision's refusals).
- The sentinel flow (public deny-all bearer credentials routing external
  clients into callout) is unchanged from the shipped design (D19).
- The callout TTL default (15 minutes) is unchanged; the Entra lane inherits
  it.
- App-role values in the tenant equal team names verbatim — no prefix
  convention, no transformation; exact name match against declared teams is
  the guard.
