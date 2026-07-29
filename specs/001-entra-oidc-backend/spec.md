# Feature Specification: Entra ID as a Second Callout Credential Backend

**Feature Branch**: `001-entra-oidc-backend`
**Created**: 2026-07-29
**Status**: Draft
**Input**: User description: "Microsoft Entra ID as a second credential backend for the NATS auth-callout issuer — the Entra/OIDC lane deferred by design decision D22, with authorization from the token's app-role claim against a small operator-declared role catalog; no rule table, no precedence, no per-user entries."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Corporate identity connects without pre-provisioning (Priority: P1)

An engineer (or an agent acting for them) whose organization uses Microsoft
Entra ID connects to the Soulstream ecosystem using their corporate sign-in.
Their tenant administrator has assigned them an application role; they present
the resulting access token (alongside the public sentinel credentials) and are
admitted with exactly the permissions that role means — no SoulIdentity API
token was created for them, and no per-person record exists in SoulIdentity.

**Why this priority**: This is the feature. It removes the per-person
provisioning step (token creation + registry row) for every member of an
Entra-managed organization, which is the main cost of onboarding at any scale.

**Independent Test**: On the test rig (a real broker with callout enabled and
a stand-in identity provider), a token carrying one cataloged role admits the
holder; the connection can do what the role allows, cannot do anything else,
and the audit log names the external identity, its role, and where it
connected from.

**Acceptance Scenarios**:

1. **Given** a valid access token for SoulIdentity's own app registration
   carrying exactly one cataloged role, **When** the holder connects through
   the callout lane, **Then** the connection is admitted with the role's
   permissions enforced by the server, and the audit records issuer, stable
   subject identifier, role, and client host.
2. **Given** the same admitted connection, **When** it attempts an operation
   outside the role's permissions, **Then** the server itself denies it.
3. **Given** an admitted claims-path connection, **When** its identity is
   inspected anywhere in SoulIdentity, **Then** it carries no admin capability
   and no personas — those are never derived from claims.

---

### User Story 2 - Operator declares what a role means; the tenant decides who holds it (Priority: P2)

The SoulIdentity operator declares a small role catalog: each entry maps one
role value to the account it admits into and the signing authority that scopes
its permissions. The Entra tenant administrator — without touching
SoulIdentity — controls who holds each role. Neither side can do the other's
job: an uncataloged role value admits no one, and no catalog entry names a
person.

**Why this priority**: The governance split is what makes the feature safe to
operate: SoulIdentity keeps deciding what a role means, the directory keeps
deciding who holds it, and neither store contains per-user mapping rules.

**Independent Test**: Inspect the complete declared configuration for a
two-account, two-role deployment: it contains zero per-user entries and zero
ordering-sensitive rules. Present a token with a role value outside the
catalog: refused.

**Acceptance Scenarios**:

1. **Given** a token carrying a role value not present in the catalog,
   **When** its holder connects, **Then** the connection is refused with a
   generic wire error and a specific audit reason.
2. **Given** a token carrying two cataloged roles, **When** its holder
   connects, **Then** the connection is refused as ambiguous (order of claims
   must never decide authorization).

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
lanes are disjoint: API tokens are checked against the token store and
registry; Entra tokens against the validator and catalog; neither consults
the other's store.

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
- A role value colliding with an internal name: inert unless the operator
  cataloged it — the catalog's exact match is the guard; the namespacing
  convention (`soulstream.<role>`) reduces accidental collisions.
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
- **FR-003**: Authorization MUST come from the token's application-role claim:
  the role value selects an entry in an operator-declared role catalog
  mapping role value → {account, signing authority}. Exact match only — no
  rule table, no precedence, no per-user entries.
- **FR-004**: A token whose role claim matches zero catalog entries MUST be
  refused; a token matching more than one catalog entry MUST be refused as
  ambiguous.
- **FR-005**: The two credential lanes MUST be disjoint: API tokens are
  resolved against the token store and registry; Entra tokens against the
  validator and catalog; neither lane consults the other's store, and no
  cross-lookup or precedence between them exists.
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
- **FR-013**: The Entra lane MUST admit [NEEDS CLARIFICATION: delegated
  (human sign-in) tokens only, or also app-only (client-credentials / daemon)
  tokens? Both carry app roles; the subject differs — a person's `oid` vs a
  service principal's `oid`].
- **FR-014**: The revocation bound MUST be [NEEDS CLARIFICATION: accepted as
  stated (token lifetime + one TTL), or tightened with a maximum-token-age
  knob that refuses tokens issued more than N minutes ago, trading tenant
  convenience for a shorter bound].
- **FR-015**: The role catalog MUST be declared [NEEDS CLARIFICATION: as
  deployment configuration read at service start (restart to change), or
  managed at runtime through admin-gated surface operations like the token
  store? This decides whether catalog changes are an operator act on the
  host or an admin act over the sealed surface].

### Key Entities

- **External access token**: the credential presented by the connecting
  client; issued by the tenant's identity provider for SoulIdentity's own
  application registration; carries issuer, audience, validity window,
  stable subject identifier, and application-role values. Never stored by
  SoulIdentity.
- **Role catalog entry**: an operator-declared mapping from one role value to
  the account it admits into and the signing authority that scopes its
  permissions. Contains no person, no ordering, no conditions.
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
  bad signature, non-allow-listed issuer, absent role claim, uncataloged
  role, ambiguous roles, signature-algorithm downgrade — eight of eight, each
  with a generic wire error and a specific audit reason.
- **SC-003**: Admission carries full attribution: for every admitted
  connection the audit log names issuer, stable subject, role, and client
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
- **SC-007**: The complete declared configuration for a two-account,
  two-role deployment contains zero per-user entries and zero
  ordering-sensitive rules.

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
- The app-role values follow the `soulstream.<role>` naming convention in the
  tenant; the catalog's exact match is the actual guard, the convention only
  reduces accidental collisions.
