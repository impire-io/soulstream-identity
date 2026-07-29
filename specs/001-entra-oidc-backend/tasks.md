# Tasks: Entra ID as a Second Callout Credential Backend

**Input**: Design documents from `/specs/001-entra-oidc-backend/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md,
contracts/entra-lane.md, quickstart.md

**Tests**: explicitly requested by the spec (FR-012) — unit tests mirroring
`internal/callout/issuer_test.go` and an e2e sibling of the M4 gate proof.
Tests are NOT optional in this project (constitution, quality gates).

**Organization**: by user story; the vault/mint/validator groundwork is
foundational (every story needs it). Commit discipline: signed commits;
`make check` green before each; wire contract and `client/` mirror change in
the same commit.

## Phase 1: Setup

- [X] T001 Add `github.com/coreos/go-oidc/v3` dependency (`go get`, tidy) in
      go.mod / go.sum (research R2)
- [X] T002 [P] Create test-only local OIDC issuer package in
      internal/oidcstub/oidcstub.go: httptest server serving
      `/.well-known/openid-configuration` + JWKS; RS256 signing with
      Entra-v2.0-shaped claims (iss, aud, oid, tid, roles, ver, iat/nbf/exp);
      key rotation (new kid), a never-published keypair, stop/start
      (research R5, quickstart Part 1)

## Phase 2: Foundational (blocking all user stories)

- [X] T003 Extend vault account-signing-key record with required `Account`
      binding: `stored`/`Entry` gain the field, `Import` gains the account
      parameter with validation (required + valid `A…` for
      KindNATSAccountSigningKey, refused for other kinds) in
      internal/vault/vault.go; update internal/vault/vault_test.go
      (data-model Team; research R1)
- [X] T004 Carry `account` through the `keys.import` wire op (required for
      account signing keys; refusal rules per contracts/entra-lane.md §2) in
      internal/service/service.go; update internal/service/service_test.go
- [X] T005 Mirror the wire change in the public client: `ImportKey` gains
      the account parameter; `Key` entries expose the read-only account
      field in client/client.go (same-commit rule with T004)
- [X] T006 Lift the authorize stage out of `ForKey` in internal/mint/mint.go:
      keep the registry path (`roleKey`) intact; add `ForTeam(v, team,
      subject, userPub, ttl)` resolving the team entry (kind + account
      binding checks, refusal reasons per data-model) and minting with
      Name=subject, IssuerAccount=team account; update
      internal/mint/mint_test.go
- [X] T007 Introduce the Validator seam in internal/callout/validator.go
      (D22's authn-backend seam): `Validator` interface, `APITokenValidator`
      wrapping the existing `Store` + `Validate`, and shape dispatch in
      `Issuer.decide` (`sit_` → API token, `eyJ` → OIDC-if-configured else
      refuse, other → refuse) in internal/callout/issuer.go — API-token lane
      behavior byte-identical; existing internal/callout/issuer_test.go must
      pass unchanged (research R4)

**Checkpoint**: `make check` green; M3/M4 e2e proofs pass with the account
binding added to their provisioning.

## Phase 3: User Story 1 — Corporate identity connects without pre-provisioning (P1) 🎯 MVP

**Goal**: a stub-issued token whose role names one declared team admits
through the sealed callout leg with server-enforced scope and full audit
attribution; no per-person record anywhere.

**Independent Test**: spec US1 acceptance scenarios 1–3 on the rig.

- [X] T008 [US1] Implement `OIDCValidator` in internal/callout/validator.go:
      go-oidc provider/verifier (exact issuer, audience, RS256 pin),
      fail-closed construction and verification, claims extraction (oid,
      roles, preferred_username, tid) per data-model External subject
- [X] T009 [US1] Wire the OIDC path in `Issuer.decide` in
      internal/callout/issuer.go: exactly-one-declared-team rule (zero →
      refuse, >1 declared matches → ambiguous; undeclared values ignored),
      `mint.ForTeam`, `admin=false`/no-personas invariant, audit line
      `callout ADMITTED lane=oidc issuer=… subject=… team=… display=…`
      per contracts §4
- [X] T010 [US1] Add lane configuration to `cmdServe` in
      cmd/soulidentity/main.go: `--oidc-issuer`/`SOULIDENTITY_OIDC_ISSUER`,
      `--oidc-audience`/`SOULIDENTITY_OIDC_AUDIENCE`; both present → lane
      constructed at startup (discovery fail-closed), else disabled
      (research R7, contracts §3)
- [X] T011 [P] [US1] Unit tests in internal/callout/issuer_test.go: stub-token
      admission with scoped/bounded claims, attribution fields asserted,
      sealed round-trip on the OIDC path (mirrors the existing harness)
- [X] T012 [US1] E2E `TestEntraGateAgainstOperatorModeServer` in
      client/callout_e2e_test.go: operator-mode rig + oidcstub; bar 1 —
      admission through the sealed leg, in-scope round-trip, out-of-scope
      denied by the server, audit attribution (issuer, oid, team, host);
      SC-001 asserted (zero per-person provisioning acts)

**Checkpoint**: US1 independently demonstrable — the MVP.

## Phase 4: User Story 2 — Operator declares the team; tenant decides membership (P2)

**Goal**: the declared-team guard proven — refusal matrix, key
infrastructure, and legibility of the declared state.

**Independent Test**: spec US2 acceptance scenarios + SC-002/004/007.

- [X] T013 [P] [US2] Unit refusal matrix in internal/callout/issuer_test.go:
      wrong audience / expired / signature by never-published key /
      non-allow-listed issuer / roles absent / role naming no declared team /
      two declared teams (ambiguous) / alg HS256-and-none — 8/8 refused,
      generic wire error, specific audit reason (SC-002)
- [X] T014 [P] [US2] Unit key-infrastructure rows in
      internal/callout/issuer_test.go: JWKS endpoint stopped → refusal;
      unknown kid → refusal; stub key rotation → new-key token admits
      without process restart (SC-004; research R2's refetch claim measured
      here)
- [X] T015 [US2] E2E rows in client/callout_e2e_test.go: undeclared-team and
      ambiguous refusals at connect with audit reasons; assert the complete
      declared state of the two-account/two-team rig contains zero per-user
      entries and no mapping store (SC-007)

## Phase 5: User Story 3 — Access ends when the directory says so (P2)

**Goal**: the accepted revocation bound demonstrated with real timings.

**Independent Test**: spec US3 acceptance scenarios + SC-005.

- [X] T016 [US3] E2E revocation-bound proof in client/callout_e2e_test.go:
      short `--callout-ttl`; admitted OIDC connection disconnected at TTL;
      reconnect with a fresh role-stripped stub token refused; reconnect
      with the still-valid original token re-admitted until expiry — the
      bound (token lifetime + one TTL) observed and asserted (SC-005)

## Phase 6: User Story 4 — Existing API-token clients untouched (P3)

**Goal**: coexistence and early refusal proven; zero regression.

**Independent Test**: spec US4 acceptance scenarios + SC-006.

- [X] T017 [US4] E2E coexistence rows in client/callout_e2e_test.go: with
      the OIDC lane configured, a `sit_` client admits via digest lookup
      exactly as before (existing `TestM4GateAgainstOperatorModeServer`
      stays green unchanged — SC-006); with the lane unconfigured, an `eyJ`
      credential refuses early with no token-store lookup attempted
      (bar 5)

## Phase 7: Polish & the hq landing duties (same merge)

- [X] T018 Design amendment in hq/02-DESIGN/auth-callout.md: D23 (the
      Validator seam + shape dispatch, fail-closed lane enablement), D24
      (role == team — the team object completed by the account binding;
      admin/personas never from claims; the revocation bound stated
      honestly; evidence classes on load-bearing claims; reversal watch
      restated: any per-user/per-subject entry in claims-path configuration,
      or admin/personas from any claim, demotes claims-derived authorization
      and returns the registry to sole policy source); D22's rule-table
      sketch marked superseded
- [X] T019 [P] Update hq/03-IMPLEMENTATION/ROADMAP.md (the Entra lane
      landed — where it sits relative to M2; open questions pruned) and
      hq/04-JOURNEY/README.md Where-things-stand
- [X] T020 Journey episode hq/04-JOURNEY/0012-entra-role-claim-lane.md per
      TEMPLATE.md (what happened, honest numbers from the e2e, evidence
      tags, Reversal condition line); index updated; `internal/hqlint`
      green
- [X] T021 Graduate the quickstart runbook substance to its durable home per
      plan.md (design/implementation docs), leave a pointer in
      specs/001-entra-oidc-backend/quickstart.md; final full `make check` +
      fresh-clone build sanity

## Dependencies

- Phase 1 → Phase 2 → Phase 3 (US1) → Phases 4/5/6 (US2/US3/US4 need US1's
  validator; their test additions are mutually independent) → Phase 7.
- T004+T005 land in one commit (wire + mirror rule). T002 ∥ T001; T003–T007
  sequential (same files chain); T011 ∥ T013/T014 once US1 code exists.

## Parallel Example

After T010: T011 (unit, internal/callout) ∥ T012 (e2e, client/) — different
packages; then T013 ∥ T014 (same file, keep sequential if editing
issuer_test.go concurrently is impractical — prefer sequential in one
sitting).

## Implementation Strategy

MVP = Phase 1–3 (US1): the lane admits, sealed, attributed — demonstrable
alone. Phases 4–6 add the refusal/rotation/revocation/coexistence proofs in
priority order; Phase 7 is the constitutionally required same-merge landing
(docs + journey + roadmap). Each phase ends `make check` green; nothing is
"done" before the gate.
