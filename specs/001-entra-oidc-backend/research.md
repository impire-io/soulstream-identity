# Research: Entra ID as a Second Callout Credential Backend

Phase 0 of [plan.md](plan.md). Each decision records rationale and the
alternatives considered; evidence classes per the working agreement — a
`[judgment]` or `[mechanism-argument]` here is confirmed or refuted by the
implement phase's measurements, which alone close the bars.

## R1 — The team's account binding lives on the vault key record

**Decision**: extend the vault's account-signing-key record (`stored` and
`Entry` in `internal/vault/vault.go`) with an `Account` field — the account
identity public key (`A…`) the signing key signs for — required at import
for `KindNATSAccountSigningKey`. The team object is then complete in one
place: team name = key name; the entry carries the signing seed, its public
half, and its account. `keys.import` (service.go:283) and `client.ImportKey`
(client.go:219) gain the field together (the wire contract and `client/`
mirror change in the same commit, per project rule).

**Rationale**: with role == team and no catalog, resolution must yield
(account, signing key) from the team name alone. The account a signing key
signs for is a fact about the key (its public half is listed in that
account's JWT), not policy — recording it at import is declaration, not a
mapping store. Mint's `IssuerAccount` needs exactly this value
`[mechanism-argument]`.

**Migration**: none needed — no release is tagged, no external consumer
exists (M2 not landed); the field is required going forward and both e2e
proofs provision fresh vaults per run. Existing dev vaults re-import.

**Alternatives considered**:
- *Teams section in the registry file* — a team → {account, key} mapping
  store; rejected: that is the catalog by another name, which the
  maintainer explicitly rejected (spec Clarifications).
- *Key-name convention* (`<account>/<team>`) — rejected: role values would
  need transformation to match (a hidden mapping), and account pubkeys leak
  into team names.
- *Derive from the account JWT* — rejected: requires operator-store access
  SoulIdentity doesn't have (D3: the server is the verifier).

## R2 — OIDC library: `github.com/coreos/go-oidc/v3`

**Decision**: validate Entra tokens with `go-oidc/v3` (`oidc.NewProvider`
for discovery, `oidc.NewRemoteKeySet`/verifier with
`SupportedSigningAlgs: ["RS256"]`, audience and issuer checks on).

**Rationale**: it is exactly the D22 sentence — discovery, JWKS, iss/aud/exp
verification — with refetch-on-unknown-kid built in (key rotation without
restart, spec SC-004) and fail-closed by construction (fetch error → verify
error → refusal) `[mechanism-argument]`. Transitive weight is one package
(`golang.org/x/oauth2`). A hand-rolled JWKS cache in the admission path is
new security machinery of exactly the kind constitution III refuses.

**Alternatives considered**:
- *`lestrrat-go/jwx/v3`* — more knobs (e.g. `jwt.WithAcceptableSkew`),
  larger API surface; recorded as the fallback if go-oidc's strictness
  bites in practice (it has no clock-skew leeway knob — see R6).
- *`golang-jwt/jwt/v5` + hand-rolled JWKS* — smallest dependency, largest
  owned security surface; rejected (constitution III).

## R3 — Entra token facts the implementation builds against

To be verified against a real tenant via the quickstart runbook; the stub
imitates these shapes `[mechanism-argument]` until then:

- **Access tokens, not ID tokens**: the credential must be an access token
  issued *for SoulIdentity's own app registration* (v2.0 `aud` = the app's
  client ID). ID tokens are audienced to the requesting client; accepting
  them would admit tokens minted for any app the user signed into.
- **v2.0 format required**: the app manifest sets
  `requestedAccessTokenVersion: 2`; v1.0 access tokens carry
  `iss=https://sts.windows.net/{tid}/`, which does not match v2.0 discovery
  (`https://login.microsoftonline.com/{tid}/v2.0`). Single-tenant issuer
  pin; `/common` metadata is out of scope.
- **`roles` claim**: emitted when the app registration defines `appRoles`
  and the subject holds an assignment — for delegated tokens (user/group
  assignment) and app-only tokens (service-principal assignment) alike.
  Value = the appRole's `value` field verbatim; array of strings; no
  group-overage indirection applies to `roles` (that mechanism belongs to
  the `groups` claim).
- **Subject**: `oid` — per-tenant stable object ID (GUID; NATS-subject-token
  safe) for users and service principals both. `sub` is pairwise per app;
  `preferred_username` is mutable and non-authoritative — logged, never
  keyed (spec FR-007).
- **Key rollover**: Entra signing keys rotate on an unannounced cadence;
  refresh-on-unknown-kid is mandatory, restart-to-pick-up-keys is
  disqualifying (spec SC-004).
- **Lifetime**: access tokens live 60–90 minutes (deliberately varied);
  with `--callout-ttl` 15m this yields the accepted revocation bound —
  lifetime + one TTL (spec FR-014).
- **"Assignment required"** on the enterprise application refuses unassigned
  subjects at the tenant before a token exists — defense in depth; the
  declared-team match remains the enforced guard.

## R4 — Dispatch: credential shape selects the validator

**Decision**: in `Issuer.decide`, dispatch on `ConnectOptions.Token`:
`sit_` prefix → API-token validator (existing behavior, untouched); `eyJ`
prefix → OIDC validator if the lane is configured, refusal if not; anything
else → refused. Wire errors stay generic ("credential rejected"); the
specific reason goes to the audit log only (D20).

**Rationale**: the two credential families are self-describing by prefix;
no configuration or probing order is involved, so no precedence exists to
reason about (spec FR-005) `[mechanism-argument]`. The `eyJ` check is a
distinct layer from `respond`'s sealed-payload detection (issuer.go:36) —
that one inspects the callout request envelope, this one the client's
presented token.

## R5 — The OIDC stub is a test-only package `internal/oidcstub`

**Decision**: a small stdlib-only package serving
`/.well-known/openid-configuration` and a JWKS endpoint over
`httptest.Server`, signing RS256 tokens with Entra-v2.0-shaped claims
(`iss`, `aud`, `oid`, `tid`, `roles`, `ver`, `iat`/`nbf`/`exp`); supports
key rotation (new `kid`), a never-published key (bad-signature rows), and
stop/start (unreachable-JWKS rows). Used by both `internal/callout` unit
tests and the `client` e2e.

**Rationale**: both test suites need the same issuer behavior; duplicating
~200 lines of crypto fixture in two `_test.go` files is worse than one
shared test-support package `[judgment]`. No production code imports it
(enforced by review; it serves tests only).

## R6 — Clock skew: no leeway configuration

**Decision**: rely on go-oidc's exact `exp`/`nbf` handling; do not add a
skew knob.

**Rationale**: the service host runs NTP-disciplined clocks in every
deployment class named so far; a skew knob is speculative configuration
(constitution III). Risk recorded: real Entra `iat`/`nbf` skew is a known
phenomenon on badly-synced hosts; if the runbook shows refusals from skew,
the recorded fallback is jwx (R2) or a documented host-clock requirement —
decided then, with the observed numbers `[judgment]`.

## R7 — Lane configuration: two flags, env fallbacks, presence enables

**Decision**: `--oidc-issuer` / `SOULIDENTITY_OIDC_ISSUER` and
`--oidc-audience` / `SOULIDENTITY_OIDC_AUDIENCE` on `cmdServe`, following
the existing callout flag conventions (main.go:265–292). Both set → lane
enabled at startup (discovery runs once, fail-closed on error); either
absent → lane disabled and `eyJ` credentials refuse early. Teams need no
configuration — they are vault state (R1).

**Rationale**: mirrors how the callout itself is presence-enabled
(`--callout-creds`/`--callout-context`); no new config file; the smallest
surface that satisfies FR-002/FR-009 `[judgment]`.
