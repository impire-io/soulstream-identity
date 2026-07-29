# Implementation Plan: Entra ID as a Second Callout Credential Backend

**Branch**: `001-entra-oidc-backend` | **Date**: 2026-07-29 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-entra-oidc-backend/spec.md`

## Summary

Add the Entra/OIDC lane deferred by D22 to the auth-callout issuer: an Entra
access token (delegated or app-only) validates against a pinned issuer,
audience, and JWKS via OIDC discovery; the token's app-role value IS the team
name and resolves directly against the teams SoulIdentity declares — no
catalog, no rule table, no per-user entries. The team object is completed by
binding each account signing key to its account at import (today the registry
row supplies the account; the OIDC lane has no row). The pipeline gains an
explicit `Validator` seam and an explicit authorize stage; mint is unchanged.
Everything fails closed; the API-token lane is untouched.

## Technical Context

**Language/Version**: Go 1.26 (module `github.com/impire-io/soulidentity`)
**Primary Dependencies**: `nats.go`, `nats-io/jwt/v2`, `nkeys`, embedded
`nats-server` (tests); NEW: `github.com/coreos/go-oidc/v3` (+ transitive
`golang.org/x/oauth2`) — see research.md R2
**Storage**: vault on NATS KV (xkey envelope); token store KV; registry JSON
file — no new stores; one new field on the vault's account-signing-key record
**Testing**: `go test ./...` via `make check`; NATS-free unit tests driving
`Issuer.respond`; operator-mode e2e with in-process `nats-server` + local
OIDC stub
**Target Platform**: the SoulIdentity service host (Linux/macOS)
**Project Type**: single Go service + public `client/` package
**Performance Goals**: callout decision adds one local JWT verification (no
network on the hot path after JWKS cache warm); JWKS fetch only at cold
start / unknown kid
**Constraints**: fail-closed in every degraded state; wire errors generic
(D20); no secrets returned (constitution I); revocation bound = token
lifetime + one callout TTL (accepted, stated in D24)
**Scale/Scope**: single-tenant issuer pin; two flags of new configuration;
no per-user state

## Constitution Check

*GATE: passed pre-Phase 0; re-checked post-Phase 1 — no violations.*

- **I. Custody without possession**: PASS — the lane stores no credential
  (the Entra token is validated, never persisted), returns no key material,
  and mints the same TTL-bounded scoped JWT as the token lane. Audit carries
  full attribution.
- **II. Server is verifier of record**: PASS — permissions stay in the
  team's scoped signing key, enforced by the server; SoulIdentity decides
  only which teams exist and that a validated subject named one. No parallel
  permission system; the registry↔key account-binding check stays a
  warn-level diagnostic.
- **III. Smallest viable**: PASS — no catalog, no rule table, no new store;
  one new record field (account binding on account signing keys), one
  `Validator` seam that D22 already names as the authn-backend seam, two
  flags. The new dependency (`go-oidc/v3`) is justified against the
  alternative: a hand-rolled JWKS cache in the admission path is exactly the
  new machinery constitution III refuses; the vetted library is the smaller
  audit surface (research.md R2).
- **IV. Documentation first-class**: PASS — D23/D24 land in
  `hq/02-DESIGN/auth-callout.md` in the same merge, with the revocation
  bound stated and the reversal watch restated; journey episode + ROADMAP in
  the same merge (tasks.md).
- **Working agreement**: the role==team decision was made by the maintainer
  after an adversarial pass (spec Clarifications, 2026-07-29); load-bearing
  claims in the design amendment carry evidence classes; only the e2e's
  measurements close the bars.

## Project Structure

### Documentation (this feature)

```text
specs/001-entra-oidc-backend/
├── plan.md              # This file
├── research.md          # Phase 0: decisions R1–R7
├── data-model.md        # Phase 1: Team, subject, lane config, refusal states
├── quickstart.md        # Phase 1: rig quickstart + real-tenant manual runbook
├── contracts/
│   └── entra-lane.md    # Phase 1: wire/config/audit contract deltas
└── tasks.md             # Phase 2 (/speckit-tasks — not created by /speckit-plan)
```

### Source Code (repository root)

```text
internal/
├── callout/
│   ├── issuer.go        # decide() gains validator dispatch (sit_ / eyJ)
│   ├── validator.go     # NEW: Validator seam; APITokenValidator; OIDCValidator
│   ├── tokens.go        # unchanged (API-token validate + Store)
│   └── issuer_test.go   # + OIDC unit rows (refusal matrix, rotation, dispatch)
├── mint/
│   └── mint.go          # authorize stage lifted out of ForKey; ForTeam sibling
├── vault/
│   └── vault.go         # stored/Entry gain Account on nats-account-signing-key
├── service/
│   └── service.go       # keys.import op carries account for signing keys
└── oidcstub/            # NEW: test-only local OIDC issuer (discovery+JWKS+RS256)

client/
├── client.go            # ImportKey gains account (wire mirror, changed together)
└── callout_e2e_test.go  # + e2e sibling: TestEntraGateAgainstOperatorModeServer

cmd/soulidentity/
└── main.go              # cmdServe: --oidc-issuer / --oidc-audience (+ env)

hq/
├── 02-DESIGN/auth-callout.md   # D23 (validator seam + dispatch), D24 (role==team)
├── 03-IMPLEMENTATION/ROADMAP.md
└── 04-JOURNEY/                  # episode 0012 (same merge)
```

**Structure Decision**: existing single-service layout; the only new
packages are `internal/callout/validator.go` (a file, not a package) and the
test-only `internal/oidcstub`.

## Complexity Tracking

No constitution violations to justify. The single new dependency is argued
under Constitution Check III and research.md R2.
