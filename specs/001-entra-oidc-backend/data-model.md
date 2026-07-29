# Data Model: Entra ID as a Second Callout Credential Backend

Phase 1 of [plan.md](plan.md). Entities, fields, relationships, and the
validation/refusal state machine.

## Team (completed entity — the unit both lanes converge on)

The team is the vault's account-signing-key entry, now carrying its account
binding (research R1). No new store.

| Field | Type | Rules |
|---|---|---|
| `name` | string (vault key name) | IS the team name; IS the Entra app-role value, verbatim; unique in the vault |
| `kind` | `nats-account-signing-key` | existing |
| `secret` | seed (`SA…`) | sealed at rest; never returned (constitution I) |
| `public_key` | `A…` | the signing key's own public half (listed in the account JWT's signing keys) |
| `account` | `A…` (NEW) | the account identity the key signs for; **required at import** for this kind; immutable (keys are immutable — reimport under a new name) |

Relationships:
- `registry.Identity.Role` → names a Team (API-token lane; unchanged field,
  now understood as the team name).
- OIDC `roles` claim value → names a Team (Entra lane; no intermediate
  store).
- Team → account: 1:1 per entry (several teams may share an account).

Validation:
- Import with `kind=nats-account-signing-key` and missing/invalid `account`
  → refused at the op.
- Warn-level diagnostic (never a gate, constitution II): a registry identity
  whose `Account` differs from its Role team's `account` binding is logged;
  the server remains the verifier of record.

## External subject (transient — never stored)

| Field | Source claim | Rules |
|---|---|---|
| `subject` | `oid` | stable per tenant; keys the mint's user name and the audit line; user or service principal |
| `display` | `preferred_username` (delegated) / absent (app-only) | audit legibility only; never keyed |
| `team` | `roles` | exactly one value must name a declared team (zero → refuse; >1 declared matches → ambiguous, refuse; values naming no team are ignored) |
| `issuer` | `iss` | must equal the configured issuer exactly |
| `audience` | `aud` | must contain the configured audience |

## OIDC lane configuration (deployment state, not data)

| Item | Source | Rules |
|---|---|---|
| issuer | `--oidc-issuer` / `SOULIDENTITY_OIDC_ISSUER` | exact v2.0 tenant issuer URL; discovery at startup, fail-closed |
| audience | `--oidc-audience` / `SOULIDENTITY_OIDC_AUDIENCE` | the app registration's client ID |
| enablement | both present | either absent → lane disabled; `eyJ` credentials refuse early |

## Validation pipeline states (per callout request)

```
credential ──sit_──▶ API-token validate (digest) ──▶ authorize: registry row ──▶ mint (unchanged)
           ──eyJ───▶ OIDC validate (iss/aud/sig/exp via JWKS)
           │              │ pass: subject{oid, roles}
           │              ▼
           │         authorize: exactly one role names a declared team
           │              │ pass: (account, team key) from the Team entry
           │              ▼
           │         mint (unchanged): scoped user JWT, admin=false, no personas,
           │                           Name=oid, IssuerAccount=team.account, TTL-bounded
           └─other──▶ refuse
```

Refusal reasons (audit-only; wire stays generic — D20): `lane disabled`,
`issuer mismatch`, `audience mismatch`, `bad signature`, `expired`/`not yet
valid`, `jwks unavailable`, `unknown kid (after refetch)`, `alg not RS256`,
`no roles claim`, `no declared team`, `ambiguous teams`, `team key wrong
kind`, `team missing account binding`.

## Unchanged entities (asserted, not modified)

- **Token store record** `{account, user, label, expires?}` — untouched;
  adding any field fires D22's reversal condition.
- **Registry Identity** `{Account, User, Personas, Role, Admin}` — schema
  untouched (`Role` gains the team reading).
- **Issued connection credential** — same shape, custody, and TTL as the
  token lane; the mint stage is shared.
