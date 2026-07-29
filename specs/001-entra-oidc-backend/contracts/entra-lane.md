# Contracts: Entra ID lane — every externally visible delta

Phase 1 of [../plan.md](../plan.md). Everything outside-observable that this
feature adds or changes. The agent's JSON wire surface is mirrored in
`client/` — wire and mirror change in the same commit (project rule; ROADMAP
one-way door "Wire contract").

## 1. Connect contract (the callout lane)

An external client connects with the existing sentinel creds file plus a
token in the NATS connect options (unchanged mechanics, D19):

| Token shape | Lane | Behavior |
|---|---|---|
| `sit_…` | API token | digest lookup → registry row → mint (unchanged) |
| `eyJ…` (JWT) | Entra/OIDC | iss/aud/sig/exp validated via JWKS; `roles` value must name exactly one declared team → mint |
| anything else | — | refused |

Wire-visible errors remain generic (`credential rejected` /
`identity not authorized`); reasons are audit-only (D20).

## 2. `keys.import` op (wire) and `client.ImportKey` (mirror)

Request gains one field:

```json
{ "name": "engineering", "kind": "nats-account-signing-key",
  "secret": "SA…", "account": "A…" }
```

- `account` (account identity public key) is **required** when
  `kind = nats-account-signing-key`; refused otherwise absent/invalid.
- Ignored (refused as unknown? no — refused invalid) for other kinds:
  supplying `account` for a non-account-signing-key kind is an error.
- `client.ImportKey(name, kind, secret string)` becomes
  `ImportKey(name, kind, secret, account string)` (breaking pre-release
  change; no tagged release exists). `keys.list` / `client.Keys()` entries
  gain the read-only `account` field.

## 3. Deployment configuration (cmdServe)

| Flag | Env | Meaning |
|---|---|---|
| `--oidc-issuer` | `SOULIDENTITY_OIDC_ISSUER` | exact v2.0 tenant issuer URL (allow-list of one) |
| `--oidc-audience` | `SOULIDENTITY_OIDC_AUDIENCE` | the app registration's client ID |

Both present → lane enabled (discovery at startup, fail-closed). Either
absent → `eyJ` credentials refuse early. No other new configuration; teams
are vault state.

## 4. Audit log contract (attribution)

Admission (Entra lane) — one line, fields fixed:

```
callout ADMITTED lane=oidc issuer=<iss> subject=<oid> team=<team>
  display=<preferred_username|-> client_host=<host> user_nkey=<key> ttl=<ttl>
```

Refusal: `callout REFUSED lane=oidc reason=<specific> …` with the same
attribution fields where known. The API-token lane's existing lines are
unchanged (regression-checked by the M4 e2e).

## 5. Explicitly unchanged

- Token store record schema and `tokens.*` / `sentinel.mint` ops.
- Registry file shape (strict-decoded; no new fields).
- The sealed-surface request/reply contract and subject space (D14/D15).
- The mint stage: scoped, permission-less user claims; TTL-bounded;
  `admin=false`, no personas on the claims path.
