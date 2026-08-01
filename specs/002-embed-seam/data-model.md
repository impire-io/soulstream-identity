# Data Model — 002-embed-seam

No stored data changes. The feature's only entities are the public options
value and the running assembly's lifecycle.

## Options (the assembly description, value-only)

| Field | Type | Required | Default | Semantics |
|---|---|---|---|---|
| `Conn` | `*nats.Conn` | yes | — | The service's connection (the service account). Owned by the caller; never closed or drained by the package. |
| `CalloutConn` | `*nats.Conn` | no | nil | The AUTH-account connection. Presence enables the callout issuer and the token/sentinel ops (mirrors the daemon's rule). |
| `VaultBucket` | `string` | no | `SOULIDENTITY_VAULT` | KV bucket holding the sealed vault. |
| `TokenBucket` | `string` | no | `SOULIDENTITY_TOKENS` | KV bucket holding API-token digests (callout only). |
| `FirstKey` | `string` | yes | — | `SX…` seed sealing the vault (D13: deployment-supplied). |
| `SurfaceKey` | `string` | yes | — | `SX…` seed sealing the request/reply surface. |
| `CalloutKey` | `string` | no | "" | `SX…` seed for sealed callout requests; optional as in the daemon. |
| `AuthKeyName` | `string` | no | `auth/issuer` | Vault name of the AUTH signing key. |
| `AuthAccount` | `string` | callout | — | AUTH account public key (`A…`); required when `CalloutConn` is set. |
| `CalloutTTL` | `time.Duration` | no | `15m` | Issued-JWT lifetime — the revocation propagation bound (D22). |
| `Prefix` | `string` | no | "" | Shared ecosystem subject prefix (D14); validated as the daemon validates it. |
| `OIDCIssuer` | `string` | no | "" | OIDC issuer URL (D23); both-or-neither with audience. |
| `OIDCAudience` | `string` | no | "" | OIDC audience; both-or-neither with issuer. |
| `Logger` | `*slog.Logger` | no | text handler on stderr | The audit/serving log destination. |

**Validation rules (construction-time, before anything serves):**

1. `Conn` non-nil; `FirstKey` and `SurfaceKey` non-empty.
2. Prefix passes the daemon's existing validation.
3. Callout both-halves: `CalloutConn` set ⇒ `AuthAccount` required;
   callout-only fields (`TokenBucket` consumed, `CalloutTTL`,
   `CalloutKey`, OIDC pair) without `CalloutConn` ⇒ refused, never a
   silently disabled issuer.
4. OIDC both-or-neither: exactly one of issuer/audience ⇒ refused.
5. Vault verification (never double-seal): a wrong `FirstKey` fails fast
   before any subscription exists.

## Lifecycle (the running assembly)

```
Options ──validate──▶ constructed ──Start──▶ serving ──ctx.Done──▶ draining ──▶ returned
              │                        │
              └─ error (nothing        └─ start error: whatever started
                 started, nothing         is drained before Run returns
                 to undo)                 the error
```

- **serving**: vault verified, KV buckets ensured, service surface
  subscribed; with callout — token store bound, issuer subscribed,
  "callout issuer serving" + "service serving" logged.
- **draining**: service and issuer subscriptions drained; the caller's
  connections untouched (R2).
