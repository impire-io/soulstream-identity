# claims-mapping-shape — investigation journey

Topic opened 2026-07-28 (operator scoping: API tokens first, Entra later).
Entries append below as the investigation happens.

## 2026-07-28 — Bar 1: the shape, written before the spike

The pipeline is three declared stages; the middle one is where both
backends meet:

```
validate(credential)        → external subject (+ claims, possibly empty)
authorize(subject, claims)  → (account, user, role, personas, admin)
mint                        → scoped user JWT via the role key (D5/D20)
```

- **API-token validator** (first backend): SHA-256 digest lookup in the
  token store. The record's whole schema: `{account, user, label,
  expires?}` — it *names* an identity and nothing else. Claims are empty;
  `authorize` is exactly a registry-row lookup (the registry-declared
  source of D2) and refuses when no row exists. Policy never enters the
  token store — that is the bar-1 boundary and D12's watched line.
- **Entra/OIDC validator** (later): issuer allow-list + JWKS signature +
  audience check; the subject comes from a configured claim. `authorize`
  is unchanged as an interface: it first tries the registry row (declared
  wins), then falls back to the declared team rules — `(issuer,
  team-claim value) → {account, role, personas}` — which is the
  claims-derived source D2 already names. Only configuration grows; the
  resolve side's interface does not [mechanism-argument].
- **Hashing, not sealing**: the verifier needs comparison, not recovery,
  so the store holds digests. Unsalted SHA-256 is honest **only because
  the tokens are generated high-entropy (256-bit)** — a dictionary attack
  has nothing to enumerate; this is explicitly not a password scheme, and
  low-entropy secrets would need a KDF. Issuance shows the plaintext once
  and never stores it [mechanism-argument].

## 2026-07-28 — Bars 2 and 3: the token backend measured on the callout rig

Spike (`scratchpad/tokenspike/`): the journey-0008 rig (operator mode,
`default_sentinel`, AUTH + APP) plus a `SOULIDENTITY_TOKENS` KV bucket on
the AUTH account and a registry stand-in holding policy. All [measured]:

- A high-entropy `sit_…` token, stored as digest-keyed record, admits its
  holder as a scoped user in APP; round-trip in scope. An unknown token is
  refused at connect.
- **Plaintext absence with a positive control**: the digest is findable in
  the raw JetStream store (method proven able to see content); the
  plaintext token is not.
- **Revocation**: deleting the record refuses the next connection attempt.
  The already-open connection *survives* revocation — recorded honestly —
  and the issued JWT's expiry is what bounds it: at TTL the server closed
  the connection (`authentication expired`), nats.go auto-reconnected,
  callout re-fired with the revoked token and was refused
  (`authorization violation`), and the connection ended. **The issued-JWT
  TTL is therefore the revocation propagation bound, enforced by the
  protocol itself** — M4 must set a deliberate TTL, and short TTLs cost
  one callout round-trip per TTL per connection, which is the knob's
  honest price.

## 2026-07-28 — what this settles

The credential store and the policy store are different stores with
different custody rules (digests vs registry rows), meeting only in
`authorize`. The Entra arrival is new validator config plus the
already-designed claims-derived rules — no new machinery. The reversal
condition's smell test stays live: any policy field proposed for the token
record schema is the observable that fires it.
