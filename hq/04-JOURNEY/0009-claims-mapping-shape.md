# Episode 0009 — The claims-mapping shape: one pipeline, policy never in the credential store (2026-07-28)

The last shape-gate on M4, opened the same day the operator scoped it —
**API tokens first, Entra later** — and graduated to design (D22 in
[`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md)) with all
three pre-registered bars passed. The question: what declared configuration
maps a validated external credential to a registry identity, such that the
API-token backend and a claims-bearing issuer are one shape with different
validators?

**The shape (Bar 1):** `validate(credential) → subject (+claims)` then
`authorize(subject, claims) → (account, user, role, personas, admin)` then
the existing mint (D20). The API-token record's whole schema is
`{account, user, label, expires?}` — it names an identity and nothing
else; authorization is entirely the registry row, and a token mapping to
no row is refused. Entra arrives later as validator configuration (issuer
allow-list, JWKS, audience, subject claim) plus the claims-derived team
rules D2 already names — feeding the same `authorize`, whose interface
does not change [mechanism-argument]. The credential store and the policy
store are different stores with different custody rules (digests vs
registry rows), meeting only in `authorize`.

**The token backend, measured (Bar 2):** on the journey-0008 callout rig, a
high-entropy `sit_…` token stored only as a SHA-256 digest key admitted
its holder as a scoped user; an unknown token was refused at connect; the
raw JetStream store held the digest (the positive control proving the
method) and never the plaintext [measured]. Unsalted SHA-256 is honest
*only* because the tokens are generated 256-bit — recorded explicitly as
not a password scheme; low-entropy secrets would need a KDF
[mechanism-argument].

**Revocation, measured honestly (Bar 3):** deleting the record refuses the
next connection attempt — but the already-open connection survives, and
what ends it is the issued JWT's expiry: the server disconnects at TTL
(`authentication expired`), the client's reconnect re-fires callout, and
the revoked token is refused (`authorization violation`) [measured]. **The
issued-JWT TTL is the revocation propagation bound, enforced by the
protocol itself** — M4 must choose the TTL deliberately, and its honest
price is one callout round-trip per TTL per open connection.

Nothing was refuted; the topic's registered reversal stays armed rather
than resolved, by design.

Reversal condition: (inherited from D12's watch, now D22's) any policy
field — permission, persona, role — proposed for the token record schema,
or later a claim rule overriding a registry column per user, is the
observable that demotes claims-derived authorization and returns the
registry to sole-source.

Trail: [`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md)
(D22); `hq/01-RESEARCH/claims-mapping-shape/` in git history
(pre-registration af5b2b0 → investigation f579470 → removed at
graduation); spike in the session scratchpad, its shape recorded in the
topic JOURNEY.
