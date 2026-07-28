# SoulIdentity — auth callout, the front door (M4)

*The design M4 implements: SoulIdentity as the NATS auth-callout issuer —
the second lane of the connection ladder (D12), representing external
identities inside NATS. Decisions here continue the numbering: D19–D21,
grounded in the sentinel-credential research
([journey 0008](../04-JOURNEY/0008-sentinel-credential-flow.md)) [measured
where tagged]. **This document is deliberately incomplete**: the
claims-mapping shape (which token issuers are trusted, which claim names
the team, how a team maps to role and personas — D2's declared
configuration) is its own gated research topic and lands here when it
concludes. The milestone and gate live in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md).*

## D19 — The connection contract: URL plus credential, sentinel underneath

What an external-identity client holds is exactly two things: the server
URL and its external credential. The preferred deployment sets
`default_sentinel` in the server config — a client presenting no NATS
credential is assigned the sentinel by the server itself, so the client
connects with the bare token option [measured]. Deployments that cannot set
it distribute an explicit **sentinel creds file**: a bearer (`BearerToken:
true`), deny-all user JWT in the AUTH account, packaged with its own seed
because the nats.go client requires the halves to match — both halves
public by design, since a bearer JWT's nonce signature authenticates
nothing (admitted with an unrelated key's signature [measured]) and
deny-all makes it a dead credential should callout ever be disabled.
Sentinel distribution therefore needs no custody story; the external
credential is the only secret the client carries.

**Reversal condition** (from the graduation): a consumer client class that
cannot set the token connect option alongside credentials (observable: a
consumer blocked at connection, recorded as an issue) re-opens the carrier
map for that class.

## D20 — The issuer is the mint with a callout trigger

SoulIdentity's callout issuer is not new machinery (constitution III): it
validates the presented credential against its authn backend, resolves the
identity to a role and personas (registry-declared or claims-derived — D2;
the mapping shape is the pending research), and then does what mint already
does — signs a scoped user JWT with the role's account signing key from the
vault (D5). Three protocol facts shape the implementation [measured]:

- The user JWT is issued **for the server-assigned ephemeral user key**
  carried in the authorization request (`user_nkey`) — the client never
  owns a key in this lane. (This corrected D12's original wording.)
- The response is an `AuthorizationResponse` JWT, audience = the requesting
  server's ID, signed by the **AUTH account key** — so the AUTH account
  seed lives in the vault alongside the role keys, under the same custody
  rules.
- **Fail-closed comes free**: no issuer response or an error response means
  no admission — an invalid token draws an authorization violation at
  connect, and an absent issuer refuses even valid credentials [measured].
  The design must never add an admit-on-timeout convenience.

Attribution: the external identity is written into the issued JWT's name
and the issuer's audit log, alongside the client host — the M4 gate's
attributability requirement is met by construction [measured].

## D21 — The AUTH account topology

A dedicated AUTH account owns the callout duty: its account JWT sets
`authorization.auth_users` (the issuer's own connection — the bypass lane
inside the callout lane, D12), `authorization.allowed_accounts` (the
target accounts the issuer may place users into — listed explicitly, never
`*`), and `authorization.xkey` (the callout xkey, so authorization
requests are sealed to the issuer — the same curve-key machinery as
D16/D17, deployment-supplied like the other seeds)
[mechanism-argument; the xkey leg is unspiked and is proven in the M4
gate]. The sentinel user lives in this account; issued users land in the
target accounts. SoulIdentity thus holds for M4: the AUTH account seed,
the callout xkey seed, and the role keys it already had — no new key
class, one new account.

## Not yet decided (pending research)

- **The claims-mapping shape** — the declared rules from validated token
  claims to (identity, role, personas). Gates the build; its research
  registers its own bars.
- **NGS**: whether a Synadia-managed server exposes callout configuration
  at all (`ngs-capabilities`) — the open half of D11's reversal condition.
