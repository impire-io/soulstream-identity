# SoulIdentity — auth callout, the front door (M4)

*The design M4 implements: SoulIdentity as the NATS auth-callout issuer —
the second lane of the connection ladder (D12), representing external
identities inside NATS. Decisions here continue the numbering: D19–D22,
grounded in the sentinel-credential and claims-mapping research
([journey 0008](../04-JOURNEY/0008-sentinel-credential-flow.md),
[journey 0009](../04-JOURNEY/0009-claims-mapping-shape.md)) [measured
where tagged]. The first authn backend is API tokens; Entra/OIDC follows
as configuration on the same shape (D22). The milestone and gate live in
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

*As built (M4, journey 0010):* operators mint the sentinel through the
admin-gated `sentinel.mint` op — the AUTH signing key never leaves the
vault to do it. One protocol fact the build measured: a sentinel signed by
a *signing key* of AUTH must carry `issuer_account` naming the AUTH
account, or the server refuses the connection before callout ever fires —
which is why the service configuration carries the AUTH account public key.

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
attributability requirement is met by construction [measured]. Wire-facing
refusal messages are deliberately generic ("credential rejected") — the
reasons live only in the audit log, so a probing client learns nothing
about which tokens exist.

## D21 — The AUTH account topology

A dedicated AUTH account owns the callout duty: its account JWT sets
`authorization.auth_users` (the issuer's own connection — the bypass lane
inside the callout lane, D12), `authorization.allowed_accounts` (the
target accounts the issuer may place users into — listed explicitly, never
`*`), and `authorization.xkey` (the callout xkey, so authorization
requests are sealed to the issuer — the same curve-key machinery as
D16/D17, deployment-supplied like the other seeds)
[measured in the M4 gate: the e2e runs with `authorization.xkey` set, the
request arrives sealed with the server's public curve key in the
`Nats-Server-Xkey` header, and the response is sealed back]. The sentinel
user lives in this account; issued users land in the target accounts.

*As built (M4, journey 0010):* the service holds **two connections** — the
sealed surface on its own account, the issuer subscription on the AUTH
account (`--callout-creds`/`--callout-context`; its presence enables the
issuer and the token/sentinel ops). SoulIdentity holds an AUTH **signing
key** in the vault (not the master; `--auth-key` names it, and
`--auth-account` carries the account public key the sentinel declares),
the optional callout xkey seed (`SOULIDENTITY_CALLOUT_KEY`), the token
bucket beside the vault bucket on the service's own account, and the role
keys it already had — no new key class, one new account.

## D22 — The mapping shape: validate, authorize, mint — policy never in the credential store

*Decided 2026-07-28 by research graduation (`claims-mapping-shape`, journey
0009; operator scoping: API tokens first, Entra later.)* The issuer runs
one declared pipeline:

1. **validate(credential) → subject (+claims).** The API-token validator
   is a SHA-256 digest lookup in the token store — a KV bucket whose
   record schema is, in full: `{account, user, label, expires?}`. The
   record *names* an identity and carries nothing else; the store holds
   digests, never plaintext (shown once at issuance) [measured]. Unsalted
   SHA-256 is honest only because tokens are generated high-entropy
   (256-bit); this is explicitly not a password scheme. The later
   Entra/OIDC validator is configuration: issuer allow-list, JWKS,
   audience, and the claim that names the subject.
2. **authorize(subject, claims) → (account, user, role, personas,
   admin).** For API tokens this is exactly the registry row (the
   registry-declared source, D2); a token mapping to no row is refused
   [measured]. Entra adds the claims-derived source D2 already names —
   declared team rules `(issuer, team-claim value) → {account, role,
   personas}` — as a fallback behind the registry row, feeding the same
   stage; the interface does not change.
3. **mint** — the existing D20 path, unchanged.

The credential store and the policy store are different stores with
different custody rules, meeting only in `authorize`. Two operational
facts, measured: **revocation** (deleting the token record) refuses the
next connection attempt, and the **issued-JWT TTL is the revocation
propagation bound** — at expiry the server disconnects, the client's
reconnect re-fires callout, and the revoked token is refused. The TTL is
therefore a deliberate M4 configuration knob (`--callout-ttl`, default
15m) whose price is one callout round-trip per TTL per open connection
[measured].

*As built (M4, journey 0010):* tokens are managed over the sealed surface
— `tokens.create` (which refuses identities the registry does not declare:
a token that could only ever be refused is a mistake caught at issuance),
`tokens.list`, `tokens.revoke` — all admin-gated (D18); the plaintext
appears exactly once, in the create response.

**Reversal condition** (inherited from D12's watch): any policy field —
permission, persona, role — proposed for the token record schema, or a
claim rule overriding a registry column per user, demotes claims-derived
authorization to a bootstrap convenience and returns the registry to sole
policy source.

## Not yet decided (pending research)

- **NGS**: whether a Synadia-managed server exposes callout configuration
  at all (`ngs-capabilities`) — the open half of D11's reversal condition.
  Blocked on operator access to the Synadia Cloud account (the account
  currently refuses connections at its plan cap [measured 2026-07-28]).
  This gates promising callout on NGS, not the self-hosted M4 build.
