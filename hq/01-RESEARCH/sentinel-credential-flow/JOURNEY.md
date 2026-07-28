# sentinel-credential-flow — investigation journey

Topic opened 2026-07-28. Entries append below as the investigation happens.

## 2026-07-28 — the mechanism, from the server's own source

Read nats-server 2.14.3 (`server/auth_callout.go`, `auth_callout_test.go`)
and jwt v2.8.2 before any experiment. The operator-mode shape
[mechanism-argument, then all measured below]:

- One account is the **AUTH account**: its account JWT carries
  `authorization {auth_users, allowed_accounts, xkey}`. `auth_users` are
  exempt from callout — that is where the issuer's own connection lives
  (the same bypass shape as D12). Requests go to `$SYS.REQ.USER.AUTH`
  inside the AUTH account as signed `AuthorizationRequest` JWTs.
- The request carries **`user_nkey` — a server-assigned ephemeral user
  key** — plus `ConnectOptions` (token, user/pass, jwt) and client/TLS
  info. The issued user JWT must be for that server-assigned key: the
  client never needs a key of its own. (This corrects D12's "issued for
  the client's own key".)
- The **sentinel** is a bearer user JWT (`BearerToken: true`) in the AUTH
  account, deny-all permissions. Bearer = no nonce signature required, so
  the JWT is distributable. `default_sentinel` in server config goes one
  further: a client presenting *no* credential is assigned the sentinel by
  the server itself.
- The issuer's response is an `AuthorizationResponse` JWT (audience = the
  requesting server's ID) signed by the **AUTH account key**, wrapping a
  user JWT signed by the **target account's (scoped) signing key** — i.e.
  exactly the vault's role keys (D5): the callout issuer is the mint with
  a different trigger.
- `authorization.xkey` exists for sealing callout requests to the issuer —
  the same curve-key machinery as D16/D17 [mechanism-argument; not
  spiked].

## 2026-07-28 — bars 1–3 measured in one spike

Spike (`scratchpad/calloutspike/`): embedded nats-server 2.14.3 in operator
mode (memory resolver), AUTH + APP accounts, APP with a scoped signing key
(`demo.>` template), `default_sentinel` configured, and a spike issuer
validating a token map. All of the following [measured]:

- **Carrier (a) — token only.** `nats.Connect(url, nats.Token("tok-daan"))`
  with no creds, no JWT, no key: admitted as a scoped user in APP, message
  round-trips in scope, out-of-scope publish draws a server permissions
  violation. The client held nothing NATS-side but the URL.
- **Carrier (b) — explicit sentinel creds.** nats.go refuses a creds file
  whose seed mismatches the JWT subject (a client-side check), so the
  distributable creds file carries the sentinel's own seed — public by
  design: the JWT is bearer and deny-all, the seed authenticates nothing.
  Works identically to (a).
- **Carrier (b2) — the signature really is ignored.** The bearer sentinel
  JWT presented with a nonce signature from an unrelated key is admitted:
  the JWT alone is the artifact.
- **Carrier (c) / reversal probe — sentinel alone grants nothing.** A bare
  connect (default sentinel assigned, no token) reaches the issuer with an
  empty token and is refused at connect. And if callout were ever disabled,
  the sentinel's own deny-all permissions make it a dead credential.
  **The registered reversal ("sentinel is secret-equivalent") is not
  triggered.**
- **Bar 3 — refusals.** Invalid token: `nats: Authorization Violation` at
  connect, refusal recorded by the issuer with the client host. Issuer
  down, valid token: fails **closed** (authorization violation, no
  admission).

Attribution: the external identity (`daan@example.com`) lands in the issued
JWT's name and the issuer's log — the audit story M4 needs.

## 2026-07-28 — what this settles for M4

The client-side contract is minimal: **URL + external token** (server has
`default_sentinel`), or **URL + sentinel creds + token** (server without
it). SoulIdentity-as-issuer is the existing mint with a callout trigger:
validate credential → map to identity/role (the claims-mapping research) →
`vault.KeyPair(role)` signs a scoped user JWT for the server-assigned
ephemeral key. Fail-closed comes free from the protocol. Open follow-ups,
deliberately not this topic: the claims-mapping shape (its own gate), and
whether NGS permits callout configuration (ngs-capabilities).
