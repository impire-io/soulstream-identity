# Episode 0010 — M4: auth callout ships, the front door opens (2026-07-28)

The front door is real: SoulIdentity is now the NATS auth-callout issuer,
built in one pass against the researched design (episodes 0008–0009,
D19–D22) and landed with every gate criterion measured in an automated
end-to-end proof. `make check` green throughout; the same-day sequence
research → design → build closed within hours of the operator's "API
tokens first" scoping.

**What the gate measured** (client/callout_e2e_test.go, embedded
operator-mode server, AUTH account with `authorization.xkey` set)
[measured]:

- A client holding only a sentinel creds file and an API token connects
  and is admitted as a scoped user in the target account — in-scope
  round-trip works, an out-of-scope publish draws the server's own
  permissions violation.
- The admission is attributable: the audit log names the external
  identity, its token label, and the client host.
- The bypass lane stays bypass: every creds-file connection in the proof
  (service, issuer, admin) produced **zero** callout decisions in the
  audit — SoulIdentity out of the path, exactly as D12 promises.
- An invalid token and a revoked token are both refused at connect, the
  refusals audited. Wire-facing errors are generic; reasons live only in
  the audit log.
- The D21 xkey leg, unspiked until now, is proven: requests arrive sealed
  (server's curve key in the `Nats-Server-Xkey` header), responses seal
  back.

**What the build surfaced** (propagated into the design in the same
change):

- *A signing-key-signed sentinel must name its account.* The e2e failed
  first with the sentinel signed by an AUTH signing key but no
  `issuer_account` — the server refused the connection before callout ever
  fired. The fix ripples into configuration: the service carries the AUTH
  account public key (`--auth-account`) so `sentinel.mint` can set it.
  A protocol fact the research phase had no reason to meet, found by the
  gate [measured].
- *The issuer is two connections.* The sealed surface lives on the
  service's own account; the callout subscription must live in the AUTH
  account — so callout deployments run one process with two credentials,
  and the token bucket sits beside the vault bucket on the service's own
  account JetStream.
- Token management became four admin-gated surface ops (`tokens.create`,
  `tokens.list`, `tokens.revoke`, `sentinel.mint`); issuance refuses
  identities the registry does not declare, catching dead tokens at
  creation instead of at the first refused connect.

**What shipped**: `internal/callout` (digest-keyed token store on KV, the
issuer with sealed-request handling and fail-closed refusals),
`mint.ForKey` (the ephemeral mint for server-assigned keys, TTL-bounded),
the four new service ops, client methods, and CLI verbs (`token
create|ls|revoke`, `sentinel`, `serve --callout-*`). The issued-JWT TTL
default is 15 minutes — the revocation propagation bound the research
measured (episode 0009), now a named knob.

Reversal condition: none of its own — a completed build; the direction
decisions it realizes carry theirs (D19's client-class carrier map, D22's
policy-field smell, D11's still-open NGS half).

Trail: [`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md)
(D19–D22 as built),
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md) (ops
table), `client/callout_e2e_test.go` (the measured gate), README and
roadmap in the same change.
