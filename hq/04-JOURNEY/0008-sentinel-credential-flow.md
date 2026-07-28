# Episode 0008 — The sentinel-credential flow: URL + token is enough (2026-07-28)

The second half of D11's reversal condition, resolved in its favor. The
question: by what exact mechanism does a client carrying only an external
credential reach an operator-mode server so auth callout can fire? Opened as
`sentinel-credential-flow` with three pre-registered bars; all three passed
the same day in one spike against embedded nats-server 2.14.3, and the topic
graduated to the M4 design doc
([`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md), D19–D21).

**The answer is smaller than the question assumed** [measured]: with
`default_sentinel` in the server config, the client holds the URL and its
external token — `nats.Connect(url, nats.Token("…"))` — and nothing else. No
creds, no JWT, no key. The server assigns the sentinel itself, fires the
callout with the token in the connect options, and the issuer's answer is a
user JWT for a **server-assigned ephemeral user key** — the client never
owns a key in this flow, which corrects D12's "issued for the client's own
key" wording. For servers without `default_sentinel`, the fallback is an
explicit sentinel creds file: a bearer, deny-all user JWT plus its own seed,
both public by design — a bearer JWT presented with an unrelated nonce
signature is admitted, so the signature authenticates nothing [measured];
nats.go merely requires the creds file's halves to match client-side.

**The refusal paths fail closed** [measured]: an invalid token draws an
authorization violation at connect with the refusal in the issuer's log; an
issuer that is down refuses even valid tokens. And the sentinel is not
secret-equivalent — alone it reaches the issuer with an empty token and is
refused, and its deny-all permissions make it a dead credential if callout
were ever disabled [mechanism-argument]. Both registered reversal
conditions checked, neither triggered.

**What it taught about M4's shape**: the callout issuer is the existing
mint with a different trigger — the response wraps a user JWT signed by the
target account's *scoped signing key*, exactly the vault's role keys (D5),
inside a response JWT signed by the AUTH account key. Attribution comes
free: the external identity lands in the issued JWT's name and the audit
log. The `authorization.xkey` field seals callout requests with the same
curve-key machinery the service surface already uses (D16/D17)
[mechanism-argument; not spiked]. What this topic deliberately did not
answer: the claims-mapping shape (which issuers, which claims, which role —
its own gated research) and whether NGS permits callout configuration
(`ngs-capabilities`).

Reversal condition: carried forward into D19 — if a consumer's client
library cannot set the token connect option alongside creds (observable: a
consumer blocked at connection, recorded as an issue), the carrier map
re-opens for that client class. D11's own reversal condition is now half
resolved: the sentinel flow is proven; the NGS half remains open.

Trail: [`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md)
(D19–D21), [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) (D12
amendment); `hq/01-RESEARCH/sentinel-credential-flow/` in git history
(pre-registration 4abf74d → investigation c8e0e6a → removed at
graduation); spike in the session scratchpad, its shape recorded in the
topic JOURNEY.
