# Episode 0003 — NATS-only and the connection ladder (2026-07-28)

Hours after the identity-plane re-centering (episode 0002), the maintainer
pushed it to its conclusion with three calls, stated in his own words
[judgment — direction calls, maintainer's]. First: NATS KV with xkey
envelope encryption is not the *next* vault backend, it is the **initial**
one — the milestone-1 file keystore is transitional. Second: the registry is
only one way to decide who is allowed what — the other is to **deduce the
team from the connection credentials themselves**, a JWT passed in the token
connection option, validated and mapped to role and personas; this runs
naturally in callout. Third: **no socket option at all** — and if a creds
file is passed in the connection options it is used directly, the bypass for
operator users, with auth callout being exactly where that line is drawn.

The third call reversed episode 0002 within the day, and the reversal is
recorded as the honest turn it is: 0002 answered the bootstrap problem ("a
client cannot reach a NATS-hosted oracle to sign the nonce of the connection
it is establishing") by keeping the socket as a bootstrap rung; the better
answer is that the pre-NATS moment never needs SoulIdentity — either you own
creds (connect directly, server-verified natively, SoulIdentity out of the
path) or you carry an external token (the server calls out on your behalf)
[mechanism-argument — this is the native NATS callout shape: callout config
names the exempt users, everything else in scope goes through the issuer].
D12 records the two-lane ladder; with it, the nonce oracle leaves the
connection story entirely (D1 amended again), D8's local mode is superseded
outright, mint mode stops being a connection mode (D4 — minting durable
creds remains the service function whose exported output is how an operator
obtains bypass credentials, sharpening D7's escape into the bypass lane's
front door), and D2 widens from "declared, never inferred" to "declared or
verifiably claimed, never guessed."

The adversarial pass ran before recording, and its residue lives in D12: the
bypass lane is raw key possession — answered as self-custody by the
identity's owner, with Constitution I's protected property sharpened to
*represented identities never touch key material* (in callout the client's
key is its own; only an ephemeral JWT is issued). Callout couples
represented users' connection availability to SoulIdentity's availability —
accepted as the cost of representation, with the bypass lane as break-glass.
Claims-derived authorization delegates trust to token issuers — deliberately,
per backend, through declared mapping rules.

What it opened: constitution 1.2.0 (NATS the *only* transport; KV the
initial backend; Principle II's policy surface admits validated claims —
Principles I–IV otherwise untouched), D2/D4/D7/D8/D10/D11 amended plus D12
new, and a resequenced roadmap: M3 is the NATS-native rebuild (service
surface + KV vault, socket and `NATSOption` retiring), M4 the callout front
door, execution order M3 → M4 → M2, with new research gates (the first-key
story now gates M3; the claims-mapping shape gates M4). Nothing was built;
docs only. The walking skeleton keeps working as shipped until M3 replaces
its surface.

Reversal condition: if a consumer class emerges that can neither hold a
creds file nor present a callout-validatable credential (observable: a
consumer integration blocked at connection, recorded as an issue), a
pre-connection local surface returns as a new D-decision. If claims-derived
mapping ends up re-creating the registry row by row (observable: per-user
mapping exceptions accumulating in configuration), claims-derived
authorization demotes to a bootstrap convenience. If the KV backend cannot
pass its gate with only ciphertext ever stored [measured], the file backend
returns as initial. Recorded identically in D12 and D10.

Trail: [`../00-GENESIS/vision.md`](../00-GENESIS/vision.md),
[`../00-GENESIS/constitution.md`](../00-GENESIS/constitution.md) (1.2.0),
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) (D2, D4, D7, D8, D10, D11
amended; D12 new),
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md) (M2–M5
resequenced, research questions); this change, following episode 0002's
commit `a9f5497` the same day.
