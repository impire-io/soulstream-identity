# Episode 0001 — Genesis: the design thread and the walking skeleton (2026-07-28)

SoulIdentity was born in one design conversation on the Soulstream side
(2026-07-28, following sealed-topics graduation — soulstream journey 0005).
The chain that forced it: Claude Desktop, LibreChat, and claude.ai-class
clients speak remote MCP, so `soulstream-mcp` must run as a shared node; a
shared node should pool NATS connections **per user** so transport identity
and NATS-level permissions stay real (and the sealed-topics design's
defense-in-depth keeps meaning something); per-user credentials need something
to mint and hold them — and a node holding raw keys would make node
compromise equal to identity theft. The answer is an **ssh-agent for
personas**: a vault that answers sign requests, keys never leaving.

The design landed as ten numbered decisions (D1–D10 in
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md)), the load-bearing ones:
nonce signing rides nats.go's own credential callbacks — the oracle plugs
into a seam the client library ships, no fork [mechanism-argument] (D1);
identities are declared `(account, user)`, never inferred — minting *is* the
membership assignment, carried by `issuer_account` (D2); signing-key↔account
binding verification is diagnostic only, because the NATS server re-checks it
on every connection and fails closed — the server is the verifier of record
[mechanism-argument] (D3); both mint mode and auth-callout mode sit on one
identity registry, and the maintainer explicitly wants both so simple
deployments are never forced into callout (D4); scoped signing keys carry the
NATS permissions so SoulIdentity's own policy is only act-as (D5); creds
export is the single, named, loudly-logged custody escape (D7).

The walking skeleton shipped the same day (commit `84bad09`): vault (0600
seed files, sign-only API), registry, agent over a 0600 Unix socket with
audit logging, mint, CLI, and the public `client` package whose
`NATSOption(account, user)` is the seam the MCP node will consume. The
end-to-end proof is in the suite and passed on its first run [measured]: a
NATS server in operator mode (memory resolver), an account whose *scoped*
signing key lives in the vault, a user JWT minted through the agent, a
connection whose nonce is signed inside the vault, an on-scope
publish/subscribe roundtrip — and an out-of-scope publish drawing a
server-side permissions violation, proving the scope (not the minted JWT) is
the policy. No seed was ever present in the client process.

Nothing was refuted; one lesson is recorded honestly: the scaffold-only first
commit (`cd04faa` — go.mod without packages) produced a red CI run
(`go test ./...`: "matched no packages"), superseded by the very next commit.
Land the scaffold together with the first package.

What it opened: soulstream feature 017 (the `Signer` interface seam) now
targets a running agent instead of an assumed one; the remote MCP node has
its identity story; and the hq structure adopted in this same change (this
episode is its first) gives the project the research → design → journey
discipline from day one.

Reversal condition: the per-operation oracle assumption — if real MCP-node
usage shows the signing round-trip dominating publish latency or connection
setup at the node's scale (observable: oracle p99 comparable to publish
latency in the node's metrics, or connection storms traced to jwtCB/sigCB
churn), the custody boundary moves from per-operation signing toward
short-lived delegated session keys, recorded as a new D-decision with its own
threat analysis. D-level reversal conditions live with their decisions in the
design doc.

Trail: [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) (D1–D10),
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md) (M1–M5),
soulstream journey 0005 and the 2026-07-28 design thread; commits `cd04faa`
(scaffold + design), `84bad09` (skeleton + e2e), this change (hq adoption).
