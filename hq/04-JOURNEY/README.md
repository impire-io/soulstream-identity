# 04-JOURNEY — the narrative record

What was built, what was measured, what was believed and then refuted, and
what each episode taught. The design docs in `../02-DESIGN/` say what the
system *is*; these episodes say how we *got here* — including the reversals,
because a refuted assumption is as load-bearing as the shipped code.

> **Keeping this log alive:** whenever work lands, a research investigation
> concludes, or a load-bearing decision is made, add a numbered episode with
> `/journey-log` (research topics get theirs via `/research-graduate`). Follow
> [`TEMPLATE.md`](TEMPLATE.md) — including its required Reversal-condition
> line and evidence-class tags. Honesty rules apply here as everywhere: record
> what actually happened, including failures, reversals, and findings that
> contradicted expectations. This duty is anchored in
> [`../00-GENESIS/how-we-work.md`](../00-GENESIS/how-we-work.md); the
> numbering and index are enforced by `internal/hqlint`.

## Where things stand (2026-07-28)

**The mission was re-centered**
([episode 0002](0002-the-identity-plane-re-centering.md), constitution
1.1.0): SoulIdentity is the identity plane of the Soulstream ecosystem — the
representation of identity for humans and agents, delivered as a NATS
service with xkey-sealed E2E request/reply (D11), external identities
(Entra/OIDC, API tokens) represented inside NATS via auth callout as the
front door, and NATS KV with xkey envelope encryption named as the next
storage backend. The planned TCP listener is dropped; the Unix socket is the
bootstrap/laptop rung.

**Milestone 1 — the walking skeleton — is shipped**
([episode 0001](0001-genesis-and-the-walking-skeleton.md)): vault, declared
identities, the agent on a Unix socket, scoped minting, and the `client`
package with `NATSOption`, proven end to end against an operator-mode NATS
server — mint through the agent, nonce signed in the vault, scope enforced by
the server, no seed ever in the client process [measured]. The design is
eleven numbered decisions in [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md);
the plan is [`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md)
(next: consumers wire in — the Soulstream `Signer` seam and the remote MCP
node's per-user pool — then the NATS service surface, then auth callout). No
release is tagged yet; open questions for later milestones (NGS signing-key
and callout capabilities, the sentinel-credential flow, the first-key story,
oracle latency under real load) are named on the roadmap.

## Episode index

| # | Episode |
|---|---|
| 0001 | [Genesis: the design thread and the walking skeleton](0001-genesis-and-the-walking-skeleton.md) |
| 0002 | [The identity-plane re-centering](0002-the-identity-plane-re-centering.md) |
