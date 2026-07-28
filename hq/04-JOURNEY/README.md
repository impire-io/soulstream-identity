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

**Milestone 3 — the NATS-native rebuild — is shipped**
([episode 0007](0007-m3-the-nats-native-rebuild.md); design
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md), D14–D18):
the service answers over sealed NATS request/reply on the caller's own
subject prefix — the principal proven by the server's publish-permission
enforcement (D15, via the scoped-key template
`soulidentity.{{account-subject()}}.{{name()}}.>`) — and the vault seals
into NATS KV with both xkeys deployment-supplied. Act-as (D6) is enforced
and audited against real principals; management is admin-gated in the
registry (D18, the socket trust model's successor). All four gate criteria
measured in the e2e proof: unauthorized act-as refused and logged, wire and
store ciphertext-only (positive-control-verified), cross-prefix requests
refused by the server itself. The socket agent, `NATSOption`, file
keystore, and `sign/nonce` are deleted. Next in the execution order: M4
(auth callout, the front door), then M2 (consumers wire in). Design and
review that preceded the build:
[episode 0005](0005-the-nats-surface-design.md),
[episode 0006](0006-design-review-amendments.md).

**The first-key story is decided — M3's research gate is open**
([episode 0004](0004-first-key-story.md), D13): the unwrapping xkey for the
KV backend's envelope encryption is a local root secret on the service host
— decided as a `0600` file, then amended at design review to
deployment-supplied environment configuration
([episode 0006](0006-design-review-amendments.md)) — named honestly as
plaintext in the same trust class as the creds file, with the envelope's
real gain being that broker disks,
replicas, and backups never hold plaintext seeds. All three pre-registered
bars passed [measured]: the sealed round-trip survives broker+service
restart unattended, the store holds ciphertext only
(positive-control-verified), and the from-nothing bootstrap is two operator
acts plus one automatic service act.

**The mission was re-centered, twice in one day**
([episode 0002](0002-the-identity-plane-re-centering.md) then
[episode 0003](0003-nats-only-and-the-connection-ladder.md); constitution
1.1.0 → 1.2.0): SoulIdentity is the identity plane of the Soulstream
ecosystem — the representation of identity for humans and agents, delivered
as a **NATS-only** service with xkey-sealed E2E request/reply (D11, D12).
There is no socket: a presented creds file bypasses SoulIdentity entirely
(self-custody, server-verified natively), everything else arrives through
auth callout, authorized by the declared registry or by validated claims in
the presented token (D2). NATS KV with xkey envelope encryption is the
vault's initial backend. The milestone-1 socket surface, `NATSOption` seam,
and file keystore are transitional until the NATS-native rebuild (M3).

**Milestone 1 — the walking skeleton — is shipped**
([episode 0001](0001-genesis-and-the-walking-skeleton.md)): vault, declared
identities, the agent on a Unix socket, scoped minting, and the `client`
package with `NATSOption`, proven end to end against an operator-mode NATS
server — mint through the agent, nonce signed in the vault, scope enforced by
the server, no seed ever in the client process [measured]. The design is
twelve numbered decisions in [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md);
the plan is [`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md)
(execution order M3 → M4 → M2: the NATS-native rebuild, then auth callout as
the front door, then consumers wire in over the NATS surface). No release is
tagged yet; open questions before their milestones (NGS callout
capabilities, the sentinel-credential flow, the first-key story, the
claims-mapping shape, service round-trip latency) are named on the roadmap.

## Episode index

| # | Episode |
|---|---|
| 0001 | [Genesis: the design thread and the walking skeleton](0001-genesis-and-the-walking-skeleton.md) |
| 0002 | [The identity-plane re-centering](0002-the-identity-plane-re-centering.md) |
| 0003 | [NATS-only and the connection ladder](0003-nats-only-and-the-connection-ladder.md) |
| 0004 | [The first-key story: a local file, named honestly](0004-first-key-story.md) |
| 0005 | [The NATS-surface design: the principal is the subject](0005-the-nats-surface-design.md) |
| 0006 | [Design review: seeds from the environment, no v1, D15 taught back](0006-design-review-amendments.md) |
| 0007 | [M3: the NATS-native rebuild ships](0007-m3-the-nats-native-rebuild.md) |
