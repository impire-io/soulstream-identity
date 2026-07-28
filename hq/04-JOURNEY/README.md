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

**M3 is fully unblocked — both its gates are met**
([episode 0005](0005-the-nats-surface-design.md), design doc
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)): the
NATS-surface design lands D14–D17 on the re-centered direction. The
load-bearing decision is D15 — operations live at
`soulidentity.v1.<account>.<user>.<op>` and the caller's claim is proven by
the server's publish-permission enforcement, no second verifier
[mechanism-argument] — which is what turns act-as (D6) from declared into
enforced. D14 versions the subject space, D16 fixes the sealed envelope
with an honest replay analysis, D17 separates the surface xkey from the
first key. Wire bodies are unchanged from milestone 1. Next: build M3
against the five acceptance criteria in the design doc.

**The first-key story is decided — M3's research gate is open**
([episode 0004](0004-first-key-story.md), D13): the unwrapping xkey for the
KV backend's envelope encryption lives in a `0600` local file beside the
service's creds, minted on the service host at first start and never leaving
it — named honestly as a plaintext root secret in the same trust class as
the creds file, with the envelope's real gain being that broker disks,
replicas, and backups never hold plaintext seeds. All three pre-registered
bars passed [measured]: the sealed round-trip survives broker+service
restart unattended, the store holds ciphertext only
(positive-control-verified), and the from-nothing bootstrap is two operator
acts plus one automatic service act. What still precedes M3's build is its
design doc.

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
