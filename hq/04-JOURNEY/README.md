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

## Where things stand (2026-07-29)

**One noun: persona** ([episode 0016](0016-one-noun-persona.md); D27 in
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md), constitution 1.3.1):
persona == identity — the ecosystem's one noun for the represented
subject, adopted from soulstream's fixed terminology; *principal* is the
server-proven (account, user) a connection speaks as (D15's term), and
"identity" survives only in the product name. The persona is born at
first encounter (D26); the vault is where its durable artifacts live. A
vocabulary pass over vision, constitution, missions, and load-bearing
comments — no type, op, or JSON field changed [measured: gate green].

**The vault is the directory — ephemeral users, keys on first touch**
([episode 0015](0015-the-vault-is-the-directory.md); D26 in
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)): episode
0014's persona-directory trust path was refuted by the operator the same
day — identity truth lives in the IAM, users are ephemeral, and no
per-user act may exist anywhere. A persona key is a capability artifact,
not identity (an access token carries no user key and cannot sign
records): the caller's own key **materializes inside the vault on first
touch**, owner-bound, and `keys.public` is the **open directory read** —
readers build verification keyrings from the identity plane; no profile
store. The sealed-communication key follows the same pattern when D9
lands.

**M2's first gate criterion is measured — the seam carries a real record**
([episode 0014](0014-the-cross-service-proof.md), re-proven on the D26
shape in 0015): a Soulstream record signed through the running
SoulIdentity service verifies in a real realm. The proof lives in `e2e/`
— a consumer-position module importing both repos (the cycle guard's
shape), riding `make test`, now with **zero per-user acts**: one team
key, one minted credential, the key materializing at signer construction,
the reader's keyring one `keys.public` answer; announce, baseline, and
turn read `SigVerified` — `unknown-key` without the keyring, the negative
control [measured]. What remains of M2 is the **node half** (one pooled
connection per user, no node-held creds), in soulstream's remote MCP node
feature — which publishes nothing per user; it builds keyrings from the
identity plane.

**The identity registry is dissolved — authorization lives in the ACLs
and the bindings** ([episode 0013](0013-the-registry-dissolves.md); D25 in
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md), amending
D2/D5/D6/D18/D22/D24): the operator's one-identity-one-persona question
unwound the ledger field by field. Persona keys carry their owner
(account, user) at import and `sign.record`/`keys.public` check the
caller against the binding; every mint resolves its signing key by the
target account's D24 team binding (ambiguity refuses); the management ops
are gated by the server's own permission enforcement on the op tail —
`requireAdmin`, the `admin` flag, `identities.*`, and `internal/registry`
are deleted; mint is an operator op (self-mint died with the row that
authorized it). The token store is the one registry standing. All three
e2e gates re-proven on the new shape [measured], including the new
op-tail proof (a represented user publishing a management op on its own
prefix: server-refused, zero service decisions) and the revocation bound
(re-admitted 5.25 s after connect at a 5 s TTL). The client now carries
the M2 seam surface: `PersonaSigner` satisfies soulstream's
`identity.Signer` structurally, exercised in the M3 rig. Next: **M2 —
consumers wire in** (the cross-repo gate proof, then the remote MCP
node).

**The Entra/OIDC lane is open — role == team, no mapping store**
([episode 0012](0012-entra-role-claim-lane.md); D23–D24 in
[`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md), built as
spec-driven feature `specs/001-entra-oidc-backend/` through the newly
enabled speckit flow): an external client presents an Entra access token
instead of an API token; the issuer validates it against one pinned
issuer/audience via JWKS discovery (fail-closed, key rollover without
restart) and authorizes by the `roles` claim — the role value IS the team
name, resolving directly against the vault's account signing keys, which
now carry their account binding at import. D22's sketched rule table was
refuted before it was built; no catalog, no per-user entries; admin and
personas never come from claims. Gate met on the stub rig [measured]:
sealed-leg admission with full attribution, the nine-row refusal matrix,
`sit_` lane untouched, and the accepted revocation asymmetry demonstrated
(token lifetime + one TTL; cached token re-admitted 5.2 s after connect
at a 5 s TTL). Real-tenant verification is a documented manual runbook.
Next in the execution order remains **M2 — consumers wire in**.

**The subject space gained its ecosystem namespace**
([episode 0011](0011-the-shared-subject-prefix.md), D14 amended at the
operator's direction): the root is `<prefix>.soulidentity` with the prefix
shared across all soulstream components (`--prefix` /
`SOULSTREAM_PREFIX`), empty by default. Environments coexist in one realm,
and the account token sits at declared position `P+2`, so a cross-account
export (`account_token_position`) extends D15's principal proof by
configuration alone. The M3 gate e2e now runs fully prefixed
(`prod.soulstream.soulidentity.>`) [measured]; the honest cost — prefix
mismatch is silent timeouts — is mitigated by the startup root log and the
shared environment variable.

**Milestone 4 — auth callout, the front door — is shipped**
([episode 0010](0010-m4-auth-callout-ships.md); design
[`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md), D19–D22,
researched in [episode 0008](0008-sentinel-credential-flow.md) and
[episode 0009](0009-claims-mapping-shape.md)): an external-identity client
holds a sentinel creds file (minted by the admin-gated `sentinel.mint` op,
public by design) and its API token; the issuer — one process, two
connections, the callout subscription in the dedicated AUTH account —
digest-validates against the token store (records name an identity, carry
no policy), authorizes via the registry row, and mints a TTL-bounded
scoped JWT for the server-assigned key with the vault's role keys. Gate
met [measured]: admission with server-enforced scope and full audit
attribution; bypass-lane connections produce zero callout decisions;
invalid and revoked tokens refused; the D21 xkey leg proven (sealed
requests and responses). Token management is four admin-gated surface ops.
Entra/OIDC arrives later as validator configuration on the same D22
interface. Open: `ngs-capabilities` (blocked on operator access to the
Synadia account; gates only the NGS deployment class), and next in the
execution order, **M2 — consumers wire in**.

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
| 0008 | [The sentinel-credential flow: URL + token is enough](0008-sentinel-credential-flow.md) |
| 0009 | [The claims-mapping shape: one pipeline, policy never in the credential store](0009-claims-mapping-shape.md) |
| 0010 | [M4: auth callout ships, the front door opens](0010-m4-auth-callout-ships.md) |
| 0011 | [The shared subject prefix: one namespace for the ecosystem](0011-the-shared-subject-prefix.md) |
| 0012 | [The Entra lane: role == team, no mapping store](0012-entra-role-claim-lane.md) |
| 0013 | [The registry dissolves: authorization in the ACLs and the bindings](0013-the-registry-dissolves.md) |
| 0014 | [The cross-service proof: the seam carries a real record](0014-the-cross-service-proof.md) |
| 0015 | [The vault is the directory: ephemeral users, keys on first touch](0015-the-vault-is-the-directory.md) |
| 0016 | [One noun: persona](0016-one-noun-persona.md) |
