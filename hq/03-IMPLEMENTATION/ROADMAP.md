# Roadmap — milestones and gates

*The design ([`../02-DESIGN/agent.md`](../02-DESIGN/agent.md)) says what
SoulIdentity is; this document decides what gets built first and behind which
gate.*

## Where we are (2026-07-29)

**One noun: persona — D27**
([journey 0016](../04-JOURNEY/0016-one-noun-persona.md), constitution
1.3.1): persona == identity, adopted from soulstream's fixed terminology;
*principal* is the server-proven (account, user); "identity" survives
only in the product name. A vocabulary pass — no wire change.

**The vault is the directory — D26, ephemeral users**
([journey 0015](../04-JOURNEY/0015-the-vault-is-the-directory.md), D26 in
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)): 0014's
persona-directory trust path refuted the same day — no per-user act
exists anywhere. The caller's own persona key materializes inside the
vault on first touch, owner-bound; `keys.public` is the open directory
read, and readers build verification keyrings from the identity plane.
The sealing key follows the same pattern when D9's sealed topics land.

**M2's signer half is measured — the cross-service proof rides the gate**
([journey 0014](../04-JOURNEY/0014-the-cross-service-proof.md), re-proven
registry-free in 0015): a Soulstream record signed through the running
service verifies in a real realm, proven from the consumer position
(`e2e/`, a separate module importing both repos — the cycle guard's shape
— soulstream pinned at v0.6.0), in `make test`, with zero per-user acts.
Remaining for M2: the node half of the gate (one pooled connection per
user, no node-held creds) — soulstream's remote MCP node feature, which
publishes nothing per user and builds keyrings from the identity plane.

**The registry dissolved — D25, same day**
([journey 0013](../04-JOURNEY/0013-the-registry-dissolves.md), D25 in
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md) amending
D2/D5/D6/D18/D22/D24): authorization lives in the transport ACLs (the op
tail of the subject, gated by the same enforcement as D15's principal)
and the vault bindings (persona keys carry their owner; every mint
resolves by the account's team binding). `internal/registry`, the `admin`
flag, `identities.*`, and self-mint are deleted; the token store is the
one registry standing; teams are accounts. All three e2e gates re-proven
[measured]. The client gained M2's seam surface (`PersonaSigner`,
`keys.public`, `sign.record` returning the public key).

**The Entra/OIDC lane — shipped 2026-07-29**
([journey 0012](../04-JOURNEY/0012-entra-role-claim-lane.md), D23–D24 in
[`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md), feature
`specs/001-entra-oidc-backend/` on the speckit flow): the second authn
backend on the D22 pipeline. Role == team — the token's app-role value
resolves directly against the declared teams (account signing keys with
their new account binding); no rule table, no catalog, no per-user
entries; admin/personas never from claims. Gate met on the local-stub rig
[measured]: sealed admission with attribution, nine-row refusal matrix,
JWKS fail-closed with restart-free key rollover, `sit_` lane untouched,
revocation bound (token lifetime + one TTL) demonstrated and accepted.
Real-tenant verification: the manual runbook in the feature's
`quickstart.md`. Next in the execution order: **M2 — consumers wire in**.

**Milestone 4 — auth callout, the front door — shipped 2026-07-28**
([journey 0010](../04-JOURNEY/0010-m4-auth-callout-ships.md), design
[`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md), D19–D22,
researched same-day in journeys 0008–0009): SoulIdentity as the callout
issuer on a dedicated AUTH account — sentinel + API token in,
TTL-bounded scoped JWT for the server-assigned key out, token management
and sentinel minting as admin-gated surface ops. Gate met [measured]:
attribution in the audit, bypass lane untouched by the issuer, invalid and
revoked tokens refused, xkey-sealed callout requests proven. Entra/OIDC
landed 2026-07-29 as the second backend (D23–D24, entry above); NGS
remains an open research question blocked on operator portal access.

**Milestone 3 — the NATS-native rebuild — shipped 2026-07-28**
([journey 0007](../04-JOURNEY/0007-m3-the-nats-native-rebuild.md), design
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md), D14–D18):
the sealed service surface on the caller's own subject prefix, the vault on
NATS KV with envelope encryption, act-as enforced against the server-proven
principal, admin-gated management (D18). Gate met [measured]: unauthorized
act-as refused and logged; wire and store ciphertext-only
(positive-control-verified); a cross-prefix request refused by the server
itself, never reaching the service. The milestone-1 socket agent,
`NATSOption` seam, file keystore, and `sign/nonce` op are deleted. Next in
the execution order: M4 (auth callout), then M2 (consumers wire in).

**Milestone 1 — the walking skeleton — shipped 2026-07-28**
([journey 0001](../04-JOURNEY/0001-genesis-and-the-walking-skeleton.md)):
vault, registry, agent over a Unix socket, mint-from-scoped-signing-keys, the
`client` package with `NATSOption`, and the end-to-end proof against an
operator-mode NATS server [measured]. No release tagged yet; the module is
consumable at `main`.

**The identity-plane re-centering — 2026-07-28**
([journey 0002](../04-JOURNEY/0002-the-identity-plane-re-centering.md),
constitution 1.1.0): the mission is the representation of identity for humans
and agents, delivered as a NATS service with xkey-sealed E2E request/reply
(D11). M3 below changed from a TCP listener to the NATS service surface;
auth callout (M4) is the flagship front door for external identities.

**Same-day follow-up — the connection ladder**
([journey 0003](../04-JOURNEY/0003-nats-only-and-the-connection-ladder.md),
constitution 1.2.0): the surface is NATS-only — no socket; connections are
creds-file bypass or callout (D12); authorization is registry-declared or
claims-derived from the presented credential (D2 amended); NATS KV is the
vault's *initial* backend, folded into M3. Execution order after the
re-centering: **M3 → M4 → M2** (M2 keeps its number, its consumers now
arrive over the NATS surface).

## Milestones

1. ✅ **M1 — walking skeleton** (shipped 2026-07-28). Local agent à la
   ssh-agent: file vault, declared identities, nonce oracle, scoped minting,
   explicit creds escape. Realizes D1, D2, D4 (mint rung), D5, D7, D8, D10
   (file backend).
2. **M2 — consumers wire in** (runs after M3/M4 since journey 0003). The
   Soulstream `Signer` seam **landed 2026-07-29** (soulstream `017-signer-seam`,
   its journey episode 0006): `identity.Signer { PublicKey() string;
   Sign(canonical []byte) (string, error) }` — deliberately the exact shape of
   this repo's `client.SignRecord(persona, canonical)`, deadline owned by the
   implementation. The remote MCP node connects per user by passing each
   user's token through callout — the `NATSOption` socket seam it was
   originally planned against is superseded. **The wiring rule (cycle
   guard)**: Go satisfies the seam structurally, so the adapter lives in the
   *consumer* binary — this repo MUST NOT import soulstream, soulstream never
   imports this repo, and consumers sit above both; a module cycle is legal
   in Go but a versioning trap we simply never enter. What the seam proved
   missing landed 2026-07-29 with D25 (journey 0013): `client.PersonaSigner`
   — the seam's exact shape, fail-fast construction (owner checked
   client-side), never ("", nil) — with the persona key materializing in
   the vault on the signer's first touch and readers resolving public
   keys from the identity plane (D26, journey 0015). Gate, half met: ✅ a
   Soulstream record signed through the service verifies in the realm
   **[measured 2026-07-29]** (journey
   [0014](../04-JOURNEY/0014-the-cross-service-proof.md), re-proven with
   zero per-user acts in [0015](../04-JOURNEY/0015-the-vault-is-the-directory.md);
   the proof sits in consumer position — the nested `e2e/` module imports
   both repos and rides `make test`); ⬜ the node holds one pooled
   connection per user with no node-held creds — soulstream's remote MCP
   node feature. This milestone lives mostly in the consuming repos; here
   it may add only what those consumers prove missing.
3. ✅ **M3 — the NATS-native rebuild** (shipped 2026-07-28,
   [journey 0007](../04-JOURNEY/0007-m3-the-nats-native-rebuild.md)). The
   agent's contract served over NATS request/reply with xkey-sealed
   payloads, the caller's NATS identity as the principal (D11/D12) — act-as
   (D6) enforced, audit entries naming the caller — and the vault on NATS
   KV with envelope encryption at rest (D10, D13). Realized the design in
   [`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)
   (D14–D18); the milestone-1 socket surface, `NATSOption` seam, file
   keystore, and `sign/nonce` op retired. Gate met [measured] in the e2e
   proof: unauthorized act-as refused and logged; request bodies ciphertext
   to an account-privileged observer; the KV store ciphertext-only at rest
   against a plaintext positive control; a cross-prefix request refused by
   the server's own permission enforcement.
4. ✅ **M4 — auth callout, the front door** (shipped 2026-07-28,
   [journey 0010](../04-JOURNEY/0010-m4-auth-callout-ships.md)).
   SoulIdentity as the NATS auth-callout issuer, API-token backend first
   (Entra/OIDC landed 2026-07-29 as D23–D24, journey 0012),
   issuing TTL-bounded ephemeral JWTs for the server-assigned user key —
   authorization from the registry row, the creds-file bypass drawn in
   callout config (D12). Realized the design in
   [`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md)
   (D19–D22). Gate met [measured] in the e2e proof: an external-credential
   connection admitted with server-enforced permissions and the identity
   attributable in the audit log; every creds-file connection verified
   natively with zero callout decisions — SoulIdentity out of the path;
   invalid and revoked tokens refused; callout requests xkey-sealed both
   ways. The NGS answer (below) gates promising callout on NGS, not this
   build.
5. **M5 — attestation issuance.** Soulstream `operated_by` attestation tokens
   issued from the vault (D6's static half). Gated on demand from the
   Soulstream side.
6. **Later**: sealing keys (D9 — unwrap-once, waits on Soulstream sealed
   topics build), further storage backends (OS keychain, Vault transit — D10),
   release pipeline (goreleaser + tag-triggered release, the archivist
   pattern) when the first external consumer wants a pinned version.

## Open research questions (before their milestones)

- **NGS/Synadia Cloud capabilities** (gates M4, informs M2): does the account
  plan expose creating/scoping account signing keys, and is auth callout
  configurable? Verify against the real account before either mode is
  promised on NGS — a `/research-start ngs-capabilities` topic when M2/M4
  planning begins. This is also half of D11's reversal condition.
- ~~**The sentinel-credential flow** (gated M4)~~ — answered 2026-07-28
  ([journey 0008](../04-JOURNEY/0008-sentinel-credential-flow.md), D19–D21
  in [`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md)): the
  client holds URL + external token only (`default_sentinel`), or a public
  bearer deny-all sentinel creds file besides; the issued JWT is for the
  server-assigned ephemeral key, minted by the vault's role keys;
  everything fails closed [measured]. D11's reversal condition is half
  resolved; the NGS half remains.
- ~~**The first-key story** (gated M3)~~ — answered 2026-07-28
  ([journey 0004](../04-JOURNEY/0004-first-key-story.md), D13): a `0600`
  local file on the service host, minted at first start; bootstrap is two
  operator acts + one automatic service act [measured].
- ~~**The claims-mapping shape** (gated M4)~~ — answered 2026-07-28
  ([journey 0009](../04-JOURNEY/0009-claims-mapping-shape.md), D22):
  validate → authorize → mint; the token record names an identity and
  carries no policy; Entra later is validator config + the D2
  claims-derived rules on the same interface; the issued-JWT TTL is the
  revocation propagation bound [measured]. D12's watch stays armed inside
  D22's reversal condition.
- **Service round-trip latency under real load** (informs M2/M3): signing
  and mint requests ride NATS request/reply, and callout sits on the connect
  path for represented users; the MCP node's real usage will measure both.
  The reversal condition in journey 0001 names what happens if the
  per-operation assumption fails.

## One-way doors

| Door | Constraint |
|---|---|
| **Custody boundary.** | Once consumers rely on "seeds never leave", any API that returns key material — however convenient — is a constitution-I amendment, not a feature. |
| **Wire contract.** | The agent's JSON surface is mirrored in `client/`; the payload shapes survive the transport swap to NATS subjects (M3) — changes after M2 must stay compatible or version the subject space. |
| **Vault record shape.** | Sealed `stored{}` records decode additively; a *required* binding on an existing kind (as D25 did to persona keys) means unbound records fail closed until re-imported — that re-import is the migration story, stated per change. The registry file door closed with the registry (D25, journey 0013). |
