# Roadmap — milestones and gates

*The design ([`../02-DESIGN/agent.md`](../02-DESIGN/agent.md)) says what
SoulIdentity is; this document decides what gets built first and behind which
gate.*

## Where we are (2026-07-28)

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
   Soulstream `Signer` seam (soulstream feature 017) consumes `sign/record`
   over the NATS surface; the remote MCP node connects per user by passing
   each user's token through callout — the `NATSOption` socket seam it was
   originally planned against is superseded. Gate: a Soulstream record
   signed through the service verifies in the realm [measured]; the node
   holds one pooled connection per user with no node-held creds. This
   milestone lives mostly in the consuming repos; here it may add only what
   those consumers prove missing.
3. **M3 — the NATS-native rebuild.** The agent's contract served over NATS
   request/reply with xkey-sealed payloads, the caller's NATS identity as
   the principal (D11/D12) — turning act-as policy (D6) from declared into
   enforced, audit entries gaining the caller — **and** the vault on its
   initial backend, NATS KV with xkey envelope encryption at rest (D10).
   The milestone-1 socket surface, `NATSOption` seam, and file keystore
   retire in this milestone. Gate: an unauthorized act-as request over NATS
   is refused and logged, a request body is unreadable to the broker, and
   the vault operates against KV with only ciphertext ever stored
   [measured]. Design doc precedes build; the first-key story is decided —
   D13, a `0600` local file beside the service creds
   ([journey 0004](../04-JOURNEY/0004-first-key-story.md)).
4. **M4 — auth callout, the front door.** SoulIdentity as the NATS
   auth-callout issuer with pluggable authn backends (KV of API tokens
   first; Entra/OIDC next), issuing ephemeral JWTs for the client's own key
   — authorization registry-declared or claims-derived from the presented
   token (D2), the creds-file bypass drawn in callout config (D12). Gate: a
   connection authenticated by an external credential, with server-enforced
   permissions and the external identity attributable in the audit log, and
   a creds-file connection verified natively with SoulIdentity out of the
   path [measured], against self-hosted NATS. Needs research first on the
   NGS side, the sentinel-credential flow, and the claims-mapping shape
   (below).
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
- **The sentinel-credential flow** (gates M4): the exact bootstrap by which a
  client carrying only an external credential (Entra/OIDC token, API token)
  reaches the server so callout can fire — sentinel creds, bearer JWT, or
  token-in-password — proven end to end. The other half of D11's reversal
  condition.
- ~~**The first-key story** (gated M3)~~ — answered 2026-07-28
  ([journey 0004](../04-JOURNEY/0004-first-key-story.md), D13): a `0600`
  local file on the service host, minted at first start; bootstrap is two
  operator acts + one automatic service act [measured].
- **The claims-mapping shape** (gates M4): which token issuers are trusted,
  which claim names the team, how a team maps to a role and allowed
  personas — the declared configuration behind claims-derived authorization
  (D2). D12's reversal condition watches this one: mapping exceptions
  accumulating per user means the registry should have stayed the sole
  source.
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
| **Registry file shape.** | Strict-decoded; additive fields require a migration story for existing data dirs. |
