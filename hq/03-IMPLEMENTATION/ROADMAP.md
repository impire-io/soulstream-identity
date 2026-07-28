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

## Milestones

1. ✅ **M1 — walking skeleton** (shipped 2026-07-28). Local agent à la
   ssh-agent: file vault, declared identities, nonce oracle, scoped minting,
   explicit creds escape. Realizes D1, D2, D4 (mint rung), D5, D7, D8, D10
   (file backend).
2. **M2 — consumers wire in.** The Soulstream `Signer` seam (soulstream
   feature 017) consumes `sign/record`; the remote MCP node consumes
   `NATSOption` with its per-user connection pool. Gate: a Soulstream record
   signed through the agent verifies in the realm [measured]; the node holds
   one pooled connection per user. This milestone lives mostly in the
   consuming repos; here it may add only what those consumers prove missing.
3. **M3 — caller authentication.** TCP listener + per-caller identity
   (tokens or mTLS), turning act-as policy (D6) from declared into enforced;
   audit entries gain the caller. Gate: an unauthorized act-as request is
   refused and logged [measured]. Design doc precedes build.
4. **M4 — auth callout.** SoulIdentity as the NATS auth-callout issuer with
   pluggable authn backends (KV first), issuing ephemeral JWTs — the third
   rung of D4. Gate: a callout-authenticated connection with server-enforced
   permissions [measured], against self-hosted NATS. Needs research first on
   the NGS side (below).
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
  planning begins.
- **Oracle latency under real load** (informs M2): the per-operation signing
  round-trip is assumed cheap on a local socket; the MCP node's real usage
  will measure it. The reversal condition in journey 0001 names what happens
  if the assumption fails.

## One-way doors

| Door | Constraint |
|---|---|
| **Custody boundary.** | Once consumers rely on "seeds never leave", any API that returns key material — however convenient — is a constitution-I amendment, not a feature. |
| **Wire contract.** | The agent's JSON surface is mirrored in `client/`; changes after M2 must stay compatible or version the path (`/v1/`). |
| **Registry file shape.** | Strict-decoded; additive fields require a migration story for existing data dirs. |
