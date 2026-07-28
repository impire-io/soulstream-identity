# SoulIdentity Vision

## What SoulIdentity is

SoulIdentity is **an ssh-agent for personas**: a small daemon that holds every
secret an operator's personas need — NATS account signing keys, NATS user
keys, persona record-signing keys, later sealing keys — behind a socket, and
answers **sign requests instead of handing out keys**. Consumers name the
identity they act for and receive signatures and minted credentials; the
seeds never cross the API.

It exists for the [Soulstream](https://github.com/impire-io/soulstream)
ecosystem's move to shared infrastructure: a remote MCP node serving Claude
Desktop, LibreChat, and other clients must hold credentials for several users,
and raw key possession would make node compromise equal to identity theft. An
oracle bounds that — a compromised consumer can *request* signatures while
inside, every request logged and attributable, but can never exfiltrate a key.

## The founding bet

The "what is needed for a working soulidentity" list stays short. A working
soulidentity is exactly:

1. A vault: named seeds in files an OS user owns.
2. A registry: declared identities — who exists, which personas they may act
   as, which role mints for them.
3. A socket answering sign and mint requests.
4. The NATS server enforcing everything else.

Nothing else. No database, no PKI, no session state, no permission engine —
the NATS server is the verifier of record, and permissions live in the scoped
signing keys and callout-issued JWTs the server already checks. If a future
addition doesn't survive this list staying this short, it becomes a pluggable
backend or it goes nowhere.

## Who it is for

Operators of Soulstream realms and personas: one person running three personas
from a laptop today; a self-hosted node serving a team's AI clients tomorrow.
The deployment ladder — shared node creds → vault-minted from scoped signing
keys → auth callout with pluggable backends — climbs with the deployment, on
one identity registry. Nobody is forced up a rung the simple case doesn't
need.

## Where it is pointed

The design decisions (D1–D10) live in
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md); the sequencing in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md):

- **The local agent** — vault, registry, nonce oracle, minting. Shipped as the
  walking skeleton.
- **Caller authentication** — a TCP listener with real per-caller identity, so
  act-as policy becomes enforced rather than declared.
- **Auth callout** — SoulIdentity as the NATS auth-callout issuer, validating
  users against pluggable backends and issuing ephemeral credentials.
- **Attestation issuance** — the operator's key lives here, so Soulstream's
  countersigned `operated_by` tokens are naturally issued here.
- **Sealing keys** — held and used to unwrap epoch keys once; never a
  per-message decrypt oracle.

## What we refuse to become

- **A KMS.** Crypto storage is commodity; backends (file keystore, OS
  keychain, Vault transit) plug in. The Soulstream-specific value is the
  persona model, act-as policy, and minting logic — never storage internals.
- **A parallel permission system.** The NATS server enforces transport
  permissions via scoped signing keys and callout JWTs. A policy store
  consulted *instead of* the server is a second source of truth; ours is only
  ever the backend of what the server enforces.
- **A PKI or identity provider.** Authentication backends (OIDC, LDAP, a KV)
  plug into callout mode; we implement none of them ourselves.
- **A required component.** Soulstream works without SoulIdentity — local
  sessions with local key files remain first-class. The agent is what makes
  *shared* infrastructure honest, not a new dependency for the laptop case.
- **A silent secret conduit.** A seed leaves the vault through exactly one
  door — explicit credential export — and that door is named, logged, and
  loud. Any design where a secret moves as a side effect is wrong.

## How ambition stays honest

Load-bearing decisions carry numbered entries in the design doc with their
reasoning and, where directional, their reversal conditions — a future
reversal is a clean, anticipated turn instead of drift. Claims carry evidence
classes, and only `[measured]` closes a debate. The full discipline lives in
[`constitution.md`](constitution.md) and [`how-we-work.md`](how-we-work.md).
