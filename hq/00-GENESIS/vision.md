# SoulIdentity Vision

*Re-centered 2026-07-28 (constitution 1.1.0, journey 0002): the mission moved
from "a local ssh-agent for personas" to the identity plane below. The custody
property is unchanged; what changed is what the project is for and where it
lives.*

## What SoulIdentity is

SoulIdentity is **the identity plane of the Soulstream ecosystem**: the
representation of identity for humans and agents alike. It is a **service on
NATS** — consumers reach it over end-to-end encrypted request/reply, xkeys
sealing every payload and the caller's own NATS identity authenticating every
request — that holds the account signing keys and answers **sign and mint
requests instead of handing out keys**. Consumers name the identity they act
for and receive signatures and minted credentials; the seeds never cross the
API.

Its central job is representation. An identity that exists outside NATS — an
Entra or OIDC principal, an API token, an agent operated on someone's behalf —
is given a real NATS identity with the right permissions, minted from the
account signing keys in the vault. Acting *as* someone is a first-class,
audited operation: the registry says who may be represented by whom, and every
mint and signature is attributable and logged. The NATS server remains the
verifier of record for everything a minted credential claims.

The custody analogy survives from genesis: like an ssh-agent, SoulIdentity
signs instead of handing out keys. A compromised consumer can *request*
signatures while inside — every request logged and attributable — but can
never exfiltrate a key.

## The founding bet

The "what is needed for a working soulidentity" list stays short. A working
soulidentity is exactly:

1. A vault: named seeds behind a pluggable storage backend, encrypted at rest
   (files today; NATS KV with xkey envelope encryption is the named next
   backend).
2. A registry: declared identities — who exists, which personas they may act
   as, which role mints for them.
3. A service surface answering sign and mint requests — **on NATS, with
   xkey-sealed payloads, as the primary surface**; a local socket remains for
   the bootstrap and laptop case, because the first NATS connection cannot be
   signed through a service reached over that same connection.
4. The NATS server enforcing everything else.

Nothing else. No PKI, no session state, no permission engine — the NATS
server is the verifier of record, and permissions live in the scoped signing
keys and callout-issued JWTs the server already checks. If a future addition
doesn't survive this list staying this short, it becomes a pluggable backend
or it goes nowhere.

## Who it is for

Humans and agents that need to *be someone* inside NATS: operators of
Soulstream realms and personas, teams whose AI clients arrive through a shared
node, and outside-world identities — Entra, OIDC, API tokens — that must be
represented inside the system with the right identity and permissions. The
deployment ladder — local socket for one operator on a laptop → the NATS
service surface for shared infrastructure → auth callout as the front door
for external identities — climbs with the deployment, on one identity
registry. Nobody is forced up a rung the simple case doesn't need.

## Where it is pointed

The design decisions (D1–D11) live in
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md); the sequencing in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md):

- **The NATS service surface** — the vault, registry, and mint reached over
  xkey-sealed request/reply, the caller authenticated by its NATS identity.
  Act-as policy becomes enforced rather than declared.
- **Auth callout** — the front door for external identities: SoulIdentity as
  the NATS auth-callout issuer, validating Entra/OIDC/API-token users against
  pluggable backends and issuing ephemeral credentials the server enforces.
- **KV-backed vault storage** — seeds in NATS KV, xkey envelope encryption at
  rest, through the D10 storage seam.
- **Attestation issuance** — the operator's key lives here, so Soulstream's
  countersigned `operated_by` tokens are naturally issued here.
- **Sealing keys** — held and used to unwrap epoch keys once; never a
  per-message decrypt oracle.
- **The local socket** — shipped first as the walking skeleton; stays as the
  bootstrap and laptop rung, not the destination.

## What we refuse to become

- **A KMS.** Crypto storage is commodity; backends (file keystore, NATS KV,
  OS keychain, Vault transit) plug in. The Soulstream-specific value is the
  persona model, act-as policy, and minting logic — never storage internals.
- **A parallel permission system.** The NATS server enforces transport
  permissions via scoped signing keys and callout JWTs. A policy store
  consulted *instead of* the server is a second source of truth; ours is only
  ever the backend of what the server enforces.
- **An identity provider.** We *represent* external identities inside NATS;
  we never become the thing that authenticates them. Authentication backends
  (Entra/OIDC, LDAP, a KV of API tokens) plug into callout mode; we implement
  none of them ourselves.
- **A required component for local sessions.** Soulstream works without
  SoulIdentity — local sessions with local key files remain first-class.
  SoulIdentity is what makes *shared* infrastructure and *external*
  identities honest, not a new dependency for the laptop case.
- **A silent secret conduit.** A seed leaves the vault through exactly one
  door — explicit credential export — and that door is named, logged, and
  loud. Any design where a secret moves as a side effect is wrong.

## How ambition stays honest

Load-bearing decisions carry numbered entries in the design doc with their
reasoning and, where directional, their reversal conditions — a future
reversal is a clean, anticipated turn instead of drift. This re-centering is
itself such a turn: journey 0002 records the argument both ways and the
condition under which the NATS-native surface demotes again. Claims carry
evidence classes, and only `[measured]` closes a debate. The full discipline
lives in [`constitution.md`](constitution.md) and
[`how-we-work.md`](how-we-work.md).
