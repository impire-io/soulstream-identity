# SoulIdentity Vision

*Re-centered 2026-07-28 (constitution 1.1.0 → 1.2.0, journeys 0002–0003): the
mission moved from "a local ssh-agent for personas" to the identity plane
below — NATS-only, no socket. The custody property is unchanged; what changed
is what the project is for and where it lives.*

*Refreshed 2026-07-29 (journeys 0013–0016, D25–D27): the ecosystem speaks
**one noun — persona** — for the represented subject, human or agent alike
(soulstream fixed the term; we adopt it). The server-proven (account, user)
a connection speaks as is the **principal** (D15's word), never a second
identity concept. Identity truth lives in the deployment's IAM; personas
are ephemeral — born at first encounter, their durable artifacts
materializing in the vault on first touch — and there is no registry of
them anywhere: the vault that custodies their keys is the directory.*

## What SoulIdentity is

SoulIdentity is **the identity plane of the Soulstream ecosystem**: the home
of the persona — human or agent, one noun, equally first-class. It is a
**service on NATS** — consumers reach it over end-to-end encrypted
request/reply, xkeys sealing every payload and the caller's own NATS
principal authenticating every request — that holds the personas' keys and
answers **sign and mint requests instead of handing out keys**. Consumers
name the persona they act for and receive signatures and minted
credentials; the seeds never cross the API.

Its central job is representation. A subject that exists outside NATS — an
Entra or OIDC subject, an API token, an agent operated on someone's behalf —
is given a real NATS principal with the right permissions, minted from the
account signing keys in the vault; its persona's durable artifacts (the
signing key today, the sealing key when sealed topics land) materialize in
the vault the first time they are needed, owner-bound, with no per-persona
provisioning act anywhere (D26). Every mint and signature is attributable
and logged against the server-proven principal. The NATS server remains
the verifier of record for everything a minted credential claims.

Not every connection goes through it. A client that presents its own creds
file in its connection options connects to NATS directly — the self-custody
bypass for operators — and SoulIdentity is simply not in that path.
Representation is for subjects that do not carry NATS credentials of their
own; auth-callout configuration is where that line is drawn.

The custody analogy survives from genesis: like an ssh-agent, SoulIdentity
signs instead of handing out keys. A compromised consumer can *request*
signatures while inside — every request logged and attributable — but can
never exfiltrate a key.

## The founding bet

The "what is needed for a working soulidentity" list stays short. A working
soulidentity is exactly:

1. A vault: named seeds behind a pluggable storage backend, encrypted at
   rest — **NATS KV with xkey envelope encryption is the initial backend**
   (the milestone-1 file keystore is transitional; the unwrapping xkey and
   the service's own creds are the only local secrets).
2. A policy surface: the **declared bindings** (D25) — a persona key
   carries its owner principal, a team key the account it signs for — plus
   the **token records** and **validated claims** carried by the connection
   credential. Declared or verifiably claimed, never guessed; op-level
   reach is the transport ACL's, and no separate ledger restates what the
   bindings already say.
3. A service surface answering sign and mint requests — **on NATS, with
   xkey-sealed payloads, and nothing else: there is no socket**. The
   pre-NATS moment is answered by the connection ladder, not a local
   surface: bring your own creds file (the self-custody bypass, used
   directly whenever presented) or bring an external token and arrive
   through auth callout.
4. The NATS server enforcing everything else.

Nothing else. No PKI, no session state, no permission engine — the NATS
server is the verifier of record, and permissions live in the scoped signing
keys and callout-issued JWTs the server already checks. If a future addition
doesn't survive this list staying this short, it becomes a pluggable backend
or it goes nowhere.

## Who it is for

Humans and agents that need to *be someone* inside NATS: operators of
Soulstream realms, teams whose AI clients arrive through a shared node, and
outside-world subjects — Entra, OIDC, API tokens — whose personas must be
represented inside the system with the right permissions. The connection
ladder is two rungs wide: bring your own creds file (self-custody —
operators, the laptop case, break-glass) or bring an external token and be
represented through auth callout. One policy surface serves both; nobody
who already owns their credentials is forced through SoulIdentity.

## Where it is pointed

The design decisions live in [`../02-DESIGN/`](../02-DESIGN/README.md); the
sequencing in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md):

- **The NATS-native rebuild** — the vault, policy surface, and mint reached
  over xkey-sealed request/reply, the caller authenticated by its NATS
  identity, and the vault on its initial backend (NATS KV, xkey envelope at
  rest). The milestone-1 socket surface and file keystore retire with it.
- **Auth callout** — the front door for external identities: SoulIdentity as
  the NATS auth-callout issuer, validating Entra/OIDC/API-token users against
  pluggable backends — registry-declared or claims-derived — and issuing
  ephemeral credentials the server enforces. Callout config is also where the
  creds-file bypass is drawn: a presented creds file is verified natively by
  the server, SoulIdentity out of the path.
- **Attestation issuance** — the operator's key lives here, so Soulstream's
  countersigned `operated_by` tokens are naturally issued here.
- **Sealing keys** — held and used to unwrap epoch keys once; never a
  per-message decrypt oracle.

## What we refuse to become

- **A KMS.** Crypto storage is commodity; backends (file keystore, NATS KV,
  OS keychain, Vault transit) plug in. The Soulstream-specific value is the
  persona model, act-as policy, and minting logic — never storage internals.
- **A parallel permission system.** The NATS server enforces transport
  permissions via scoped signing keys and callout JWTs. A policy store
  consulted *instead of* the server is a second source of truth; ours is only
  ever the backend of what the server enforces.
- **An identity provider.** We *represent* external subjects inside NATS;
  we never become the thing that authenticates them, and identity truth —
  who exists, who belongs — stays in the deployment's IAM. Authentication
  backends (Entra/OIDC, LDAP, a KV of API tokens) plug into callout mode;
  we implement none of them ourselves. Tested and held 2026-08-02
  (journey 0019): the ecosystem's default IdP is the sibling project
  soulfold — a standard OIDC issuer the callout issuer cannot
  distinguish from Entra.
- **A required component for local sessions.** Soulstream works without
  SoulIdentity — a creds file in hand connects directly (the bypass is
  first-class, not a workaround), and local sessions with local key files
  remain legitimate. SoulIdentity is what makes *shared* infrastructure and
  *external* identities honest, not a new dependency for whoever already
  owns their identity.
- **A silent secret conduit.** A seed leaves the vault through exactly one
  door — explicit credential export — and that door is named, logged, and
  loud. Any design where a secret moves as a side effect is wrong.

## How ambition stays honest

Load-bearing decisions carry numbered entries in the design doc with their
reasoning and, where directional, their reversal conditions — a future
reversal is a clean, anticipated turn instead of drift. This re-centering is
itself such a turn — twice in one day: journeys 0002 and 0003 record the
arguments both ways and the conditions under which the NATS-native surface
demotes again. Claims carry
evidence classes, and only `[measured]` closes a debate. The full discipline
lives in [`constitution.md`](constitution.md) and
[`how-we-work.md`](how-we-work.md).
