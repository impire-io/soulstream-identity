# SoulIdentity — the agent design

*The identity plane of the Soulstream ecosystem: an identity vault, a signing
oracle, and a NATS credential minter, delivered as a NATS service. Decisions
below are numbered D1–D13; each records its reasoning so it can be re-argued
honestly later. Milestone status lives in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md).*

## What it is

SoulIdentity is the representation of identity for humans and agents in the
Soulstream ecosystem. It holds every secret its identities need — NATS
account signing keys, NATS user keys, persona Ed25519 record-signing keys,
later X25519 sealing keys — and answers **sign and mint requests instead of
handing out keys**. Consumers (the Soulstream CLI, MCP servers, the remote
MCP node, the NATS server itself in callout mode) authenticate, name the
identity they act for, and receive signatures and minted credentials. The
seeds never cross the API.

The surface is NATS-native and it is the only one (D11): request/reply with
xkey-sealed payloads, the caller authenticated by its own NATS identity.
There is no socket. The pre-NATS moment is answered by the connection ladder
(D12), not a local surface: a client presenting a creds file in its
connection options connects directly — the server verifies it natively and
SoulIdentity is not in the path — while a client presenting an external
token arrives through auth callout. The shipped walking skeleton's socket
surface is transitional and retires when the NATS surface lands (M3).

## Why it exists

Three forces converged (Soulstream journey, 2026-07-28 design thread; the
third named at the 2026-07-28 re-centering, journey 0002):

1. **Remote MCP.** Claude Desktop, LibreChat, claude.ai connectors and most
   non-CLI clients speak remote MCP, so `soulstream-mcp` must run as a shared
   node. A node serving several users must hold credentials for all of them —
   raw key possession by the node would make node compromise equal to
   identity theft. An oracle bounds that: a compromised node can *request*
   signatures while inside — every request logged and attributable — but can
   never exfiltrate a key.
2. **Per-user NATS identity.** The node pools NATS connections **per user**
   (sessions of one user share a connection) so NATS-level permissions stay
   real — defense in depth beside the Soulstream signature, and the layer the
   sealed-topics design leans on for subject restrictions. Per-user
   connections need per-user credentials, which something must mint and hold.
3. **External identities.** Humans and agents arrive with outside-world
   identities — an Entra/OIDC principal, an API token — and must be
   *represented* inside NATS: the right identity, the right permissions,
   minted from the account signing keys and fully attributable. Something
   that already holds those keys and the act-as registry is the natural
   place; this is what moved representation from a later rung to the mission
   (journey 0002).

## D1 — Nonce signing is the local seam

NATS NKey authentication is challenge-response: the server sends a nonce, the
client signs it. `nats.go` accepts the signature as a **callback**
(`nats.Nkey(pub, sigCB)`, `nats.UserJWT(jwtCB, sigCB)`) precisely so the seed
can live elsewhere. SoulIdentity implements that callback over the agent
socket. No fork, no patched client — the oracle plugs into the seam the
client library ships with.

The same pattern extends up one layer: Soulstream record signing becomes
"sign these canonical bytes as persona X" (the `Signer` seam in the
soulstream library, feature 017). One agent, two signature kinds, one audit
trail.

*Amended 2026-07-28 (journey 0002): demoted from "the native seam" to the
local one.* The nonce oracle only works over a non-NATS transport — a client
cannot reach a NATS-hosted oracle to sign the nonce of the very connection it
is establishing [mechanism-argument].

*Amended again the same day (journey 0003): with the socket dropped (D12),
the nonce oracle leaves the connection story entirely.* Connections are
creds-bypass or callout — nothing signs nonces through SoulIdentity anymore.
What survives of D1 is the layer above: record signing ("sign these
canonical bytes as persona X") stays a signing-oracle request, served over
the NATS surface on an already-established connection. The `NATSOption`
client seam built in milestone 1 is superseded with the socket.

## D2 — Identities are declared or verifiably claimed, never guessed

An identity is registered as `{account, user, allowed personas, role}` —
keyed by **(account, user)**, never by bare name, so multi-account vaults
stay unambiguous. Which account a user belongs to is decided at registration
(minting *is* the assignment; the minted JWT's `issuer_account` carries it),
not detected.

*Amended 2026-07-28 (journey 0003): the registry is one source of the
act-as/mint decision, not the only one.* The second source is a **validated
claim** carried by the connection credential itself — a JWT passed in the
token connection option, its issuer on an allow-list, signature and audience
checked — from which the team is deduced: which role, which permissions,
which personas. This runs naturally in callout mode, where the credential is
in hand at the moment of decision. It is not inference: nothing is guessed;
an identity is either *declared* (a registry row) or *verifiably claimed* (a
validated token), and the mapping rules — which issuers are trusted, which
claim names the team, which team maps to which role — are themselves
declared configuration. The trust delegated to a token issuer is delegated
deliberately, per backend. The one inference-shaped problem that remains —
does this signing key actually belong to that account? — is still not ours
to enforce:

## D3 — Binding verification is diagnostic, optional, never a gate

The NATS server is the verifier of record: a user JWT minted from a key that
is not in the account's `signing_keys` is rejected at connection time — the
failure is closed. Load-time verification (fetch the account JWT, check the
key appears) adds no security and can drift the day after it passes. So it
is a **warn-level convenience**: verify when the account JWT is reachable,
warn on mismatch, never hard-fail. Air-gapped prep and pre-provisioning
loads stay legal.

## D4 — Two enforcement modes, one registry

Deployments climb a ladder; the identity registry is the same at every rung:

1. **Shared node creds** — zero setup, no per-user transport identity. The
   degraded floor, stated as such.
2. **Mint mode** — durable user JWTs signed by *account signing keys held in
   the vault*. The simple self-custody path: load your account's signing
   key(s), register identities, mint.
3. **Auth-callout mode** — SoulIdentity (or a plugin behind it) acts as the
   NATS auth-callout service: it validates the connecting user against a
   pluggable backend (KV of API tokens, Entra/OIDC, LDAP, …) and issues
   **ephemeral** user JWTs. *Amended 2026-07-28 (journey 0002): this rung is
   the flagship, not the ceiling* — it is the front door through which
   external identities get represented inside NATS, and the callout protocol
   is already a NATS service speaking xkey-encrypted payloads, i.e. the same
   shape as the primary surface (D11).

*Amended again the same day (journey 0003): the ladder collapses into the
two-lane road of D12.* A client with a creds file connects directly —
server-verified, SoulIdentity out of the path (rung 1's shared-node-creds
floor disappears: a node no longer needs shared creds, it passes each user's
token through callout). A client with an external token goes through callout,
authorized by registry or claims (D2). Mint mode stops being a *connection*
mode: minting durable JWTs remains a service function whose output — an
exported creds file, through the loud D7 escape — is exactly how an operator
obtains their bypass credentials.

A policy KV consulted *instead of* NATS enforcement would be a second source
of truth; the same KV as the *backend of the callout issuer* is the native
model — the server enforces what the issuer decides. That is the answer to
"is this against the NATS way of minting users": SoulIdentity *becomes* the
minter, in whichever mode the deployment picks.

## D5 — Scoped signing keys carry the NATS permissions

In mint mode, permission policy lives NATS-side: the account defines
**scoped signing keys** (roles with permission templates), and any user JWT
signed by a scoped key gets exactly the scope's permissions — enforced by
the server, impossible to exceed at mint time. SoulIdentity's mint decision
reduces to "which scoped key = which role" (`role` on the identity record
names the vault key). The registry then holds only what is genuinely
Soulstream-level: **which identity may act as which persona**. Transport
permissions native, act-as policy ours.

## D6 — Act-as is the runtime shadow of `operated_by`

Soulstream 014 made operator accountability a countersigned, static claim
(`operated_by` + attestation). The agent's act-as grant is the same fact at
runtime: the registry says which authenticated identity may sign as which
persona, every signature request is checked against it and logged. The agent
is also the natural issuer of attestation tokens — the operator's key lives
here. Static claim in the registry (the realm's), runtime enforcement in the
agent (the operator's).

## D7 — Custody is honest, and export is explicit

Minted user keys are generated inside the vault and stay there; export
exists as an **explicit custody escape** (`export_creds`), named as such in
the API — the operator chooses to move a secret out of custody; it never
happens as a side effect.

*Amended 2026-07-28 (journey 0003):* the escape is now also the front door
of the bypass lane (D12) — an exported creds file is how an operator obtains
self-custody credentials, so export is a legitimate end state for an
identity's *owner*, still explicit and loudly logged. The custody property
Constitution I protects sharpens rather than weakens: *represented*
identities — external users, agents on shared infrastructure — never touch
key material at any point; in callout the client's key is its own and only
an ephemeral JWT is issued for it. (The original "the standard flow never
materialises a creds file" claim described the nonce-oracle flow, which left
the connection story with D1.)

## D8 — Local mode's principal was the OS user (superseded)

*Superseded 2026-07-28 (journey 0003, D12): there is no socket and no local
mode; the principal is always the caller's NATS identity.* Recorded for
history: milestone 1 authenticated the way ssh-agent does — socket mode
0600, vault dir 0700, whoever owns the socket owns the agent, claimed
identities honour-system within that boundary, every operation logged. The
2026-07-28 re-centering first demoted the socket to a bootstrap rung
(journey 0002), then dropped it hours later when the creds-file bypass
proved the better answer to the pre-NATS moment (D12). The API shape carries
the identity parameter throughout, so the NATS surface changes the checking,
not the contract.

## D9 — Sealed topics: unwrap once, no decrypt oracle

When sealed topics land, long-lived X25519 sealing keys belong in the vault
and are used *rarely*: to unwrap an epoch key. The symmetric epoch key —
already a shared group secret, not an identity — is then released to the
member's session for message decryption. Per-message decryption through an
oracle is a non-goal; nobody should later design one by symmetry.

## D10 — Storage backends are pluggable; the vault is not a KMS

The Soulstream-specific value is the persona model, act-as policy, and
minting logic. Crypto storage is commodity: the backend interface is the
extension point. *Amended 2026-07-28 (journeys 0002–0003): NATS KV with xkey
envelope encryption at rest is the vault's **initial** backend* — seeds
stored only as ciphertext in a KV bucket, unwrapped inside the vault
process; the milestone-1 file keystore (0600 seed files, matching
`soulstream key init` conventions) is transitional and retires with the
NATS-native rebuild (M3). Stated honestly: envelope encryption relocates the
root secret, it does not eliminate it — the unwrapping xkey seed and the
service's own NATS creds are the only local secrets, and the first-key story
was researched and decided as D13 (journey 0004). OS keychains and a Vault
transit engine remain later options. SoulIdentity wraps storage, it does not
reimplement it.

## D11 — The service surface is NATS-native

*Decided 2026-07-28 at the identity-plane re-centering (journey 0002),
superseding the planned TCP listener.* SoulIdentity's primary surface is a
NATS service: request/reply on its own subject space, every payload sealed
end-to-end with xkeys (the caller encrypts to the service's curve key and
vice versa, so not even the NATS server sees request bodies), and the caller
authenticated by its own NATS identity — which becomes the principal that
act-as policy (D6) is enforced against and that audit entries name.

Why NATS instead of the TCP-plus-tokens listener the genesis planned
[mechanism-argument]:

- **Caller authentication comes free and is the same trust fabric.** A TCP
  listener needs a parallel credential scheme (tokens, mTLS) — a second
  identity system inside an identity project. On NATS the caller already
  *is* an authenticated identity the server verified.
- **It is the shape callout already has.** Auth-callout mode (D4 rung 3) is
  by protocol a NATS service receiving xkey-encrypted requests. One surface
  shape serves both the API and the callout duty.
- **It composes with the ecosystem.** Consumers of SoulIdentity are NATS
  clients already; a NATS surface needs no new listener, port, or TLS story.

The strongest argument against, recorded at full strength: the bootstrap.
The minter of NATS credentials cannot itself require NATS credentials to
reach — so the NATS surface can never be the *only* surface. The answer is
the ladder (D4, D8): the local socket serves the pre-NATS moment and the
laptop case, callout's sentinel-credential flow serves external identities,
and durable minted creds serve everything in between. Additionally, callout
requires server-config control — self-hosted yes, managed NATS (NGS) an open
research question on the roadmap.

**Reversal condition** (written at decision time): if, by the time the first
external consumer needs external-identity onboarding, auth callout cannot be
enabled on the deployment class consumers actually run (the NGS research
verdict [measured]) or a sentinel-credential onboarding of an external
identity cannot pass an end-to-end proof [measured], the NATS-native surface
demotes to an optional mode and the local socket returns to the primary
surface.

*Amended 2026-07-28 (journey 0003): the surface is NATS-only.* The
bootstrap answer above ("the local socket serves the pre-NATS moment")
lasted hours: the creds-file bypass is the better answer (D12), and the
socket is dropped rather than demoted. The reversal condition stands, with
D12 adding its own: a consumer class that fits neither lane brings a
pre-connection local surface back as a new decision.

## D12 — The connection ladder: creds bypass or callout, nothing between

*Decided 2026-07-28 (journey 0003), superseding the socket-as-bootstrap-rung
answer recorded hours earlier (journey 0002).* How anything connects to NATS
in a SoulIdentity deployment is exactly one of two lanes:

- **Creds bypass.** A client that presents a creds file (or nkey seed) in
  its connection options connects directly; the server verifies it natively
  and SoulIdentity is not in the path. This is the self-custody lane:
  operators, break-glass, the laptop case, and SoulIdentity's own service
  connection. Creds are obtained through the loud export escape (D7) or
  external tooling (`nsc`).
- **Callout.** A client that presents an external credential — a JWT in the
  token connection option, an API token — is authenticated by SoulIdentity
  as the auth-callout issuer: the credential is validated, the team deduced
  (registry-declared or claims-derived — D2), and an ephemeral user JWT is
  issued for the client's own key.

Auth-callout configuration is where the line is drawn: the server's callout
config names the users exempt from callout (the bypass lane, verified
natively), and every other connection in scope goes through the issuer —
this is the native NATS callout shape, not machinery we build
[mechanism-argument].

Argued against at full strength before deciding. First: the bypass lane is
raw key possession — the thing the genesis warns about. Answer: possession
by the identity's *owner* is self-custody, not a custody leak; what
Constitution I protects is that *represented* identities never touch key
material, and in the callout lane they never do. Second: callout on the
connect path couples represented users' connection availability to
SoulIdentity's availability [mechanism-argument]. Answer: accepted as the
cost of representation; the bypass lane is unaffected, and operators always
have the break-glass path.

**Reversal condition** (written at decision time): if a consumer class
emerges that can neither hold a creds file nor present a
callout-validatable credential (observable: a consumer integration blocked
at connection, recorded as an issue), a pre-connection local surface
returns as a new D-decision. If claims-derived mapping ends up re-creating
the registry row by row (observable: per-user mapping exceptions
accumulating in configuration), claims-derived authorization demotes to a
bootstrap convenience and the registry returns as the sole policy source.

## D13 — The first key: a local file, named honestly

*Decided 2026-07-28 by research graduation (`first-key-story`, journey
0004).* The unwrapping xkey for the KV backend's envelope encryption (D10)
lives in a **local file, mode `0600`, beside the service's own creds file**
— the raw `SX…` curve seed, minted by the service itself on first start and
refused overwrite thereafter. Stated without euphemism: the root secret is a
plaintext file on the service host, readable by the service user and root —
exactly the trust class of `service.creds` next to it. What the envelope
buys is not local-host protection; it is that the KV bucket — broker disks,
replicas, backups, anything account-credentialed — never holds a plaintext
seed [measured, journey 0004].

The bootstrap, from nothing, is two operator acts and one automatic service
act [measured]:

1. **Operator:** provision the realm — the service's account and its creds
   file, the one artifact that crosses a machine boundary (`nsc` or the
   mint escape, D7).
2. **Operator:** start the deployment (server reachable, JetStream on).
3. **Service, first start:** mint the xkey into its file, create the KV
   bucket. The first key never leaves the host it was minted on.

Alternatives are recorded in the graduation table (journey 0004): OS
keychains fail headless deployments, passphrase-derivation fails unattended
restart or degrades into this file, and a KMS moves the same root secret one
indirection away at the cost of an external system — those remain later
backends on D10's ladder, re-opened per deployment class if one cannot hold
a `0600` file. Rotation is a named operation — mint a new xkey, walk the
bucket re-sealing — even while M3 ships without automating it.

**Reversal condition** (from the graduation): a deployment class blocked on
read-only or secretless hosts (recorded as an issue) re-opens the
keychain/KMS rows as that class's home.

## Milestone 1 — the walking skeleton

- `internal/vault` — file-backed keystore: NATS nkey seeds (account signing
  keys, user keys) and persona Ed25519 seeds; import/list/sign; seeds are
  write-only through the API.
- `internal/registry` — identity records `{account, user, personas, role}`,
  strict-decoded JSON, act-as checks.
- `internal/mint` — user JWTs signed by the identity's role key
  (`issuer_account` set, permissions left to the scope), user keys generated
  in-vault; explicit creds export.
- `internal/agent` + `cmd/soulidentity serve` — HTTP over a Unix socket:
  status, keys, identities, sign-nonce, sign-record, mint.
- `client` — Go client for the socket plus `NATSOption(account, user)`
  returning a `nats.Option` whose JWT and signature callbacks run through
  the agent (the seam the remote MCP node consumes).
- End-to-end proof: an embedded NATS server in operator mode (memory
  resolver, account with a scoped signing key), a vault-minted user JWT, and
  a connection whose nonce is signed by the agent — the seed never leaving
  the vault [measured, in the test suite].

Out of scope for milestone 1 (and shipped without them): the NATS service
surface (D11), auth callout, attestation issuance, sealing keys, the KV
storage backend — each has a decision above naming its direction. After the
same-day re-centering (journeys 0002–0003), the skeleton's socket surface,
`NATSOption` client seam, and file keystore are transitional — they work as
shipped and retire with the NATS-native rebuild (M3); the vault, registry,
and mint internals carry forward unchanged.
