# SoulIdentity — the agent design

*An ssh-agent for personas: an identity vault, a signing oracle, and a NATS
credential minter for the Soulstream ecosystem. Decisions below are numbered
D1–D10; each records its reasoning so it can be re-argued honestly later.
Milestone status lives in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md).*

## What it is

SoulIdentity is a small daemon that holds every secret an operator's personas
need — NATS account signing keys, NATS user keys, persona Ed25519
record-signing keys, later X25519 sealing keys — behind a socket, and answers
**sign requests instead of handing out keys**. Consumers (the Soulstream CLI,
MCP servers, the future remote MCP node) authenticate to the agent, name the
identity they act for, and receive signatures and minted credentials. The
seeds never cross the API.

The shape is deliberately ssh-agent's: a local Unix socket where filesystem
permissions are the authentication, a vault directory owned by the OS user,
and a client library that plugs the oracle into the places that used to read
key files. A remote/TCP mode with real authentication layers on later without
changing the model — the socket is just the first, simplest boundary.

## Why it exists

Two forces converged (Soulstream journey, 2026-07-28 design thread):

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

## D1 — Nonce signing is the native seam

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

## D2 — Identities are declared, never inferred

An identity is registered as `{account, user, allowed personas, role}` —
keyed by **(account, user)**, never by bare name, so multi-account vaults
stay unambiguous. Which account a user belongs to is decided at registration
(minting *is* the assignment; the minted JWT's `issuer_account` carries it),
not detected. The only inference-shaped problem — does this signing key
actually belong to that account? — is not ours to enforce:

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
   pluggable backend (KV, OIDC, LDAP, …) and issues **ephemeral** user JWTs.
   For dynamic fleets and external identity providers.

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

Minted user keys are generated inside the vault and stay there; connecting
uses the JWT plus the nonce oracle, so the standard flow never materialises
a creds file. For tools that need one (`nats` CLI), export exists as an
**explicit custody escape** (`export_creds`), named as such in the API — the
operator chooses to move a secret out of custody; it never happens as a side
effect.

## D8 — Local mode's principal is the OS user

Milestone 1 authenticates the way ssh-agent does: socket mode 0600, vault
dir 0700 — whoever owns the socket owns the agent. Claimed identities on the
local socket are honour-system within that boundary and every operation is
still logged. Real per-caller authentication (tokens, mTLS) arrives with the
TCP listener; the API shape already carries the identity parameter so
nothing changes but the checking.

## D9 — Sealed topics: unwrap once, no decrypt oracle

When sealed topics land, long-lived X25519 sealing keys belong in the vault
and are used *rarely*: to unwrap an epoch key. The symmetric epoch key —
already a shared group secret, not an identity — is then released to the
member's session for message decryption. Per-message decryption through an
oracle is a non-goal; nobody should later design one by symmetry.

## D10 — Storage backends are pluggable; the vault is not a KMS

The Soulstream-specific value is the persona model, act-as policy, and
minting logic. Crypto storage is commodity: milestone 1 is a file keystore
(0600 seed files, matching `soulstream key init` conventions); the backend
interface is the extension point for OS keychains or a Vault transit engine
later. SoulIdentity wraps storage, it does not reimplement it.

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

Out of scope for milestone 1: TCP listener + caller authentication, auth
callout, attestation issuance, sealing keys, non-file storage backends —
each has a decision above naming its direction.
