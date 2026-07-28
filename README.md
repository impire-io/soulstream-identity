# SoulIdentity

**The identity plane for the
[Soulstream](https://github.com/impire-io/soulstream) ecosystem.**
SoulIdentity is the representation of identity for humans and agents: a
service that holds account signing keys, user keys, and persona
record-signing keys, and answers *sign and mint requests* instead of handing
out keys. Consumers name the identity they act for and receive signatures and
minted NATS credentials; the seeds never cross the API. Identities arriving
from the outside world — Entra/OIDC principals, API tokens — get represented
inside NATS with the right identity and permissions, every mint attributable.

The surface is NATS-native — request/reply with xkey-sealed end-to-end
encryption, the caller authenticated by its own NATS identity — and it is
the only one. Operations live on the caller's own subject prefix
(`soulidentity.<account>.<user>.<op>`), and the claim is trustworthy because
the server's publish permissions only let the rightful identity use it.
Connections follow a two-lane ladder: bring your own creds file (the
self-custody bypass — used directly whenever presented, SoulIdentity out of
the path) or bring an external token and arrive through auth callout
(the next milestone).

The design — the decisions and their reasoning — lives in
[hq/02-DESIGN/](hq/02-DESIGN/README.md). **How this project is run
lives in [hq/](hq/README.md)** — vision and constitution
([hq/00-GENESIS/](hq/00-GENESIS/README.md)), the roadmap
([hq/03-IMPLEMENTATION/ROADMAP.md](hq/03-IMPLEMENTATION/ROADMAP.md)), and the
journey log ([hq/04-JOURNEY/](hq/04-JOURNEY/README.md)); agents start at
[AGENTS.md](AGENTS.md).

## Quick start

```sh
go install github.com/impire-io/soulidentity/cmd/soulidentity@latest

# Operator, once: mint the two xkeys into your secret store —
# the vault's first key and the surface key (seed on stdout):
export SOULIDENTITY_FIRST_KEY=$(soulidentity keygen)
export SOULIDENTITY_SURFACE_KEY=$(soulidentity keygen)

# Run the service on its NATS connection (creds file = the bypass lane).
# The vault lives in a KV bucket, sealed; the registry file declares who
# exists — including the first admin row:
soulidentity serve --creds-file ./service.creds --registry ./registry.json &

# As an admin identity, load your account's (scoped) signing key:
soulidentity key import --creds-file ./ops.creds --as AC...PUBKEY/ops \
  --name acme-persona-role --kind nats-account-signing-key --seed-file ./SA.nk

# Register an identity: who it is, which personas it may act as,
# which role (vault key) mints its credentials:
soulidentity identity add --creds-file ./ops.creds --as AC...PUBKEY/ops \
  --account AC...PUBKEY --user daan --personas daan,smith --role acme-persona-role

# Mint daan's creds (the explicit custody escape — self-custody onboarding):
soulidentity mint --creds-file ./ops.creds --as AC...PUBKEY/ops \
  --account AC...PUBKEY --user daan --creds > daan.creds
```

Signing a Soulstream record from Go — the persona key never leaves the vault,
and the service enforces who may act as which persona:

```go
nc, _ := nats.Connect(url, nats.UserCredentials("daan.creds"))
c := client.New(nc, "AC...PUBKEY", "daan")
sig, _ := c.SignRecord("daan", canonicalBytes)
```

## What it is not

Not a KMS (storage backends are pluggable; NATS KV with xkey envelope
encryption is the initial backend), not an identity
provider (external identities are represented, never authenticated by us —
authn backends plug into callout mode), not an authorization server for your
realm (NATS enforces transport permissions via scoped signing keys or auth
callout; SoulIdentity decides only who may act as which persona), and not a
place secrets leave: credential export exists solely as an explicit, named
custody escape.

## Status

Milestone 3 — the NATS-native rebuild. The sealed service surface, the vault
on NATS KV with envelope encryption at rest, act-as enforced against the
server-proven caller, and an audit log that names real principals — proven
end to end against an embedded NATS server in operator mode (unauthorized
act-as refused, wire and store ciphertext-only, cross-prefix requests
refused by the server itself). The milestone-1 socket agent, file keystore,
and nonce oracle are retired. See
[hq/03-IMPLEMENTATION/ROADMAP.md](hq/03-IMPLEMENTATION/ROADMAP.md) for what
comes next (auth callout as the front door with claims-derived
authorization, then consumers wiring in; attestation issuance, sealing
keys).

## License

MIT.
