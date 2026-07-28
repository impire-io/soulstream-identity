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
the only one. Connections follow a two-lane ladder: bring your own creds
file (the self-custody bypass — used directly whenever presented,
SoulIdentity out of the path) or bring an external token and arrive through
auth callout. What ships today is milestone 1's local socket agent, a
transitional surface that retires when the NATS-native rebuild lands.

The design — the decisions and their reasoning — lives in
[hq/02-DESIGN/agent.md](hq/02-DESIGN/agent.md). **How this project is run
lives in [hq/](hq/README.md)** — vision and constitution
([hq/00-GENESIS/](hq/00-GENESIS/README.md)), the roadmap
([hq/03-IMPLEMENTATION/ROADMAP.md](hq/03-IMPLEMENTATION/ROADMAP.md)), and the
journey log ([hq/04-JOURNEY/](hq/04-JOURNEY/README.md)); agents start at
[AGENTS.md](AGENTS.md).

## Quick start

```sh
go install github.com/impire-io/soulidentity/cmd/soulidentity@latest

soulidentity serve &                            # agent on the default socket

# Load your NATS account's (scoped) signing key into the vault:
soulidentity key import --name acme-persona-role \
  --kind nats-account-signing-key --seed-file ./SA.nk

# Register an identity: who it is, which personas it may act as,
# which role (vault key) mints its credentials:
soulidentity identity add --account AC...PUBKEY --user daan \
  --personas daan,smith --role acme-persona-role

# Mint a user JWT (the user key is generated inside the vault and stays there):
soulidentity mint --account AC...PUBKEY --user daan
```

Connecting to NATS from Go, with the nonce signed by the agent — no key file
anywhere:

```go
c := client.New(client.DefaultSocket())
opt, _ := c.NATSOption("AC...PUBKEY", "daan")
nc, _ := nats.Connect(url, opt)
```

## What it is not

Not a KMS (storage backends are pluggable; NATS KV with xkey envelope
encryption is the initial backend, the milestone-1 file keystore
transitional), not an identity
provider (external identities are represented, never authenticated by us —
authn backends plug into callout mode), not an authorization server for your
realm (NATS enforces transport permissions via scoped signing keys or auth
callout; SoulIdentity decides only who may act as which persona), and not a
place secrets leave: credential export exists solely as an explicit, named
custody escape.

## Status

Milestone 1 — walking skeleton. Local socket agent, file vault, identity
registry, mint-from-scoped-signing-keys, NATS nonce oracle, proven end to end
against an embedded NATS server in operator mode. The quick start above
documents this shipped, transitional surface. See
[hq/03-IMPLEMENTATION/ROADMAP.md](hq/03-IMPLEMENTATION/ROADMAP.md) for what
replaces it (the NATS-native rebuild — service surface plus KV vault, socket
retiring — then auth callout as the front door with claims-derived
authorization, attestation issuance, sealing keys).

## License

MIT.
