# SoulIdentity

**The identity plane for the
[Soulstream](https://github.com/impire-io/soulstream-core) ecosystem.**
SoulIdentity is the home of the **persona** — the ecosystem's one noun for
a represented subject, human or agent alike: a service that holds the
account signing keys, user keys, and persona record-signing keys, and
answers *sign and mint requests* instead of handing out keys. Consumers
name the persona they act for and receive signatures and minted NATS
credentials; the seeds never cross the API. Identity truth lives in your
IAM: subjects arriving from the outside world — Entra/OIDC, API tokens —
get represented inside NATS with the right permissions, their personas
born on first encounter, every mint attributable.

The surface is NATS-native — request/reply with xkey-sealed end-to-end
encryption, the caller authenticated by its own NATS identity — and it is
the only one. Operations live on the caller's own subject prefix
(`[<prefix>.]soulstream-identity.<account>.<user>.<op>`, the optional prefix being
the ecosystem-wide namespace shared by every soulstream component), and the
claim is trustworthy because the server's publish permissions only let the
rightful identity use it.
Connections follow a two-lane ladder: bring your own creds file (the
self-custody bypass — used directly whenever presented, SoulIdentity out of
the path) or bring an external token and arrive through auth callout
(the next milestone).

The design — the decisions and their reasoning — lives in
[../soul-hq/02-DESIGN/soulstream-identity/](../soul-hq/02-DESIGN/soulstream-identity/README.md). **How this project is run
lives in [../soul-hq/](../soul-hq/README.md)** — vision and constitution
([../soul-hq/00-GENESIS/](../soul-hq/00-GENESIS/README.md)), the roadmap
([../soul-hq/03-IMPLEMENTATION/ROADMAP.md](../soul-hq/03-IMPLEMENTATION/ROADMAP.md)), and the
journey log ([../soul-hq/04-JOURNEY/](../soul-hq/04-JOURNEY/README.md)); agents start at
[AGENTS.md](AGENTS.md).

## Quick start

```sh
go install github.com/impire-io/soulstream-identity/cmd/soulstream-identity@latest

# Operator, once: mint the two xkeys into your secret store —
# the vault's first key and the surface key (seed on stdout):
export SOULIDENTITY_FIRST_KEY=$(soulstream-identity keygen)
export SOULIDENTITY_SURFACE_KEY=$(soulstream-identity keygen)

# Run the service on its NATS connection (creds file = the bypass lane).
# The vault lives in a KV bucket, sealed. There is no registry: who may
# reach which op is your permission templates (the operator's creds carry
# the management ops; represented users get sign.record + keys.public —
# and grants.> where outbound grants are declared, see below).
soulstream-identity serve --creds-file ./service.creds &

# As the operator, declare the team: the account's (scoped) signing key,
# bound to the account it signs for — the binding IS the declaration:
soulstream-identity key import --creds-file ./ops.creds --as AC...PUBKEY/ops \
  --name acme --kind nats-account-signing-key --account AC...PUBKEY \
  --seed-file ./SA.nk

# Nothing declares daan: users are ephemeral, admitted from the credential
# they present, and daan's persona signing key MATERIALIZES inside the
# vault on his first signature, owner-bound (D26). (Bring-your-own keys
# can still be imported with --name persona/daan --user daan.)

# Mint daan's creds (the explicit custody escape — self-custody onboarding);
# the signing key resolves by the account's team binding:
soulstream-identity mint --creds-file ./ops.creds --as AC...PUBKEY/ops \
  --account AC...PUBKEY --user daan --creds > daan.creds
```

Signing a Soulstream record from Go — the persona key never leaves the
vault (it never existed anywhere else: it materializes there on first
touch), and the key's owner binding decides who may sign with it. The
bound signer satisfies soulstream's `identity.Signer` seam structurally
(neither repo imports the other), and readers resolve any persona's
public key from the same service — the vault is the realm's key
directory:

```go
nc, _ := nats.Connect(url, nats.UserCredentials("daan.creds"))
c := client.New(nc, "AC...PUBKEY", "daan")
signer, _ := c.PersonaSigner("daan") // first touch: the key materializes
sig, _ := signer.Sign(canonicalBytes)

pub, _ := reader.PersonaPublicKey("daan") // the directory read (D26)
```

## Outbound grants — the broker (D30–D34)

Declaring resources (`--grants-catalog resources.json`, a JSON array of
`{name, auth_url, token_url, revoke_url?, client_id, client_secret?,
scopes?, redirect_uri}`) switches on the `grants.*` op family: per-persona
OAuth custody in its own sealed CAS bucket (`--grants-bucket`, default
`SOULIDENTITY_GRANTS`), with the derived short-lived access token the only
thing any caller ever receives — the refresh token never crosses the wire
and never rests unsealed (D32).

The deployment duty (D25's stated shapes): a represented user's scope
template grows exactly one line beside `sign.record` and `keys.public` —

```
[<prefix>.]identity.{{account-subject()}}.{{name()}}.grants.>
```

so it is the transport, never the broker, that keeps every persona to its
own grants: a publish to another persona's grants subject dies at the
server as a permissions violation (D15/D30).

```sh
soulstream-identity grant link   --creds-file ./daan.creds --as AC...PUBKEY/daan --resource github
# open the printed URL, consent, then complete with the redirect's code:
soulstream-identity grant link   --creds-file ./daan.creds --as AC...PUBKEY/daan --link-id <id> --code <code>
soulstream-identity grant access --creds-file ./daan.creds --as AC...PUBKEY/daan --resource github
```

An agent acting on a persona's behalf presents a subject-signed, bounded
delegation with `on_behalf_of` (D33, `client.MintDelegation`); the broker
honors it only from the delegation's actor — the server-proven caller —
and audits both personas on every decision.

## What it is not

Not a KMS (storage backends are pluggable; NATS KV with xkey envelope
encryption is the initial backend), not an identity
provider (external identities are represented, never authenticated by us —
authn backends plug into callout mode), not an authorization server for your
realm (NATS enforces transport permissions via scoped signing keys or auth
callout; SoulIdentity decides only who may act as which persona), and not a
place secrets leave: credential export exists solely as an explicit, named
custody escape. There is no identity ledger either: authorization lives in
the transport ACLs (which ops a credential reaches) and the vault's key
bindings (which account a team key signs for, which identity owns a
persona key).

## Status

Milestones 3 and 4 — the NATS-native service and the auth-callout
admission lane. The sealed service surface on the caller's own subject prefix, the
vault on NATS KV with envelope encryption at rest, act-as enforced against
the server-proven caller — and SoulIdentity as the callout issuer: an
external client brings a public sentinel creds file plus an API token, and
receives a TTL-bounded scoped identity, fully attributable in the audit
log, with revocation propagating at the JWT's expiry. Both milestones are
proven end to end against embedded NATS servers in operator mode; creds-file
connections stay natively verified with the issuer out of the path. See
[../soul-hq/03-IMPLEMENTATION/ROADMAP.md](../soul-hq/03-IMPLEMENTATION/ROADMAP.md) for what
comes next (consumers wiring in; Entra/OIDC as callout configuration;
attestation issuance, sealing keys).

## License

[Fair-code](https://faircode.io), under the [Sustainable Use License](LICENSE) —
free to use, modify, and self-host for internal or non-commercial use; offering
it to others as a paid product or service requires an agreement — see
[impire.io/license](https://impire.io/license/). Versions released before this
change remain MIT.
