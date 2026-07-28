# SoulIdentity — the NATS surface (M3)

*The design the NATS-native rebuild implements: the agent's contract served
over NATS request/reply with xkey-sealed payloads (D11), the caller's NATS
identity as the principal (D12), and the vault on its initial KV backend
(D10, D13). Decisions here continue the numbering from
[`agent.md`](agent.md): D14–D17. The milestone and its gate live in
[`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md).*

## What it covers

The same contract the walking skeleton served over HTTP-on-a-socket, served
as a NATS service: the wire bodies are unchanged (the one-way door in the
roadmap: payload shapes survive the transport swap), the transport and the
principal change. This document specifies the subject space, how the caller
becomes a verified principal, the sealed envelope, the two curve keys, the
KV vault layout, the configuration surface, and the acceptance criteria.
The socket surface, the `NATSOption` client seam, the file keystore, and the
`sign/nonce` operation retire.

## The operations

| Subject (op suffix) | Milestone-1 op | Body shapes |
|---|---|---|
| `soulidentity.v1.status` *(open)* | `GET /v1/status` | unchanged |
| `soulidentity.v1.xkey` *(open, new)* | — | `{"xkey": "<service curve public key>"}` |
| `soulidentity.v1.<acct>.<user>.keys.list` | `GET /v1/keys` | unchanged |
| `soulidentity.v1.<acct>.<user>.keys.import` | `POST /v1/keys` | unchanged |
| `soulidentity.v1.<acct>.<user>.identities.list` | `GET /v1/identities` | unchanged |
| `soulidentity.v1.<acct>.<user>.identities.put` | `POST /v1/identities` | unchanged |
| `soulidentity.v1.<acct>.<user>.sign.record` | `POST /v1/sign/record` | unchanged |
| `soulidentity.v1.<acct>.<user>.mint` | `POST /v1/mint` | unchanged (creds export stays the loud D7 escape) |
| — | `POST /v1/sign/nonce` | **retired** — the nonce oracle left the connection story (D1, journey 0003) |

`client/` rebuilds on NATS request/reply with the same mirror types; the
socket transport and `NATSOption` go with it.

## D14 — The subject space is versioned and principal-scoped

Operations live at `soulidentity.v1.<account>.<user>.<op>`, with exactly two
open subjects outside the principal scope: `status` and `xkey` (discovery —
they reveal nothing an account member couldn't learn by connecting). `v1`
answers the wire-contract one-way door: a breaking payload change after
consumers exist is a new subject version, not a mutation. The
`<account>.<user>` tokens are not routing decoration; they are the
principal claim — which D15 makes trustworthy.

## D15 — The principal is the subject, and the server enforces it

The NATS service surface has no native "caller identity" on a message. The
decision: **the claimed principal is read off the subject, and its proof is
the server's publish-permission enforcement** — a caller may only publish to
`soulidentity.v1.<account>.<user>.>` for the identity it *is*, because its
user JWT (scoped signing key template in mint mode, callout-issued
permissions in callout mode, D5/D12) allows exactly its own prefix. The
service never re-verifies the claim; it trusts what the server already
enforced. This is constitution II applied to our own front door: the server
is the verifier of record, and SoulIdentity's own check remains only "may
this principal act as that persona" (D6) — now against a server-proven
principal, which is what turns act-as from declared into enforced [M3 gate,
mechanism-argument].

Argued against at full strength: a deployment whose permissions are lax — a
wildcard publish allow, a legacy account without scoped keys — collapses
the proof; the subject claim becomes self-asserted, exactly the
honour-system D8 retired. Answer: that deployment has already lost transport
authorization everywhere, not just here — subject-scoped permissions are
the *same* mechanism every NATS deployment relies on for any subject; there
is no second verifier to appeal to (constitution II), and inventing one
(request signatures, a parallel token check) would rebuild the identity
plane's machinery inside its own API. The design's duty is loudness, not a
gate: the deployment docs state the permission-template requirement, and
minted/callout-issued JWTs carry the correct prefix by construction.

**Reversal condition** (written at decision time): a deployment class that
cannot express per-user publish scoping (observable: a consumer's JWTs
cannot carry the prefix template, recorded as an issue — the NGS research is
the first place this could surface) forces a caller-authentication mechanism
inside the envelope, as a new D-decision.

## D16 — The sealed envelope

Every principal-scoped request body is sealed; the broker sees ciphertext
(D11). The envelope is small and boring:

- **Request** (JSON, plaintext outer): `{"v": 1, "xkey": "<ephemeral client
  curve public key>", "data": "<base64 xkv1 ciphertext>"}` — `data` is the
  op's unchanged JSON body, sealed to the service's surface xkey (D17).
- **Reply**: same envelope, `data` sealed to the request's ephemeral xkey,
  `xkey` carrying the service's. Errors travel inside the sealed body —
  the broker learns success/failure timing, not content.
- **Discovery**: `soulidentity.v1.xkey` returns the service's surface
  public key unsealed — it is public material; pinning it out of band is
  the deployment's option, not a protocol requirement.
- The two open ops (`status`, `xkey`) are plaintext both ways.

Replay, analyzed honestly [mechanism-argument]: a broker (or anyone with
publish permission on a victim's prefix — which D15 confines to the victim
itself) can redeliver a captured sealed request. It cannot read the reply —
sealed to the original ephemeral key. Of the state-changing ops, `import`
refuses overwrite (idempotent under replay), `identities.put` is declarative
last-write-wins, and a replayed `mint` yields a duplicate credential sealed
to a key the attacker lacks, visible as a duplicate in the audit log. Judged
acceptable for M3 [judgment]; if callout or a new op changes this calculus,
an inner timestamp/nonce goes into the sealed body as a compatible addition.

## D17 — Two curve keys, two domains

The service holds two xkeys, both raw `SX…` seed files `0600` beside its
creds, both minted on first start (the D13 pattern):

- **The first key** (`first-key.xk`, D13) — unseals the vault's KV records.
  Never advertised, never leaves the host.
- **The surface key** (`service.xk`) — advertised via discovery, seals
  request/reply traffic.

One key could serve both; it doesn't, because the domains rotate and expose
differently [mechanism-argument]: the surface key's public half is
broadcast and its rotation is a connection-level event consumers notice at
discovery, while the first key's rotation is a silent bucket re-seal walk
(D13); sharing one keypair across an advertised domain and an at-rest
domain couples those lifecycles and violates domain separation for no
saving but one file.

## The vault on KV

Realizing D10 + D13, proven mechanically in journey 0004 [measured]:

- One bucket (default `SOULIDENTITY_VAULT`), keys = vault names verbatim
  (the KV key grammar is a superset of the vault name grammar), values =
  the vault's `stored{}` JSON sealed `xkv1` to the first key's public half,
  self-sealed.
- The vault process unseals in memory only; `internal/vault` remains the
  custody boundary (constitution I) — the backend swap changes where
  ciphertext rests, not what the API returns.
- First start: mint `first-key.xk` (refuse overwrite), create the bucket.
  No migration tooling from the file keystore: milestone 1 shipped
  unreleased with no external consumers, so the file backend retires by
  deletion, not conversion [judgment].
- The registry stays a local strict-decoded JSON file in M3: it is declared
  configuration, not secret material — moving it to KV is a later
  convenience, not part of this milestone (constitution III).

## Configuration surface

- NATS connection: a creds file (the service's own bypass lane, D12) or a
  NATS context; URL and creds path.
- Paths: `first-key.xk`, `service.xk`, registry file, all defaulting beside
  the data dir.
- Bucket name; subject prefix fixed at `soulidentity.v1` (a deployment
  needing isolation runs its own account — subjects are account-local).

## Audit

Every principal-scoped op emits one structured log entry: principal
(account, user — as server-enforced by D15), op, target (key name /
identity / persona), decision (allowed, refused and why). The creds-export
path of `mint` stays loud (D7). The audit gains what M3 exists to add: a
caller that is a verified identity, not a claimed one.

## Acceptance criteria (the M3 gate, expanded)

1. An unauthorized act-as request over NATS — a principal whose registry
   row does not allow the persona — is refused and the refusal logged with
   the server-enforced principal [measured].
2. A request body published on the wire is unreadable to the broker: an
   account-privileged observer subscribed to the request subject captures
   ciphertext only [measured].
3. The vault operates against KV with only ciphertext at rest: the
   journey-0004 positive-control grep, run against the live system's store
   [measured].
4. A caller attempting an op on another identity's subject prefix is
   refused by the *server* (publish permission), never reaching the service
   [measured] — the D15 proof.
5. The walking skeleton's socket surface, `NATSOption`, and file keystore
   are gone; `client/` speaks NATS request/reply with unchanged types.
