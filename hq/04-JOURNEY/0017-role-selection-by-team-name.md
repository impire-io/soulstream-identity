# Episode 0017 — Role selection by declared team name: the ephemeral mint op (2026-07-31)

The first consumer-proven M2 ask arrived exactly the way the design said it
would. Soulrealm's fleet research (their journey 0010, design 0003-fleet)
needs one scoped signing key **per role** on one realm account — which makes
the account multi-team, the observable D5's amendment reversal condition
watches: a second signing key imported for an already-bound account, refused
as ambiguous, recorded as an issue (soulidentity#1). As that condition
instructs, role selection reopened as a new D-decision — **D28**, in
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md): the selector is **declared
configuration, the team name** (a vault account signing key with its D24
account binding), never a field on a token record (D22's watch). The claims
lane had already made this move ("the role value IS the team name", D24);
D28 extends it to the client-facing surface as the `mint.ephemeral` op:
caller-supplied user **public** key (the workload generates its keypair
locally — no vault entry, no seed in either direction, the response is the
JWT alone; the creds escape cannot exist here, there is no seed to export),
team by name, **tags** stamped into the user claims for scoped templates to
resolve, TTL required (the D22 revocation propagation bound). Soulrealm
measured the safety property this rests on: the per-tag template clamp holds
in both directions, and a user JWT carrying its own permissions but signed
by a scoped key is rejected at connection time — the mint path cannot
over-scope [measured, soulrealm journey 0010, nats-server 2.14.3]. Our own
gate now proves the op end to end [measured, e2e proof 6]: an ephemeral
by-name-minted JWT for a caller-held key admits to the operator-mode realm
under the template's scope, tags land in the claims (NATS tag semantics —
lowercased, trimmed, deduplicated), and with a second team imported the
binding-resolved durable mint refuses as ambiguous while both roles stay
reachable by name.

Reversed: the totality of the D5 amendment's collapse ("the role field had
no second value left to select") — a multi-team account is now sanctioned,
but only where a declared name selects the role; the binding-resolved lanes
(durable `mint`, token-lane callout) deliberately keep refusing ambiguity,
so import order still never decides which key signs [mechanism-argument].

Opened, deliberately not built (constitution III): the token lane's own
named-team answer — node enrollment (API token → node creds) resolves by
account binding today and will hit the same ambiguity refusal on a
multi-team account; its answer must again be declared configuration, never
a token-record field (named in D28, trigger: a consumer blocked on that
refusal, recorded as an issue). And per-team **tag policy** — who may
request which tag values — is named as a watch, not a seam: the template
clamps the shape, TTL bounds the credential, every mint is attributed
[judgment: no worse than a free-minting single-node runner today].

Reversal condition: a deployment whose role landscape outgrows declared
names (observable: a consumer computing team names client-side to simulate
policy, recorded as an issue) reopens role selection a second time — any
answer stays declared configuration, never a token-record field.

Trail: [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) D28 + the D5
amendment pointer; [`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)
ops table (`mint.ephemeral`); soulidentity#1 (soulrealm's evidence:
their journey 0010, design 0003-fleet §5); `internal/mint.ForTeam` /
`internal/service` (`mint.ephemeral`) / `client.MintEphemeral`; the M3-gate
e2e proof 6; commits on `main`.
