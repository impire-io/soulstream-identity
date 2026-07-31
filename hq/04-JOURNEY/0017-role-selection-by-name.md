# Episode 0017 — Role selection by declared name: the ephemeral mint op (2026-07-31)

The first consumer-proven M2 ask arrived exactly the way the design said it
would. Soulrealm's fleet research (their journey 0010, design 0003-fleet)
needs one scoped signing key **per role** on one realm account — which makes
the account multi-role, the observable D5's amendment reversal condition
watches: a second signing key imported for an already-bound account, refused
as ambiguous, recorded as an issue (soulidentity#1). As that condition
instructs, role selection reopened as a new D-decision — **D28**, in
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md): the selector is **declared
configuration, the role name** (a vault account signing key with its D24
account binding), never a field on a token record (D22's watch). The claims
lane had already made this move (D24 — the roles claim names the declared
signing key); D28 extends it to the client-facing surface as the
`mint.ephemeral` op: caller-supplied user **public** key (the workload
generates its keypair locally — no vault entry, no seed in either
direction, the response is the JWT alone; the creds escape cannot exist
here, there is no seed to export), role by name, **tags** stamped into the
user claims for scoped templates to resolve, TTL required (the D22
revocation propagation bound). Soulrealm measured the safety property this
rests on: the per-tag template clamp holds in both directions, and a user
JWT carrying its own permissions but signed by a scoped key is rejected at
connection time — the mint path cannot over-scope [measured, soulrealm
journey 0010, nats-server 2.14.3]. Our own gate now proves the op end to
end [measured, e2e proof 6]: an ephemeral by-name-minted JWT for a
caller-held key admits to the operator-mode realm under the template's
scope, tags land in the claims (NATS tag semantics — lowercased, trimmed,
deduplicated), and with a second role imported the binding-resolved durable
mint refuses as ambiguous while both roles stay reachable by name.

Reversed, twice. First, the totality of the D5 amendment's collapse ("the
role field had no second value left to select") — a multi-role account is
now sanctioned, but only where a declared name selects the role; the
binding-resolved lanes (durable `mint`, token-lane callout) deliberately
keep refusing ambiguity, so import order still never decides which key
signs [mechanism-argument]. Second, the decision's own first noun, hours
after landing: it shipped saying "team" for the declared signing key, and
the operator corrected it the same day — **a team is the account, the
tenant** (journey 0013's own line, "teams are accounts"); the declared
signing key is a **role**, D5's original word. "Multi-team account" was
incoherent the moment D28 made accounts multi-role. The wire field, client
parameter, CLI flag, and internal identifiers renamed team → role before
any consumer wired in — the D27 discipline (one noun), applied to
authorization [judgment: renaming the just-published wire field now, with
zero consumers, is the last cheap moment it will ever have].

Opened, deliberately not built (constitution III): the token lane's own
named-role answer — node enrollment (API token → node creds) resolves by
account binding today and will hit the same ambiguity refusal on a
multi-role account; its answer must again be declared configuration, never
a token-record field (named in D28, trigger: a consumer blocked on that
refusal, recorded as an issue). And per-role **tag policy** — who may
request which tag values — is named as a watch, not a seam: the template
clamps the shape, TTL bounds the credential, every mint is attributed
[judgment: no worse than a free-minting single-node runner today].

Reversal condition: a deployment whose role landscape outgrows declared
names (observable: a consumer computing role names client-side to simulate
policy, recorded as an issue) reopens role selection a second time — any
answer stays declared configuration, never a token-record field.

Trail: [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) D28 + the D5
amendment pointer; [`../02-DESIGN/auth-callout.md`](../02-DESIGN/auth-callout.md)
D24's noun amendment; [`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)
ops table (`mint.ephemeral`); soulidentity#1 (soulrealm's evidence: their
journey 0010, design 0003-fleet §5); `internal/mint.ForRole` /
`internal/service` (`mint.ephemeral`) / `client.MintEphemeral`; the M3-gate
e2e proof 6; commits on `main` (fed475b and the rename that followed).
