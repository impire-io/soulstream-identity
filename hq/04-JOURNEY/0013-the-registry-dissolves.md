# Episode 0013 — The registry dissolves: authorization in the ACLs and the bindings (2026-07-29)

The operator opened M2's client work with a question and kept pulling until
the ledger came apart: every identity is unique — a human and an agent
equally, Soulstream's own "no second door" — so why does one identity carry
a *list* of personas? And once the persona list fell, why a registry row at
all, when the connection already proves (account, user)? Answered field by
field, nothing survived. `personas` fell to one-identity-one-persona: the
persona signing key now carries its **owner (account, user)** at import —
the exact D24 move, the binding is the declaration — and `sign.record`
checks the caller against it (D6 amended). `role` fell to the collapse D24
had already started: role == team == the account signing key bound to the
target account; every mint path resolves by that binding, none refuses,
two refuse as ambiguous (D5 amended). `admin` fell to the transport ACL:
the op tail of `<root>.<account>.<user>.<op>` is gated by the same
publish-permission enforcement D15 already trusts for the principal —
represented users' scope templates grant `sign.record` and the new
`keys.public`, the operator's creds grant the op space, and `requireAdmin`
is deleted (D18 superseded, D25). Bare existence was a restatement of the
token store — the one registry still standing, and it was never policy
(D22). `internal/registry` is deleted; the connection ladder is confirmed
as exactly three ways in: API token, OIDC access token, creds file.

Two honest consequences surfaced in the adversarial pass and were built
in, not around. **Self-mint died with the row that authorized it**: with
no registry, an admitted-but-undeclared identity could have converted an
ephemeral admission into durable creds, so `mint` is now an operator op
outright — issuing durable credentials is provisioning [judgment]. **The
Entra rig's two-teams-one-account shape was refuted by its own lane's new
resolution rule** [mechanism-argument]: the token lane resolves the team
by the record's account, so two teams bound to one account refuse as
ambiguous — the rig was rebuilt with teams as accounts (ENG, PLAT), which
is what the model now honestly says a team is. The admin boundary is
restated plainly in D25: it is a deployment property (a template granting
the op tail `>` grants management), the same trust class D15 accepted for
the principal — no second verifier, and rebuilding one service-side would
restore the ledger.

All three gates re-proven on the new shape [measured]: the M3 rig with
five proofs — owner-binding refusal logged (an owned-by-other key and a
missing key refuse identically, no vault probe), wire ciphertext,
store ciphertext against the positive control, cross-prefix refused by
the server, and the new op-tail proof: a represented user publishing
`keys.list` on its *own* prefix draws a permissions violation and zero
service decisions. The M4 and Entra gates pass registry-free — admission,
attribution, the nine-row matrix, `sit_` coexistence, and the revocation
bound re-measured at 5.25 s after connect on the 5 s-TTL rig. What it
opened for M2: the client now carries the seam surface — `PersonaSigner`
(structural `identity.Signer`, fail-fast construction over `keys.public`,
never ("", nil)) — exercised in the M3 rig; the cross-repo gate proof (a
record signed here verifying in a real realm) remains, and an OIDC-admitted
user can now sign the moment its owned persona key exists, no per-user
declaration anywhere.

Reversal condition: a deployment class whose permission templates cannot
scope the op tail (observable: a scope template unable to express per-op
publish grammar — the NGS research is the first place to look) restores a
service-side op gate; a deployment needing two permission scopes inside
one account (observable: a second signing key import refused as ambiguous,
recorded as an issue) reopens role selection; a real consumer need for
signing with an unowned persona (observable: a refused `sign.record`
recorded as an issue) adds delegation as a second binding on the key —
never a registry list; a demonstrated non-operator durable-creds need
reopens self-mint. Each returns as a new D-decision.

Trail: `hq/02-DESIGN/agent.md` (D2, D5, D6 amended),
`hq/02-DESIGN/nats-surface.md` (D18 superseded, D25 added),
`hq/02-DESIGN/auth-callout.md` (D22, D24 amended); constitution 1.3.0
(Principle II's policy surface restated as the bindings, III's growth on
vault + token store); `internal/registry` deleted; `client/` gains
`PersonaSigner`/`PersonaPublicKey`, loses `Identity`; the `identity` CLI
subcommands and `--registry` flag removed; committed as the episode's
change-set on `main`.
