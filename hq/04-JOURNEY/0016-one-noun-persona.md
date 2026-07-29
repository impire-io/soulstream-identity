# Episode 0016 — One noun: persona (2026-07-29)

The day's last confusion was ours, not the system's: episode 0015's own
summary said "persona keys are capability, not identity," and the operator
rightly asked what SoulIdentity is even about if a persona is not an
identity — the mission is the home of everything around an identity, and
two nouns for one concept had been shearing against each other all day.
The operator's resolution: **persona == identity, one noun, and the
persona is created automatically when first encountered** (which D26
already built); the vault is the acknowledged place these personas' durable
artifacts live. The only open question was which word wins.

The choice was nearly forced [mechanism-argument]: soulstream's core
design fixed *persona* as "the only noun for an identity, everywhere in
the spec," and it is baked into its wire — `Soulstream-Author`, the
`SOULSTREAM.PERSONA.NOTIFY.>` subjects — so choosing "identity" would
either leave the ecosystem speaking two languages forever or force a
breaking cross-repo rename. The operator confirmed **persona** (D27). The
vocabulary, fixed: *persona* — who, the represented subject, human or
agent, born at first encounter; *principal* — the server-proven (account,
user) a connection speaks as, D15's own term, a transport fact and never
a second identity concept; *subject* — an external provider's
representation before admission (the validator seam already said
`ExternalSubject`); *"identity"* survives only in the product name and
"the identity plane" as the layer's description.

The pass that followed touched words, not wire: the vision refreshed
(including two registry-era sentences D25 had missed — the founding bet's
policy surface now names the bindings), constitution 1.3.1 (Principle II
restated in the fixed vocabulary; identity truth named as the IAM's),
CLAUDE.md/AGENTS.md/README missions, and the load-bearing code comments
(owner *principal*, external *subject*); the callout's generic wire
refusal tightened from "identity not authorized" to "not authorized". No
type, op, or JSON field changed — the contract was already speaking
correctly [measured: full gate green, all rigs unchanged].

What it taught: episode 0015 closed with "the registry instinct returns
in disguises"; the naming confusion was the same failure one level up —
a second noun is how a second concept sneaks in, and a second concept is
how a second store gets justified. One noun is the cheapest guard.

Reversal condition: soulstream renaming its own noun (observable: a
soulstream release changing the `Soulstream-Author` vocabulary or the
persona subjects) reopens the alignment (D27); otherwise none — records a
terminology decision and its doc pass.

Trail: `hq/02-DESIGN/agent.md` (D27), `hq/00-GENESIS/vision.md`
(refreshed), `hq/00-GENESIS/constitution.md` (1.3.1), CLAUDE.md,
AGENTS.md, README.md, comment pass across `internal/` and `client/`;
committed as the episode's change-set on `main`.
