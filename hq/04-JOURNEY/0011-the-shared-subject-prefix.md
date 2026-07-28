# Episode 0011 — The shared subject prefix: one namespace for the ecosystem (2026-07-28)

An operator-directed amendment to D14, made and landed the day after M4
shipped: the subject root becomes `<prefix>.soulidentity`, with the prefix
a **configurable, ecosystem-shared namespace** (empty by default — the bare
root is unchanged). The operator's reasoning, recorded as given: the same
realm must host the service in different environments; the prefix should be
one value across all soulstream components so they can rely on each other;
and the grammar should leave the account token at a position an export can
pin with `account_token_position`, opening the import/export door.

The shape decided: the prefix *prepends* a **fixed service segment** rather
than replacing it — if the prefix replaced `soulidentity`, ecosystem
services could not share one prefix without colliding [mechanism-argument].
The account token's position is `P+2` (1-based, `P` = prefix token count),
so the cross-account export is pure configuration:
`export <prefix>.soulidentity.*.> with account_token_position = P+2` — the
server then forces every importing account's public key into that token,
which is D15's principal proof crossing the account boundary with no new
machinery. Prefix grammar: dot-separated `[A-Za-z0-9_-]+` tokens, no
wildcards, validated at startup and in the CLI.

What changed in code: `service.WithPrefix` / `client.WithPrefix`, the
`--prefix` flag on every NATS-speaking command defaulting to the shared
`SOULSTREAM_PREFIX` environment variable, and prefix validation. The M3
gate e2e now runs entirely under `prod.soulstream.soulidentity.>` —
including the server-side scope template
(`prod.soulstream.soulidentity.{{account-subject()}}.{{name()}}.>`), the
privileged observer, and the cross-prefix refusal — proving D15 holds
unchanged under a prefixed root [measured]; the M4 e2e keeps the bare
default covered. `make check` green.

The honest cost, argued at decision time: the prefix is deployment
agreement, and a mismatched consumer gets silent request timeouts, not
errors. Mitigations shipped with the change: the service logs its full
subject root at startup, and the CLI reads the ecosystem-wide environment
variable so the agreement has one natural home.

Reversal condition: recurring mismatch-timeout incidents attributed to
prefix drift across components (observable: support issues naming the
prefix) move service discovery to a well-known unprefixed subject as a new
D-decision.

Trail: [`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md) (D14
amendment, ops-table note, config surface); `client/e2e_test.go` (the
prefixed M3 gate); README in the same change.
