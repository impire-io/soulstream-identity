# Episode 0014 — The cross-service proof: the seam carries a real record (2026-07-29)

M2's first gate criterion is measured: **a Soulstream record signed through
the running SoulIdentity service verifies in a real realm** [measured]. The
rig lives where the cycle guard says a consumer lives — a separate module
`e2e/` that imports *both* repos (soulidentity via `replace` to the working
tree, soulstream pinned at the published v0.6.0), sitting above the two
modules that must never import each other. It rides `make test`, so the
proof is part of the standard gate, not a side script.

The consumer story it runs, end to end on one operator-mode server: the
service custodies daan's owner-bound persona key (D6 as amended, D25);
daan holds **one minted scoped credential whose template carries both
subject spaces** — the narrow SoulIdentity user ops (`sign.record`,
`keys.public`; no management op is grantable, the D25 shape) beside the
Soulstream realm subjects — and **one connection** serves both clients:
`client.PersonaSigner` slots into `realm.Config.Signer` unmodified,
structural satisfaction working exactly as soulstream's journey 0006
designed it. Daan publishes a profile carrying the vault key's public
half, starts a topic, posts a turn; a separate reader builds its keyring
**from the persona directory** (`registry.All` → `BuildKeyring` — the real
trust path, no out-of-band key handoff) and reads announce, baseline, and
turn all `SigVerified`; the negative control — the same ops without a
keyring read `unknown-key` — shows the verdict is earned, not defaulted
[measured]. The persona seed existed in exactly two places: the operator's
import act and the vault; daan's process never held it.

What it taught: soulstream's `Connect` deliberately publishes nothing —
the directory entry is the author's explicit act (`registry.Publish`), so
a consumer wiring the seam must publish the profile or its records read
`unknown-key` forever; that duty belongs in the node's connect path when
it arrives. What remains of the M2 gate is the **node half** — one pooled
connection per user with no node-held creds — which lives in soulstream's
remote MCP node feature, not here; the scoped-template shape this rig
proved (both subject spaces on one credential) is exactly what that node's
per-user connections will mint through callout.

Reversal condition: the rig pins soulstream at a released version, so a
soulstream API change can break `e2e/` while both repos' mains are green
(observable: the e2e module failing on symbols its pinned version lacks) —
that failure moves the version pin forward as an ordinary chore; if it
recurs enough to be a tax, the proof migrates to a consumer repository as
a new decision. Otherwise none — records a completed measurement.

Trail: `e2e/` (module `github.com/impire-io/soulidentity/e2e`,
`m2_gate_test.go`), `Makefile` (tidy/test/lint run the module),
`hq/03-IMPLEMENTATION/ROADMAP.md` M2; soulstream v0.6.0's seam (their
journey 0006); committed as the episode's change-set on `main`.
