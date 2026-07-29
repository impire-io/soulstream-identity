# Agent guide for SoulIdentity

Durable instructions for any coding agent working in this repository. The full
rules live in `hq/00-GENESIS/`; this file is the orientation and the
non-negotiables.

## Orientation (read in this order)

1. `hq/00-GENESIS/` — [`vision.md`](hq/00-GENESIS/vision.md) (the identity
   plane on NATS: representation of identity for humans and agents, and what
   it refuses to become — not a KMS, not a parallel permission system, not an
   identity provider, not required for local sessions),
   [`constitution.md`](hq/00-GENESIS/constitution.md) (the articles no change
   may violate, plus the anti-drift working agreement), and
   [`how-we-work.md`](hq/00-GENESIS/how-we-work.md) (pipeline, research
   lifecycle, the journey duty). Decisions are held against these.
2. `hq/04-JOURNEY/README.md` — where things stand + the episode index.
3. `hq/03-IMPLEMENTATION/ROADMAP.md` — the milestones and their gates.
4. `hq/02-DESIGN/` — the design docs and their numbered decisions (D1–D13 in
   `agent.md`, D14–D18 in `nats-surface.md`, D19–D22 in `auth-callout.md`);
   code comments cite these D-numbers.

## Non-negotiables (constitution articles, in brief)

- **Quality gate before "done"** (all green, none skipped, before every
  commit): `make check` — fmt, tidy, build, test, lint; `make test`
  (`go test ./...`) includes the hq structural lint (`internal/hqlint`) and
  the operator-mode end-to-end proof.
- **Custody without possession** (I): no API returns a seed or private key;
  signatures and minted tokens only. The one escape (creds export) is
  explicit and loudly logged. In-process key material stays inside
  `internal/vault`.
- **The server is the verifier of record** (II): transport permissions live
  NATS-side (scoped signing keys, callout JWTs); SoulIdentity's own policy is
  only who exists and who may act as which persona. Binding checks the server
  will repeat are diagnostics, never gates.
- **Smallest viable implementation** (III): growth is new modes and backends
  on the same vault + registry, never new machinery; scope creep is a review
  blocker.
- **Documentation is first-class** (IV): plain words, decisions numbered with
  reasoning, docs in the same change as behavior.
- **The working agreement** (anti-drift): load-bearing claims carry an
  evidence class (`[measured]` / `[mechanism-argument]` / `[judgment]`, only
  measured closes a debate); direction decisions record their reversal
  condition when made; sign every commit; never commit
  `.claude/settings.local.json`.

## The flow

- **Research** runs through `/research-start` → investigate →
  `/research-graduate` (`hq/01-RESEARCH/`).
- **Feature work is spec-driven via speckit**: `/speckit-specify` →
  `/speckit-clarify` → `/speckit-plan` → `/speckit-tasks` →
  `/speckit-implement`, on numbered feature branches with artifacts under
  `specs/`. The speckit constitution (`.specify/memory/constitution.md`) is a
  projection of `hq/00-GENESIS/` — on conflict, hq wins. The hq duties below
  apply unchanged to speckit-driven work.
- **Implementation** follows the roadmap's milestones against the design docs;
  landing means gate green, roadmap updated, journey episode written, design
  propagated — in the same merge.
- **The journey duty (required):** every landed milestone, concluded
  investigation, or load-bearing decision gets a numbered episode in
  `hq/04-JOURNEY/` — `/journey-log` does this.
