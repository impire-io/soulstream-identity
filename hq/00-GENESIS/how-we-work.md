# How we work

The process companion to [`constitution.md`](constitution.md): the pipeline,
the lifecycles, the duties, and how all of it is enforced.
[`../README.md`](../README.md) holds the one-screen map.

## The pipeline

```
question ──/research-start──▶ 01-RESEARCH/<slug>/     (state: active)
                                   │
                     /research-graduate <slug>
                        │            │           │
                     design       artifact    abandoned
                        │            │           │
                        ▼            │           │
              02-DESIGN doc          │           │
                        │            ▼           ▼
              milestone on the    04-JOURNEY episode (always; folder removed)
              ROADMAP, then code
                        │
                        ▼
        landed ──▶ /journey-log episode + ROADMAP updated
                        │
                        ▼
        design docs updated (behavioral changes propagate back)
```

Two hard boundaries:

- **Research is for finding out whether/how; it never produces code directly.**
  It uses the pre-registration method below and ends only through
  `/research-graduate`.
- **Implementation follows a design.** A milestone on the roadmap points at
  the design doc (and D-numbers) it realizes; a capability that isn't decided
  yet starts as research, not as code.

## Research (`01-RESEARCH/`)

One folder per topic, created with `/research-start <slug>`. The folder's
`README.md` (from [`../01-RESEARCH/TEMPLATE.md`](../01-RESEARCH/TEMPLATE.md))
carries: Title, State (`active | graduated | abandoned`), Abstract, the
Question, and **pre-registered bars** — the pass/fail criteria written *before*
any experiment runs. The folder's `JOURNEY.md` records the investigation as it
happens.

- **Method:** hypothesis → cheap discriminating experiment → verdict, one
  variable at a time. Experiment scripts live in the session scratchpad;
  conclusions, documents, and principled code changes land in git.
- **Always committed and pushed** — even work that will be abandoned. The
  point is a permanent trail; abandoned research keeps its full history in git
  after the folder is gone.
- **Ending:** `/research-graduate <slug> --to design|artifact|abandoned`
  composes the topic's journey into the next-numbered `04-JOURNEY/` episode
  (verdict, evidence tags, reversal condition included), creates or updates
  the design doc when the outcome is a design, and removes the topic folder in
  every case. An abandoned topic is a *result*, recorded with the same care as
  a success.

## Design (`02-DESIGN/`)

The normative design of the agent and its modes. Documents are written
functional-level — the capability, its seams, its configuration surface, its
acceptance criteria — with every load-bearing decision numbered (D1, D2, …)
and carrying its reasoning. Every behavioral change made during
implementation propagates back into the design docs it touches — the docs
describe the system as it *is*. A new capability that isn't yet decided
starts as research, not as a design doc.

## Implementation (`03-IMPLEMENTATION/`)

[`ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md) is the live plan: milestones,
in order, each behind a gate and pointing at the design it realizes. Landing
work means: gate green, roadmap updated, journey episode written, design docs
propagated — in the same merge.

## Journey (`04-JOURNEY/`)

The append-only log: one numbered episode (`NNNN-slug.md`) per landed
milestone, concluded research topic, or load-bearing decision — written with
`/journey-log` (or `/research-graduate`, which writes it for research). The
[`TEMPLATE.md`](../04-JOURNEY/TEMPLATE.md) requires: what happened with the
honest numbers, what was refuted or reversed, evidence-class tags on
load-bearing claims, and a **Reversal condition** line. `README.md` carries
the preamble, the episode index, and the "Where things stand" summary — both
refreshed with every episode.

## The working agreement (anti-drift)

The four correctives are constitution articles (see The Working Agreement
there); this is how they run day to day:

- **When to teach-back:** any decision that changes the custody boundary, an
  enforcement mode, a scope, or a public claim. The assistant asks for the
  restatement; the decision is recorded only after it survives.
- **Tagging:** write `[measured]` / `[mechanism-argument]` / `[judgment]`
  inline where the claim is made — in conversation, in episodes, in design
  docs. If a debate is being closed by anything other than `[measured]`, stop
  and say so.
- **Reversal conditions:** phrased as observable evidence, not vibes. Written
  at decision time, never retrofitted.
- **Adversarial pass:** for calls that change the custody boundary or an
  enforcement mode, the assistant argues the other side at full strength
  *before* the decision.

## Enforcement (how this stays true without willpower)

1. **The structural lint.** `internal/hqlint` rides the standard gate under
   `go test ./...` (locally and in CI): hq layout, research-state legality,
   episode numbering and required fields, index completeness, and that
   relative links inside `hq/` resolve.
2. **The skills.** `/research-start`, `/research-graduate`, `/journey-log`
   make the transitions one command each, so the right order is the easy
   order. They stage explicit paths and commit signed.
3. **Orientation.** Root `CLAUDE.md` and `AGENTS.md` point every session here
   first.

## Quality gates (the non-negotiables, in one place)

- Gate: `make check` (fmt, tidy, build, test, lint) — all green, nothing
  skipped, before any "done" and before every commit. `make test`
  (`go test ./...`) includes the hq structural lint and the operator-mode
  end-to-end proof.
- Keep pure logic (vault operations, registry policy, claims assembly)
  separate from transport so it unit-tests without a server; the e2e test is
  the one place a real NATS server runs.
- Sign every commit. Never commit `.claude/settings.local.json`.
- Custody without possession (constitution I) and server-is-verifier
  (constitution II) apply to every change, product or research.
