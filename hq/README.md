# HQ — SoulIdentity's headquarters

Everything about *how this project is run* lives here. The code lives in the
package directories (`client/`, `cmd/`, `internal/`); everything else — why
SoulIdentity exists, what we're investigating, what we've designed, what we're
building, and what happened — lives in one of the areas below.

| Area | What it holds | When you touch it |
|---|---|---|
| [`00-GENESIS/`](00-GENESIS/README.md) | Vision, constitution, working agreement | When deciding *whether* / *how* to do something |
| [`01-RESEARCH/`](01-RESEARCH/README.md) | Active research topics (one folder each) | While investigating an open question |
| [`02-DESIGN/`](02-DESIGN/README.md) | The normative design of the agent and its modes | When research graduates, or a build changes behavior |
| [`03-IMPLEMENTATION/`](03-IMPLEMENTATION/README.md) | The roadmap: milestones, in order, behind their gates | When planning or landing work |
| [`04-JOURNEY/`](04-JOURNEY/README.md) | Numbered episodes: the honest log of what happened | Whenever work lands, research concludes, or a load-bearing decision is made |

A `99-ARCHIVE/` area appears when material is superseded — kept for provenance
with its content frozen, history rather than live design.

## The pipeline

```
01-RESEARCH ──graduates──▶ 02-DESIGN ──milestones──▶ code
     │                         ▲                       │
     │ (abandoned)             │ (behavioral changes   │
     │                         │  propagate back)      │
     ▼                         │                       ▼
04-JOURNEY ◀──────── every ending writes an episode ◀── 03-IMPLEMENTATION
                                                        (ROADMAP updated)
```

- Research topics live in `01-RESEARCH/<slug>/` and end in exactly one of three
  states: **graduated to design**, **graduated to artifact**, or **abandoned**.
  Every ending produces a numbered episode in `04-JOURNEY/`; the topic folder is
  then removed (git history keeps the full trail).
- Designs in `02-DESIGN/` are written functional-level: capability, seams,
  configuration surface, acceptance criteria — explicit enough to implement
  without guessing. Decisions carry D-numbers with their reasoning so they can
  be re-argued honestly later.
- The lifecycle transitions are mechanized as skills: `/research-start`,
  `/research-graduate`, `/journey-log`. The structure itself is enforced by
  `internal/hqlint`, which rides the standard quality gate (`make test`).

**If in doubt** — about whether to build something, how to decide, or whether a
shortcut is acceptable — the answer is in [`00-GENESIS/`](00-GENESIS/README.md).
Hold the decision against `vision.md` and `constitution.md`; if it still isn't
clear, that's a teach-back conversation, not a judgment call to make alone.
