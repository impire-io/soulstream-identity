# 01-RESEARCH — active investigations

One folder per open research topic. Each folder is a self-contained
investigation: a `README.md` (from [`TEMPLATE.md`](TEMPLATE.md)) stating the
question, its state, and the **pre-registered bars**, plus a `JOURNEY.md`
recording the investigation as it happens, plus whatever documents the work
produces.

Research is for the questions that come *before* a design — "does Synadia
Cloud expose scoped signing keys?", "does this callout flow behave the way we
think?" — the ones where the answer decides whether or how to build.

## Lifecycle

```
/research-start <slug>            state: active
        │
        ▼
  investigate (pre-registered bars → cheap discriminating
  experiments → honest verdict; scratchpad for scripts,
  repo for conclusions; commit and push as you go)
        │
        ▼
/research-graduate <slug> --to design | artifact | abandoned
        │
        ├─ always: composes the topic's journey into the next-numbered
        │          hq/04-JOURNEY/ episode (verdict, evidence tags,
        │          reversal condition)
        ├─ design:   creates/updates the hq/02-DESIGN doc
        ├─ artifact: the deliverable itself ships (example, tool, doc)
        └─ always: the topic folder is REMOVED — git history keeps the trail
```

## Rules

- **States are exactly** `active`, `graduated`, `abandoned` — and no folder
  with a terminal state lingers here (the structural lint enforces both).
- **Always committed and pushed**, including work heading for abandonment.
  Abandoned research is a result: it gets the same quality of episode as a
  success, and its full history survives in git after the folder is gone.
- **Bars before experiments.** The pass/fail criteria are written down before
  any run; if a bar proves degenerate it is amended openly with the raw
  numbers recorded in the topic's JOURNEY.md.
