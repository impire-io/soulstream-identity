---
name: "research-graduate"
description: "Close a research topic (design | artifact | abandoned): compose its journey episode, create/update the design doc when graduating to design, remove the topic folder."
argument-hint: "<slug> --to design|artifact|abandoned"
compatibility: "Requires the hq/ structure (hq/01-RESEARCH, hq/02-DESIGN, hq/04-JOURNEY)"
metadata:
  author: "soulidentity-hq"
user-invocable: true
disable-model-invocation: false
---

## User Input

```text
$ARGUMENTS
```

Parse `$ARGUMENTS` as `<slug>` and `--to design|artifact|abandoned`. Both are
required; if the outcome is missing, ask — do not infer it.

## Steps

1. **Load the topic.** `hq/01-RESEARCH/<slug>/README.md` and its `JOURNEY.md`
   must exist and State must be `active`; otherwise stop and report. Read the
   pre-registered bars and the topic journey in full.

2. **Verdict first.** Fill the topic README's Verdict section: PASS/FAIL per
   pre-registered bar with the honest numbers, each load-bearing claim tagged
   `[measured]` / `[mechanism-argument]` / `[judgment]`. If a bar was amended
   during the work, the amendment and the raw numbers that forced it must
   already be in the topic journey — if they aren't, stop and reconstruct
   honestly with the user.

3. **Compose the episode** — never a raw file move. Determine the next free
   episode number `NNNN` in `hq/04-JOURNEY/` and write
   `hq/04-JOURNEY/NNNN-<slug>.md` following `hq/04-JOURNEY/TEMPLATE.md`: the
   question, the bars and their verdicts with numbers, what was refuted or
   reversed, what it taught or opened, evidence-class tags, and a
   **Reversal condition:** line (for an abandoned topic: what evidence would
   reopen it; this line is required — the structural lint checks it). Fold in the
   topic journey's substance; link the trail documents.

4. **Route the outcome.**
   - `design`: create or update the design doc under `hq/02-DESIGN/` —
     functional level, decisions numbered (D-entries) with their reasoning,
     explicit enough to implement without guessing. The episode links it.
   - `artifact`: the deliverable ships wherever it belongs (an example, a doc,
     a tool); the episode links it.
   - `abandoned`: nothing ships; the episode is the record.

5. **Update the index.** Add the episode to the index table in
   `hq/04-JOURNEY/README.md` and refresh its "Where things stand" section. If the
   outcome closes or reshapes a roadmap item, update
   `hq/03-IMPLEMENTATION/ROADMAP.md` accordingly.

6. **Remove the topic folder** — on **every** outcome, including graduation
   (`git rm -r hq/01-RESEARCH/<slug>/`). Git history keeps the full trail; a
   lingering terminal-state folder fails the structural lint.

7. **Gate, commit (never push).** Run the full quality gate (`make check`) —
   the structural lint (`internal/hqlint`, under `make test`) must be green.
   Stage only the touched paths by explicit pathspec (never `git add .`/`-A`);
   signed commit (`git commit -S`):
   `docs(research): graduate <slug> --to <outcome> — <one-line verdict>`, with the
   standard co-author trailer (`Co-Authored-By: Claude Fable 5
   <noreply@anthropic.com>`). Remind the human to push.
