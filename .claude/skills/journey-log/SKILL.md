---
name: "journey-log"
description: "Append a numbered journey episode for completed work, a concluded investigation, or a load-bearing decision; refresh the index, Where-things-stand, and roadmap."
argument-hint: "What happened (work landed / decision made), or empty to log the work just completed in this session"
compatibility: "Requires the hq/ structure (hq/04-JOURNEY/TEMPLATE.md)"
metadata:
  author: "soulidentity-hq"
user-invocable: true
disable-model-invocation: false
---

## User Input

```text
$ARGUMENTS
```

If `$ARGUMENTS` is empty, the subject is the work completed in the current
session; reconstruct it from the conversation and `git log`.

## Steps

1. **Scope check.** An episode is warranted for: landed work (a milestone or a
   behavior-changing feature), a concluded investigation (research topics get
   theirs via `/research-graduate` instead — do not duplicate), or a
   load-bearing decision (custody-boundary change, enforcement-mode change,
   criterion amendment, refuted hypothesis, direction call). If none applies,
   say so and stop.

2. **Write the episode.** Next free number `NNNN` in `hq/04-JOURNEY/`, file
   `NNNN-<short-kebab-slug>.md`, following `hq/04-JOURNEY/TEMPLATE.md` exactly:
   what happened with the honest numbers (spreads, not bare means), what was
   refuted or reversed, what it taught or opened, evidence-class tags
   (`[measured]` / `[mechanism-argument]` / `[judgment]`) on load-bearing claims,
   the trail (docs, commits), and the required **Reversal condition:** line. For
   direction decisions the working agreement applies first: teach-back before
   recording, adversarial pass for calls that change the custody boundary or an
   enforcement mode (`hq/00-GENESIS/constitution.md`, The Working Agreement).

3. **Refresh the surroundings, same change-set:** add the episode to the index in
   `hq/04-JOURNEY/README.md`; refresh its "Where things stand" section; update the
   affected item in `hq/03-IMPLEMENTATION/ROADMAP.md`; propagate behavioral
   changes into the `hq/02-DESIGN/` docs they touch.

4. **Gate, commit (never push).** Full quality gate green (`make check` —
   includes the `internal/hqlint` structural lint under `make test`). Stage only
   the touched paths by explicit pathspec (never `git add .`/`-A`); signed commit
   (`git commit -S`) — ideally amend/join the commit of the work the episode
   describes, otherwise `docs(journey): NNNN — <title>` with the standard
   co-author trailer (`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`).
   Remind the human to push.
