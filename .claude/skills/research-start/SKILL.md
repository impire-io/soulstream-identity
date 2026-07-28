---
name: "research-start"
description: "Open a new research topic in hq/01-RESEARCH with a pre-registration README and its own journey file."
argument-hint: "<slug> — short kebab-case topic name, optionally followed by the question"
compatibility: "Requires the hq/ structure (hq/01-RESEARCH/TEMPLATE.md)"
metadata:
  author: "soulstream-hq"
user-invocable: true
disable-model-invocation: false
---

## User Input

```text
$ARGUMENTS
```

Parse `$ARGUMENTS` as: a kebab-case `<slug>` (required, first token), and
optionally the research question in the remaining text. If the slug is missing
or not kebab-case, ask for it instead of guessing.

## Steps

1. **Refuse duplicates and illegal states.** If `hq/01-RESEARCH/<slug>/` already
   exists, stop and report it. Read `hq/00-GENESIS/how-we-work.md` (Research
   section) if you have not this session.

2. **Create the topic folder** `hq/01-RESEARCH/<slug>/` containing:
   - `README.md` — a copy of `hq/01-RESEARCH/TEMPLATE.md` with the title,
     `**State:** active`, `**Started:** <today>`, and — if the user supplied the
     question — the Abstract and Question sections drafted from it. The
     **pre-registered bars must be written before any experiment runs**: if the
     user's input doesn't determine them yet, draft them with the user now (they
     are the point of the file), never leave placeholder text and move on.
     Include the Reversal condition, phrased as observable evidence.
   - `JOURNEY.md` — a header line naming the topic and start date, otherwise
     empty; the investigation appends here as it happens.

3. **Commit (never push).** Stage **only** `hq/01-RESEARCH/<slug>/` by explicit
   pathspec (never `git add .`/`-A`), then create a signed commit
   (`git commit -S`): `docs(research): open <slug> — <one-line question>`,
   ending with the repository's standard co-author trailer
   (`Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`). Pushing is the
   human's act; remind them research is always pushed (`git push`) so the trail
   exists even if the topic is later abandoned.

4. **Report**: the folder path, the bars as registered, and the reminder that
   the topic ends only through `/research-graduate <slug> --to
   design|artifact|abandoned`.
