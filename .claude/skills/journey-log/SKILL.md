---
name: "journey-log"
description: "Append a numbered journey episode in the soul-hq for a completed feature, concluded investigation, or load-bearing decision; refresh the index, Where-things-stand, and roadmap."
argument-hint: "What happened (feature landed / decision made), or empty to log the work just completed in this session"
compatibility: "Requires the sibling soul-hq checkout (../soul-hq)"
metadata:
  author: "soul-hq"
user-invocable: true
disable-model-invocation: false
---

## User Input

```text
$ARGUMENTS
```

This project's headquarters lives in the sibling repository `../soul-hq` —
research, designs, the roadmap, and the journey for the whole ecosystem live
there, not in this repo.

**Follow `../soul-hq/.claude/skills/journey-log/SKILL.md`** with the component
preset to `soulstream-identity`, performing every file operation, the quality gate
(`make fmt && make test && make lint`), and the signed commit inside
`../soul-hq` (never push — pushing stays a human act). If the sibling
checkout is missing, stop and say so instead of improvising.
