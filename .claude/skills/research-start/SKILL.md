---
name: "research-start"
description: "Open a new research topic in the soul-hq (../soul-hq/01-RESEARCH) with a pre-registration README and its own journey file."
argument-hint: "<slug> — short kebab-case topic name, optionally followed by the question"
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

**Follow `../soul-hq/.claude/skills/research-start/SKILL.md`** with the component
preset to `soulstream-identity`, performing every file operation, the quality gate
(`make fmt && make test && make lint`), and the signed commit inside
`../soul-hq` (never push — pushing stays a human act). If the sibling
checkout is missing, stop and say so instead of improvising.
