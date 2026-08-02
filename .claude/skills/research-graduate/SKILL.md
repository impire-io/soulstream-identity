---
name: "research-graduate"
description: "Close a soul-hq research topic (design | artifact | abandoned): compose its journey episode, update the design doc, remove the topic folder."
argument-hint: "<slug> --to design|artifact|abandoned"
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

**Follow `../soul-hq/.claude/skills/research-graduate/SKILL.md`** with the component
preset to `soulidentity`, performing every file operation, the quality gate
(`make fmt && make test && make lint`), and the signed commit inside
`../soul-hq` (never push — pushing stays a human act). If the sibling
checkout is missing, stop and say so instead of improvising.
