# Tasks: The Grants Broker

## Slice 1 — landed on this branch (overnight 2026-08-17, operator directive)

- [x] T001 `internal/grants`: sealed CAS store seam (KV + Mem), grant/link
      records, broker core (link start/complete, access with rotation
      discipline, list, revoke), delegation verification (D30–D33).
- [x] T002 `internal/grants`: HTTP provider (code exchange with PKCE,
      refresh redemption, RFC 7009 revoke) — the repo's first outbound
      HTTP, confined to provider.go, declared endpoints only.
- [x] T003 Tests: rotation persists (3×), concurrent stampede under
      `-race` (8-way, both reuse regimes, line survives), revoke refuses
      with probe-proof refusals, delegation matrix (allowed + 5 refusal
      classes), link ceremony against a stand-in AS over real HTTP,
      at-rest positive control (refresh token greps from plaintext, not
      from sealed bytes).
- [x] T004 `internal/service/ops_grants.go`: the op family on the
      dispatch, capability check, both-persona audit on every on-behalf
      decision; service tests drive the sealed surface including a real
      vault-materialized persona key signing a delegation and a stolen
      delegation refusing.
- [x] T005 `client/grants.go`: wire mirror + `MintDelegation` (one
      sign.record round-trip).
- [x] T006 `embed.Options.GrantResources`/`GrantsBucket` + daemon
      `--grants-catalog`/`--grants-bucket` (one assembly, two
      entrypoints).

## Remaining — for review and the next session

- [ ] T007 Consumer-position e2e (`e2e/` or `e2e/embedgate/`): SC-001's
      transport clause on an operator-mode server — the scope template
      grows the grants op tail, a second persona's publish to the
      victim's grants subject is server-refused with the delivery-log
      proof. (The mechanism is measured in the research rig — hq episode
      0104 — but the repo's own gate should carry it.)
- [ ] T008 CLI verbs (`soulstream-identity grant link|access|ls|revoke`)
      and the usage block; deployment docs for the scope-template line
      (the D25 stated-shapes duty).
- [ ] T009 The real-provider runbook (SC-005, the research residue):
      GitHub or Google — register the app, link, rotate, revoke; a
      quickstart.md human step, never a gate test.
- [ ] T010 Design propagation check after review: grants.md D31's
      crash-window wording vs the implemented poll-for-rotation; the
      contention-deadline decision recorded here lands in the design doc
      if review keeps it.
- [ ] T011 Journey episode + roadmap/index refresh in soul-hq at landing
      (the journey duty runs at merge, not at branch).
