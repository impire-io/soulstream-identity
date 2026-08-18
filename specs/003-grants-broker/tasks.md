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

## Review pass — 2026-08-18 (morning review, slice landed)

Review verdict: sound. Three review additions on this branch: the
delegation gains a not-before check (`issued_at` validated, D33 amended),
the no-key-subject refusal is tested directly at both layers, and the
provider sends `Accept: application/json` (GitHub answers form-encoded
without it — found writing T009, would have failed the SC-005 walk).
Named residue, accepted: a revoke racing a rotation best-effort-revokes
the pre-rotation token upstream; custody deletion is the decision either
way.

- [x] T007 Consumer-position e2e: `e2e/embedgate` `TestGrantsGate` —
      the scope template carries the grants op tail; alice links against
      a strict rotating stand-in AS and accesses twice; bob's publish to
      alice's grants subject dies at the server (permissions violation
      on bob's own connection, request unanswered) and the delivery log
      shows alice's subject served exactly twice; revocation refuses.
- [x] T008 CLI verbs `grant link|access|ls|revoke` + usage block;
      README grows the outbound-grants section with the scope-template
      line (the D25 stated-shapes duty).
- [x] T009 The real-provider runbook written into quickstart.md (GitHub
      preferred — rotating refresh tokens exercise D31 live; Google
      alternative with the offline-ask baked into AuthURL). The live
      walk itself is the operator's checkbox there — SC-005 stays open
      until a human runs it.
- [x] T010 Design propagated: grants.md D31 records the time-bounded
      contention deadline and the poll-for-rotation bridge; D33 records
      the not-before check.
- [ ] T011 Journey episode + roadmap/index refresh in soul-hq at landing
      (the journey duty runs at merge, not at branch).
