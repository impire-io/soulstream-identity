# Tasks: The Embed Seam

**Input**: Design documents from `/specs/002-embed-seam/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/embed.md, quickstart.md

**Tests**: mandatory in this project (constitution overrides the template's
optional default). US1's test is the new compiler-proof gate module; US2's
tests are the existing e2e suites, unchanged.

**Organization**: grouped by user story; US1 is the MVP increment.

## Format: `[ID] [P?] [Story] Description`

## Phase 1: Setup

*No setup tasks — existing module, no new dependencies, tooling already
configured (plan.md Technical Context).*

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: the public package both stories serve through.

- [X] T001 Create `embed/embed.go`: package doc (operator surface vs
      `client/`'s consumer surface, custody note), `Options` struct
      exactly as `contracts/embed.md` defines it, defaults application
      (`VaultBucket`, `TokenBucket`, `AuthKeyName`, `CalloutTTL`,
      `Logger`), and construction-time validation per data-model.md rules
      1–4 (required fields; prefix via `service.ValidatePrefix`; callout
      both-halves — including callout-dependent options refused without
      `CalloutConn`; OIDC both-or-neither).
- [X] T002 Implement `Run(ctx, Options) error` in `embed/embed.go`: the
      `cmdServe` lift — JetStream handle, KV buckets
      (`CreateOrUpdateKeyValue`), `vault.New` + `Verify` (fail fast,
      data-model rule 5), token store + `service.New(WithCallout…,
      WithPrefix…)` + `svc.Start(o.Conn)`, issuer (`callout.NewIssuer`,
      `WithOIDC` when configured, `Start(o.CalloutConn)`), the two
      serving log lines with today's keys (research R6), block on
      `ctx.Done()`, drain the service and issuer subscriptions only —
      never the caller's connections (research R2) — and return
      `ctx.Err()`.

**Checkpoint**: `go build ./...` green; the package exposes exactly one
type and one function, no `internal/` type in the signature.

---

## Phase 3: User Story 1 — A distribution hosts the identity plane in its own process (P1) 🎯 MVP

**Goal**: a consumer module outside the repo namespace assembles and runs
the plane through `embed.Run` with zero `internal/` imports.

**Independent Test**: `cd e2e/embedgate && go test ./...` — the toolchain
itself rejects any `internal/` import (module path
`soulidentity.invalid/embedgate`), and the M4 admission shape passes.

- [X] T003 [US1] Create `e2e/embedgate/go.mod`: module
      `soulidentity.invalid/embedgate` (research R3), go 1.26.2, requires
      soulidentity v0.0.0 + nats-server/nats.go/jwt/nkeys at the repo's
      pinned versions, `replace github.com/impire-io/soulidentity =>
      ../..`, header comment stating the compiler-proof purpose and
      never-published nature.
- [X] T004 [US1] Write the ceremony half of
      `e2e/embedgate/gate_test.go`: operator-mode embedded server with
      auth callout (operator/SYS/AUTH/APP accounts, AUTH
      `EnableExternalAuthorization` + `AllowedAccounts` + xkey, APP
      scoped signing key, MEMORY resolver preload, JetStream store dir),
      bootstrap creds (service, ops, issuer user), the three curve
      seeds — the `client/callout_e2e_test.go` ceremony re-expressed
      consumer-side (research R4; soulnode's rig is the fourth prior).
- [X] T005 [US1] Write the scenario half of `e2e/embedgate/gate_test.go`:
      start `embed.Run` in a goroutine (service + callout conns from the
      ceremony), wait for readiness (status answer), then through public
      `client`: import the two signing keys, create a `sit_` token, mint
      the sentinel; prove admission (sentinel + token connects, persona
      attributed), invalid-token refusal, revoked-token refusal, `callout
      REFUSED` in the captured audit log; cancel ctx and assert `Run`
      returns with subscriptions drained (spec US1 scenarios 1–3).
- [X] T006 [US1] Wire `e2e/embedgate` into the `Makefile`: `tidy`,
      `test`, and `lint` each gain the `cd e2e/embedgate && …` line
      beside the existing `e2e` lines (plan structure decision).

**Checkpoint**: US1 independently deliverable — the seam exists and is
compiler-proven from consumer position.

---

## Phase 4: User Story 2 — The daemon serves through the same assembly (P2)

**Goal**: one assembly, two entrypoints; the daemon's contract unchanged.

**Independent Test**: the existing e2e gates (M3 sealed surface, M4
callout, M2 cross-service) pass without modification.

- [X] T007 [US2] Refactor `cmdServe` in `cmd/soulidentity/main.go` to
      parse flags/env and own its connections exactly as today, then
      delegate assembly to `embed.Run(ctx, …)`; keep the daemon's
      post-Run connection drains (research R2); map misconfiguration
      errors where flags add information (research R5); delete the
      now-duplicated assembly code.
- [X] T008 [US2] Run the unchanged existing suites — `go test ./...` and
      `cd e2e && go test ./...` — and confirm the M3/M4/M2 gates pass
      with zero test edits (spec SC-002); fix parity gaps in
      `embed/embed.go` if any surface.

**Checkpoint**: both entrypoints serve the identical assembly.

---

## Phase 5: Polish & Landing

- [X] T009 [P] Verify `specs/002-embed-seam/quickstart.md` against the
      real surface (import alias, field names, make line) and correct any
      drift; confirm package doc reads plainly (constitution IV).
- [X] T010 Full gate: `make check` (fmt, tidy — now three modules, build,
      test, lint) all green, nothing skipped (spec SC-004).
- [X] T011 Landing duties in the same merge (how-we-work): journey
      episode via `/journey-log` (D29 + this feature; evidence tags;
      reversal condition), `hq/03-IMPLEMENTATION/ROADMAP.md` M2 entry
      updated (second consumer served — the embed seam), design
      propagation check (D29 already in `hq/02-DESIGN/agent.md`; amend if
      implementation shifted behavior), spec `Status: Draft` →
      implemented.

## Dependencies

```
T001 ─▶ T002 ─┬▶ T003 ─▶ T004 ─▶ T005 ─▶ T006   (US1)
              └▶ T007 ─▶ T008                    (US2)
T009 [P] anytime after T002; T010 after T006+T008; T011 last
```

US1 and US2 are independent after Phase 2 and can proceed in parallel
(different files: `e2e/embedgate/*` vs `cmd/soulidentity/main.go`).

## Implementation Strategy

MVP = Phase 2 + US1 (the seam, compiler-proven). US2 is the drift guard
and lands in the same feature since it deletes the duplicated assembly.
Estimated shape: ~150 LOC package, ~250 LOC gate module, net-negative cmd.
