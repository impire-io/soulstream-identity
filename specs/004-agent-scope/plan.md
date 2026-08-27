# Implementation Plan: The agent scope — one template, resolved per mint

**Branch**: `004-agent-scope` | **Date**: 2026-08-27 | **Spec**: [spec.md](spec.md)

## Summary

Export the canonical agent permission template beside the persona scope in
`client/scope.go` — the workloads agent derivation with its dynamic parts
as scoped-signer tag functions — plus the e2e that turns research 0126's
measured rig into a standing test and first-verifies multi-tag expansion
and the zero-tag line drop. Nothing else changes: D28 already stamps tags;
authorization stays the server's template expansion.

## Technical Context

**Language/Version**: Go 1.25 (repo standard)
**Primary Dependencies**: existing only; no new module requirements
**Storage**: none
**Testing**: template unit (string equality); `client/agentscope_e2e_test.go`
on the operator-mode rig pattern of `client/e2e_test.go`
**Constraints**: no service/mint/vault change; no tag function in any deny
list; template strings single-sourced here
**Scale/Scope**: one source file, one unit, one e2e file

## Constitution Check

- **I Custody Without Possession — PASS**: nothing touches key material.
- **II The seam, not a silo — PASS**: a permission template, usable by any
  deployment; no Soulstream-only endpoint.
- **III Decided-then-built — PASS**: design 0005 §5 [V] and D28 are the
  decided basis; the two under-measured server behaviors are measured by
  this feature's own e2e before anything builds on them.
- **D25 (ACL is the authorization) — PASS**: the template IS the policy;
  no rule table appears.

## Project Structure

```text
specs/004-agent-scope/   # spec.md, plan.md, tasks.md
client/
├── scope.go             # + AgentScopeRole, AgentScopePubAllow/SubAllow
├── scope_test.go        # NEW: pinned template lists
└── agentscope_e2e_test.go  # NEW: the 0126 rig as a standing test
```

## Complexity Tracking

No constitution violations to justify.
