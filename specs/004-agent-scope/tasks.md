# Tasks: The agent scope — one template, resolved per mint

**Input**: spec.md, plan.md in this directory.

- [x] T001 `client/scope.go`: `AgentScopeRole` + `AgentScopePubAllow`/`AgentScopeSubAllow`
      (FR-002/FR-003), doc naming the workloads pairing and the deny-list rule.
- [x] T002 `client/scope_test.go`: pinned template lists (SC-004).
- [x] T003 `client/agentscope_e2e_test.go`: operator-mode rig — role key under the
      exported template, D28 mint with tool/topic/persona tags; multi-tag
      expansion, third-tool refusal with zero deliveries, topic clamp,
      zero-tool admit-and-reach-nothing (SC-001..003, FR-005).
- [x] T004 `make fmt && make test && make lint` green, e2e modules included.
