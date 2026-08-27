# Feature Specification: The agent scope — one template, resolved per mint

**Feature Branch**: `004-agent-scope`
**Created**: 2026-08-27
**Status**: Draft
**Input**: soul-hq designs [`0005-agent-declaration.md`](../../../soul-hq/02-DESIGN/soulstream-workloads/0005-agent-declaration.md) §5 and [`0003-fleet.md`](../../../soul-hq/02-DESIGN/soulstream-workloads/0003-fleet.md) §5: the identity half of the `capability-minting` arc. D28's `mint.ephemeral` already stamps tags; what is missing is the **template vocabulary** — the canonical agent permission scope with the dynamic parts as tag functions (`{{tag(topic)}}`, `{{tag(tool)}}`, `{{name()}}`), exported from `client` so every founding ceremony and authority renders the same template from one source and cannot drift (the D47 discipline). No op, mint, or service change.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A tagged mint is clamped by the template alone (Priority: P1)

A deployment's account carries a scoped signer under the agent role whose template is this package's exported scope. A D28 ephemeral mint against that role with `tool:`/`topic:`/`persona:` tags admits a workload that reaches exactly its tagged subjects — the whole policy is the template expansion, server-side; zero authorization code anywhere else.

**Why this priority**: This is the arc's identity half — and the first shipped `{{tag()}}` template in the ecosystem (research 0126 measured it in a rig; this makes it a standing test).

**Independent Test**: The e2e rig mints against a role key endorsed with the exported template and measures granted/refused at the transport.

**Acceptance Scenarios**:

1. **Given** a mint tagged `tool:toola, tool:toolb`, **When** the workload calls both tools, **Then** both answer (multi-tag expansion measured); **When** it publishes to a third tool subject, **Then** the server refuses and the third responder receives nothing.
2. **Given** a mint tagged `topic:t-ab12`, **When** the workload publishes an op on that topic's subject, **Then** it arrives; **When** it publishes on another topic's subject, **Then** the server refuses.
3. **Given** a mint with **no** `tool:` tags, **When** the workload connects, **Then** the connection admits (the zero-tag template line drops instead of failing auth) and every tool-namespace publish refuses.

---

### User Story 2 - One source, no drift (Priority: P1)

The ceremony that founds an account and the authority that amends one render the agent template by calling this package — never by copying strings.

**Why this priority**: The byon rc.10 lesson: founding-time templates make widening a per-deployment migration; a drifted copy is a silent policy fork.

**Independent Test**: Unit pins the exported lists; consumers are compiled against the exported functions.

**Acceptance Scenarios**:

1. **Given** the exported pub/sub lists, **When** compared to the workloads runtime's agent permission derivation, **Then** they are the same subjects with the dynamic parts as tag functions (asserted by the pinned unit here; drift-courted end-to-end by the product's consumer-position e2e).

---

### Edge Cases

- Tags are stamped lowercased/trimmed/deduped by the claim layer; the tag values workloads renders are already lowercase-only by its name grammar — no case gap.
- The mention/notify subscribe rides `{{name()}}` (the persona IS the minted user under D28), so reachability cannot drift from attribution; the `persona:` tag still stamps for claims-level audit.
- The template must never place a tag function in a deny list (a missing tag would fail authorization outright instead of dropping the line).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `client` MUST export the agent scope as `AgentScopeRole` and `AgentScopePubAllow`/`AgentScopeSubAllow`, mirroring the persona-scope surface.
- **FR-002**: The publish template MUST be exactly: the tagged topic's ops subject, the notify publish wildcard, the tagged tool subjects, the inbox wildcard, and the one JetStream info subject — the workloads agent derivation with dynamic parts as tag functions.
- **FR-003**: The subscribe template MUST be exactly: the tagged topic's ops subject, the topic info wildcard, the minted user's own notify subject (`{{name()}}`), and the inbox wildcard.
- **FR-004**: No allow entry may use a tag function in a deny list; no service, mint, or vault change ships in this feature.
- **FR-005**: The e2e MUST measure the two server behaviors the arc depends on before anything builds on them: multi-value tag expansion (two tools both reachable) and the zero-matching-tag line drop (connection still admits).

### Key Entities

- **Agent scope**: the canonical permission template a deployment's agent-role scoped signer carries.
- **Tag function**: the server-side template token (`{{tag(k)}}`, `{{name()}}`) resolved per admitted user from its claims.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Both tagged tools answer through one minted credential; a third refuses server-side with zero deliveries [measured in `make test`].
- **SC-002**: The tagged topic op arrives; an untagged topic publish refuses [measured].
- **SC-003**: A zero-tool mint admits and reaches no tool subject [measured].
- **SC-004**: The exported template lists are pinned byte-for-byte by unit test.
- **SC-005**: Full gate green: `make fmt && make test && make lint`, e2e modules included.

## Assumptions

- The workloads repo dual-writes the tag key names (`tool`/`topic`/`persona`) — the cycle guard forbids a shared constant; the product's e2e is the drift court.
- Account provisioning that installs the agent-role scoped signer (ceremony, kit, tenancy authority) is the product arc's half (its spec 013), not this feature's.
