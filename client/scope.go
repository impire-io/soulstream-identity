package client

// The canonical persona scope (D47, hq
// 02-DESIGN/soulstream-identity/platform-topology.md): the permission
// template a deployment's scoped signing keys carry — what an admitted
// persona may do. Exported so the founding ceremony and the tenancy
// authority render the SAME template from one source and cannot drift
// (the spec-010 SC-004 discipline extended to tenancy). The `{{…}}`
// tokens are the server's scoped-signer template functions, resolved per
// admitted user.

// PersonaScopePubAllow returns the publish allow-list of the canonical
// persona scope. prefix is the deployment's shared ecosystem prefix (D14),
// empty for the bare default root; it applies to the identity-plane
// subjects only — the record's and JetStream's spaces are their own.
func PersonaScopePubAllow(prefix string) []string {
	root := Segment
	if prefix != "" {
		root = prefix + "." + Segment
	}
	return []string{
		root + ".status",
		root + ".xkey",
		root + ".{{account-subject()}}.{{name()}}.sign.record",
		root + ".{{account-subject()}}.{{name()}}.keys.public",
		root + ".{{account-subject()}}.{{name()}}.grants.>",
		root + ".{{account-subject()}}.{{name()}}.approvals.>",
		// The sealing custodian's one op (sealing-keys.md D52): unwrapping
		// is the persona's own act on its own prefix, like signing.
		root + ".{{account-subject()}}.{{name()}}.seal.unwrap",
		"SOULSTREAM.>",
		"$JS.API.>",
		"$KV.>",
		"$O.>",
		"$SYS.REQ.USER.INFO",
	}
}

// PersonaScopeSubAllow returns the subscribe allow-list of the canonical
// persona scope. The prefix parameter is accepted for symmetry; no
// identity-plane subject appears on the subscribe side today.
func PersonaScopeSubAllow(_ string) []string {
	return []string{"_INBOX.>", "SOULSTREAM.>"}
}

// AgentScopeRole is the scoped-signer role label a deployment's agent-role
// signing key carries. The signing key is imported into the vault under the
// deployment's chosen role name (D24 binding); D28's mint.ephemeral selects
// it by that name and the server clamps every minted workload to the
// template below.
const AgentScopeRole = "soulstream-agent"

// AgentScopePubAllow returns the publish allow-list of the canonical agent
// scope (hq design 0005 §5): the workloads runtime's agent permission
// derivation with the dynamic parts as scoped-signer tag functions —
// `{{tag(topic)}}` and `{{tag(tool)}}` resolve from the mint's tags, so the
// template is the entire policy and a workload reaches exactly what its
// declaration named. The tag keys (`tool`, `topic`, `persona`) are
// dual-written in the workloads repo's minter (the cycle guard forbids a
// shared constant); the product's consumer-position e2e is the drift court.
// A tag function must NEVER appear in a deny list — a missing tag would
// fail authorization outright instead of dropping the line. The prefix
// parameter is accepted for symmetry; the record's subjects carry no
// ecosystem prefix.
func AgentScopePubAllow(_ string) []string {
	return []string{
		"SOULSTREAM.TOPICS.OPS.{{tag(topic)}}",
		"SOULSTREAM.PERSONA.NOTIFY.*",
		"SOULSTREAM.SVC.{{tag(tool)}}",
		"_INBOX.>",
		"$JS.API.INFO",
	}
}

// AgentScopeSubAllow returns the subscribe allow-list of the canonical
// agent scope. The notify subject rides `{{name()}}` — under D28 the
// persona IS the minted user's name, so reachability cannot drift from
// attribution (the `persona:` tag still stamps into the claims for audit).
func AgentScopeSubAllow(_ string) []string {
	return []string{
		"SOULSTREAM.TOPICS.OPS.{{tag(topic)}}",
		"SOULSTREAM.TOPICS.INFO.>",
		"SOULSTREAM.PERSONA.NOTIFY.{{name()}}",
		"_INBOX.>",
	}
}
