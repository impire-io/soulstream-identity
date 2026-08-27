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
