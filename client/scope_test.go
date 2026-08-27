package client_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/impire-io/soulstream-identity/client"
)

// TestAgentScopeTemplatesPinned (spec 004 SC-004): the exported agent scope
// is the workloads agent derivation with the dynamic parts as tag
// functions, byte-for-byte. A change here is a policy change for every
// deployment founded from it — it must be deliberate.
func TestAgentScopeTemplatesPinned(t *testing.T) {
	wantPub := []string{
		"SOULSTREAM.TOPICS.OPS.{{tag(topic)}}",
		"SOULSTREAM.PERSONA.NOTIFY.*",
		"SOULSTREAM.SVC.{{tag(tool)}}",
		"_INBOX.>",
		"$JS.API.INFO",
	}
	if got := client.AgentScopePubAllow(""); !reflect.DeepEqual(got, wantPub) {
		t.Fatalf("AgentScopePubAllow = %v, want %v", got, wantPub)
	}
	wantSub := []string{
		"SOULSTREAM.TOPICS.OPS.{{tag(topic)}}",
		"SOULSTREAM.TOPICS.INFO.>",
		"SOULSTREAM.PERSONA.NOTIFY.{{name()}}",
		"_INBOX.>",
	}
	if got := client.AgentScopeSubAllow(""); !reflect.DeepEqual(got, wantSub) {
		t.Fatalf("AgentScopeSubAllow = %v, want %v", got, wantSub)
	}
	if client.AgentScopeRole != "soulstream-agent" {
		t.Fatalf("AgentScopeRole = %q", client.AgentScopeRole)
	}
	// The deny-list rule (FR-004) is structural: this package exports allow
	// lists only, and no entry smuggles a deny marker.
	for _, s := range append(client.AgentScopePubAllow(""), client.AgentScopeSubAllow("")...) {
		if strings.HasPrefix(s, "!") || strings.Contains(s, " ") {
			t.Fatalf("template entry %q is not a plain subject", s)
		}
	}
}
