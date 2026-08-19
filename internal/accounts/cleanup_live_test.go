//go:build byon_live

package accounts

import (
	"strings"
	"testing"
)

// TestCleanupProbeAccounts removes every bar1-probe-* account a
// measurement run left behind (a failed run cannot always reach its own
// cleanup — the control plane 503s while it settles). Touches nothing
// else in the system.
func TestCleanupProbeAccounts(t *testing.T) {
	client, systemID, ctx := cpClient(t)
	authority := &ProviderAPI{Client: client, SystemID: systemID,
		Log: func(f string, a ...any) { t.Logf(f, a...) }}
	accounts, _, err := client.SystemAPI.ListAccounts(ctx, systemID).Execute()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range accounts.Items {
		if !strings.HasPrefix(strings.ToLower(a.Name), "bar1-probe-") {
			continue
		}
		if err := authority.Delete(ctx, a.Name); err != nil {
			t.Errorf("delete %s: %v", a.Name, err)
		}
	}
}
