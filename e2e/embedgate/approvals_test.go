// The approvals gate (approvals.md D42–D45, episode 0119): the loop that
// research measured as unclosable closes, in consumer position. A deferred
// op refuses with a machine-readable ticket; the ticket is durable, its
// expiry witnessed; the human's yes is minted and presented through the
// public client; the retry serves; the conversion is one-shot; the deny
// and expiry arms end their tickets by name; an approval from outside the
// rule's approvers clause refuses; and nothing anywhere — store, reply,
// audit — carries the deferred invocation's arguments.
package embedgate

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/embed"
)

func TestApprovalsGate(t *testing.T) {
	c := provision(t)

	audit := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(audit, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- embed.Run(ctx, embed.Options{
			Conn: c.ncService, CalloutConn: c.ncCallout,
			FirstKey: c.firstSeed, SurfaceKey: c.surfaceSeed,
			CalloutKey: c.calloutSeed, AuthAccount: c.authPub,
			CalloutTTL: 2 * time.Minute,
			GuardrailRules: []embed.GuardrailRule{{
				Name: "defer-secret-puts", When: `action == "secrets.put"`, Effect: "defer",
				Approvers: []string{"approver-ext"},
			}},
			TicketTTL: 3 * time.Second,
			Logger:    logger,
		})
	}()
	ops := client.New(c.ncOps, c.appPub, "ops")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := ops.Status(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("service never served")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := ops.ImportKey("acme", client.KindNATSAccountSigningKey, c.acmeSKSeed, c.appPub, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ImportKey("auth/issuer", client.KindNATSAccountSigningKey, c.authSKSeed, c.authPub, ""); err != nil {
		t.Fatal(err)
	}

	// The approver and a rogue, admitted through callout. They only ever
	// MINT (one sign.record, in the template); presenting stays the
	// originator's own act.
	sentinel, err := ops.MintSentinel()
	if err != nil {
		t.Fatal(err)
	}
	sentinelPath := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(sentinelPath, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatal(err)
	}
	dial := func(persona string) *client.Client {
		tok, err := ops.CreateToken(c.appPub, persona, "approvals gate", 0)
		if err != nil {
			t.Fatal(err)
		}
		nc, err := nats.Connect(c.url, nats.UserCredentials(sentinelPath), nats.Token(tok.Token),
			nats.RetryOnFailedConnect(false), nats.MaxReconnects(0))
		if err != nil {
			t.Fatalf("%s admission: %v", persona, err)
		}
		t.Cleanup(nc.Close)
		return client.New(nc, c.appPub, persona)
	}
	approver := dial("approver-ext")
	rogue := dial("rogue-ext")

	// The emit half, machine-readable: the refusal parses into the ticket
	// the caller now holds, window included (D42's structured refusal).
	const plantedArg = "s3cr3t-planted-argument-value"
	put := func(value string) (client.Deferral, error) {
		_, err := ops.SecretPut("plans/launch", []byte(value), 0)
		if err == nil {
			return client.Deferral{}, nil
		}
		if d, ok := client.ParseDeferral(err); ok {
			return d, err
		}
		return client.Deferral{}, err
	}
	d1, err := put(plantedArg)
	if err == nil || d1.InvocationID == "" {
		t.Fatalf("the defer did not emit a parseable ticket: %v", err)
	}
	if d1.Rule != "defer-secret-puts" || d1.ExpiresAt.IsZero() {
		t.Fatalf("the deferral is incomplete: %+v", d1)
	}

	// The ticket is readable by its originator — and by nobody else, the
	// same not-found either way.
	tk, err := ops.ApprovalStatus(d1.InvocationID)
	if err != nil || tk.State != "pending" || tk.Action != "secrets.put" {
		t.Fatalf("status: %+v %v", tk, err)
	}
	imposter := client.New(c.ncOps, c.appPub, "someone-else", client.WithTimeout(3*time.Second))
	if _, err := imposter.ApprovalStatus(d1.InvocationID); err == nil ||
		!strings.Contains(err.Error(), "no such ticket") {
		t.Fatalf("another principal read the ticket: %v", err)
	}

	// The approver sees it pending — and the standing rules, approvers
	// clause included, without keeping any copy (D43).
	pending, err := ops.PendingApprovals()
	if err != nil || len(pending) != 1 || pending[0].InvocationID != d1.InvocationID {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	rules, err := ops.GuardrailRules()
	if err != nil || len(rules) != 1 || rules[0].Approvers[0] != "approver-ext" {
		t.Fatalf("guardrail.list: %+v %v", rules, err)
	}

	// The loop closes: mint, present, retry serves, ticket spent.
	yes, err := approver.MintApproval(d1.InvocationID, "ops", 2*time.Minute)
	if err != nil {
		t.Fatalf("minting the yes: %v", err)
	}
	if err := ops.PresentApproval(d1.InvocationID, yes); err != nil {
		t.Fatalf("presenting: %v", err)
	}
	if tk, _ := ops.ApprovalStatus(d1.InvocationID); tk.State != "approved" || tk.ResolvedBy != "approver-ext" {
		t.Fatalf("the yes is not witnessed: %+v", tk)
	}
	if _, err := put(plantedArg); err != nil {
		t.Fatalf("the approved retry did not serve: %v", err)
	}
	if tk, _ := ops.ApprovalStatus(d1.InvocationID); tk.State != "spent" {
		t.Fatalf("the conversion is not witnessed: %+v", tk)
	}

	// One-shot: the same invocation defers again — a fresh ask reopens a
	// fresh window; nothing about the spent yes carries over.
	d2, err := put(plantedArg)
	if err == nil || d2.InvocationID != d1.InvocationID {
		t.Fatalf("the next ask did not defer on a reopened ticket: %+v %v", d2, err)
	}

	// The deny arm: same verification shape, the ticket ends denied, and
	// a yes presented after the no refuses by the ticket's state.
	no, err := approver.MintApproval(d1.InvocationID, "ops", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.DenyApproval(d1.InvocationID, no); err != nil {
		t.Fatalf("denying: %v", err)
	}
	if tk, _ := ops.ApprovalStatus(d1.InvocationID); tk.State != "denied" {
		t.Fatalf("the no is not witnessed: %+v", tk)
	}
	late, err := approver.MintApproval(d1.InvocationID, "ops", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.PresentApproval(d1.InvocationID, late); err == nil ||
		!strings.Contains(err.Error(), "denied") {
		t.Fatalf("a yes after the no: want the by-state refusal, got %v", err)
	}

	// D45: a well-formed approval from outside the rule's approvers
	// clause refuses by name.
	d3, err := put("a different value entirely")
	if err == nil || d3.InvocationID == "" || d3.InvocationID == d1.InvocationID {
		t.Fatalf("no fresh deferral for the rogue arm: %+v %v", d3, err)
	}
	rogueYes, err := rogue.MintApproval(d3.InvocationID, "ops", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.PresentApproval(d3.InvocationID, rogueYes); err == nil ||
		!strings.Contains(err.Error(), "not an approver") {
		t.Fatalf("a rogue's approval: want the by-name refusal, got %v", err)
	}

	// Expiry, witnessed: the window passes, the state is written expired
	// on observation, and a yes after the clock refuses by state.
	time.Sleep(3200 * time.Millisecond)
	if tk, _ := ops.ApprovalStatus(d3.InvocationID); tk.State != "expired" || tk.ResolvedAt == "" {
		t.Fatalf("expiry is not witnessed: %+v", tk)
	}
	lateYes, err := approver.MintApproval(d3.InvocationID, "ops", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := ops.PresentApproval(d3.InvocationID, lateYes); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("a yes after the window: want the by-state refusal, got %v", err)
	}

	// Bar 3's at-rest arm, finally runnable: the ticket store carries the
	// invocation's name and never its arguments — sealed, scanned raw,
	// with the plant control fired. The audit says nothing either.
	js, err := jetstream.New(c.ncOps)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.KeyValue(context.Background(), "SOULIDENTITY_TICKETS")
	if err != nil {
		t.Fatal(err)
	}
	scan := func() int {
		hits := 0
		lister, err := kv.ListKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for name := range lister.Keys() {
			entry, err := kv.Get(context.Background(), name)
			if err != nil {
				continue
			}
			if strings.Contains(string(entry.Value()), plantedArg) {
				hits++
			}
		}
		return hits
	}
	if got := scan(); got != 0 {
		t.Fatalf("the ticket store carries the deferred arguments: %d hits", got)
	}
	if _, err := kv.Create(context.Background(), "planted-control", []byte("x"+plantedArg+"x")); err != nil {
		t.Fatal(err)
	}
	if got := scan(); got != 1 {
		t.Fatalf("positive control did not fire: %d hits", got)
	}
	_ = kv.Delete(context.Background(), "planted-control")
	if strings.Contains(audit.String(), plantedArg) {
		t.Fatal("the audit log carries the deferred arguments")
	}

	cancel()
	select {
	case err := <-runErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("plane: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("plane did not drain")
	}
}
