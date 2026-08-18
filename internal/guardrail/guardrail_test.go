package guardrail

import (
	"strings"
	"testing"
	"time"
)

func testEval(t *testing.T, rules ...Rule) *Evaluator {
	t.Helper()
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Load(rules); err != nil {
		t.Fatal(err)
	}
	return e
}

func in(principal, action string, args map[string]any) Input {
	return Input{Principal: principal, Action: action, Args: args,
		Raw: []byte(action), Time: time.Now()}
}

// TestThreeOutcomesFirstMatchWins (B3): allow, deny, defer — first
// matching rule decides; no match allows.
func TestThreeOutcomesFirstMatchWins(t *testing.T) {
	e := testEval(t,
		Rule{Name: "block-prod", When: `action == "tokens.create" && string(args.label) == "prod"`, Effect: Deny},
		Rule{Name: "human-for-export", When: `action == "mint" && has(args.export_creds) && args.export_creds == true`, Effect: Defer},
		Rule{Name: "agents-allowed", When: `principal.endsWith("/agent")`, Effect: Allow},
	)
	if d := e.Evaluate(in("a/u", "tokens.create", map[string]any{"label": "prod"})); d.Effect != Deny || d.Rule != "block-prod" {
		t.Fatalf("deny: %+v", d)
	}
	if d := e.Evaluate(in("a/u", "mint", map[string]any{"export_creds": true})); d.Effect != Defer || d.InvocationID == "" {
		t.Fatalf("defer: %+v", d)
	}
	if d := e.Evaluate(in("a/agent", "tokens.create", map[string]any{"label": "prod"})); d.Effect != Deny {
		t.Fatalf("order: first match must win: %+v", d)
	}
	if d := e.Evaluate(in("a/u", "sign.record", nil)); d.Effect != Allow || d.Rule != "" {
		t.Fatalf("no-match allow: %+v", d)
	}
}

// TestHostileRulesRefusedOrTerminated (B7, the pre-registered Bar 3
// criteria at the real chokepoint's evaluator).
func TestHostileRulesRefusedOrTerminated(t *testing.T) {
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	// Unparseable and type-broken: refused at load, whole set refused.
	if err := e.Load([]Rule{{Name: "ok", When: "true", Effect: Allow}, {Name: "bad", When: "action == &&", Effect: Deny}}); err == nil {
		t.Fatal("unparseable rule loaded")
	}
	if err := e.Load([]Rule{{Name: "typed", When: `principal + 42 == "x"`, Effect: Deny}}); err == nil {
		t.Fatal("type-broken rule loaded")
	}
	if err := e.Load([]Rule{{Name: "weird", When: "true", Effect: "maybe"}}); err == nil {
		t.Fatal("unknown effect loaded")
	}
	// The running set stayed the previous (empty) one: still all-allow.
	if d := e.Evaluate(in("a/u", "anything", nil)); d.Effect != Allow {
		t.Fatalf("failed load must not disturb the running set: %+v", d)
	}
	// A cost bomb terminates within the discipline's bound, never the caller's patience.
	bomb := `[0,1,2,3,4,5,6,7,8,9].map(a, [0,1,2,3,4,5,6,7,8,9].map(b, [0,1,2,3,4,5,6,7,8,9].map(c, [0,1,2,3,4,5,6,7,8,9].map(d, [0,1,2,3,4,5,6,7,8,9].map(e, a+b+c+d+e))))).size() > 0`
	if err := e.Load([]Rule{{Name: "bomb", When: bomb, Effect: Allow}}); err != nil {
		t.Fatalf("bomb compiles (cost is a runtime bound): %v", err)
	}
	t0 := time.Now()
	d := e.Evaluate(in("a/u", "anything", nil))
	if dt := time.Since(t0); dt > 100*time.Millisecond {
		t.Fatalf("bomb took %v", dt)
	}
	// The erroring rule fails CLOSED.
	if d.Effect != Deny || !strings.Contains(d.Rule, "fails closed") {
		t.Fatalf("bomb decision: %+v", d)
	}
}

// TestApprovalsSingleUse (B4/D38): a deferred invocation with a granted
// approval allows exactly once; the id binds principal+action+args.
func TestApprovalsSingleUse(t *testing.T) {
	e := testEval(t, Rule{Name: "human", When: `action == "mint"`, Effect: Defer})
	req := in("a/u", "mint", nil)
	d := e.Evaluate(req)
	if d.Effect != Defer {
		t.Fatalf("defer: %+v", d)
	}
	e.Approve(d.InvocationID, time.Now())
	first := e.Evaluate(req)
	if first.Effect != Allow || !first.Approved {
		t.Fatalf("approved run: %+v", first)
	}
	if again := e.Evaluate(req); again.Effect != Defer {
		t.Fatalf("approval must spend: %+v", again)
	}
	// A different invocation never rides someone else's approval.
	other := in("a/u", "mint", nil)
	other.Raw = []byte("different-args")
	e.Approve(d.InvocationID, time.Now())
	if od := e.Evaluate(other); od.Effect != Defer {
		t.Fatalf("approval generalized: %+v", od)
	}
	// An expired approval is dead.
	e.Approve(d.InvocationID, time.Now().Add(-time.Hour))
	if ed := e.Evaluate(req); ed.Effect != Defer {
		t.Fatalf("expired approval spent: %+v", ed)
	}
}

// TestHotSwapConverges (B6): a loaded rule set replaces the old one
// without any restart.
func TestHotSwapConverges(t *testing.T) {
	e := testEval(t, Rule{Name: "deny-all-mints", When: `action == "mint"`, Effect: Deny})
	if d := e.Evaluate(in("a/u", "mint", nil)); d.Effect != Deny {
		t.Fatalf("before swap: %+v", d)
	}
	if err := e.Load([]Rule{}); err != nil {
		t.Fatal(err)
	}
	if d := e.Evaluate(in("a/u", "mint", nil)); d.Effect != Allow {
		t.Fatalf("after swap: %+v", d)
	}
}
