// Package guardrail is the evaluator (D37 — hq
// 02-DESIGN/soulstream-identity/tenancy.md) at its first unskippable
// chokepoint: a rule answers what the transport cannot — may THIS
// invocation, with THESE arguments, NOW, proceed — and never re-answers
// what the server already proved. The discipline is belt-and-braces,
// mandated by measurement (a cost limit alone let an input bomb take
// 622ms to die): a tight cost limit, an interrupt check, and a context
// deadline as the hard stop. Rules are data, hot-swappable; every
// evaluation is observable, including the allows.
package guardrail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
)

// Effect is a rule's conclusion — the three outcomes (B3).
type Effect string

// The three outcomes. Defer means: only after a human decides (D38).
const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
	Defer Effect = "defer"
)

// Rule is one data-carried rule: first match decides.
type Rule struct {
	Name   string `json:"name"`
	When   string `json:"when"` // CEL over {principal, action, args, now}
	Effect Effect `json:"effect"`
}

// Input is one invocation at the chokepoint (B9): the server-proven
// principal, the action, its arguments, the moment — nothing richer.
type Input struct {
	Principal string
	Action    string
	Args      map[string]any
	// Raw is the request body as presented — the invocation-identity
	// bytes an approval binds to (D38).
	Raw  []byte
	Time time.Time
}

// Decision is one observable evaluation outcome.
type Decision struct {
	Effect Effect
	Rule   string // the deciding rule's name; "" when no rule matched
	// InvocationID identifies THIS invocation for approval binding —
	// set on Defer, and on the Allow that consumed an approval.
	InvocationID string
	// Approved marks an Allow that spent a standing approval.
	Approved bool
}

const (
	costLimit     = 10_000
	interruptFreq = 100
	evalDeadline  = 25 * time.Millisecond
	// approvalTTL bounds a granted approval: minutes, never standing.
	approvalTTL = 5 * time.Minute
)

type compiledRule struct {
	rule Rule
	prg  cel.Program
}

// Evaluator evaluates rules and holds the approval state (single-use,
// TTL-bounded, in memory — a restart drops pending approvals, which
// fails closed).
type Evaluator struct {
	env *cel.Env

	mu        sync.RWMutex
	rules     []compiledRule
	approvals map[string]time.Time // invocation id → expiry

	now func() time.Time
}

// New builds an evaluator with no rules (everything allows).
func New() (*Evaluator, error) {
	env, err := cel.NewEnv(
		cel.Variable("principal", cel.StringType),
		cel.Variable("action", cel.StringType),
		cel.Variable("args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("now", cel.IntType),
	)
	if err != nil {
		return nil, fmt.Errorf("guardrail: env: %w", err)
	}
	return &Evaluator{env: env, approvals: map[string]time.Time{}, now: time.Now}, nil
}

// Load compiles and swaps the rule set atomically: any invalid rule
// refuses the whole load by name (B6/B7 — refusal at load, and the
// running set stays whole).
func (e *Evaluator) Load(rules []Rule) error {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		switch r.Effect {
		case Allow, Deny, Defer:
		default:
			return fmt.Errorf("guardrail: rule %q has unknown effect %q", r.Name, r.Effect)
		}
		ast, iss := e.env.Compile(r.When)
		if iss != nil && iss.Err() != nil {
			return fmt.Errorf("guardrail: rule %q refused at compile: %w", r.Name, iss.Err())
		}
		prg, err := e.env.Program(ast, cel.CostLimit(costLimit), cel.InterruptCheckFrequency(interruptFreq))
		if err != nil {
			return fmt.Errorf("guardrail: rule %q refused at program construction: %w", r.Name, err)
		}
		compiled = append(compiled, compiledRule{rule: r, prg: prg})
	}
	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()
	return nil
}

// InvocationID names one invocation for approval binding: the
// server-proven principal, the action, and the argument bytes as
// presented — reproducible by the approving side from the same facts.
func InvocationID(principal, action string, raw []byte) string {
	h := sha256.New()
	h.Write([]byte(principal))
	h.Write([]byte{0})
	h.Write([]byte(action))
	h.Write([]byte{0})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Evaluate runs the rule set, first match deciding; no match allows. A
// rule that errors at evaluation fails CLOSED (deny, by name): an
// erroring rule must never grant, and the caller never waits past the
// deadline. A Defer with a live, unspent approval for this exact
// invocation converts to Allow and spends it (D38: exactly once).
func (e *Evaluator) Evaluate(in Input) Decision {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	input := map[string]any{
		"principal": in.Principal,
		"action":    in.Action,
		"args":      in.Args,
		"now":       in.Time.Unix(),
	}
	for _, cr := range rules {
		ctx, cancel := context.WithTimeout(context.Background(), evalDeadline)
		out, _, err := cr.prg.ContextEval(ctx, input)
		cancel()
		if err != nil {
			return Decision{Effect: Deny, Rule: cr.rule.Name + " (evaluation error — fails closed)"}
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return Decision{Effect: Deny, Rule: cr.rule.Name + " (non-boolean — fails closed)"}
		}
		if !matched {
			continue
		}
		if cr.rule.Effect != Defer {
			return Decision{Effect: cr.rule.Effect, Rule: cr.rule.Name}
		}
		id := InvocationID(in.Principal, in.Action, in.Raw)
		if e.spendApproval(id, in.Time) {
			return Decision{Effect: Allow, Rule: cr.rule.Name, InvocationID: id, Approved: true}
		}
		return Decision{Effect: Defer, Rule: cr.rule.Name, InvocationID: id}
	}
	return Decision{Effect: Allow}
}

// Approve records a granted approval for one invocation: usable exactly
// once, dead after the TTL.
func (e *Evaluator) Approve(invocationID string, now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.approvals[invocationID] = now.Add(approvalTTL)
}

// spendApproval consumes a live approval; expired ones are swept as met.
func (e *Evaluator) spendApproval(id string, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	exp, ok := e.approvals[id]
	if !ok {
		return false
	}
	delete(e.approvals, id)
	return now.Before(exp)
}
