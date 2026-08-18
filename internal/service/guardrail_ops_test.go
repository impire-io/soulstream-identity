package service

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/internal/delegation"
	"github.com/impire-io/soulstream-identity/internal/guardrail"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

func guardrailHarness(t *testing.T) (*Service, *vault.Vault, string, *guardrail.Evaluator) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatal(err)
	}
	e, err := guardrail.New()
	if err != nil {
		t.Fatal(err)
	}
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()
	s, err := New(v, string(surfaceSeed), nil, WithGuardrail(e))
	if err != nil {
		t.Fatal(err)
	}
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	return s, v, accPub, e
}

// TestGuardrailChokepoint (D37): a denying rule refuses the op before
// dispatch; the allow path is untouched; guardrail.load hot-swaps.
func TestGuardrailChokepoint(t *testing.T) {
	s, _, accPub, _ := guardrailHarness(t)

	// Load a rule through the surface itself (the operator's lane).
	if err := call(t, s, accPub, "ops", "guardrail.load", guardrailLoadRequest{Rules: []guardrail.Rule{
		{Name: "no-alice-signing", When: `principal.endsWith("/alice") && action == "sign.record"`, Effect: guardrail.Deny},
	}}, nil); err != nil {
		t.Fatalf("load: %v", err)
	}

	// alice's sign.record refuses AT the chokepoint, by rule name.
	err := call(t, s, accPub, "alice", "sign.record",
		signRecordRequest{Key: PersonaKeyPrefix + "alice", Canonical: base64.StdEncoding.EncodeToString([]byte("x"))}, nil)
	if err == nil || !strings.Contains(err.Error(), "no-alice-signing") {
		t.Fatalf("chokepoint: want rule refusal, got %v", err)
	}
	// bob's identical op proceeds past the guardrail (and succeeds fully —
	// his persona key materializes).
	if err := call(t, s, accPub, "bob", "sign.record",
		signRecordRequest{Key: PersonaKeyPrefix + "bob", Canonical: base64.StdEncoding.EncodeToString([]byte("x"))}, nil); err != nil {
		t.Fatalf("allow path: %v", err)
	}

	// Hot swap to empty: alice signs again.
	if err := call(t, s, accPub, "ops", "guardrail.load", guardrailLoadRequest{Rules: nil}, nil); err != nil {
		t.Fatal(err)
	}
	if err := call(t, s, accPub, "alice", "sign.record",
		signRecordRequest{Key: PersonaKeyPrefix + "alice", Canonical: base64.StdEncoding.EncodeToString([]byte("x"))}, nil); err != nil {
		t.Fatalf("after swap: %v", err)
	}
}

// TestApprovalFlow (D38): a deferred op proceeds exactly once after a
// subject-signed approval delegation names its invocation; a stolen
// approval refuses as an actor mismatch.
func TestApprovalFlow(t *testing.T) {
	s, v, accPub, _ := guardrailHarness(t)
	if err := call(t, s, accPub, "ops", "guardrail.load", guardrailLoadRequest{Rules: []guardrail.Rule{
		{Name: "human-for-keys-list", When: `action == "keys.list"`, Effect: guardrail.Defer},
	}}, nil); err != nil {
		t.Fatal(err)
	}

	// The deferred op names its invocation id in the refusal.
	err := call(t, s, accPub, "agent", "keys.list", struct{}{}, nil)
	if err == nil || !strings.Contains(err.Error(), "invocation ") {
		t.Fatalf("defer: %v", err)
	}
	id := err.Error()[strings.LastIndex(err.Error(), " ")+1:]
	id = strings.TrimSuffix(id, ")")

	// daan (the approving human) signs the approval with his REAL persona
	// key — materialized in the vault, resolved from the directory.
	if _, err := v.GeneratePersonaKey(PersonaKeyPrefix+"daan", accPub, "daan"); err != nil {
		t.Fatal(err)
	}
	mint := func(actor, invocation string) approvalPresentRequest {
		payload, _ := json.Marshal(delegation.Claims{
			Subject: "daan", Actor: actor, Resources: []string{"invocation:" + invocation},
			IssuedAt:  time.Now().UTC().Format(time.RFC3339),
			ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
		})
		sig, err := v.SignRecord(PersonaKeyPrefix+"daan", payload)
		if err != nil {
			t.Fatal(err)
		}
		return approvalPresentRequest{InvocationID: invocation,
			DelegationPayload: base64.StdEncoding.EncodeToString(payload), DelegationSig: sig}
	}

	// Stolen: mallory presents agent's approval — actor mismatch.
	if err := call(t, s, accPub, "mallory", "approvals.present", mint("agent", id), nil); err == nil ||
		!strings.Contains(err.Error(), "actor") {
		t.Fatalf("stolen approval: %v", err)
	}

	// The actor presents it; the deferred op then serves exactly once.
	if err := call(t, s, accPub, "agent", "approvals.present", mint("agent", id), nil); err != nil {
		t.Fatalf("present: %v", err)
	}
	if err := call(t, s, accPub, "agent", "keys.list", struct{}{}, nil); err != nil {
		t.Fatalf("approved run: %v", err)
	}
	if err := call(t, s, accPub, "agent", "keys.list", struct{}{}, nil); err == nil {
		t.Fatal("approval did not spend")
	}
}
