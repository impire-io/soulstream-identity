// The guardrail at its chokepoint (tenancy.md D37/D38): every sealed op
// is evaluated before dispatch — refuse here and the action never had
// authority. guardrail.load is the operator's hot-reload (B6, gated by
// the permission template like every management op); approvals.present
// converts a deferred invocation with a subject-signed approval
// delegation — usable exactly once, bounded in minutes (B4).

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/impire-io/soulstream-identity/internal/delegation"
	"github.com/impire-io/soulstream-identity/internal/guardrail"
)

// guardExempt names the ops the evaluator never gates: its own control
// surface (a rule must not be able to lock the operator out of fixing
// the rules) and approval presentation itself.
func guardExempt(op string) bool {
	return op == "guardrail.load" || op == "approvals.present"
}

// guardCheck runs the chokepoint. Deny and Defer refuse the op; every
// evaluation is observable (B5) — allows at debug, everything else loud.
func (s *Service) guardCheck(account, user, op string, body []byte) error {
	if s.guardrail == nil || guardExempt(op) {
		return nil
	}
	args := map[string]any{}
	_ = jsonUnmarshalLoose(body, &args)
	d := s.guardrail.Evaluate(guardrail.Input{
		Principal: account + "/" + user, Action: op, Args: args,
		Raw: body, Time: time.Now(),
	})
	switch d.Effect {
	case guardrail.Allow:
		if d.Approved {
			s.log.Info("guardrail APPROVED", "op", op, "account", account, "user", user,
				"rule", d.Rule, "invocation", d.InvocationID)
		} else {
			s.log.Debug("guardrail allow", "op", op, "account", account, "user", user, "rule", d.Rule)
		}
		return nil
	case guardrail.Defer:
		s.log.Warn("guardrail DEFERRED", "op", op, "account", account, "user", user,
			"rule", d.Rule, "invocation", d.InvocationID)
		return fmt.Errorf("service: this invocation needs a human approval (rule %s; invocation %s)", d.Rule, d.InvocationID)
	default:
		s.log.Warn("guardrail DENIED", "op", op, "account", account, "user", user, "rule", d.Rule)
		return fmt.Errorf("service: refused by guardrail rule %s", d.Rule)
	}
}

type guardrailLoadRequest struct {
	Rules []guardrail.Rule `json:"rules"`
}

type approvalPresentRequest struct {
	InvocationID      string `json:"invocation_id"`
	DelegationPayload string `json:"delegation_payload"`
	DelegationSig     string `json:"delegation_sig"`
}

func (s *Service) dispatchGuardrail(account, user, op string, body []byte) (any, error) {
	if s.guardrail == nil {
		return nil, errors.New("service: this deployment runs no guardrail")
	}
	switch op {
	case "guardrail.load":
		var req guardrailLoadRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if err := s.guardrail.Load(req.Rules); err != nil {
			return nil, err
		}
		s.allow(account, user, op, "rules", len(req.Rules))
		return struct{}{}, nil

	case "approvals.present":
		var req approvalPresentRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		claims, payload, sig, err := delegation.Parse(req.DelegationPayload, req.DelegationSig)
		if err != nil {
			return nil, err
		}
		// The actor is the server-proven caller — a stolen approval
		// refuses exactly as a stolen delegation does (D33's rule).
		if claims.Actor != user {
			return nil, errors.New("service: caller is not the approval's actor")
		}
		want := "invocation:" + req.InvocationID
		if !slices.Contains(claims.Resources, want) {
			return nil, fmt.Errorf("service: approval does not name %s", want)
		}
		now := time.Now()
		if exp, perr := time.Parse(time.RFC3339, claims.ExpiresAt); perr != nil || now.After(exp) {
			return nil, errors.New("service: approval expired")
		}
		if iss, perr := time.Parse(time.RFC3339, claims.IssuedAt); perr != nil || now.Before(iss) {
			return nil, errors.New("service: approval not yet valid")
		}
		entry, err := s.ownedOrDirectoryPersonaKey(claims.Subject)
		if err != nil {
			return nil, errors.New("service: approver has no persona key")
		}
		if err := delegation.VerifySig(payload, sig, entry.PublicKey); err != nil {
			return nil, err
		}
		s.guardrail.Approve(req.InvocationID, now)
		// Both personas on the record (D38 inherits D33's audit duty).
		s.allow(account, user, op, "approver", claims.Subject, "invocation", req.InvocationID)
		return struct{}{}, nil

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}

// ownedOrDirectoryPersonaKey resolves the approver's public key from the
// vault directory (D26's open read) without materializing anything.
func (s *Service) ownedOrDirectoryPersonaKey(persona string) (entry struct{ PublicKey string }, err error) {
	e, gerr := s.vault.Get(PersonaKeyPrefix + persona)
	if gerr != nil {
		return entry, gerr
	}
	entry.PublicKey = e.PublicKey
	return entry, nil
}

// jsonUnmarshalLoose decodes without the strict unknown-field rule: the
// evaluator sees whatever shape the op carries; strictness stays the
// dispatch layer's.
func jsonUnmarshalLoose(data []byte, out any) error {
	return json.Unmarshal(data, out)
}
