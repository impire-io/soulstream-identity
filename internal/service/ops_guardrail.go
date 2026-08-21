// The guardrail at its chokepoint (tenancy.md D37/D38, approvals.md
// D42–D45): every sealed op is evaluated before dispatch — refuse here and
// the action never had authority. A deferral becomes a durable ticket with
// a human-window TTL and witnessed transitions (D42); the refusal names
// the ticket, the rule, and the window, machine-readably (the client's
// ParseDeferral is the mirror). approvals.present converts a deferred
// invocation with a subject-signed approval delegation — usable exactly
// once, bounded in minutes (B4) — now checked against the ticket's window
// and the deciding rule's approvers clause (D45); approvals.deny is the
// human's no, the same verification shape. The status/pending/list reads
// are D43's: a surface shows the loop without keeping a copy.

package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/impire-io/soulstream-identity/internal/delegation"
	"github.com/impire-io/soulstream-identity/internal/guardrail"
	"github.com/impire-io/soulstream-identity/internal/tickets"
)

// guardExempt names the op families the evaluator never gates: its own
// control and read surface, and the approval loop itself — a rule must
// not be able to lock the operator out of fixing the rules, and a rule
// deferring approvals.status would deadlock the very loop that resolves
// deferrals.
func guardExempt(op string) bool {
	return strings.HasPrefix(op, "guardrail.") || strings.HasPrefix(op, "approvals.")
}

// guardCheck runs the chokepoint. Deny and Defer refuse the op; every
// evaluation is observable (B5) — allows at debug, everything else loud.
// A Defer opens (or re-opens) the invocation's ticket when a ticket store
// stands; the refusal carries the ticket's window either way.
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
			// The loop's last transition, witnessed: the ticket is spent.
			if s.tickets != nil {
				if _, err := s.tickets.Spend(d.InvocationID); err != nil {
					s.log.Warn("ticket spend failed", "invocation", d.InvocationID, "err", err)
				}
			}
		} else {
			s.log.Debug("guardrail allow", "op", op, "account", account, "user", user, "rule", d.Rule)
		}
		return nil
	case guardrail.Defer:
		s.log.Warn("guardrail DEFERRED", "op", op, "account", account, "user", user,
			"rule", d.Rule, "invocation", d.InvocationID)
		if s.tickets != nil {
			t, err := s.tickets.Ensure(d.InvocationID, account+"/"+user, op, d.Rule)
			if err != nil {
				s.log.Warn("ticket open failed", "invocation", d.InvocationID, "err", err)
			} else {
				return fmt.Errorf("service: this invocation needs a human approval (rule %s; invocation %s; expires %s)",
					d.Rule, d.InvocationID, t.ExpiresAt)
			}
		}
		return fmt.Errorf("service: this invocation needs a human approval (rule %s; invocation %s)", d.Rule, d.InvocationID)
	default:
		s.log.Warn("guardrail DENIED", "op", op, "account", account, "user", user, "rule", d.Rule)
		return fmt.Errorf("service: refused by guardrail rule %s", d.Rule)
	}
}

type guardrailLoadRequest struct {
	Rules []guardrail.Rule `json:"rules"`
}

type guardrailListResponse struct {
	Rules []guardrail.Rule `json:"rules"`
}

type approvalPresentRequest struct {
	InvocationID      string `json:"invocation_id"`
	DelegationPayload string `json:"delegation_payload"`
	DelegationSig     string `json:"delegation_sig"`
}

type approvalStatusRequest struct {
	InvocationID string `json:"invocation_id"`
}

type approvalPendingResponse struct {
	Tickets []tickets.Ticket `json:"tickets"`
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

	case "guardrail.list":
		// The read half guardrail.load never had (D43): rules are shown,
		// never copied.
		return guardrailListResponse{Rules: s.guardrail.Rules()}, nil

	case "approvals.present", "approvals.deny":
		var req approvalPresentRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		claims, err := s.verifyApproval(user, req)
		if err != nil {
			return nil, err
		}
		if op == "approvals.deny" {
			if s.tickets == nil {
				return nil, errors.New("service: this deployment custodies no tickets — nothing to deny")
			}
			if _, err := s.tickets.Deny(req.InvocationID, claims.Subject); err != nil {
				return nil, err
			}
			s.allow(account, user, op, "approver", claims.Subject, "invocation", req.InvocationID)
			return struct{}{}, nil
		}
		if s.tickets != nil {
			if _, err := s.tickets.Approve(req.InvocationID, claims.Subject); err != nil {
				return nil, err
			}
		}
		s.guardrail.Approve(req.InvocationID, time.Now())
		// Both personas on the record (D38 inherits D33's audit duty).
		s.allow(account, user, op, "approver", claims.Subject, "invocation", req.InvocationID)
		return struct{}{}, nil

	case "approvals.status":
		var req approvalStatusRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if s.tickets == nil {
			return nil, errors.New("service: this deployment custodies no tickets")
		}
		t, err := s.tickets.Get(req.InvocationID)
		if err != nil {
			return nil, err
		}
		// The originator's own tickets, or the management lane publishing
		// on the originator's tail — the transport's line, restated here
		// against the server-proven caller.
		if t.Principal != account+"/"+user {
			return nil, tickets.ErrNotFound
		}
		return t, nil

	case "approvals.pending":
		if s.tickets == nil {
			return nil, errors.New("service: this deployment custodies no tickets")
		}
		list, err := s.tickets.Pending()
		if err != nil {
			return nil, err
		}
		return approvalPendingResponse{Tickets: list}, nil

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}

// verifyApproval is the shared verification for a human's signed yes or
// no: the artifact is a D33 delegation naming the invocation, its actor
// the server-proven caller, its signer resolvable, its window live — and
// the deciding rule's approvers clause honored (D45), consulted against
// the CURRENT rule set: policy governs at the moment of the answer.
func (s *Service) verifyApproval(user string, req approvalPresentRequest) (delegation.Claims, error) {
	claims, payload, sig, err := delegation.Parse(req.DelegationPayload, req.DelegationSig)
	if err != nil {
		return delegation.Claims{}, err
	}
	// The actor is the server-proven caller — a stolen approval refuses
	// exactly as a stolen delegation does (D33's rule).
	if claims.Actor != user {
		return delegation.Claims{}, errors.New("service: caller is not the approval's actor")
	}
	want := "invocation:" + req.InvocationID
	if !slices.Contains(claims.Resources, want) {
		return delegation.Claims{}, fmt.Errorf("service: approval does not name %s", want)
	}
	now := time.Now()
	if exp, perr := time.Parse(time.RFC3339, claims.ExpiresAt); perr != nil || now.After(exp) {
		return delegation.Claims{}, errors.New("service: approval expired")
	}
	if iss, perr := time.Parse(time.RFC3339, claims.IssuedAt); perr != nil || now.Before(iss) {
		return delegation.Claims{}, errors.New("service: approval not yet valid")
	}
	if s.tickets != nil {
		t, terr := s.tickets.Get(req.InvocationID)
		if terr == nil {
			if rule, ok := s.guardrail.RuleNamed(t.Rule); ok && len(rule.Approvers) > 0 &&
				!slices.Contains(rule.Approvers, claims.Subject) {
				return delegation.Claims{}, fmt.Errorf("service: %s is not an approver for rule %s", claims.Subject, t.Rule)
			}
		}
	}
	entry, err := s.ownedOrDirectoryPersonaKey(claims.Subject)
	if err != nil {
		return delegation.Claims{}, errors.New("service: approver has no persona key")
	}
	if err := delegation.VerifySig(payload, sig, entry.PublicKey); err != nil {
		return delegation.Claims{}, err
	}
	return claims, nil
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

// actingFieldOf reads the canonical's acting claim, "" when none exists
// — record canonicals carry it since v2; delegation payloads and other
// signed material do not.
func actingFieldOf(canonical []byte) string {
	var probe struct {
		Acting string `json:"acting"`
	}
	if err := json.Unmarshal(canonical, &probe); err != nil {
		return ""
	}
	return probe.Acting
}
