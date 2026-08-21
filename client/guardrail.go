// The approvals half of the consumer surface
// (../soul-hq/02-DESIGN/soulstream-identity/approvals.md D42–D45): the
// loop's public ends. A deferral refuses with a machine-readable ticket
// (ParseDeferral is the mirror of that refusal); the human's yes or no is
// a delegation this client already knows how to mint (an approval IS a
// D33 delegation naming "invocation:<id>"); presenting, denying, and the
// status/pending/rules reads are one call each. Reachability is the
// deployment's permission template on the op tails, as everywhere.

package client

import (
	"errors"
	"regexp"
	"time"
)

// GuardrailRule is one data-carried rule, the wire shape of
// guardrail.load and guardrail.list. Approvers names who may answer this
// rule's deferrals (D45); empty means any directory-resolvable persona,
// stated rather than implied.
type GuardrailRule struct {
	Name      string   `json:"name"`
	When      string   `json:"when"`
	Effect    string   `json:"effect"`
	Approvers []string `json:"approvers,omitempty"`
}

// ApprovalTicket is one deferred invocation as custody describes it
// (D42). It carries the invocation's name and never its arguments.
type ApprovalTicket struct {
	InvocationID string `json:"invocation_id"`
	Principal    string `json:"principal"`
	Action       string `json:"action"`
	Rule         string `json:"rule"`
	State        string `json:"state"`
	CreatedAt    string `json:"created_at"`
	ExpiresAt    string `json:"expires_at"`
	ResolvedBy   string `json:"resolved_by,omitempty"`
	ResolvedAt   string `json:"resolved_at,omitempty"`
}

// Deferral is a parsed refusal: the ticket the caller now holds.
type Deferral struct {
	Rule         string
	InvocationID string
	// ExpiresAt is the ticket's human-window end, zero when the
	// deployment custodies no tickets.
	ExpiresAt time.Time
}

// deferralRe mirrors the service's refusal line — rule, invocation, and
// (when tickets are custodied) the window.
var deferralRe = regexp.MustCompile(
	`needs a human approval \(rule ([^;)]+); invocation ([0-9a-f]+)(?:; expires ([^)]+))?\)`)

// ParseDeferral reads a deferred-invocation refusal back into its ticket.
// False for any other error: the caller branches on deferral-or-not
// without string matching of its own.
func ParseDeferral(err error) (Deferral, bool) {
	if err == nil {
		return Deferral{}, false
	}
	m := deferralRe.FindStringSubmatch(err.Error())
	if m == nil {
		return Deferral{}, false
	}
	d := Deferral{Rule: m[1], InvocationID: m[2]}
	if m[3] != "" {
		if exp, perr := time.Parse(time.RFC3339, m[3]); perr == nil {
			d.ExpiresAt = exp
		}
	}
	return d, true
}

// MintApproval composes and signs the human's answer as the calling
// persona: exactly a delegation whose one resource names the invocation
// (D38 — no second artifact kind exists). actor is the principal whose
// retry will present it.
func (c *Client) MintApproval(invocationID, actor string, ttl time.Duration) (Delegation, error) {
	if invocationID == "" {
		return Delegation{}, errors.New("client: an approval names its invocation")
	}
	return c.MintDelegation(c.user, actor, []string{"invocation:" + invocationID}, nil, ttl)
}

// PresentApproval converts a deferred invocation with a signed yes: the
// loop's missing link, one call over the op that always existed. The
// caller must be the approval's named actor — presenting is the
// originator's own act.
func (c *Client) PresentApproval(invocationID string, d Delegation) error {
	return c.call("approvals.present", map[string]string{
		"invocation_id":      invocationID,
		"delegation_payload": d.Payload,
		"delegation_sig":     d.Sig,
	}, nil)
}

// DenyApproval records the human's no, same verification shape as the
// yes; the ticket ends denied, witnessed.
func (c *Client) DenyApproval(invocationID string, d Delegation) error {
	return c.call("approvals.deny", map[string]string{
		"invocation_id":      invocationID,
		"delegation_payload": d.Payload,
		"delegation_sig":     d.Sig,
	}, nil)
}

// ApprovalStatus reads one ticket — the caller's own: another
// principal's ticket answers not-found, indistinguishably.
func (c *Client) ApprovalStatus(invocationID string) (ApprovalTicket, error) {
	var out ApprovalTicket
	err := c.call("approvals.status", map[string]string{"invocation_id": invocationID}, &out)
	return out, err
}

type approvalPendingResponse struct {
	Tickets []ApprovalTicket `json:"tickets"`
}

// PendingApprovals lists the tickets awaiting a decision — the
// approver-side read (management-gated until per-rule scoping refines
// it).
func (c *Client) PendingApprovals() ([]ApprovalTicket, error) {
	var out approvalPendingResponse
	err := c.call("approvals.pending", struct{}{}, &out)
	return out.Tickets, err
}

type guardrailListResponse struct {
	Rules []GuardrailRule `json:"rules"`
}

// GuardrailRules reads the standing rule set — the read half the hot
// reload never had. A surface shows rules; it keeps no copy.
func (c *Client) GuardrailRules() ([]GuardrailRule, error) {
	var out guardrailListResponse
	err := c.call("guardrail.list", struct{}{}, &out)
	return out.Rules, err
}

// GuardrailLoad hot-swaps the rule set (B6): all-or-nothing, an invalid
// rule refusing the whole load while the running set stays whole.
func (c *Client) GuardrailLoad(rules []GuardrailRule) error {
	return c.call("guardrail.load", map[string]any{"rules": rules}, nil)
}
