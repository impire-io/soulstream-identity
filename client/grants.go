// The grants half of the consumer surface
// (../soul-hq/02-DESIGN/soulstream-identity/grants.md D30–D34): outbound
// credentials brokered by the identity plane. Every method operates on the
// CALLER's own grants — the subject space makes any other persona's
// unreachable, so there is no persona parameter anywhere. What comes back
// from Access is the derived short-lived token only (D32); refresh tokens
// have no client-facing representation at all.

package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// GrantLink is a started linking ceremony: the URL the persona opens in
// their own browser, and the id the completing call presents.
type GrantLink struct {
	AuthorizeURL string `json:"authorize_url"`
	LinkID       string `json:"link_id"`
}

// GrantInfo is one custodied grant, public form.
type GrantInfo struct {
	Resource string   `json:"resource"`
	Scopes   []string `json:"scopes,omitempty"`
	LinkedAt string   `json:"linked_at"`
}

// GrantAccess is a served access token — derived, short-lived, expiring.
type GrantAccess struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at,omitempty"`
}

// Delegation is the on-behalf proof an actor presents (D33): minted by the
// subject — its payload signed with the subject's persona key — and honored
// only from the actor's own connection.
type Delegation struct {
	Payload string `json:"delegation_payload"`
	Sig     string `json:"delegation_sig"`
}

// DelegationClaims is the payload shape the subject signs. Times are
// RFC 3339 UTC.
type DelegationClaims struct {
	Subject   string   `json:"subject"`
	Actor     string   `json:"actor"`
	Resources []string `json:"resources"`
	Scopes    []string `json:"scopes,omitempty"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
}

// MintDelegation composes and signs a delegation as the calling persona —
// one sign.record round-trip; the persona key materializes on first touch
// (D26). The subject is the caller: delegating is always a self-act.
func (c *Client) MintDelegation(subject, actor string, resources, scopes []string, ttl time.Duration) (Delegation, error) {
	now := time.Now().UTC()
	payload, err := json.Marshal(DelegationClaims{
		Subject: subject, Actor: actor, Resources: resources, Scopes: scopes,
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339),
	})
	if err != nil {
		return Delegation{}, fmt.Errorf("client: encode delegation: %w", err)
	}
	sig, err := c.SignRecord(subject, payload)
	if err != nil {
		return Delegation{}, err
	}
	return Delegation{Payload: base64.StdEncoding.EncodeToString(payload), Sig: sig}, nil
}

// GrantLinkStart begins the linking ceremony for a declared resource.
func (c *Client) GrantLinkStart(resource string) (GrantLink, error) {
	var out GrantLink
	err := c.call("grants.link.start", map[string]string{"resource": resource}, &out)
	return out, err
}

// GrantLinkComplete redeems the ceremony's code; custody begins.
func (c *Client) GrantLinkComplete(linkID, code string) error {
	return c.call("grants.link.complete", map[string]string{"link_id": linkID, "code": code}, nil)
}

// GrantAccessToken serves the caller's own access token for resource.
func (c *Client) GrantAccessToken(resource string) (GrantAccess, error) {
	var out GrantAccess
	err := c.call("grants.access", map[string]string{"resource": resource}, &out)
	return out, err
}

// GrantAccessOnBehalf serves the subject's token to its delegated actor —
// the caller must be the delegation's actor (server-proven, D33).
func (c *Client) GrantAccessOnBehalf(resource, subject string, d Delegation) (GrantAccess, error) {
	var out GrantAccess
	err := c.call("grants.access", map[string]string{
		"resource": resource, "on_behalf_of": subject,
		"delegation_payload": d.Payload, "delegation_sig": d.Sig,
	}, &out)
	return out, err
}

// GrantAccessExchange serves a lane-3 resource (D34): the caller's own
// bearer — presented, never retained — exchanged at the declared IdP
// for a token scoped to the resource's audience. No linking ceremony
// exists for exchange resources.
func (c *Client) GrantAccessExchange(resource, subjectToken string) (GrantAccess, error) {
	var out GrantAccess
	err := c.call("grants.access", map[string]string{
		"resource": resource, "subject_token": subjectToken,
	}, &out)
	return out, err
}

// Grants lists the caller's own custodied grants, public form.
func (c *Client) Grants() ([]GrantInfo, error) {
	var out struct {
		Grants []GrantInfo `json:"grants"`
	}
	err := c.call("grants.list", struct{}{}, &out)
	return out.Grants, err
}

// GrantRevoke deletes the caller's grant for resource (upstream revocation
// best-effort behind it).
func (c *Client) GrantRevoke(resource string) error {
	return c.call("grants.revoke", map[string]string{"resource": resource}, nil)
}
