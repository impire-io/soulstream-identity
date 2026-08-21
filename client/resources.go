// The resources half of the consumer surface
// (../soul-hq/02-DESIGN/soulstream-identity/external-tools.md D40): the
// tool catalog's custody side, editable at runtime. Management ops — the
// deployment's permission template decides who reaches the tail, exactly
// as it does for guardrail.load. The client secret crosses the sealed wire
// inbound once, on add, and has no outbound representation anywhere: list
// serves public halves only.

package client

// ResourceConfig is a full resource declaration, the resources.add body —
// the same shape a deployment declares statically.
type ResourceConfig struct {
	Name             string   `json:"name"`
	AuthURL          string   `json:"auth_url,omitempty"`
	TokenURL         string   `json:"token_url,omitempty"`
	RevokeURL        string   `json:"revoke_url,omitempty"`
	ClientID         string   `json:"client_id"`
	ClientSecret     string   `json:"client_secret,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	RedirectURI      string   `json:"redirect_uri,omitempty"`
	ExchangeTokenURL string   `json:"exchange_token_url,omitempty"`
	ExchangeAudience string   `json:"exchange_audience,omitempty"`
}

// ResourceInfo is one catalog entry's public half — what resources.list
// serves. Declared marks an entry from the deployment's configuration
// (the operator's explicit hand, not editable through the op).
type ResourceInfo struct {
	Name             string   `json:"name"`
	AuthURL          string   `json:"auth_url,omitempty"`
	TokenURL         string   `json:"token_url,omitempty"`
	RevokeURL        string   `json:"revoke_url,omitempty"`
	ClientID         string   `json:"client_id"`
	Scopes           []string `json:"scopes,omitempty"`
	RedirectURI      string   `json:"redirect_uri,omitempty"`
	ExchangeTokenURL string   `json:"exchange_token_url,omitempty"`
	ExchangeAudience string   `json:"exchange_audience,omitempty"`
	Declared         bool     `json:"declared,omitempty"`
}

type resourceListResponse struct {
	Resources []ResourceInfo `json:"resources"`
}

// ResourceAdd makes a resource usable at runtime: validated like a
// declared one, live on return, no restart anywhere.
func (c *Client) ResourceAdd(r ResourceConfig) error {
	return c.call("resources.add", r, nil)
}

// ResourceRemove retires a runtime resource. Standing grants keep their
// custody; the next ceremony refuses by name. Removing what is absent
// already happened; a declared resource refuses.
func (c *Client) ResourceRemove(name string) error {
	return c.call("resources.remove", map[string]string{"name": name}, nil)
}

// Resources lists the catalog's public halves.
func (c *Client) Resources() ([]ResourceInfo, error) {
	var out resourceListResponse
	err := c.call("resources.list", struct{}{}, &out)
	return out.Resources, err
}
