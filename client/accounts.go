package client

// The tenancy surface (D35, D47 — hq
// 02-DESIGN/soulstream-identity/tenancy.md and platform-topology.md):
// accounts born, suspended, resumed, and resolved over the sealed ops.
// Operator ops, gated by the transport ACL on the op tail (D25) — a
// deployment running no account authority answers every call with its
// refusal. Types mirror the service's JSON wire contract.

// Account is an account record as the service shows it: the name→key
// resolution (display-layer, never security-layer — A10 puts the key
// itself in the record) and the lifecycle status.
type Account struct {
	Name      string `json:"name"`
	Account   string `json:"account"` // the public key
	Status    string `json:"status"`
	CreatedAt string `json:"created_at,omitempty"`
}

// AccountCreate births a tenant account: the complete artifact lands as
// one act, its signing key enters the vault bound to the new account
// (mintable immediately, D47: born admissible), and AUTH learns it. An
// operator op (D25).
func (c *Client) AccountCreate(name string) (Account, error) {
	var out Account
	err := c.call("accounts.create", map[string]string{"name": name}, &out)
	return out, err
}

// AccountResolve answers name → record. An operator op (D25).
func (c *Client) AccountResolve(name string) (Account, error) {
	var out Account
	err := c.call("accounts.resolve", map[string]string{"name": name}, &out)
	return out, err
}

// Accounts lists every account record. An operator op (D25).
func (c *Client) Accounts() ([]Account, error) {
	var out struct {
		Accounts []Account `json:"accounts"`
	}
	err := c.call("accounts.list", struct{}{}, &out)
	return out.Accounts, err
}

// AccountSuspend refuses the account's next connection; data untouched.
// An operator op (D25).
func (c *Client) AccountSuspend(name string) (Account, error) {
	var out Account
	err := c.call("accounts.suspend", map[string]string{"name": name}, &out)
	return out, err
}

// AccountResume restores a suspended account's admission. An operator
// op (D25).
func (c *Client) AccountResume(name string) (Account, error) {
	var out Account
	err := c.call("accounts.resume", map[string]string{"name": name}, &out)
	return out, err
}
