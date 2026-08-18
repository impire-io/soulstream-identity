// The secrets half of the consumer surface (tenancy.md D36): the
// custodian stores caller-named secrets, per-persona trees structural —
// every method reaches only the CALLER's own tree, so there is no
// persona parameter anywhere. Values ride the sealed envelope both ways
// and rest sealed under the deployment's first key.

package client

import (
	"encoding/base64"
	"fmt"
)

// Secret is one fetched secret: the value and the revision that
// conditions the next write (D2).
type Secret struct {
	Value []byte
	Rev   uint64
}

// SecretPut writes the caller's secret at path iff the stored revision
// equals expectedRev (0 = create). Returns the new revision.
func (c *Client) SecretPut(path string, value []byte, expectedRev uint64) (uint64, error) {
	var out struct {
		Rev uint64 `json:"rev"`
	}
	err := c.call("secrets.put", map[string]any{
		"path": path, "value": base64.StdEncoding.EncodeToString(value),
		"expected_rev": expectedRev,
	}, &out)
	return out.Rev, err
}

// SecretGet fetches the caller's secret at path.
func (c *Client) SecretGet(path string) (Secret, error) {
	var out struct {
		Value string `json:"value"`
		Rev   uint64 `json:"rev"`
	}
	if err := c.call("secrets.get", map[string]string{"path": path}, &out); err != nil {
		return Secret{}, err
	}
	value, err := base64.StdEncoding.DecodeString(out.Value)
	if err != nil {
		return Secret{}, fmt.Errorf("soulstream-identity: secret value decode: %w", err)
	}
	return Secret{Value: value, Rev: out.Rev}, nil
}

// SecretPaths lists the caller's own secret paths.
func (c *Client) SecretPaths() ([]string, error) {
	var out struct {
		Paths []string `json:"paths"`
	}
	err := c.call("secrets.list", struct{}{}, &out)
	return out.Paths, err
}

// SecretDelete removes the caller's secret at path.
func (c *Client) SecretDelete(path string) error {
	return c.call("secrets.delete", map[string]string{"path": path}, nil)
}
