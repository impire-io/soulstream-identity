// Package delegation holds the D33 artifact's primitives — parse and
// signature verification against the directory encoding — shared by the
// grants broker (on-behalf access) and the guardrail (approvals, D38).
// Callers own their check ORDER and bounds; these are the pieces.
package delegation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// Claims is the payload shape the subject signs (D33).
type Claims struct {
	Subject   string   `json:"subject"`
	Actor     string   `json:"actor"`
	Resources []string `json:"resources"`
	Scopes    []string `json:"scopes,omitempty"`
	IssuedAt  string   `json:"issued_at"`
	ExpiresAt string   `json:"expires_at"`
}

// ErrUnreadable covers undecodable payloads or signatures.
var ErrUnreadable = errors.New("delegation: payload or signature unreadable")

// Parse decodes the presented pair without verifying anything.
func Parse(payloadB64, sigB64 string) (Claims, []byte, []byte, error) {
	payload, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return Claims{}, nil, nil, fmt.Errorf("%w: payload is not base64", ErrUnreadable)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return Claims{}, nil, nil, fmt.Errorf("%w: signature is not base64", ErrUnreadable)
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, nil, nil, fmt.Errorf("%w: payload is not a delegation", ErrUnreadable)
	}
	return c, payload, sig, nil
}

// VerifySig checks the subject's signature over the payload against the
// directory-encoded (base64 raw Ed25519) public key.
func VerifySig(payload, sig []byte, pubB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: subject key is unreadable", ErrUnreadable)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("delegation: signature does not verify")
	}
	return nil
}
