// The issuer: the mint with a callout trigger (../soul-hq/02-DESIGN/soulstream-identity/auth-callout.md
// D20). It validates the presented token (D22 stage 1), authorizes against
// the vault's role bindings (stage 2 — D24, D25), and answers the server
// with a scoped ephemeral user JWT for the server-assigned key. No response
// or an error response means no admission — fail-closed is the protocol's
// own property; nothing here may add an admit-on-timeout convenience.

package callout

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/internal/mint"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

// Subject is the callout protocol's fixed request subject, inside the AUTH
// account (D21).
const Subject = "$SYS.REQ.USER.AUTH"

// xkeyHeader carries the server's public curve key on sealed requests.
const xkeyHeader = "Nats-Server-Xkey"

// jwtPrefix is how an unsealed JWT payload starts; anything else on a sealed
// deployment is ciphertext.
const jwtPrefix = "eyJ"

// Issuer answers auth-callout requests from the vault.
type Issuer struct {
	vault       *vault.Vault
	api         *APITokenValidator // the sit_ lane (D22)
	oidc        *OIDCValidator     // the eyJ lane (D23); nil = lane disabled
	authKeyName string             // vault name of the AUTH account signing key (D21)
	ttl         time.Duration
	calloutKey  nkeys.KeyPair // optional curve key; set when requests arrive sealed
	log         *slog.Logger
}

// IssuerOption configures optional issuer behavior at construction.
type IssuerOption func(*Issuer)

// WithOIDC enables the eyJ lane with a constructed validator (D23). Without
// it, eyJ credentials refuse early — the lane fails closed by absence.
func WithOIDC(v *OIDCValidator) IssuerOption {
	return func(i *Issuer) { i.oidc = v }
}

// NewIssuer builds the issuer. calloutXKeySeed may be empty for deployments
// whose AUTH account declares no authorization xkey; ttl bounds every issued
// credential and is the revocation propagation bound (D22).
func NewIssuer(v *vault.Vault, tokens Store, authKeyName string, ttl time.Duration, calloutXKeySeed string, log *slog.Logger, opts ...IssuerOption) (*Issuer, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if authKeyName == "" {
		return nil, errors.New("callout: the AUTH signing key's vault name is required")
	}
	if ttl <= 0 {
		return nil, errors.New("callout: a positive ttl is required")
	}
	i := &Issuer{vault: v, api: NewAPITokenValidator(tokens), authKeyName: authKeyName, ttl: ttl, log: log}
	if seed := strings.TrimSpace(calloutXKeySeed); seed != "" {
		kp, err := nkeys.FromCurveSeed([]byte(seed))
		if err != nil {
			return nil, fmt.Errorf("callout: callout key is not a curve (SX…) seed: %w", err)
		}
		i.calloutKey = kp
	}
	for _, opt := range opts {
		opt(i)
	}
	return i, nil
}

// Start subscribes the issuer on nc — a connection authenticated as one of
// the AUTH account's auth_users (the bypass inside the callout lane, D21).
func (i *Issuer) Start(nc *nats.Conn) (*nats.Subscription, error) {
	sub, err := nc.Subscribe(Subject, func(msg *nats.Msg) {
		reply := i.respond(msg.Data, msg.Header.Get(xkeyHeader))
		if reply != nil && msg.Reply != "" {
			_ = msg.Respond(reply)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("callout: subscribe: %w", err)
	}
	return sub, nil
}

// respond computes the full response bytes for one authorization request —
// NATS-free so it unit-tests without a server. A nil return answers nothing:
// the server refuses on its own timeout (fail closed).
func (i *Issuer) respond(data []byte, serverXKey string) []byte {
	payload := data
	sealed := false
	if !bytes.HasPrefix(data, []byte(jwtPrefix)) {
		// Ciphertext: only openable on a deployment that gave us the key.
		if i.calloutKey == nil || serverXKey == "" {
			i.log.Warn("callout request refused", "err", "sealed request without a callout key")
			return nil
		}
		opened, err := i.calloutKey.Open(data, serverXKey)
		if err != nil {
			i.log.Warn("callout request refused", "err", "request cannot be unsealed")
			return nil
		}
		payload, sealed = opened, true
	}
	req, err := jwt.DecodeAuthorizationRequestClaims(string(payload))
	if err != nil {
		i.log.Warn("callout request refused", "err", "request does not decode: "+err.Error())
		return nil
	}

	userJWT, decisionErr := i.decide(req)
	resp := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	resp.Audience = req.Server.ID
	if decisionErr != nil {
		resp.Error = decisionErr.Error()
	} else {
		resp.Jwt = userJWT
	}
	authKP, err := i.vault.KeyPair(i.authKeyName)
	if err != nil {
		i.log.Error("callout response unsignable", "err", err.Error(), "auth_key", i.authKeyName)
		return nil
	}
	token, err := resp.Encode(authKP)
	if err != nil {
		i.log.Error("callout response encode failed", "err", err.Error())
		return nil
	}
	out := []byte(token)
	if sealed {
		// Symmetric hygiene: a sealed request gets a sealed response.
		if out, err = i.calloutKey.Seal(out, serverXKey); err != nil {
			i.log.Error("callout response seal failed", "err", err.Error())
			return nil
		}
	}
	return out
}

// decide is D22's pipeline behind the D23 dispatch: the credential's shape
// selects the lane — no probing order, no precedence — then each lane runs
// validate, authorize, and the shared mint.
func (i *Issuer) decide(req *jwt.AuthorizationRequestClaims) (string, error) {
	cred := req.ConnectOptions.Token
	switch {
	case strings.HasPrefix(cred, TokenPrefix):
		return i.decideToken(req, cred)
	case strings.HasPrefix(cred, jwtPrefix):
		return i.decideOIDC(req, cred)
	default:
		i.log.Warn("callout REFUSED", "err", "credential shape unknown",
			"client_host", req.ClientInformation.Host, "client_name", req.ConnectOptions.Name)
		return "", errors.New("credential rejected")
	}
}

// decideToken is the sit_ lane: digest validation, then authorize-and-mint
// via the role bound to the token record's account (D22 as amended, D25) —
// the same declared role set the OIDC lane resolves by name (D24).
func (i *Issuer) decideToken(req *jwt.AuthorizationRequestClaims, cred string) (string, error) {
	sub, err := i.api.Validate(cred)
	if err != nil {
		i.log.Warn("callout REFUSED", "err", err.Error(),
			"client_host", req.ClientInformation.Host, "client_name", req.ConnectOptions.Name)
		return "", errors.New("credential rejected")
	}
	userJWT, err := mint.ForKey(i.vault, sub.Account, sub.User, req.UserNkey, i.ttl)
	if err != nil {
		i.log.Warn("callout REFUSED", "err", err.Error(),
			"account", sub.Account, "user", sub.User, "label", sub.Label,
			"client_host", req.ClientInformation.Host)
		return "", errors.New("not authorized")
	}
	// The attribution the M4 gate requires: external subject, label, host.
	i.log.Info("callout ADMITTED", "account", sub.Account, "user", sub.User,
		"label", sub.Label, "client_host", req.ClientInformation.Host,
		"user_nkey", req.UserNkey, "ttl", i.ttl.String())
	return userJWT, nil
}

// decideOIDC is the eyJ lane (D23/D24): validate against the pinned issuer,
// authorize by the declared role the roles claim names, mint for the
// server-assigned key. The claims path never confers admin or personas —
// the mint issues the same scoped, permission-less claims as every lane.
func (i *Issuer) decideOIDC(req *jwt.AuthorizationRequestClaims, cred string) (string, error) {
	if i.oidc == nil {
		i.log.Warn("callout REFUSED", "lane", string(LaneOIDC), "err", "oidc lane not configured",
			"client_host", req.ClientInformation.Host, "client_name", req.ConnectOptions.Name)
		return "", errors.New("credential rejected")
	}
	sub, err := i.oidc.Validate(cred)
	if err != nil {
		i.log.Warn("callout REFUSED", "lane", string(LaneOIDC), "err", err.Error(),
			"client_host", req.ClientInformation.Host, "client_name", req.ConnectOptions.Name)
		return "", errors.New("credential rejected")
	}
	role, err := i.roleFor(sub.Roles)
	if err != nil {
		i.log.Warn("callout REFUSED", "lane", string(LaneOIDC), "err", err.Error(),
			"issuer", sub.Issuer, "subject", sub.OID,
			"client_host", req.ClientInformation.Host)
		return "", errors.New("not authorized")
	}
	userJWT, _, err := mint.ForRole(i.vault, role, sub.OID, req.UserNkey, i.ttl, nil)
	if err != nil {
		i.log.Warn("callout REFUSED", "lane", string(LaneOIDC), "err", err.Error(),
			"issuer", sub.Issuer, "subject", sub.OID, "role", role,
			"client_host", req.ClientInformation.Host)
		return "", errors.New("not authorized")
	}
	display := sub.Display
	if display == "" {
		display = "-" // app-only tokens carry no preferred_username
	}
	i.log.Info("callout ADMITTED", "lane", string(LaneOIDC), "issuer", sub.Issuer,
		"subject", sub.OID, "role", role, "display", display,
		"client_host", req.ClientInformation.Host,
		"user_nkey", req.UserNkey, "ttl", i.ttl.String())
	return userJWT, nil
}

// roleFor is D24's authorize: exactly one roles-claim value must name a
// declared role — an account signing key carrying its account binding (the
// one noun, D28: a role is the declared signing key; a team is the account,
// the tenant). Values naming nothing are inert (the tenant cannot invent
// roles); more than one match is ambiguous and refuses, because claim
// order must never decide authorization.
func (i *Issuer) roleFor(roles []string) (string, error) {
	if len(roles) == 0 {
		return "", errors.New("token carries no roles claim")
	}
	var declared []string
	for _, role := range roles {
		if role == i.authKeyName {
			continue // the issuer's own signing key is infrastructure, never a role
		}
		e, err := i.vault.Get(role)
		if err != nil {
			continue // undeclared (or unresolvable) role values are inert
		}
		if e.Kind != vault.KindNATSAccountSigningKey || e.Account == "" {
			continue
		}
		declared = append(declared, role)
	}
	switch len(declared) {
	case 0:
		return "", fmt.Errorf("no declared role among roles %v", roles)
	case 1:
		return declared[0], nil
	default:
		return "", fmt.Errorf("ambiguous roles %v", declared)
	}
}
