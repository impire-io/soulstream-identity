// The issuer: the mint with a callout trigger (hq/02-DESIGN/auth-callout.md
// D20). It validates the presented token (D22 stage 1), authorizes via the
// registry (stage 2, inside mint.MintForKey), and answers the server with a
// scoped ephemeral user JWT for the server-assigned key. No response or an
// error response means no admission — fail-closed is the protocol's own
// property; nothing here may add an admit-on-timeout convenience.

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

	"github.com/impire-io/soulidentity/internal/mint"
	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
)

// Subject is the callout protocol's fixed request subject, inside the AUTH
// account (D21).
const Subject = "$SYS.REQ.USER.AUTH"

// xkeyHeader carries the server's public curve key on sealed requests.
const xkeyHeader = "Nats-Server-Xkey"

// jwtPrefix is how an unsealed JWT payload starts; anything else on a sealed
// deployment is ciphertext.
const jwtPrefix = "eyJ"

// Issuer answers auth-callout requests from the vault and registry.
type Issuer struct {
	vault       *vault.Vault
	reg         *registry.Registry
	tokens      Store
	authKeyName string // vault name of the AUTH account signing key (D21)
	ttl         time.Duration
	calloutKey  nkeys.KeyPair // optional curve key; set when requests arrive sealed
	log         *slog.Logger
}

// NewIssuer builds the issuer. calloutXKeySeed may be empty for deployments
// whose AUTH account declares no authorization xkey; ttl bounds every issued
// credential and is the revocation propagation bound (D22).
func NewIssuer(v *vault.Vault, reg *registry.Registry, tokens Store, authKeyName string, ttl time.Duration, calloutXKeySeed string, log *slog.Logger) (*Issuer, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if authKeyName == "" {
		return nil, errors.New("callout: the AUTH signing key's vault name is required")
	}
	if ttl <= 0 {
		return nil, errors.New("callout: a positive ttl is required")
	}
	i := &Issuer{vault: v, reg: reg, tokens: tokens, authKeyName: authKeyName, ttl: ttl, log: log}
	if seed := strings.TrimSpace(calloutXKeySeed); seed != "" {
		kp, err := nkeys.FromCurveSeed([]byte(seed))
		if err != nil {
			return nil, fmt.Errorf("callout: callout key is not a curve (SX…) seed: %w", err)
		}
		i.calloutKey = kp
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

// decide is D22's pipeline: validate the token, then authorize-and-mint via
// the registry row's role key for the server-assigned user key.
func (i *Issuer) decide(req *jwt.AuthorizationRequestClaims) (string, error) {
	rec, err := Validate(i.tokens, req.ConnectOptions.Token)
	if err != nil {
		i.log.Warn("callout REFUSED", "err", err.Error(),
			"client_host", req.ClientInformation.Host, "client_name", req.ConnectOptions.Name)
		return "", errors.New("credential rejected")
	}
	userJWT, err := mint.ForKey(i.vault, i.reg, rec.Account, rec.User, req.UserNkey, i.ttl)
	if err != nil {
		i.log.Warn("callout REFUSED", "err", err.Error(),
			"account", rec.Account, "user", rec.User, "label", rec.Label,
			"client_host", req.ClientInformation.Host)
		return "", errors.New("identity not authorized")
	}
	// The attribution the M4 gate requires: external identity, label, host.
	i.log.Info("callout ADMITTED", "account", rec.Account, "user", rec.User,
		"label", rec.Label, "client_host", req.ClientInformation.Host,
		"user_nkey", req.UserNkey, "ttl", i.ttl.String())
	return userJWT, nil
}
