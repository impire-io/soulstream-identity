// The local-operator authority (A8's self-hosted arm): the operator
// signing key lives in the vault and never leaves it; account JWTs are
// signed in-process and landed on the server's resolver through the
// system-account connection — the one act. Suspension rebuilds the SAME
// complete artifact with connections refused: deterministic from the
// record, no per-account state held here.

package accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/internal/vault"
)

// claimsUpdateSubject is the resolver push: the account JWT, operator-
// signed, as the request body; the server stores or refuses.
const claimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"

// LocalOperator signs with the vault-held operator key and pushes over
// the system-account connection.
type LocalOperator struct {
	// Vault holds the operator key under OperatorKeyName.
	Vault *vault.Vault
	// OperatorKeyName is the vault name of the SO… seed.
	OperatorKeyName string
	// Sys is the system-account connection the pushes ride.
	Sys *nats.Conn
	// Timeout bounds one push. Zero means 5s.
	Timeout time.Duration
}

func (l *LocalOperator) timeout() time.Duration {
	if l.Timeout > 0 {
		return l.Timeout
	}
	return 5 * time.Second
}

// buildJWT encodes the COMPLETE account artifact: identity, name,
// signing key, unlimited JetStream, and the suspension state as the
// connection limit. Determinism is the suspend/resume contract.
func (l *LocalOperator) buildJWT(accountPub, name, signingPub string, suspended bool) (string, error) {
	opKP, err := l.Vault.KeyPair(l.OperatorKeyName)
	if err != nil {
		return "", fmt.Errorf("accounts: operator key: %w", err)
	}
	ac := jwt.NewAccountClaims(accountPub)
	ac.Name = name
	ac.SigningKeys.Add(signingPub)
	ac.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: -1, DiskStorage: -1, Streams: -1, Consumer: -1,
	}
	if suspended {
		ac.Limits.Conn = 0
	} else {
		ac.Limits.Conn = -1
	}
	token, err := ac.Encode(opKP)
	if err != nil {
		return "", fmt.Errorf("accounts: encode account jwt: %w", err)
	}
	return token, nil
}

func (l *LocalOperator) push(ctx context.Context, token string) error {
	msg, err := l.Sys.RequestWithContext(ctx, claimsUpdateSubject, []byte(token))
	if err != nil {
		return fmt.Errorf("accounts: resolver push: %w", err)
	}
	// The resolver answers a JSON envelope; an error inside is a refusal.
	var resp struct {
		Error *struct {
			Description string `json:"description"`
		} `json:"error"`
	}
	if err := json.Unmarshal(msg.Data, &resp); err == nil && resp.Error != nil {
		return fmt.Errorf("accounts: resolver refused: %s", resp.Error.Description)
	}
	return nil
}

// CreateAccount implements Authority: generate, build complete, land as
// one act. The signing key seed goes back to the engine's caller for
// vault custody; nothing here retains it.
func (l *LocalOperator) CreateAccount(ctx context.Context, name string) (string, string, string, error) {
	acctKP, err := nkeys.CreateAccount()
	if err != nil {
		return "", "", "", err
	}
	acctPub, _ := acctKP.PublicKey()
	skKP, err := nkeys.CreateAccount()
	if err != nil {
		return "", "", "", err
	}
	skPub, _ := skKP.PublicKey()
	skSeed, _ := skKP.Seed()

	token, err := l.buildJWT(acctPub, name, skPub, false)
	if err != nil {
		return "", "", "", err
	}
	pctx, cancel := context.WithTimeout(ctx, l.timeout())
	defer cancel()
	if err := l.push(pctx, token); err != nil {
		return "", "", "", err
	}
	return acctPub, skPub, string(skSeed), nil
}

// SetSuspended implements Authority: re-land the complete artifact with
// the connection limit flipped.
func (l *LocalOperator) SetSuspended(ctx context.Context, rec Record, suspended bool) error {
	token, err := l.buildJWT(rec.PublicKey, rec.Name, rec.SigningKey, suspended)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithTimeout(ctx, l.timeout())
	defer cancel()
	return l.push(pctx, token)
}
