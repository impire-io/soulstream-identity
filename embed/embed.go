// Package embed is the operator surface of the identity plane: it assembles
// and runs what `soulstream-identity serve` runs — the sealed service surface and,
// when the callout half is supplied, the callout issuer — inside the
// caller's own process, against connections the caller already holds.
//
// Think of it as the difference between renting the service a room and
// letting it live in your house: the plane behaves identically either way,
// and the daemon itself is this package's first consumer (one assembly, two
// entrypoints — D29 in ../soul-hq/02-DESIGN/soulstream-identity/agent.md).
//
// The other public package, client, is the consumer surface: who *calls*
// the plane. This one is for who *hosts* it. Provisioning (key imports,
// tokens, the sentinel) deliberately stays on the sealed wire through
// client — embedding changes where the plane runs, never who may mutate it.
//
// Custody is unchanged (D13 as amended): the seeds arrive as
// deployment-supplied strings, live only in process memory, and are never
// written anywhere by this package.
package embed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulstream-identity/internal/callout"
	"github.com/impire-io/soulstream-identity/internal/grants"
	"github.com/impire-io/soulstream-identity/internal/guardrail"
	"github.com/impire-io/soulstream-identity/internal/sealedstore"
	"github.com/impire-io/soulstream-identity/internal/secrets"
	"github.com/impire-io/soulstream-identity/internal/service"
	"github.com/impire-io/soulstream-identity/internal/vault"
	"github.com/impire-io/soulstream-identity/internal/version"
)

// Options describes an assembly of the identity plane, by value. Zero
// values keep the daemon's defaults; no internal type appears here.
type Options struct {
	// Conn is the service's connection (the service account). Required.
	// The caller owns it: Run never dials, closes, or drains it.
	Conn *nats.Conn

	// CalloutConn is the AUTH-account connection. Its presence enables
	// the callout issuer and the token/sentinel ops — the daemon's rule.
	CalloutConn *nats.Conn

	// VaultBucket is the KV bucket holding the sealed vault.
	// Default "SOULIDENTITY_VAULT".
	VaultBucket string

	// TokenBucket is the KV bucket holding API-token digests (callout
	// only). Default "SOULIDENTITY_TOKENS".
	TokenBucket string

	// FirstKey is the SX… seed sealing the vault (D13:
	// deployment-supplied). Required.
	FirstKey string

	// SurfaceKey is the SX… seed sealing the request/reply surface.
	// Required.
	SurfaceKey string

	// CalloutKey is the SX… seed for sealed callout requests; optional,
	// as on the daemon — only deployments whose AUTH account declares
	// authorization.xkey need it.
	CalloutKey string

	// AuthKeyName is the vault name of the AUTH account signing key.
	// Default "auth/issuer".
	AuthKeyName string

	// AuthAccount is the AUTH account public key (A…). Required when
	// CalloutConn is set.
	AuthAccount string

	// CalloutTTL is the issued-JWT lifetime — the revocation propagation
	// bound (D22). Default 15m.
	CalloutTTL time.Duration

	// Prefix is the shared ecosystem subject prefix (D14).
	Prefix string

	// OIDCIssuer and OIDCAudience enable the external-JWT lane (D23);
	// both or neither.
	OIDCIssuer   string
	OIDCAudience string

	// Logger receives the audit and serving lines. Default: text handler
	// on stderr.
	Logger *slog.Logger

	// GrantResources declares the outbound-grant resources (D34 lane 2);
	// non-empty enables the grants.* ops. Value-only, like everything
	// here — no per-user configuration exists (D26's spirit).
	GrantResources []GrantResource

	// GrantsBucket is the KV bucket holding sealed grant custody (its own
	// domain, D31 — never the key vault). Default "SOULIDENTITY_GRANTS".
	GrantsBucket string

	// SecretsBucket is the KV bucket holding the sealed general secret
	// store (its own domain, D36). Default "SOULIDENTITY_SECRETS".
	SecretsBucket string

	// EnableGuardrail puts the evaluator on the op path (D37) even with
	// an empty rule set (the operator loads rules live via
	// guardrail.load). Non-empty GuardrailRules enables it implicitly.
	EnableGuardrail bool

	// GuardrailRules is the starting rule set: first match decides;
	// effects are allow | deny | defer. Invalid rules refuse startup.
	GuardrailRules []GuardrailRule
}

// GuardrailRule is one data-carried rule, by value.
type GuardrailRule struct {
	Name   string
	When   string
	Effect string
}

// GrantResource is one declared remote system, by value.
type GrantResource struct {
	Name         string
	AuthURL      string
	TokenURL     string
	RevokeURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// withDefaults returns a copy with the daemon's defaults applied.
func (o Options) withDefaults() Options {
	if o.VaultBucket == "" {
		o.VaultBucket = "SOULIDENTITY_VAULT"
	}
	if o.TokenBucket == "" {
		o.TokenBucket = "SOULIDENTITY_TOKENS"
	}
	if o.AuthKeyName == "" {
		o.AuthKeyName = "auth/issuer"
	}
	if o.GrantsBucket == "" {
		o.GrantsBucket = "SOULIDENTITY_GRANTS"
	}
	if o.SecretsBucket == "" {
		o.SecretsBucket = "SOULIDENTITY_SECRETS"
	}
	if o.CalloutTTL == 0 {
		o.CalloutTTL = 15 * time.Minute
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return o
}

// validate enforces the daemon's construction rules before anything
// serves: required fields, the prefix shape, callout both-halves, and
// OIDC both-or-neither. A callout-dependent option without the callout
// connection is refused — never a silently disabled issuer.
func (o Options) validate() error {
	if o.Conn == nil {
		return errors.New("embed: Conn is required (the service connection)")
	}
	if o.FirstKey == "" {
		return errors.New("embed: FirstKey is required (the vault first key seed)")
	}
	if o.SurfaceKey == "" {
		return errors.New("embed: SurfaceKey is required (the surface xkey seed)")
	}
	if err := service.ValidatePrefix(o.Prefix); err != nil {
		return err
	}
	if o.CalloutConn != nil && o.AuthAccount == "" {
		return errors.New("embed: callout needs AuthAccount (the AUTH account public key)")
	}
	if o.CalloutConn == nil {
		if o.CalloutKey != "" || o.OIDCIssuer != "" || o.OIDCAudience != "" {
			return errors.New("embed: callout options without CalloutConn — supply the AUTH-account connection or drop them")
		}
	}
	if (o.OIDCIssuer == "") != (o.OIDCAudience == "") {
		return errors.New("embed: the oidc lane needs both OIDCIssuer and OIDCAudience")
	}
	return nil
}

// Run assembles the identity plane and serves until ctx ends, then drains
// what it started — its own subscriptions, never the caller's connections
// — and returns ctx.Err(). Construction errors (validation, vault
// verification, bucket creation, OIDC discovery) return before anything
// serves.
func Run(ctx context.Context, o Options) error {
	o = o.withDefaults()
	if err := o.validate(); err != nil {
		return err
	}

	js, err := jetstream.New(o.Conn)
	if err != nil {
		return fmt.Errorf("jetstream: %w", err)
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: o.VaultBucket})
	if err != nil {
		return fmt.Errorf("kv bucket %s: %w", o.VaultBucket, err)
	}
	v, err := vault.New(vault.NewKVStore(kv), o.FirstKey)
	if err != nil {
		return err
	}
	// Fail fast on a mis-supplied first key: never double-seal a vault.
	if err := v.Verify(); err != nil {
		return err
	}

	// The callout half: enabled exactly when the AUTH-account connection
	// is supplied (the daemon's rule, D21).
	var svcOpts []service.Option
	var issuer *callout.Issuer
	if o.CalloutConn != nil {
		tokensKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: o.TokenBucket})
		if err != nil {
			return fmt.Errorf("kv bucket %s: %w", o.TokenBucket, err)
		}
		store := callout.NewKVTokenStore(tokensKV)
		svcOpts = append(svcOpts, service.WithCallout(store, o.AuthKeyName, o.AuthAccount))

		// The OIDC lane (D23): both present enables it; discovery runs
		// now and fails closed.
		var issOpts []callout.IssuerOption
		if o.OIDCIssuer != "" {
			oidcVal, err := callout.NewOIDCValidator(ctx, o.OIDCIssuer, o.OIDCAudience)
			if err != nil {
				return err
			}
			issOpts = append(issOpts, callout.WithOIDC(oidcVal))
		}
		issuer, err = callout.NewIssuer(v, store, o.AuthKeyName, o.CalloutTTL, o.CalloutKey, o.Logger, issOpts...)
		if err != nil {
			return err
		}
	}

	// The grants half (D30/D31): enabled exactly when resources are
	// declared; custody in its own sealed bucket, the same first key.
	if len(o.GrantResources) > 0 {
		grantsKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: o.GrantsBucket})
		if err != nil {
			return fmt.Errorf("kv bucket %s: %w", o.GrantsBucket, err)
		}
		resources := make([]grants.Resource, len(o.GrantResources))
		for i, r := range o.GrantResources {
			resources[i] = grants.Resource(r)
		}
		broker, err := grants.New(grants.NewKVStore(grantsKV), o.FirstKey, resources, &grants.HTTPProvider{},
			func(subject string) (string, error) {
				e, err := v.Get(service.PersonaKeyPrefix + subject)
				if err != nil {
					return "", err
				}
				return e.PublicKey, nil
			})
		if err != nil {
			return err
		}
		svcOpts = append(svcOpts, service.WithGrants(broker))
	}

	// The secret store (tenancy.md D36): always on — the surface is
	// principal-scoped, an empty domain costs nothing, and reachability
	// stays the deployment's permission-template decision.
	secretsKV, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: o.SecretsBucket})
	if err != nil {
		return fmt.Errorf("kv bucket %s: %w", o.SecretsBucket, err)
	}
	secretStore, err := secrets.New(sealedstore.NewKVStore(secretsKV), o.FirstKey)
	if err != nil {
		return err
	}
	svcOpts = append(svcOpts, service.WithSecrets(secretStore))

	// The guardrail (D37): enabled deliberately — an evaluator with no
	// rules allows everything but keeps the load/approve ops alive.
	if o.EnableGuardrail || len(o.GuardrailRules) > 0 {
		eval, err := guardrail.New()
		if err != nil {
			return err
		}
		rules := make([]guardrail.Rule, len(o.GuardrailRules))
		for i, r := range o.GuardrailRules {
			rules[i] = guardrail.Rule{Name: r.Name, When: r.When, Effect: guardrail.Effect(r.Effect)}
		}
		if err := eval.Load(rules); err != nil {
			return err
		}
		svcOpts = append(svcOpts, service.WithGuardrail(eval))
	}

	svcOpts = append(svcOpts, service.WithPrefix(o.Prefix))
	svc, err := service.New(v, o.SurfaceKey, o.Logger, svcOpts...)
	if err != nil {
		return err
	}
	sub, err := svc.Start(o.Conn)
	if err != nil {
		return err
	}
	var issuerSub *nats.Subscription
	if issuer != nil {
		issuerSub, err = issuer.Start(o.CalloutConn)
		if err != nil {
			_ = sub.Drain()
			return err
		}
		if err := o.CalloutConn.Flush(); err != nil {
			_ = issuerSub.Drain()
			_ = sub.Drain()
			return fmt.Errorf("callout flush: %w", err)
		}
		o.Logger.Info("callout issuer serving", "subject", callout.Subject,
			"token_bucket", o.TokenBucket, "ttl", o.CalloutTTL.String(),
			"sealed_requests", o.CalloutKey != "", "oidc", o.OIDCIssuer != "")
	}

	// The root is logged deliberately: a consumer with a mismatched prefix
	// sees timeouts, and this line is where the mismatch is diagnosed.
	o.Logger.Info("service serving", "subjects", svc.Root()+".>", "bucket", o.VaultBucket,
		"version", version.Version)

	<-ctx.Done()

	// Drain what Run started — never the caller's connections — and
	// confirm the server processed the unsubscribes (the flush roundtrip
	// orders behind them), so "Run returned" means "the surface is
	// silent" even while the caller's connections live on.
	if issuerSub != nil {
		_ = issuerSub.Drain()
		_ = o.CalloutConn.FlushTimeout(5 * time.Second)
	}
	_ = sub.Drain()
	_ = o.Conn.FlushTimeout(5 * time.Second)
	return ctx.Err()
}
