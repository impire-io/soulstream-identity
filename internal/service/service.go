// Package service is SoulIdentity's NATS surface (hq/02-DESIGN/nats-surface.md):
// request/reply on soulidentity.<account>.<user>.<op> with xkey-sealed payloads
// (D16), plus the two open ops (status, xkey — D14). The principal is read off
// the subject and is trustworthy because the server's publish-permission
// enforcement already proved it (D15) — this package never re-verifies the
// claim, it only applies SoulIdentity's own policy: who is admin, who may act
// as which persona (D6), who may mint for whom.
package service

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/callout"
	"github.com/impire-io/soulidentity/internal/mint"
	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
	"github.com/impire-io/soulidentity/internal/version"
)

// Segment is the service's fixed token in the subject space. The full root
// is <prefix>.<Segment> where the prefix is the deployment's shared
// ecosystem namespace, empty by default (D14 as amended, journey 0011) —
// fixed per service so ecosystem components can share one prefix without
// colliding.
const Segment = "soulidentity"

// SubjectRoot computes the subject root for a deployment prefix ("" means
// the bare service segment). The account token sits at position
// len(prefix tokens)+2 (1-based) — the position an export's
// account_token_position declares for cross-account imports.
func SubjectRoot(prefix string) string {
	if prefix == "" {
		return Segment
	}
	return prefix + "." + Segment
}

// ValidatePrefix enforces the prefix grammar: dot-separated tokens of
// [A-Za-z0-9_-]+ — no wildcards, no spaces, no '$' (subject tokens, chosen
// by the deployment, shared verbatim by every consumer).
func ValidatePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	for _, tok := range strings.Split(prefix, ".") {
		if tok == "" {
			return fmt.Errorf("service: prefix %q has an empty token", prefix)
		}
		for _, r := range tok {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
				r == '_', r == '-':
			default:
				return fmt.Errorf("service: prefix %q: token %q may only contain [A-Za-z0-9_-]", prefix, tok)
			}
		}
	}
	return nil
}

// PersonaKeyPrefix is the vault-name convention binding a registry persona to
// its signing key: persona <p> signs with vault key "persona/<p>". Act-as
// (D6) is checked against exactly this binding.
const PersonaKeyPrefix = "persona/"

// Service wires the vault and registry behind the sealed NATS surface.
type Service struct {
	vault      *vault.Vault
	reg        *registry.Registry
	surface    nkeys.KeyPair
	surfacePub string
	log        *slog.Logger

	// The callout half (hq/02-DESIGN/auth-callout.md): the token store the
	// tokens.* ops manage, the vault name of the AUTH signing key
	// sentinel.mint signs with, and the AUTH account public key the sentinel
	// declares as issuer_account (a signing-key-signed user JWT must name
	// its account or the server refuses it before callout ever fires).
	// Nil/empty = those ops refuse.
	tokens      callout.Store
	authKeyName string
	authAccount string

	// root is the subject root: <prefix>.<Segment>, bare Segment by default.
	root string
}

// Option configures a Service.
type Option func(*Service)

// WithCallout enables the token-management and sentinel ops: tokens live in
// store, authKeyName is the vault name of the AUTH account signing key (D21)
// that signs sentinels, and authAccount is the AUTH account's public key.
func WithCallout(store callout.Store, authKeyName, authAccount string) Option {
	return func(s *Service) {
		s.tokens = store
		s.authKeyName = authKeyName
		s.authAccount = authAccount
	}
}

// WithPrefix namespaces the subject space under the deployment's shared
// ecosystem prefix (D14 as amended, journey 0011). Every consumer must be
// configured with the same prefix — a mismatch is silent timeouts, which is
// why the service logs its root at startup.
func WithPrefix(prefix string) Option {
	return func(s *Service) {
		s.root = SubjectRoot(prefix)
	}
}

// New builds the service around its surface key ("SX…" seed, deployment-
// supplied — D17). A nil logger logs to a discarding handler.
func New(v *vault.Vault, r *registry.Registry, surfaceSeed string, log *slog.Logger, opts ...Option) (*Service, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	kp, err := nkeys.FromCurveSeed([]byte(strings.TrimSpace(surfaceSeed)))
	if err != nil {
		return nil, fmt.Errorf("service: surface key is not a curve (SX…) seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("service: surface key public half: %w", err)
	}
	s := &Service{vault: v, reg: r, surface: kp, surfacePub: pub, log: log, root: Segment}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Root returns the service's full subject root.
func (s *Service) Root() string {
	return s.root
}

// Start subscribes the service to its subject space on nc.
func (s *Service) Start(nc *nats.Conn) (*nats.Subscription, error) {
	sub, err := nc.Subscribe(s.root+".>", func(msg *nats.Msg) {
		reply := s.respond(msg.Subject, msg.Data)
		if msg.Reply != "" {
			_ = msg.Respond(reply)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("service: subscribe: %w", err)
	}
	return sub, nil
}

// Wire types. The client package mirrors these; the JSON is the contract —
// unchanged from milestone 1 except the retired sign/nonce.

type statusResponse struct {
	Version string `json:"version"`
}

type xkeyResponse struct {
	XKey string `json:"xkey"`
}

// envelope is the sealed transport shape (D16): a plaintext outer JSON whose
// data is xkv1 ciphertext (encoding/json renders []byte as base64).
type envelope struct {
	XKey string `json:"xkey"`
	Data []byte `json:"data"`
}

type importKeyRequest struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Secret string `json:"secret"`
}

type keysResponse struct {
	Keys []vault.Entry `json:"keys"`
}

type identitiesResponse struct {
	Identities []registry.Identity `json:"identities"`
}

type signRecordRequest struct {
	Key       string `json:"key"`
	Canonical string `json:"canonical"` // base64 (std) canonical record bytes
}

type signRecordResponse struct {
	Sig string `json:"sig"` // the base64 string Soulstream-Sig carries
}

type mintRequest struct {
	Account     string `json:"account"`
	User        string `json:"user"`
	ExportCreds bool   `json:"export_creds,omitempty"`
}

type mintResponse struct {
	JWT           string `json:"jwt"`
	UserPublicKey string `json:"user_public_key"`
	// Creds is present only when the caller explicitly asked for the custody
	// escape (hq/02-DESIGN/agent.md D7).
	Creds string `json:"creds,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// respond computes the full reply bytes for one request — the whole surface,
// NATS-free so it unit-tests without a server.
func (s *Service) respond(subject string, data []byte) []byte {
	rest, ok := strings.CutPrefix(subject, s.root+".")
	if !ok {
		return marshal(errorResponse{Error: "service: unknown subject"})
	}
	tokens := strings.Split(rest, ".")
	// The two open ops answer in plaintext (D14): public material only.
	if len(tokens) == 1 {
		switch tokens[0] {
		case "status":
			return marshal(statusResponse{Version: version.Version})
		case "xkey":
			return marshal(xkeyResponse{XKey: s.surfacePub})
		}
		return marshal(errorResponse{Error: "service: unknown subject"})
	}
	if len(tokens) < 3 {
		return marshal(errorResponse{Error: "service: unknown subject"})
	}
	account, user, op := tokens[0], tokens[1], strings.Join(tokens[2:], ".")

	// Before a secure channel exists, errors are plaintext and content-free.
	var env envelope
	if err := unmarshalStrict(data, &env); err != nil || env.XKey == "" || len(env.Data) == 0 {
		s.refuse(account, user, op, errors.New("service: request is not a sealed envelope"))
		return marshal(errorResponse{Error: "service: request is not a sealed envelope"})
	}
	plain, err := s.surface.Open(env.Data, env.XKey)
	if err != nil {
		s.refuse(account, user, op, errors.New("service: request cannot be unsealed"))
		return marshal(errorResponse{Error: "service: request cannot be unsealed"})
	}

	result, err := s.dispatch(account, user, op, plain)
	var body []byte
	if err != nil {
		s.refuse(account, user, op, err)
		body = marshal(errorResponse{Error: err.Error()})
	} else {
		body = marshal(result)
	}
	sealed, serr := s.surface.Seal(body, env.XKey)
	if serr != nil {
		return marshal(errorResponse{Error: "service: reply cannot be sealed"})
	}
	return marshal(envelope{XKey: s.surfacePub, Data: sealed})
}

// dispatch applies per-op authorization and runs the op. The (account, user)
// principal is server-proven (D15); everything here is SoulIdentity policy.
func (s *Service) dispatch(account, user, op string, body []byte) (any, error) {
	switch op {
	case "keys.list":
		if err := s.requireAdmin(account, user, op); err != nil {
			return nil, err
		}
		keys, err := s.vault.List()
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op)
		return keysResponse{Keys: keys}, nil

	case "keys.import":
		if err := s.requireAdmin(account, user, op); err != nil {
			return nil, err
		}
		var req importKeyRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		entry, err := s.vault.Import(req.Name, vault.Kind(req.Kind), req.Secret)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op, "key", entry.Name, "kind", entry.Kind)
		return entry, nil

	case "identities.list":
		if err := s.requireAdmin(account, user, op); err != nil {
			return nil, err
		}
		ids, err := s.reg.List()
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op)
		return identitiesResponse{Identities: ids}, nil

	case "identities.put":
		if err := s.requireAdmin(account, user, op); err != nil {
			return nil, err
		}
		var id registry.Identity
		if err := unmarshalStrict(body, &id); err != nil {
			return nil, err
		}
		if err := s.reg.Put(id); err != nil {
			return nil, err
		}
		s.allow(account, user, op, "target_account", id.Account, "target_user", id.User,
			"personas", id.Personas, "role", id.Role, "admin", id.Admin)
		return id, nil

	case "sign.record":
		var req signRecordRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		persona, ok := strings.CutPrefix(req.Key, PersonaKeyPrefix)
		if !ok || persona == "" {
			return nil, fmt.Errorf("service: record signing uses %s<persona> keys, got %q", PersonaKeyPrefix, req.Key)
		}
		allowed, err := s.reg.AllowedPersona(account, user, persona)
		if err != nil {
			return nil, err
		}
		if !allowed {
			// THE act-as gate (D6), now against a server-proven principal.
			return nil, fmt.Errorf("service: %s/%s may not act as persona %q", account, user, persona)
		}
		canonical, err := base64.StdEncoding.DecodeString(req.Canonical)
		if err != nil {
			return nil, fmt.Errorf("service: canonical is not base64: %w", err)
		}
		sig, err := s.vault.SignRecord(req.Key, canonical)
		if err != nil {
			return nil, err
		}
		s.allow(account, user, op, "persona", persona)
		return signRecordResponse{Sig: sig}, nil

	case "mint":
		var req mintRequest
		if err := unmarshalStrict(body, &req); err != nil {
			return nil, err
		}
		if req.Account != account || req.User != user {
			// Minting for another identity is provisioning: admins only.
			if err := s.requireAdmin(account, user, op); err != nil {
				return nil, err
			}
		}
		res, err := mint.Mint(s.vault, s.reg, req.Account, req.User)
		if err != nil {
			return nil, err
		}
		resp := mintResponse{JWT: res.JWT, UserPublicKey: res.UserPublicKey}
		if req.ExportCreds {
			creds, cerr := mint.ExportCreds(s.vault, req.Account, req.User, res.JWT)
			if cerr != nil {
				return nil, cerr
			}
			resp.Creds = creds
			// The custody escape is always loud in the audit log.
			s.log.Warn("creds EXPORTED (custody escape)", "op", "mint.export-creds",
				"account", account, "user", user,
				"target_account", req.Account, "target_user", req.User)
		}
		s.allow(account, user, op, "target_account", req.Account, "target_user", req.User,
			"user_key", res.UserPublicKey)
		return resp, nil

	case "tokens.create", "tokens.list", "tokens.revoke", "sentinel.mint":
		return s.dispatchCallout(account, user, op, body)

	default:
		return nil, fmt.Errorf("service: unknown op %q", op)
	}
}

// requireAdmin gates the management ops on a declared admin row (D2).
func (s *Service) requireAdmin(account, user, op string) error {
	id, ok, err := s.reg.Get(account, user)
	if err != nil {
		return err
	}
	if !ok || !id.Admin {
		return fmt.Errorf("service: %s requires an admin identity, and %s/%s is not one", op, account, user)
	}
	return nil
}

// allow and refuse are the audit trail: every op logs its server-proven
// principal and the decision.
func (s *Service) allow(account, user, op string, kv ...any) {
	s.log.Info("ok", append([]any{"op", op, "account", account, "user", user}, kv...)...)
}

func (s *Service) refuse(account, user, op string, err error) {
	s.log.Warn("refused", "op", op, "account", account, "user", user, "err", err.Error())
}
