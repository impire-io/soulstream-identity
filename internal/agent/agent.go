// Package agent serves the vault and registry over a Unix socket: HTTP+JSON,
// ssh-agent trust model — socket mode 0600, the OS user is the principal
// (hq/02-DESIGN/agent.md D8). Every operation is audit-logged; secrets are write-only
// through this surface, with credential export as the one named escape.
package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/impire-io/soulidentity/internal/mint"
	"github.com/impire-io/soulidentity/internal/registry"
	"github.com/impire-io/soulidentity/internal/vault"
	"github.com/impire-io/soulidentity/internal/version"
)

// Agent wires the vault and registry behind the HTTP surface.
type Agent struct {
	vault *vault.Vault
	reg   *registry.Registry
	log   *slog.Logger
}

// New builds an agent. A nil logger logs to a discarding handler.
func New(v *vault.Vault, r *registry.Registry, log *slog.Logger) *Agent {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Agent{vault: v, reg: r, log: log}
}

// Wire types. The client package mirrors these; the JSON is the contract.

type statusResponse struct {
	Version string `json:"version"`
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

type signNonceRequest struct {
	Key   string `json:"key"`
	Nonce string `json:"nonce"` // base64 (std)
}

type signNonceResponse struct {
	Sig string `json:"sig"` // base64 (std), raw signature bytes
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

// Handler returns the agent's HTTP surface.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, statusResponse{Version: version.Version})
	})
	mux.HandleFunc("GET /v1/keys", a.handleListKeys)
	mux.HandleFunc("POST /v1/keys", a.handleImportKey)
	mux.HandleFunc("GET /v1/identities", a.handleListIdentities)
	mux.HandleFunc("POST /v1/identities", a.handlePutIdentity)
	mux.HandleFunc("POST /v1/sign/nonce", a.handleSignNonce)
	mux.HandleFunc("POST /v1/sign/record", a.handleSignRecord)
	mux.HandleFunc("POST /v1/mint", a.handleMint)
	return mux
}

func (a *Agent) handleListKeys(w http.ResponseWriter, _ *http.Request) {
	keys, err := a.vault.List()
	if err != nil {
		a.fail(w, "keys.list", err)
		return
	}
	writeJSON(w, http.StatusOK, keysResponse{Keys: keys})
}

func (a *Agent) handleImportKey(w http.ResponseWriter, r *http.Request) {
	var req importKeyRequest
	if !decode(w, r, &req) {
		return
	}
	entry, err := a.vault.Import(req.Name, vault.Kind(req.Kind), req.Secret)
	if err != nil {
		a.fail(w, "keys.import", err, "key", req.Name)
		return
	}
	a.log.Info("key imported", "op", "keys.import", "key", entry.Name, "kind", entry.Kind)
	writeJSON(w, http.StatusCreated, entry)
}

func (a *Agent) handleListIdentities(w http.ResponseWriter, _ *http.Request) {
	ids, err := a.reg.List()
	if err != nil {
		a.fail(w, "identities.list", err)
		return
	}
	writeJSON(w, http.StatusOK, identitiesResponse{Identities: ids})
}

func (a *Agent) handlePutIdentity(w http.ResponseWriter, r *http.Request) {
	var id registry.Identity
	if !decode(w, r, &id) {
		return
	}
	if err := a.reg.Put(id); err != nil {
		a.fail(w, "identities.put", err, "account", id.Account, "user", id.User)
		return
	}
	a.log.Info("identity declared", "op", "identities.put",
		"account", id.Account, "user", id.User, "personas", id.Personas, "role", id.Role)
	writeJSON(w, http.StatusOK, id)
}

func (a *Agent) handleSignNonce(w http.ResponseWriter, r *http.Request) {
	var req signNonceRequest
	if !decode(w, r, &req) {
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		a.fail(w, "sign.nonce", fmt.Errorf("nonce is not base64: %w", err), "key", req.Key)
		return
	}
	sig, err := a.vault.SignNonce(req.Key, nonce)
	if err != nil {
		a.fail(w, "sign.nonce", err, "key", req.Key)
		return
	}
	a.log.Info("nonce signed", "op", "sign.nonce", "key", req.Key)
	writeJSON(w, http.StatusOK, signNonceResponse{Sig: base64.StdEncoding.EncodeToString(sig)})
}

func (a *Agent) handleSignRecord(w http.ResponseWriter, r *http.Request) {
	var req signRecordRequest
	if !decode(w, r, &req) {
		return
	}
	canonical, err := base64.StdEncoding.DecodeString(req.Canonical)
	if err != nil {
		a.fail(w, "sign.record", fmt.Errorf("canonical is not base64: %w", err), "key", req.Key)
		return
	}
	sig, err := a.vault.SignRecord(req.Key, canonical)
	if err != nil {
		a.fail(w, "sign.record", err, "key", req.Key)
		return
	}
	a.log.Info("record signed", "op", "sign.record", "key", req.Key)
	writeJSON(w, http.StatusOK, signRecordResponse{Sig: sig})
}

func (a *Agent) handleMint(w http.ResponseWriter, r *http.Request) {
	var req mintRequest
	if !decode(w, r, &req) {
		return
	}
	res, err := mint.Mint(a.vault, a.reg, req.Account, req.User)
	if err != nil {
		a.fail(w, "mint", err, "account", req.Account, "user", req.User)
		return
	}
	resp := mintResponse{JWT: res.JWT, UserPublicKey: res.UserPublicKey}
	if req.ExportCreds {
		creds, cerr := mint.ExportCreds(a.vault, req.Account, req.User, res.JWT)
		if cerr != nil {
			a.fail(w, "mint.export-creds", cerr, "account", req.Account, "user", req.User)
			return
		}
		resp.Creds = creds
		// The custody escape is always loud in the audit log.
		a.log.Warn("creds EXPORTED (custody escape)", "op", "mint.export-creds",
			"account", req.Account, "user", req.User)
	}
	a.log.Info("user JWT minted", "op", "mint", "account", req.Account,
		"user", req.User, "user_key", res.UserPublicKey)
	writeJSON(w, http.StatusOK, resp)
}

// fail maps package sentinels to HTTP statuses and audit-logs the refusal.
func (a *Agent) fail(w http.ResponseWriter, op string, err error, kv ...any) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, vault.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, vault.ErrExists):
		status = http.StatusConflict
	default:
		// Shape problems are the caller's; only genuine I/O stays a 500.
		if _, ok := err.(*json.SyntaxError); ok {
			status = http.StatusBadRequest
		} else if status == http.StatusInternalServerError && isValidationError(err) {
			status = http.StatusBadRequest
		}
	}
	a.log.Warn("refused", append([]any{"op", op, "err", err.Error(), "status", status}, kv...)...)
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

// isValidationError reports whether err is a caller mistake rather than an
// agent failure. Package errors are fmt-wrapped, so match on the message
// prefixes the packages own.
func isValidationError(err error) bool {
	msg := err.Error()
	for _, prefix := range []string{"vault:", "registry:", "mint:"} {
		if len(msg) >= len(prefix) && msg[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func decode(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid request: " + err.Error()})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Serve listens on a Unix socket (0600 — the filesystem is the authentication,
// D8) until ctx ends. A stale socket file from a dead agent is replaced.
func Serve(ctx context.Context, socket string, h http.Handler) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return fmt.Errorf("agent: create socket dir: %w", err)
	}
	if _, err := os.Stat(socket); err == nil {
		// Live agent or stale file? A connect attempt tells.
		if conn, derr := net.DialTimeout("unix", socket, time.Second); derr == nil {
			_ = conn.Close()
			return fmt.Errorf("agent: %s already has a running agent", socket)
		}
		if err := os.Remove(socket); err != nil {
			return fmt.Errorf("agent: replace stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return fmt.Errorf("agent: listen %s: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("agent: restrict socket: %w", err)
	}

	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-done:
		return fmt.Errorf("agent: serve: %w", err)
	}
}
