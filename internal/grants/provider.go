// The provider-facing half: plain OAuth over HTTP — code exchange (PKCE),
// refresh redemption, RFC 7009 revocation. This is the repo's first
// outbound HTTP surface, deliberately confined to this file and driven only
// by deployment-declared Resource endpoints — never a discovered or
// caller-supplied URL.

package grants

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPProvider implements Provider against real authorization servers.
type HTTPProvider struct {
	// Client is the HTTP client; a nil Client uses a 15s-timeout default.
	Client *http.Client
}

func (p *HTTPProvider) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Exchange implements Provider (authorization_code + PKCE).
func (p *HTTPProvider) Exchange(ctx context.Context, res Resource, code, verifier string) (TokenSet, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {res.RedirectURI},
		"client_id":     {res.ClientID},
	}
	return p.token(ctx, res, form)
}

// Redeem implements Provider (refresh_token).
func (p *HTTPProvider) Redeem(ctx context.Context, res Resource, refreshToken string) (TokenSet, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {res.ClientID},
	}
	return p.token(ctx, res, form)
}

// ExchangeToken implements Provider (RFC 8693, lane 3): the subject
// token in the form, the audience declared, the client authenticated by
// registration (Basic; a secret rides only when declared) — the shape
// the fold's own exchange e2e measured from the RP side.
func (p *HTTPProvider) ExchangeToken(ctx context.Context, res Resource, subjectToken string) (TokenSet, error) {
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {res.ExchangeAudience},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, res.ExchangeTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(res.ClientID, res.ClientSecret)
	resp, err := p.client().Do(req)
	if err != nil {
		return TokenSet{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return TokenSet{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return TokenSet{}, fmt.Errorf("grants: exchange endpoint %s: status %d: %.200s", res.Name, resp.StatusCode, body)
	}
	var raw struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.AccessToken == "" {
		return TokenSet{}, fmt.Errorf("grants: exchange endpoint %s: unreadable response", res.Name)
	}
	ts := TokenSet{AccessToken: raw.AccessToken}
	if raw.ExpiresIn > 0 {
		ts.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return ts, nil
}

// Revoke implements Provider (RFC 7009); best-effort by contract.
func (p *HTTPProvider) Revoke(ctx context.Context, res Resource, refreshToken string) error {
	if res.RevokeURL == "" {
		return nil
	}
	form := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {res.ClientID},
	}
	if res.ClientSecret != "" {
		form.Set("client_secret", res.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, res.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("grants: revoke at %s: status %d", res.Name, resp.StatusCode)
	}
	return nil
}

func (p *HTTPProvider) token(ctx context.Context, res Resource, form url.Values) (TokenSet, error) {
	if res.ClientSecret != "" {
		form.Set("client_secret", res.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, res.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// GitHub answers form-encoded unless asked for JSON; every other
	// provider either ignores this or already speaks it.
	req.Header.Set("Accept", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return TokenSet{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return TokenSet{}, err
	}
	if resp.StatusCode != http.StatusOK {
		// The provider's error body is operator-diagnostic, not secret;
		// tokens never appear in error responses.
		return TokenSet{}, fmt.Errorf("grants: token endpoint %s: status %d: %.200s", res.Name, resp.StatusCode, body)
	}
	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return TokenSet{}, fmt.Errorf("grants: token endpoint %s: unreadable response", res.Name)
	}
	if raw.AccessToken == "" {
		return TokenSet{}, fmt.Errorf("grants: token endpoint %s: no access token", res.Name)
	}
	ts := TokenSet{AccessToken: raw.AccessToken, RefreshToken: raw.RefreshToken}
	if raw.ExpiresIn > 0 {
		ts.ExpiresAt = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return ts, nil
}
