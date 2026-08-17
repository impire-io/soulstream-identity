package grants

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

func newTestBroker(t *testing.T, store Store, provider Provider, resolver SubjectKeyResolver, resources ...Resource) *Broker {
	t.Helper()
	kp, _ := nkeys.CreateCurveKeys()
	seed, _ := kp.Seed()
	if resolver == nil {
		resolver = func(string) (string, error) { return "", errors.New("no resolver") }
	}
	b, err := New(store, string(seed), resources, provider, resolver)
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	return b
}

var testResource = Resource{
	Name: "dex", AuthURL: "https://as.test/auth", TokenURL: "https://as.test/token",
	ClientID: "broker", RedirectURI: "https://shell.test/cb", Scopes: []string{"openid", "offline_access"},
}

// rotatingProvider mimics the measured Dex semantics: redeem rotates; a
// spent token inside the reuse window answers as a retry; outside, refuses.
type rotatingProvider struct {
	mu      sync.Mutex
	live    string
	spent   map[string]spentInfo
	counter int
	reuse   time.Duration
}

type spentInfo struct {
	successor string
	at        time.Time
}

func newRotatingProvider(initial string, reuse time.Duration) *rotatingProvider {
	return &rotatingProvider{live: initial, spent: map[string]spentInfo{}, reuse: reuse}
}

func (p *rotatingProvider) Exchange(_ context.Context, _ Resource, code, _ string) (TokenSet, error) {
	if code != "good-code" {
		return TokenSet{}, errors.New("bad code")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return TokenSet{AccessToken: "at-linked", RefreshToken: p.live}, nil
}

func (p *rotatingProvider) Redeem(_ context.Context, _ Resource, rt string) (TokenSet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rt == p.live {
		p.counter++
		next := fmt.Sprintf("rt-%d", p.counter)
		p.spent[rt] = spentInfo{successor: next, at: time.Now()}
		p.live = next
		return TokenSet{AccessToken: fmt.Sprintf("at-%d", p.counter), RefreshToken: next}, nil
	}
	if info, ok := p.spent[rt]; ok && time.Since(info.at) < p.reuse {
		return TokenSet{AccessToken: "at-retry", RefreshToken: info.successor}, nil
	}
	return TokenSet{}, errors.New("refresh token invalid or already claimed")
}

func (p *rotatingProvider) Revoke(_ context.Context, _ Resource, _ string) error { return nil }

func (p *rotatingProvider) redeemable(rt string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return rt == p.live
}

func seedGrant(t *testing.T, b *Broker, persona, resource, refreshToken string) {
	t.Helper()
	g := grantRecord{RefreshToken: refreshToken, LinkedAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err := b.store.put(grantName(persona, resource), g, 0); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// TestAccessRotationPersists: three redemptions, each rotated successor
// CAS-persisted (SC-001's rotation clause).
func TestAccessRotationPersists(t *testing.T) {
	prov := newRotatingProvider("rt-0", 0)
	b := newTestBroker(t, NewMemStore(), prov, nil, testResource)
	seedGrant(t, b, "alice", "dex", "rt-0")

	for i := 1; i <= 3; i++ {
		ts, err := b.Access(context.Background(), "alice", "dex")
		if err != nil {
			t.Fatalf("access %d: %v", i, err)
		}
		if ts.AccessToken == "" {
			t.Fatalf("access %d: empty token", i)
		}
	}
	var g grantRecord
	if _, err := b.store.get(grantName("alice", "dex"), &g); err != nil {
		t.Fatal(err)
	}
	if !prov.redeemable(g.RefreshToken) {
		t.Fatal("stored refresh token is not the live line after rotations")
	}
}

// TestConcurrentAccessLosesNothing: the D31 stampede under -race — every
// call serves, the stored line stays redeemable, both reuse regimes.
func TestConcurrentAccessLosesNothing(t *testing.T) {
	for _, reuse := range []time.Duration{0, 500 * time.Millisecond} {
		t.Run(fmt.Sprintf("reuse=%s", reuse), func(t *testing.T) {
			prov := newRotatingProvider("rt-0", reuse)
			b := newTestBroker(t, NewMemStore(), prov, nil, testResource)
			seedGrant(t, b, "alice", "dex", "rt-0")

			const N = 8
			var wg sync.WaitGroup
			errs := make([]error, N)
			for i := range N {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ts, err := b.Access(context.Background(), "alice", "dex")
					if err == nil && ts.AccessToken == "" {
						err = errors.New("empty access token")
					}
					errs[i] = err
				}(i)
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Errorf("access %d: %v", i, err)
				}
			}
			var g grantRecord
			if _, err := b.store.get(grantName("alice", "dex"), &g); err != nil {
				t.Fatalf("grant gone after race: %v", err)
			}
			if !prov.redeemable(g.RefreshToken) {
				t.Error("stored refresh token no longer redeemable — the line is lost")
			}
		})
	}
}

// TestRevokeRefuses: custody deletion refuses the next access (SC-001).
func TestRevokeRefuses(t *testing.T) {
	prov := newRotatingProvider("rt-0", 0)
	b := newTestBroker(t, NewMemStore(), prov, nil, testResource)
	seedGrant(t, b, "alice", "dex", "rt-0")

	if err := b.Revoke(context.Background(), "alice", "dex"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := b.Access(context.Background(), "alice", "dex"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("access after revoke: want ErrNotFound, got %v", err)
	}
	// The refusal for a never-linked resource is identical — no probe.
	_, err1 := b.Access(context.Background(), "alice", "dex")
	_, err2 := b.Access(context.Background(), "mallory", "dex")
	if err1.Error() != err2.Error() {
		t.Errorf("refusals differ: %q vs %q", err1, err2)
	}
}

// TestDelegationMatrix: D33's measured rows — one allowed path, the
// refusal classes, actor bound to the caller argument (the op layer passes
// the server-proven principal).
func TestDelegationMatrix(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	resolver := func(subject string) (string, error) {
		if subject == "daan" {
			return pubB64, nil
		}
		return "", errors.New("no key")
	}
	prov := newRotatingProvider("rt-0", 0)
	b := newTestBroker(t, NewMemStore(), prov, resolver, testResource)
	seedGrant(t, b, "daan", "dex", "rt-0")

	mint := func(subject, actor string, resources []string, ttl time.Duration) (string, string) {
		payload, _ := json.Marshal(Delegation{
			Subject: subject, Actor: actor, Resources: resources,
			IssuedAt:  time.Now().UTC().Format(time.RFC3339),
			ExpiresAt: time.Now().Add(ttl).UTC().Format(time.RFC3339),
		})
		sig := ed25519.Sign(priv, payload)
		return base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(sig)
	}

	payload, sig := mint("daan", "agent-scribe", []string{"dex"}, time.Minute)

	// Allowed: the actor itself.
	if ts, err := b.AccessOnBehalf(context.Background(), "agent-scribe", "daan", "dex", payload, sig); err != nil || ts.AccessToken == "" {
		t.Fatalf("delegated access: %v", err)
	}
	// No delegation.
	if _, err := b.AccessOnBehalf(context.Background(), "agent-scribe", "daan", "dex", "", ""); !errors.Is(err, ErrDelegationInvalid) {
		t.Errorf("no delegation: want ErrDelegationInvalid, got %v", err)
	}
	// Stolen: a different caller presents the same valid delegation.
	if _, err := b.AccessOnBehalf(context.Background(), "mallory", "daan", "dex", payload, sig); !errors.Is(err, ErrActorMismatch) {
		t.Errorf("stolen delegation: want ErrActorMismatch, got %v", err)
	}
	// Expired.
	ep, es := mint("daan", "agent-scribe", []string{"dex"}, -time.Second)
	if _, err := b.AccessOnBehalf(context.Background(), "agent-scribe", "daan", "dex", ep, es); !errors.Is(err, ErrDelegationInvalid) {
		t.Errorf("expired delegation: want ErrDelegationInvalid, got %v", err)
	}
	// Out-of-bounds resource.
	op, os := mint("daan", "agent-scribe", []string{"github"}, time.Minute)
	if _, err := b.AccessOnBehalf(context.Background(), "agent-scribe", "daan", "dex", op, os); !errors.Is(err, ErrDelegationInvalid) {
		t.Errorf("out-of-bounds: want ErrDelegationInvalid, got %v", err)
	}
	// Tampered payload: signature no longer verifies.
	tampered := base64.StdEncoding.EncodeToString([]byte(strings.Replace(mustDecode(t, payload), "dex", "hex", 1)))
	if _, err := b.AccessOnBehalf(context.Background(), "agent-scribe", "daan", "hex", tampered, sig); !errors.Is(err, ErrDelegationInvalid) {
		t.Errorf("tampered: want ErrDelegationInvalid, got %v", err)
	}
}

func mustDecode(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestLinkCeremonyAgainstStandinAS: US2 end to end over real HTTP — link
// start (PKCE), scripted consent, complete, access — and the at-rest
// positive control: the refresh token greps out of the plaintext record
// and NOT out of the sealed bytes (SC-002).
func TestLinkCeremonyAgainstStandinAS(t *testing.T) {
	const refreshToken = "rt-secret-0"
	var lastChallenge string
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			switch r.PostForm.Get("grant_type") {
			case "authorization_code":
				if r.PostForm.Get("code") != "good-code" {
					http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
					return
				}
				sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(sum[:]) != lastChallenge {
					http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "at-0", "refresh_token": refreshToken, "expires_in": 300,
				})
			case "refresh_token":
				if r.PostForm.Get("refresh_token") != refreshToken {
					http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "at-1", "refresh_token": refreshToken, "expires_in": 300,
				})
			default:
				http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer as.Close()

	store := NewMemStore()
	res := Resource{
		Name: "standin", AuthURL: as.URL + "/auth", TokenURL: as.URL + "/token",
		ClientID: "broker", RedirectURI: "https://shell.test/cb", Scopes: []string{"offline_access"},
	}
	b := newTestBroker(t, store, &HTTPProvider{}, nil, res)

	authorizeURL, linkID, err := b.LinkStart("alice", "standin")
	if err != nil {
		t.Fatalf("link start: %v", err)
	}
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") != linkID {
		t.Fatalf("authorize url malformed: %s", authorizeURL)
	}
	lastChallenge = u.Query().Get("code_challenge")

	if err := b.LinkComplete(context.Background(), "alice", linkID, "good-code"); err != nil {
		t.Fatalf("link complete: %v", err)
	}
	// The ceremony is single-use.
	if err := b.LinkComplete(context.Background(), "alice", linkID, "good-code"); !errors.Is(err, ErrLinkInvalid) {
		t.Errorf("replayed ceremony: want ErrLinkInvalid, got %v", err)
	}

	ts, err := b.Access(context.Background(), "alice", "standin")
	if err != nil || ts.AccessToken == "" {
		t.Fatalf("access after link: %v", err)
	}
	infos, err := b.List("alice")
	if err != nil || len(infos) != 1 || infos[0].Resource != "standin" {
		t.Fatalf("list: %v %+v", err, infos)
	}

	// At-rest positive control (the D13 idiom): plaintext contains the
	// secret, the sealed record does not.
	plain, _ := json.Marshal(grantRecord{RefreshToken: refreshToken})
	if !strings.Contains(string(plain), refreshToken) {
		t.Fatal("positive control broken")
	}
	sealed := store.SealedBytes(grantName("alice", "standin"))
	if len(sealed) == 0 {
		t.Fatal("no sealed record")
	}
	if strings.Contains(string(sealed), refreshToken) {
		t.Fatal("refresh token rests unsealed")
	}
}
