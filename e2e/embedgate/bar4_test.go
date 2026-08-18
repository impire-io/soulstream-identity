// Bar 4 (platform-tenancy-guardrails, carried as the C4 build's gate):
// a grant is real, scoped, and revocable — measured on the full
// composition in consumer position: the standing consent record is
// soulstream-core's grant vocabulary (v0.10.0), the enforcement is the
// identity plane's delegation broker, and the minting surface consults
// the record's projection before it mints, exactly the S8 split.
package embedgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/impire-io/soulstream-core/realm"
	"github.com/impire-io/soulstream-core/topic"
	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/embed"
)

func TestBar4GrantConsent(t *testing.T) {
	c := provision(t)

	// The stand-in AS (the TestGrantsGate idiom): strict rotation.
	var asMu sync.Mutex
	liveRefresh := ""
	rotations := 0
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		asMu.Lock()
		defer asMu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			liveRefresh = "rt-0"
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-0", "refresh_token": liveRefresh, "expires_in": 3600})
		case "refresh_token":
			if r.Form.Get("refresh_token") != liveRefresh {
				http.Error(w, "stale", http.StatusBadRequest)
				return
			}
			rotations++
			liveRefresh = fmt.Sprintf("rt-%d", rotations)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("at-%d", rotations), "refresh_token": liveRefresh, "expires_in": 3600})
		default:
			http.Error(w, "unsupported", http.StatusBadRequest)
		}
	}))
	defer as.Close()

	audit := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(audit, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- embed.Run(ctx, embed.Options{
			Conn: c.ncService, CalloutConn: c.ncCallout,
			FirstKey: c.firstSeed, SurfaceKey: c.surfaceSeed,
			CalloutKey: c.calloutSeed, AuthAccount: c.authPub,
			CalloutTTL: 2 * time.Minute,
			GrantResources: []embed.GrantResource{{
				Name: "dex", AuthURL: as.URL + "/auth", TokenURL: as.URL + "/token",
				ClientID: "broker", RedirectURI: "https://shell.invalid/cb",
			}},
			Logger: logger,
		})
	}()
	ops := client.New(c.ncOps, c.appPub, "ops")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := ops.Status(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("service never served")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := ops.ImportKey("acme", client.KindNATSAccountSigningKey, c.acmeSKSeed, c.appPub, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.ImportKey("auth/issuer", client.KindNATSAccountSigningKey, c.authSKSeed, c.authPub, ""); err != nil {
		t.Fatal(err)
	}

	// The realm substrate, provisioned once by ops (a full APP user).
	rcOps, err := realm.NewClient(ctx, c.ncOps, realm.Config{Realm: "acme", Persona: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rcOps.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	// Two represented users, admitted through callout with the realm-capable template.
	daanTok, err := ops.CreateToken(c.appPub, "daan-ext", "bar4", 0)
	if err != nil {
		t.Fatal(err)
	}
	scribeTok, err := ops.CreateToken(c.appPub, "scribe-ext", "bar4", 0)
	if err != nil {
		t.Fatal(err)
	}
	sentinel, err := ops.MintSentinel()
	if err != nil {
		t.Fatal(err)
	}
	sentinelPath := filepath.Join(t.TempDir(), "sentinel.creds")
	if err := os.WriteFile(sentinelPath, []byte(sentinel.Creds), 0o600); err != nil {
		t.Fatal(err)
	}
	dial := func(token string) *nats.Conn {
		nc, err := nats.Connect(c.url, nats.UserCredentials(sentinelPath), nats.Token(token),
			nats.RetryOnFailedConnect(false), nats.MaxReconnects(0))
		if err != nil {
			t.Fatalf("admission: %v", err)
		}
		t.Cleanup(nc.Close)
		return nc
	}
	ncDaan, ncScribe := dial(daanTok.Token), dial(scribeTok.Token)
	daanID := client.New(ncDaan, c.appPub, "daan-ext")
	scribeID := client.New(ncScribe, c.appPub, "scribe-ext")
	rcDaan, err := realm.NewClient(ctx, ncDaan, realm.Config{Realm: "acme", Persona: "daan-ext"})
	if err != nil {
		t.Fatal(err)
	}
	rcScribe, err := realm.NewClient(ctx, ncScribe, realm.Config{Realm: "acme", Persona: "scribe-ext"})
	if err != nil {
		t.Fatal(err)
	}

	// Custody: daan links the dex grant (the outbound half the actor will use).
	link, err := daanID.GrantLinkStart("dex")
	if err != nil {
		t.Fatal(err)
	}
	if err := daanID.GrantLinkComplete(link.LinkID, "consented"); err != nil {
		t.Fatal(err)
	}

	// The standing consent record: daan grants scribe the dex scope, in the topic.
	h, err := topic.StartTopic(ctx, rcDaan, topic.StartTopicInput{Name: "bar4"})
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := h.IssueGrant(ctx, "scribe-ext", "resource:dex", time.Now().Add(time.Hour).UTC())
	if err != nil {
		t.Fatal(err)
	}

	// The minting surface's duty (S8): consult the projection, then mint.
	mintIfConsented := func(ttl time.Duration) (client.Delegation, error) {
		mt, err := topic.Open(rcDaan, h.Path()).Materialise(ctx)
		if err != nil {
			return client.Delegation{}, err
		}
		for _, g := range mt.Grants {
			if g.Grantee == "scribe-ext" && g.Scope == "resource:dex" && g.ActiveAt(time.Now()) {
				return daanID.MintDelegation("daan-ext", "scribe-ext", []string{"dex"}, nil, ttl)
			}
		}
		return client.Delegation{}, errors.New("no active consent — mint refused")
	}

	// Clause 1: the granted action, dually attributed on both surfaces.
	del, err := mintIfConsented(2 * time.Second)
	if err != nil {
		t.Fatalf("consented mint: %v", err)
	}
	if access, err := scribeID.GrantAccessOnBehalf("dex", "daan-ext", del); err != nil || access.AccessToken == "" {
		t.Fatalf("delegated access: %v", err)
	}
	if !strings.Contains(audit.String(), "subject=daan-ext") {
		t.Fatal("on-behalf audit does not name the subject")
	}
	sh := topic.Open(rcScribe, h.Path())
	if _, err := sh.Materialise(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := sh.PostTurnOnBehalf(ctx, "acted for daan", topic.GrantAuthority{Grant: grantID, Granter: "daan-ext"}); err != nil {
		t.Fatal(err)
	}
	mt, err := h.Materialise(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var attributed bool
	for _, contrib := range mt.Contributions {
		if contrib.Author == "scribe-ext" && contrib.Authority != nil && contrib.Authority.Granter == "daan-ext" {
			attributed = true
		}
	}
	if !attributed {
		t.Fatal("record does not attribute both personas")
	}

	// Clause 2: revocation stops the action — the next mint refuses on the
	// projection, and the in-flight delegation dies at its TTL bound.
	if _, err := h.RevokeGrant(ctx, grantID); err != nil {
		t.Fatal(err)
	}
	if _, err := mintIfConsented(2 * time.Second); err == nil {
		t.Fatal("mint served after revocation")
	}
	time.Sleep(2200 * time.Millisecond) // past the minted delegation's TTL
	if _, err := scribeID.GrantAccessOnBehalf("dex", "daan-ext", del); err == nil {
		t.Fatal("in-flight delegation survived past its bound")
	}

	// Clause 3: revocation disturbed neither persona's own standing.
	if own, err := daanID.GrantAccessToken("dex"); err != nil || own.AccessToken == "" {
		t.Fatalf("subject's own access disturbed: %v", err)
	}
	if _, err := sh.PostTurn(ctx, "still myself"); err != nil {
		t.Fatalf("actor's own standing disturbed: %v", err)
	}
}
