// The resources gate (external-tools.md D40, episode 0118): the catalog's
// custody half is runtime state. The acceptance bar is Bar 1's shape,
// priced by its measured baseline: a resource added through the op serves
// its first ceremony with zero restarts, while a 5ms-cadence probe on a
// pre-existing resource shows no failed access and no gap beyond 50ms.
// Beside it: persistence across a plane restart, removal semantics, the
// declared-name refusal, the management gate at the transport, and the
// secret sealed at rest with a fired positive control.
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
	"github.com/nats-io/nats.go/jetstream"

	"github.com/impire-io/soulstream-identity/client"
	"github.com/impire-io/soulstream-identity/embed"
)

func TestResourcesGate(t *testing.T) {
	c := provision(t)

	// The stand-in AS, shared by both resources: rotation per the
	// TestGrantsGate idiom, generous enough for a 5ms probe.
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
	run := func(ctx context.Context) chan error {
		errCh := make(chan error, 1)
		go func() {
			errCh <- embed.Run(ctx, embed.Options{
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
		return errCh
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	runErr := run(ctx1)
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

	// A represented user with standing custody on the declared resource.
	aliceTok, err := ops.CreateToken(c.appPub, "alice-ext", "resources gate", 0)
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
	violations := make(chan string, 8)
	ncAlice, err := nats.Connect(c.url,
		nats.UserCredentials(sentinelPath), nats.Token(aliceTok.Token),
		nats.RetryOnFailedConnect(false), nats.MaxReconnects(0),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			select {
			case violations <- err.Error():
			default:
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	defer ncAlice.Close()
	alice := client.New(ncAlice, c.appPub, "alice-ext", client.WithTimeout(2*time.Second))
	link, err := alice.GrantLinkStart("dex")
	if err != nil {
		t.Fatal(err)
	}
	if err := alice.GrantLinkComplete(link.LinkID, "consented"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.GrantAccessToken("dex"); err != nil {
		t.Fatal(err)
	}

	// The probe: the pre-existing resource's access at 5ms cadence,
	// across the add. The acceptance bar reads off these samples.
	type sample struct {
		at time.Time
		ok bool
	}
	var samples []sample
	probeCtx, stopProbe := context.WithCancel(context.Background())
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-probeCtx.Done():
				return
			case <-tick.C:
				_, err := alice.GrantAccessToken("dex")
				samples = append(samples, sample{at: time.Now(), ok: err == nil})
			}
		}
	}()
	time.Sleep(250 * time.Millisecond)

	// The act under test: a resource added through the op, live on return.
	const plantedSecret = "sekret-planted-never-at-rest-unsealed"
	addReturned := time.Now()
	if err := ops.ResourceAdd(client.ResourceConfig{
		Name: "extra", AuthURL: as.URL + "/auth", TokenURL: as.URL + "/token",
		ClientID: "broker", ClientSecret: plantedSecret,
		RedirectURI: "https://shell.invalid/cb",
	}); err != nil {
		t.Fatalf("resources.add: %v", err)
	}
	if _, err := alice.GrantLinkStart("extra"); err != nil {
		t.Fatalf("the added resource did not serve its first ceremony: %v", err)
	}
	firstServe := time.Since(addReturned)

	time.Sleep(250 * time.Millisecond)
	stopProbe()
	<-probeDone

	failed := 0
	var maxGap time.Duration
	var lastOK time.Time
	for _, s := range samples {
		if !s.ok {
			failed++
			continue
		}
		if !lastOK.IsZero() && s.at.Sub(lastOK) > maxGap {
			maxGap = s.at.Sub(lastOK)
		}
		lastOK = s.at
	}
	t.Logf("probe across the add: %d accesses, %d failed, max gap %s; the added resource served %s after add returned",
		len(samples), failed, maxGap, firstServe)
	if failed != 0 {
		t.Fatalf("the add disturbed the pre-existing resource: %d failed accesses", failed)
	}
	if maxGap > 50*time.Millisecond {
		t.Fatalf("the add opened a %s gap in the pre-existing resource's service (bar: 50ms)", maxGap)
	}

	// The list serves public halves, marks the declared entry, and by
	// construction has no secret field to leak.
	list, err := ops.Resources()
	if err != nil || len(list) != 2 {
		t.Fatalf("resources.list: %v (%d)", err, len(list))
	}
	if list[0].Name != "dex" || !list[0].Declared || list[1].Name != "extra" || list[1].Declared {
		t.Fatalf("the list misdescribes the catalog: %+v", list)
	}

	// The secret rests sealed: the raw bucket never holds it in the
	// clear, and the audit never says it — with the plant control fired.
	js, err := jetstream.New(c.ncOps)
	if err != nil {
		t.Fatal(err)
	}
	kv, err := js.KeyValue(context.Background(), "SOULIDENTITY_GRANTS")
	if err != nil {
		t.Fatal(err)
	}
	scan := func() int {
		hits := 0
		lister, err := kv.ListKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for name := range lister.Keys() {
			entry, err := kv.Get(context.Background(), name)
			if err != nil {
				continue
			}
			if strings.Contains(string(entry.Value()), plantedSecret) {
				hits++
			}
		}
		return hits
	}
	if got := scan(); got != 0 {
		t.Fatalf("the client secret rests unsealed: %d hits", got)
	}
	if _, err := kv.Create(context.Background(), "planted-control", []byte("x"+plantedSecret+"x")); err != nil {
		t.Fatal(err)
	}
	if got := scan(); got != 1 {
		t.Fatalf("positive control did not fire: %d hits", got)
	}
	if err := kv.Delete(context.Background(), "planted-control"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit.String(), plantedSecret) {
		t.Fatal("the audit log carries the client secret")
	}

	// The management gate is the transport's: a represented user's own
	// resources tail is not in the template, so the server kills the
	// publish before the service hears it.
	if err := alice.ResourceAdd(client.ResourceConfig{
		Name: "rogue", AuthURL: as.URL + "/auth", TokenURL: as.URL + "/token",
		ClientID: "broker", RedirectURI: "https://shell.invalid/cb",
	}); !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("a represented user's resources.add: want server-side timeout, got %v", err)
	}
	select {
	case v := <-violations:
		if !strings.Contains(v, "Permissions Violation") {
			t.Fatalf("alice's violation says %q", v)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no permissions violation surfaced on alice's connection")
	}

	// Persistence: the runtime resource survives a plane restart.
	cancel1()
	select {
	case err := <-runErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first run did not drain")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	runErr2 := run(ctx2)
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err := ops.Status(); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("restarted service never served")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := alice.GrantLinkStart("extra"); err != nil {
		t.Fatalf("the stored resource did not survive the restart: %v", err)
	}

	// Removal: the next ceremony refuses; standing custody is untouched;
	// removing again already happened; a declared name refuses.
	if err := ops.ResourceRemove("extra"); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.GrantLinkStart("extra"); err == nil {
		t.Fatal("a removed resource still serves ceremonies")
	}
	if _, err := alice.GrantAccessToken("dex"); err != nil {
		t.Fatalf("removal disturbed another resource's custody: %v", err)
	}
	if err := ops.ResourceRemove("extra"); err != nil {
		t.Fatalf("removing twice: %v", err)
	}
	if err := ops.ResourceRemove("dex"); err == nil ||
		!strings.Contains(err.Error(), "declared in configuration") {
		t.Fatalf("removing a declared resource: want the by-name refusal, got %v", err)
	}
	select {
	case err := <-runErr2:
		t.Fatalf("second run ended early: %v", err)
	default:
	}
}
