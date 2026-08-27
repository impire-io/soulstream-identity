//go:build byon_live

// Bar 1's PROVIDER arm (hq episode 0107's one named residue): the same
// runtime-account-birth measurement the local arm passed, re-run where
// a hosting provider custodies the operator key and exposes only an
// API. Never part of the default gate — it needs a real Synadia Cloud
// system and a control-plane token:
//
//	SOULSTREAM_CP_TOKEN=… SOULSTREAM_CP_SYSTEM=<system id or name> \
//	  go test -tags byon_live -run TestBar1ProviderArm ./internal/accounts/ -v
//
// It creates throwaway accounts named bar1-probe-* and deletes them
// again, and it touches nothing else in the system.
package accounts

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/synadia-io/control-plane-sdk-go/syncp"
)

func cpClient(t *testing.T) (*syncp.APIClient, string, context.Context) {
	t.Helper()
	token := os.Getenv("SOULSTREAM_CP_TOKEN")
	system := os.Getenv("SOULSTREAM_CP_SYSTEM")
	if token == "" || system == "" {
		t.Skip("SOULSTREAM_CP_TOKEN and SOULSTREAM_CP_SYSTEM required")
	}
	// Base URL and token ride the context, as the product's driver does
	// it — the SDK reads them from there, not from headers.
	client := syncp.NewAPIClient(syncp.NewConfiguration())
	ctx := context.WithValue(context.Background(), syncp.ContextServerVariables,
		map[string]string{"baseUrl": "https://cloud.synadia.com"})
	ctx = context.WithValue(ctx, syncp.ContextAccessToken, token)

	// Team → system, by id or case-insensitive name (the product's
	// resolution path, borrowed).
	teams, _, err := client.SessionAPI.ListTeams(ctx).Execute()
	if err != nil {
		t.Fatalf("list teams: %v", err)
	}
	for _, team := range teams.Items {
		systems, _, err := client.TeamAPI.ListTeamSystems(ctx, team.Id).Execute()
		if err != nil {
			t.Fatalf("list systems for team %s: %v", team.Name, err)
		}
		for _, s := range systems.Items {
			if s.Id == system || strings.EqualFold(s.Name, system) {
				if os.Getenv("SOULSTREAM_CP_NATS_URL") == "" &&
					s.DirectConnectionOpts != nil && s.DirectConnectionOpts.OverrideUrls != nil {
					t.Setenv("SOULSTREAM_CP_NATS_URL", *s.DirectConnectionOpts.OverrideUrls)
				}
				return client, s.Id, ctx
			}
		}
	}
	t.Fatalf("system %q not found in any team", system)
	return nil, "", ctx
}

// TestBar1ProviderArm: an account born at runtime through the provider
// API, a principal in it admitted and completing a round trip on the
// real cloud, zero restarts of anything, no usable half-account before
// completion, and a pre-existing account serving continuously
// throughout.
func TestBar1ProviderArm(t *testing.T) {
	client, systemID, ctx := cpClient(t)

	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	authority := &ProviderAPI{
		Client: client, SystemID: systemID,
		Log: func(f string, a ...any) { t.Logf(f, a...) },
	}
	engine, err := New(sealedstore.NewMemStore(), string(firstSeed), authority)
	if err != nil {
		t.Fatal(err)
	}

	stamp := time.Now().UTC().Format("150405")
	nameAuth := "bar1-probe-auth-" + stamp // the throwaway AUTH stand-in (D47 coupling)
	nameA := "bar1-probe-a-" + stamp       // the pre-existing account
	nameB := "bar1-probe-b-" + stamp       // born inside the measured window
	t.Cleanup(func() {
		// The API context carries the base URL and token — a bare
		// Background() cannot reach the control plane at all.
		for _, n := range []string{nameA, nameB, nameAuth} {
			if err := authority.Delete(ctx, n); err != nil {
				t.Logf("cleanup %s: %v", n, err)
			}
		}
	})

	// D47's coupling, measured against the real control plane without
	// touching the system's actual AUTH account: a throwaway stand-in is
	// born first (coupling off), then every later creation must teach it.
	authRec, _, err := engine.Create(ctx, nameAuth)
	if err != nil {
		t.Fatalf("create the AUTH stand-in: %v", err)
	}
	// A faithful stand-in is a callout account: the JWT rule refuses
	// allowed_accounts without auth_users, so seed one throwaway auth
	// user before the coupling writes to it (measured 2026-08-27: a bare
	// stand-in drew 400 Bad Request on the first amend).
	calloutKP, _ := nkeys.CreateUser()
	calloutPub, _ := calloutKP.PublicKey()
	standIn, err := authority.accountByPublicKey(ctx, authRec.PublicKey)
	if err != nil || standIn == nil {
		t.Fatalf("find the AUTH stand-in: %v", err)
	}
	if _, _, err := client.AccountAPI.UpdateAccount(ctx, standIn.Id).
		AccountUpdateRequest(syncp.AccountUpdateRequest{JwtSettings: &syncp.AccountJWTSettingsPatch{
			Authorization: &syncp.Nullable[syncp.ExternalAuthorizationPatch]{
				Val:         syncp.ExternalAuthorizationPatch{AuthUsers: []string{calloutPub}},
				ZeroIsValid: true,
			},
		}}).Execute(); err != nil {
		t.Fatalf("seed the stand-in's auth_users: %v", err)
	}
	authority.AuthAccount = authRec.PublicKey

	// The pre-existing account, and a probe that must never falter.
	bornA := time.Now()
	recA, seedA, err := engine.Create(ctx, nameA)
	if err != nil {
		t.Fatalf("create the pre-existing account: %v", err)
	}
	t.Logf("account A born in %v (%s)", time.Since(bornA).Round(time.Millisecond), recA.PublicKey)
	if len(seedA) == 0 || !strings.HasPrefix(seedA, "SA") {
		t.Fatalf("A's signing seed is not an account seed")
	}

	// Bar 2's clause on this arm: before B exists, nothing resolves it.
	if _, err := engine.Resolve(nameB); err == nil {
		t.Fatal("an unborn account resolved")
	}

	probeStop := make(chan struct{})
	probeFail := make(chan error, 1)
	probes := 0
	// The probe must be joined before the deletion cleanup frees A's
	// name — on the first live run (2026-08-27) a straggling iteration
	// re-created A mid-cleanup and leaked it. t.Cleanup is LIFO:
	// registered here, after the deletion cleanup, this runs first.
	var probeErr error
	stopProbe := sync.OnceFunc(func() {
		close(probeStop)
		probeErr = <-probeFail // nil once the goroutine closes it on its way out
	})
	t.Cleanup(stopProbe)
	go func() {
		for {
			select {
			case <-probeStop:
				close(probeFail)
				return
			default:
			}
			probes++
			if _, err := engine.Resolve(nameA); err != nil {
				probeFail <- fmt.Errorf("A stopped resolving mid-run: %w", err)
				return
			}
			if _, _, _, err := authority.CreateAccount(ctx, nameA); err == nil {
				probeFail <- fmt.Errorf("A's name was re-creatable mid-run")
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()

	// Bar 1: B is born at runtime — one act, nothing restarted.
	bornB := time.Now()
	recB, seedB, err := engine.Create(ctx, nameB)
	if err != nil {
		t.Fatalf("create B at runtime: %v", err)
	}
	birth := time.Since(bornB)
	t.Logf("account B born in %v (%s)", birth.Round(time.Millisecond), recB.PublicKey)
	if recB.PublicKey == "" || !strings.HasPrefix(recB.PublicKey, "A") {
		t.Fatalf("B has no account public key: %+v", recB)
	}
	if len(seedB) == 0 {
		t.Fatal("B's signing seed did not come back — nothing to custody")
	}

	// A principal in the newborn account connects to the real cloud and
	// completes a round trip: the account is not merely recorded, it
	// serves.
	//
	// The signing key is programmatic, so the user JWT is minted here
	// exactly as the mint path does it — no seed leaves this process.
	if err := roundTripInAccount(t, recB.PublicKey, seedB); err != nil {
		t.Fatalf("round trip in the newborn account: %v", err)
	}

	// The D47 coupling, read back from the control plane: the stand-in
	// AUTH's allowed_accounts learned BOTH tenants born after it.
	authView, err := authority.accountByPublicKey(ctx, authRec.PublicKey)
	if err != nil || authView == nil {
		t.Fatalf("find the AUTH stand-in: %v", err)
	}
	full, _, err := client.AccountAPI.GetAccount(ctx, authView.Id).Execute()
	if err != nil {
		t.Fatalf("get the AUTH stand-in: %v", err)
	}
	var allowed []string
	if full.JwtSettings != nil && full.JwtSettings.Authorization != nil {
		allowed = full.JwtSettings.Authorization.AllowedAccounts
	}
	for _, want := range []string{recA.PublicKey, recB.PublicKey} {
		found := false
		for _, a := range allowed {
			if a == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("AUTH stand-in allowed_accounts missing %s (have %v)", want, allowed)
		}
	}
	t.Logf("AUTH stand-in learned both tenants: %v", allowed)

	// Suspension and resume through the provider API.
	if _, err := engine.SetSuspended(ctx, nameB, true); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if rec, err := engine.Resolve(nameB); err != nil || rec.Status != Suspended {
		t.Fatalf("after suspend: %+v (%v)", rec, err)
	}
	if _, err := engine.SetSuspended(ctx, nameB, false); err != nil {
		t.Fatalf("resume: %v", err)
	}

	stopProbe()
	if probeErr != nil {
		t.Fatalf("the pre-existing account did not serve continuously: %v", probeErr)
	}
	t.Logf("A probed %d times through the window, uninterrupted", probes)
}

// roundTripInAccount mints a user against the account's programmatic
// signing key and completes a publish/subscribe round trip on the real
// cloud — the account does not merely exist, it serves. The seed never
// leaves this process; only the JWT travels.
func roundTripInAccount(t *testing.T, accountPub, signingSeed string) error {
	t.Helper()
	url := os.Getenv("SOULSTREAM_CP_NATS_URL")
	if url == "" {
		// Bar 1's central clause is "the new principal connects and
		// completes a round trip" — without the system's URL the arm is
		// not measured, and saying so is the honest outcome.
		return fmt.Errorf("SOULSTREAM_CP_NATS_URL is unset — Bar 1's round-trip clause cannot be measured")
	}
	skKP, err := nkeys.FromSeed([]byte(signingSeed))
	if err != nil {
		return fmt.Errorf("signing seed: %w", err)
	}
	uKP, _ := nkeys.CreateUser()
	uPub, _ := uKP.PublicKey()
	uSeed, _ := uKP.Seed()
	uc := jwt.NewUserClaims(uPub)
	uc.Name = "bar1-probe"
	uc.IssuerAccount = accountPub
	// The mint shape (D5/D47): scoped, permission-less — the signing-key
	// group's scope is the whole policy. Before D47 the group was plain
	// and this user connected inert; the round trip below is the proof.
	uc.SetScoped(true)
	uc.Expires = time.Now().Add(15 * time.Minute).Unix()
	token, err := uc.Encode(skKP)
	if err != nil {
		return fmt.Errorf("mint user: %w", err)
	}

	// A newborn account's JWT propagates to the edge; give it a bounded
	// window rather than asserting instantaneous convergence.
	var nc *nats.Conn
	deadline := time.Now().Add(60 * time.Second)
	for {
		nc, err = nats.Connect(url, nats.UserJWTAndSeed(token, string(uSeed)),
			nats.RetryOnFailedConnect(false), nats.MaxReconnects(0), nats.Timeout(5*time.Second))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("admission into the newborn account: %w", err)
		}
		time.Sleep(2 * time.Second)
	}
	defer nc.Close()

	// Inside the persona scope: subscribe + publish must round-trip.
	sub, err := nc.SubscribeSync("SOULSTREAM.bar1.probe")
	if err != nil {
		return fmt.Errorf("scoped user cannot subscribe (the inert defect): %w", err)
	}
	if err := nc.Publish("SOULSTREAM.bar1.probe", []byte("alive")); err != nil {
		return err
	}
	msg, err := sub.NextMsg(10 * time.Second)
	if err != nil {
		return fmt.Errorf("round trip: %w", err)
	}
	t.Logf("scoped round trip in the newborn account: %q", msg.Data)
	return nil
}
