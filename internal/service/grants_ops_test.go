package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/internal/grants"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

// staticProvider serves fixed tokens — the ops tests exercise the surface,
// not rotation (that is the grants package's own suite).
type staticProvider struct{}

func (staticProvider) Exchange(context.Context, grants.Resource, string, string) (grants.TokenSet, error) {
	return grants.TokenSet{AccessToken: "at-x", RefreshToken: "rt-x"}, nil
}

func (staticProvider) Redeem(_ context.Context, _ grants.Resource, rt string) (grants.TokenSet, error) {
	return grants.TokenSet{AccessToken: "at-for-" + rt, RefreshToken: rt}, nil
}

func (staticProvider) Revoke(context.Context, grants.Resource, string) error { return nil }

func grantsHarness(t *testing.T) (*Service, *vault.Vault, string, *grants.Broker) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()

	res := grants.Resource{
		Name: "dex", AuthURL: "https://as.test/auth", TokenURL: "https://as.test/token",
		ClientID: "broker", RedirectURI: "https://shell.test/cb",
	}
	// The subject-key resolver is the vault directory read (D26/D33).
	resolver := func(subject string) (string, error) {
		e, err := v.Get(PersonaKeyPrefix + subject)
		if err != nil {
			return "", err
		}
		return e.PublicKey, nil
	}
	broker, err := grants.New(grants.NewMemStore(), string(firstSeed), []grants.Resource{res}, staticProvider{}, resolver)
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()
	s, err := New(v, string(surfaceSeed), nil, WithGrants(broker))
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return s, v, accPub, broker
}

// seedGrantViaLink runs the real link path against the broker with the
// static provider, so custody exists the way production creates it.
func seedGrantViaLink(t *testing.T, b *grants.Broker, persona string) {
	t.Helper()
	_, linkID, err := b.LinkStart(persona, "dex")
	if err != nil {
		t.Fatalf("link start: %v", err)
	}
	if err := b.LinkComplete(context.Background(), persona, linkID, "any"); err != nil {
		t.Fatalf("link complete: %v", err)
	}
}

// TestGrantsOwnAccess: the persona in every grants op is the subject-token
// user — respond() has no other input for it, which IS the design (D30):
// the op layer cannot be talked into another persona's grant.
func TestGrantsOwnAccess(t *testing.T) {
	s, _, accPub, broker := grantsHarness(t)
	seedGrantViaLink(t, broker, "alice")

	var access grantAccessResponse
	if err := call(t, s, accPub, "alice", "grants.access", grantAccessRequest{Resource: "dex"}, &access); err != nil {
		t.Fatalf("own access: %v", err)
	}
	if access.AccessToken == "" {
		t.Fatal("empty access token")
	}

	// bob's own subject reaches only bob's (absent) grant.
	err := call(t, s, accPub, "bob", "grants.access", grantAccessRequest{Resource: "dex"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no grant") {
		t.Fatalf("bob's access: want grant-not-found, got %v", err)
	}

	var list grantsListResponse
	if err := call(t, s, accPub, "alice", "grants.list", struct{}{}, &list); err != nil || len(list.Grants) != 1 {
		t.Fatalf("alice list: %v %+v", err, list)
	}
	var bobList grantsListResponse
	if err := call(t, s, accPub, "bob", "grants.list", struct{}{}, &bobList); err != nil || len(bobList.Grants) != 0 {
		t.Fatalf("bob list: %v %+v", err, bobList)
	}

	if err := call(t, s, accPub, "alice", "grants.revoke", grantRevokeRequest{Resource: "dex"}, nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := call(t, s, accPub, "alice", "grants.access", grantAccessRequest{Resource: "dex"}, nil); err == nil {
		t.Fatal("access after revoke served")
	}
}

// TestGrantsOnBehalf: the delegation is signed with the subject's REAL
// persona key — materialized in the vault by first touch, resolved through
// the directory — and the actor is the subject-token user of the calling
// subject, so a stolen delegation refuses.
func TestGrantsOnBehalf(t *testing.T) {
	s, v, accPub, broker := grantsHarness(t)
	seedGrantViaLink(t, broker, "daan")

	// daan's persona key materializes (D26) and signs the delegation — in
	// production this is one sign.record call by daan's own client.
	if _, err := v.GeneratePersonaKey(PersonaKeyPrefix+"daan", accPub, "daan"); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(grants.Delegation{
		Subject: "daan", Actor: "agent-scribe", Resources: []string{"dex"},
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := v.SignRecord(PersonaKeyPrefix+"daan", payload)
	if err != nil {
		t.Fatal(err)
	}
	req := grantAccessRequest{
		Resource: "dex", OnBehalfOf: "daan",
		DelegationPayload: base64.StdEncoding.EncodeToString(payload),
		DelegationSig:     sig,
	}

	// The actor's own subject: allowed.
	var access grantAccessResponse
	if err := call(t, s, accPub, "agent-scribe", "grants.access", req, &access); err != nil || access.AccessToken == "" {
		t.Fatalf("delegated access: %v", err)
	}

	// Any other subject-token user presenting the same delegation: the
	// caller is server-proven, the delegation names agent-scribe — refused.
	err = call(t, s, accPub, "mallory", "grants.access", req, nil)
	if err == nil || !strings.Contains(err.Error(), "actor") {
		t.Fatalf("stolen delegation: want actor mismatch, got %v", err)
	}

	// A subject with no persona key cannot be impersonated: a delegation
	// naming it — however validly signed — has no verification path in the
	// directory, never a fallback.
	ghostPayload, err := json.Marshal(grants.Delegation{
		Subject: "ghost", Actor: "agent-scribe", Resources: []string{"dex"},
		IssuedAt:  time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	ghostSig, err := v.SignRecord(PersonaKeyPrefix+"daan", ghostPayload)
	if err != nil {
		t.Fatal(err)
	}
	noKey := grantAccessRequest{
		Resource: "dex", OnBehalfOf: "ghost",
		DelegationPayload: base64.StdEncoding.EncodeToString(ghostPayload),
		DelegationSig:     ghostSig,
	}
	err = call(t, s, accPub, "agent-scribe", "grants.access", noKey, nil)
	if err == nil || !strings.Contains(err.Error(), "persona key") {
		t.Fatalf("ghost subject: want no-persona-key refusal, got %v", err)
	}
}

// TestGrantsRefuseUnconfigured: a service without WithGrants refuses the
// family by name.
func TestGrantsRefuseUnconfigured(t *testing.T) {
	s, _, accPub := harness(t)
	err := call(t, s, accPub, "alice", "grants.access", grantAccessRequest{Resource: "dex"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no grant resources") {
		t.Fatalf("want unconfigured refusal, got %v", err)
	}
}

func (staticProvider) ExchangeToken(_ context.Context, _ grants.Resource, st string) (grants.TokenSet, error) {
	return grants.TokenSet{AccessToken: "xt-for-" + st}, nil
}
