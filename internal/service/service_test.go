package service

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulidentity/internal/callout"
	"github.com/impire-io/soulidentity/internal/vault"
)

// harness: a service over a MemStore vault. There is no admin fixture and no
// registry: which principals reach which ops is the server's permission
// enforcement (D25), outside respond()'s world — these tests drive the ops
// directly and prove the data-dependent policy, the bindings.
func harness(t *testing.T) (*Service, *vault.Vault, string) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()
	s, err := New(v, string(surfaceSeed), nil)
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return s, v, accPub
}

// call drives one sealed round-trip through respond, exactly as a client
// would: ephemeral curve key, sealed request, opened reply.
func call(t *testing.T, s *Service, account, user, op string, body, out any) error {
	t.Helper()
	var x xkeyResponse
	if err := json.Unmarshal(s.respond(Segment+".xkey", nil), &x); err != nil {
		t.Fatalf("xkey discovery: %v", err)
	}
	eph, _ := nkeys.CreateCurveKeys()
	ephPub, _ := eph.PublicKey()
	plain, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode body: %v", err)
	}
	sealed, err := eph.Seal(plain, x.XKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	req := marshal(envelope{XKey: ephPub, Data: sealed})
	reply := s.respond(strings.Join([]string{Segment, account, user, op}, "."), req)

	var env envelope
	if err := json.Unmarshal(reply, &env); err != nil || len(env.Data) == 0 {
		// Not an envelope: a plaintext refusal.
		var er errorResponse
		if jerr := json.Unmarshal(reply, &er); jerr == nil && er.Error != "" {
			return &wireError{er.Error}
		}
		t.Fatalf("reply is neither envelope nor error: %s", reply)
	}
	opened, err := eph.Open(env.Data, x.XKey)
	if err != nil {
		t.Fatalf("open reply: %v", err)
	}
	var er errorResponse
	if json.Unmarshal(opened, &er) == nil && er.Error != "" {
		return &wireError{er.Error}
	}
	if out != nil {
		if err := json.Unmarshal(opened, out); err != nil {
			t.Fatalf("decode reply: %v", err)
		}
	}
	return nil
}

type wireError struct{ msg string }

func (e *wireError) Error() string { return e.msg }

func TestOpenOpsArePlaintext(t *testing.T) {
	s, _, _ := harness(t)
	var st statusResponse
	if err := json.Unmarshal(s.respond(Segment+".status", nil), &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	var x xkeyResponse
	if err := json.Unmarshal(s.respond(Segment+".xkey", nil), &x); err != nil {
		t.Fatalf("xkey: %v", err)
	}
	if !strings.HasPrefix(x.XKey, "X") {
		t.Fatalf("xkey %q is not a curve public key", x.XKey)
	}
}

func TestKeyManagementRoundTrip(t *testing.T) {
	s, _, acc := harness(t)
	ukp, _ := nkeys.CreateUser()
	seed, _ := ukp.Seed()

	var entry vault.Entry
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "imported", Kind: string(vault.KindNATSUserKey), Secret: string(seed),
	}, &entry); err != nil {
		t.Fatalf("import: %v", err)
	}
	var keys keysResponse
	if err := call(t, s, acc, "ops", "keys.list", struct{}{}, &keys); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].Name != "imported" {
		t.Fatalf("list: %+v", keys.Keys)
	}
	// The import surface enforces the binding rules end to end.
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "persona/unbound", Kind: string(vault.KindPersonaSigningKey),
		Secret: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)),
	}, nil); err == nil {
		t.Fatal("a persona key without its owner binding must refuse")
	}
}

func TestOwnerBindingGatesSigning(t *testing.T) {
	s, _, acc := harness(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	personaSeed := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "persona/daan", Kind: string(vault.KindPersonaSigningKey),
		Secret: personaSeed, Account: acc, User: "daan",
	}, nil); err != nil {
		t.Fatalf("import persona key: %v", err)
	}

	canonical := base64.StdEncoding.EncodeToString([]byte("canonical-bytes"))
	var sig signRecordResponse
	if err := call(t, s, acc, "daan", "sign.record",
		signRecordRequest{Key: "persona/daan", Canonical: canonical}, &sig); err != nil {
		t.Fatalf("owner signing refused: %v", err)
	}
	if sig.Sig == "" {
		t.Fatal("empty signature")
	}
	if sig.PublicKey == "" {
		t.Fatal("sign.record did not return the persona public key")
	}

	// THE gate (D6 as amended): mallory does not own the key.
	if err := call(t, s, acc, "mallory", "sign.record",
		signRecordRequest{Key: "persona/daan", Canonical: canonical}, nil); err == nil ||
		!strings.Contains(err.Error(), "no persona key") {
		t.Fatalf("non-owner signing must refuse, got %v", err)
	}
	// A missing key refuses with the same wording — the refusal is not a
	// vault probe.
	missErr := call(t, s, acc, "mallory", "sign.record",
		signRecordRequest{Key: "persona/ghost", Canonical: canonical}, nil)
	if missErr == nil || !strings.Contains(missErr.Error(), "no persona key") {
		t.Fatalf("missing key must refuse identically, got %v", missErr)
	}
	// Keys outside the persona/ convention cannot sign records at all.
	if err := call(t, s, acc, "daan", "sign.record",
		signRecordRequest{Key: "imported", Canonical: canonical}, nil); err == nil {
		t.Fatal("non-persona key name accepted for record signing")
	}

	// keys.public is the directory read (D26): ANY authenticated caller
	// resolves any persona's public form — that is how readers build
	// verification keyrings without a profile store.
	var pub vault.Entry
	if err := call(t, s, acc, "daan", "keys.public",
		keyPublicRequest{Key: "persona/daan"}, &pub); err != nil {
		t.Fatalf("owner keys.public refused: %v", err)
	}
	if pub.PublicKey != sig.PublicKey {
		t.Fatalf("keys.public %q != sign.record public key %q", pub.PublicKey, sig.PublicKey)
	}
	var reader vault.Entry
	if err := call(t, s, acc, "mallory", "keys.public",
		keyPublicRequest{Key: "persona/daan"}, &reader); err != nil {
		t.Fatalf("a reader must resolve another persona's public key (D26): %v", err)
	}
	if reader.PublicKey != pub.PublicKey || reader.Account != acc || reader.User != "daan" {
		t.Fatalf("directory read: %+v", reader)
	}
	// A non-persona key is not in the directory.
	if err := call(t, s, acc, "mallory", "keys.public",
		keyPublicRequest{Key: "imported"}, nil); err == nil {
		t.Fatal("a non-persona key answered the directory read")
	}
}

func TestPersonaKeyMaterializesOnFirstUse(t *testing.T) {
	s, _, acc := harness(t)
	canonical := base64.StdEncoding.EncodeToString([]byte("first-ever-bytes"))

	// No import, no provisioning act of any kind: mallory signs with her
	// own persona name and the key materializes in the vault, owner-bound
	// to the server-proven principal (D26).
	var sig signRecordResponse
	if err := call(t, s, acc, "mallory", "sign.record",
		signRecordRequest{Key: "persona/mallory", Canonical: canonical}, &sig); err != nil {
		t.Fatalf("first-use signing refused: %v", err)
	}
	if sig.Sig == "" || sig.PublicKey == "" {
		t.Fatalf("materialized signing: %+v", sig)
	}
	// The key is stable: a second touch signs with the same key.
	var again signRecordResponse
	if err := call(t, s, acc, "mallory", "sign.record",
		signRecordRequest{Key: "persona/mallory", Canonical: canonical}, &again); err != nil {
		t.Fatalf("second signing refused: %v", err)
	}
	if again.PublicKey != sig.PublicKey {
		t.Fatalf("persona key changed across touches: %q != %q", again.PublicKey, sig.PublicKey)
	}
	// keys.public materializes too — a signer can exist before anything
	// was signed.
	var fresh vault.Entry
	if err := call(t, s, acc, "daan", "keys.public",
		keyPublicRequest{Key: "persona/daan"}, &fresh); err != nil {
		t.Fatalf("keys.public first touch refused: %v", err)
	}
	if fresh.PublicKey == "" || fresh.User != "daan" {
		t.Fatalf("materialized on read: %+v", fresh)
	}
	// The cross-account collision cost, first owner wins: a daan in
	// ANOTHER account cannot sign with (or take) the existing name.
	acc2KP, _ := nkeys.CreateAccount()
	acc2, _ := acc2KP.PublicKey()
	if err := call(t, s, acc2, "mallory", "sign.record",
		signRecordRequest{Key: "persona/mallory", Canonical: canonical}, nil); err == nil ||
		!strings.Contains(err.Error(), "no persona key") {
		t.Fatalf("a second account's claimant must refuse, got %v", err)
	}
}

func TestMintResolvesByBinding(t *testing.T) {
	s, _, acc := harness(t)
	askKP, _ := nkeys.CreateAccount()
	askSeed, _ := askKP.Seed()
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "acme", Kind: string(vault.KindNATSAccountSigningKey), Secret: string(askSeed), Account: acc,
	}, nil); err != nil {
		t.Fatalf("import signing key: %v", err)
	}

	var res mintResponse
	if err := call(t, s, acc, "ops", "mint",
		mintRequest{Account: acc, User: "daan"}, &res); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := jwt.DecodeUserClaims(res.JWT); err != nil {
		t.Fatalf("minted JWT does not decode: %v", err)
	}

	// An account with no bound team refuses — the binding is the only
	// authorize source (D25).
	strayKP, _ := nkeys.CreateAccount()
	strayPub, _ := strayKP.PublicKey()
	if err := call(t, s, acc, "ops", "mint",
		mintRequest{Account: strayPub, User: "daan"}, nil); err == nil {
		t.Fatal("minted for an account with no bound team")
	}

	var withCreds mintResponse
	if err := call(t, s, acc, "ops", "mint",
		mintRequest{Account: acc, User: "daan", ExportCreds: true}, &withCreds); err != nil {
		t.Fatalf("mint with creds escape: %v", err)
	}
	if !strings.Contains(withCreds.Creds, "-----BEGIN USER NKEY SEED-----") {
		t.Fatal("creds escape did not render a creds file")
	}
}

func TestMintEphemeralSelectsTeamByName(t *testing.T) {
	s, _, acc := harness(t)
	askKP, _ := nkeys.CreateAccount()
	askSeed, _ := askKP.Seed()
	var team vault.Entry
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "soulrealm-agent", Kind: string(vault.KindNATSAccountSigningKey), Secret: string(askSeed), Account: acc,
	}, &team); err != nil {
		t.Fatalf("import signing key: %v", err)
	}
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()

	var res mintEphemeralResponse
	if err := call(t, s, acc, "ops", "mint.ephemeral", mintEphemeralRequest{
		Team: "soulrealm-agent", User: "prober", UserPublicKey: upub,
		TTLSeconds: 60, Tags: []string{"topic:planning-x7", "persona:prober"},
	}, &res); err != nil {
		t.Fatalf("mint.ephemeral: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(res.JWT)
	if err != nil {
		t.Fatalf("ephemeral JWT does not decode: %v", err)
	}
	if uc.Subject != upub {
		t.Fatalf("subject %q is not the caller's key %q", uc.Subject, upub)
	}
	if uc.Issuer != team.PublicKey || uc.IssuerAccount != acc {
		t.Fatalf("issuer chain wrong: %q / %q", uc.Issuer, uc.IssuerAccount)
	}
	if !uc.HasEmptyPermissions() {
		t.Fatal("ephemeral JWT carries its own permissions — the scope must be the whole policy")
	}
	if uc.Expires == 0 {
		t.Fatal("ephemeral JWT carries no expiry")
	}
	if !uc.Tags.Contains("topic:planning-x7") || !uc.Tags.Contains("persona:prober") {
		t.Fatalf("tags missing from claims: %v", uc.Tags)
	}

	// The response is the JWT alone — no key material rides back (D28,
	// constitution I): the wire struct has no other field to leak into.

	// A mint without its user refuses: attribution is the surface's promise.
	if err := call(t, s, acc, "ops", "mint.ephemeral", mintEphemeralRequest{
		Team: "soulrealm-agent", UserPublicKey: upub, TTLSeconds: 60,
	}, nil); err == nil || !strings.Contains(err.Error(), "names its user") {
		t.Fatalf("user-less mint must refuse, got %v", err)
	}
	if err := call(t, s, acc, "ops", "mint.ephemeral", mintEphemeralRequest{
		Team: "nobody", User: "prober", UserPublicKey: upub, TTLSeconds: 60,
	}, nil); err == nil {
		t.Fatal("unknown team accepted")
	}
	if err := call(t, s, acc, "ops", "mint.ephemeral", mintEphemeralRequest{
		Team: "soulrealm-agent", User: "prober", UserPublicKey: upub,
	}, nil); err == nil {
		t.Fatal("zero ttl accepted — an unbounded ephemeral credential")
	}

	// The D28 collision, driven through the ops: a second team on the same
	// account makes the binding-resolved durable mint refuse as ambiguous,
	// while by-name ephemeral minting reaches both roles.
	ask2KP, _ := nkeys.CreateAccount()
	ask2Seed, _ := ask2KP.Seed()
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "soulrealm-tool", Kind: string(vault.KindNATSAccountSigningKey), Secret: string(ask2Seed), Account: acc,
	}, nil); err != nil {
		t.Fatalf("import second team: %v", err)
	}
	if err := call(t, s, acc, "ops", "mint",
		mintRequest{Account: acc, User: "daan"}, nil); err == nil ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("binding path must refuse a multi-team account as ambiguous, got %v", err)
	}
	if err := call(t, s, acc, "ops", "mint.ephemeral", mintEphemeralRequest{
		Team: "soulrealm-tool", User: "prober", UserPublicKey: upub, TTLSeconds: 60,
	}, &res); err != nil {
		t.Fatalf("mint.ephemeral for the second role: %v", err)
	}
}

func TestTokenAndSentinelOps(t *testing.T) {
	s, _, acc := harness(t)
	// Without callout configuration the ops refuse.
	if err := call(t, s, acc, "ops", "tokens.list", struct{}{}, nil); err == nil ||
		!strings.Contains(err.Error(), "callout") {
		t.Fatalf("token op without callout config: %v", err)
	}

	authAccKP, _ := nkeys.CreateAccount()
	authAccPub, _ := authAccKP.PublicKey()
	authKP, _ := nkeys.CreateAccount()
	authSeed, _ := authKP.Seed()
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "auth/issuer", Kind: string(vault.KindNATSAccountSigningKey), Secret: string(authSeed), Account: authAccPub,
	}, nil); err != nil {
		t.Fatalf("import auth key: %v", err)
	}
	store := callout.NewMemTokenStore()
	WithCallout(store, "auth/issuer", authAccPub)(s)

	// Issuance refuses an account no team is bound to (fail at issuance,
	// not at callout), then works once the team is declared.
	strayKP, _ := nkeys.CreateAccount()
	strayPub, _ := strayKP.PublicKey()
	if err := call(t, s, acc, "ops", "tokens.create",
		tokenCreateRequest{Account: strayPub, User: "daan"}, nil); err == nil {
		t.Fatal("token created for an account with no bound team")
	}
	askKP, _ := nkeys.CreateAccount()
	askSeed, _ := askKP.Seed()
	if err := call(t, s, acc, "ops", "keys.import", importKeyRequest{
		Name: "acme", Kind: string(vault.KindNATSAccountSigningKey), Secret: string(askSeed), Account: acc,
	}, nil); err != nil {
		t.Fatalf("import team key: %v", err)
	}
	if err := call(t, s, acc, "ops", "tokens.create",
		tokenCreateRequest{Account: acc, User: ""}, nil); err == nil {
		t.Fatal("token created without a user")
	}
	var created tokenCreateResponse
	if err := call(t, s, acc, "ops", "tokens.create",
		tokenCreateRequest{Account: acc, User: "daan", Label: "laptop"}, &created); err != nil {
		t.Fatalf("tokens.create: %v", err)
	}
	if !strings.HasPrefix(created.Token, callout.TokenPrefix) || created.Digest == "" {
		t.Fatalf("issuance shape: %+v", created)
	}
	if callout.Digest(created.Token) != created.Digest {
		t.Fatal("returned digest does not match the token")
	}
	if _, ok, _ := store.Get(created.Digest); !ok {
		t.Fatal("record not stored")
	}

	var listed tokensResponse
	if err := call(t, s, acc, "ops", "tokens.list", struct{}{}, &listed); err != nil {
		t.Fatalf("tokens.list: %v", err)
	}
	if len(listed.Tokens) != 1 || listed.Tokens[0].Label != "laptop" {
		t.Fatalf("list: %+v", listed.Tokens)
	}
	for _, e := range listed.Tokens {
		if strings.Contains(e.Digest, callout.TokenPrefix) {
			t.Fatal("a plaintext token leaked into the listing")
		}
	}

	if err := call(t, s, acc, "ops", "tokens.revoke",
		tokenRevokeRequest{Digest: created.Digest}, nil); err != nil {
		t.Fatalf("tokens.revoke: %v", err)
	}
	if _, ok, _ := store.Get(created.Digest); ok {
		t.Fatal("record survived revocation")
	}

	// The sentinel: bearer, deny-all, signed by the AUTH key, creds included.
	var sentinel sentinelResponse
	if err := call(t, s, acc, "ops", "sentinel.mint", struct{}{}, &sentinel); err != nil {
		t.Fatalf("sentinel.mint: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(sentinel.JWT)
	if err != nil {
		t.Fatalf("sentinel does not decode: %v", err)
	}
	authPub, _ := authKP.PublicKey()
	if !uc.BearerToken || uc.Issuer != authPub {
		t.Fatalf("sentinel shape: bearer=%v issuer=%q", uc.BearerToken, uc.Issuer)
	}
	if len(uc.Pub.Deny) == 0 || len(uc.Sub.Deny) == 0 {
		t.Fatal("sentinel is not deny-all")
	}
	if !strings.Contains(sentinel.Creds, "-----BEGIN NATS USER JWT-----") {
		t.Fatal("sentinel creds not rendered")
	}
}

func TestPrefixedSubjectSpace(t *testing.T) {
	s, v, acc := harness(t)
	WithPrefix("prod.soulstream")(s)
	if s.Root() != "prod.soulstream."+Segment {
		t.Fatalf("root: %q", s.Root())
	}

	// Open ops answer under the prefixed root and nowhere else.
	var st statusResponse
	if err := json.Unmarshal(s.respond(s.Root()+".status", nil), &st); err != nil {
		t.Fatalf("prefixed status: %v", err)
	}
	var er errorResponse
	if err := json.Unmarshal(s.respond(Segment+".status", nil), &er); err != nil || er.Error == "" {
		t.Fatal("bare-root subject answered on a prefixed service")
	}

	// A sealed principal op works under the prefixed root: drive respond the
	// way call() does, but against the prefixed subject.
	ukp, _ := nkeys.CreateUser()
	seed, _ := ukp.Seed()
	if _, err := v.Import("imported", vault.KindNATSUserKey, string(seed), "", ""); err != nil {
		t.Fatalf("import: %v", err)
	}
	var x xkeyResponse
	if err := json.Unmarshal(s.respond(s.Root()+".xkey", nil), &x); err != nil {
		t.Fatalf("xkey: %v", err)
	}
	eph, _ := nkeys.CreateCurveKeys()
	ephPub, _ := eph.PublicKey()
	plain, _ := json.Marshal(struct{}{})
	sealedBody, err := eph.Seal(plain, x.XKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	req := marshal(envelope{XKey: ephPub, Data: sealedBody})
	reply := s.respond(s.Root()+"."+acc+".ops.keys.list", req)
	var env envelope
	if err := json.Unmarshal(reply, &env); err != nil || len(env.Data) == 0 {
		t.Fatalf("prefixed principal op did not answer an envelope: %s", reply)
	}
	opened, err := eph.Open(env.Data, x.XKey)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var keys keysResponse
	if err := json.Unmarshal(opened, &keys); err != nil || len(keys.Keys) == 0 {
		t.Fatalf("prefixed op result: %s", opened)
	}
}

func TestValidatePrefix(t *testing.T) {
	for _, good := range []string{"", "prod", "prod.soulstream", "a-b_c.d1"} {
		if err := ValidatePrefix(good); err != nil {
			t.Fatalf("legal prefix %q refused: %v", good, err)
		}
	}
	for _, bad := range []string{".", "a..b", "a.*", "a.>", "$SYS", "sp ace", "a."} {
		if err := ValidatePrefix(bad); err == nil {
			t.Fatalf("prefix %q must be refused", bad)
		}
	}
}

func TestMalformedRequestsRefusePlaintext(t *testing.T) {
	s, _, acc := harness(t)
	reply := s.respond(strings.Join([]string{Segment, acc, "daan", "mint"}, "."), []byte("not-json"))
	var er errorResponse
	if err := json.Unmarshal(reply, &er); err != nil || er.Error == "" {
		t.Fatalf("malformed request must draw a plaintext error, got %s", reply)
	}
	if err := call(t, s, acc, "daan", "no.such.op", struct{}{}, nil); err == nil ||
		!strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("unknown op: %v", err)
	}
	var er2 errorResponse
	if err := json.Unmarshal(s.respond(Segment+".nope", nil), &er2); err != nil || er2.Error == "" {
		t.Fatal("unknown open subject must draw an error")
	}
}
