package service

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"

	"github.com/impire-io/soulstream-identity/internal/sealedstore"
	"github.com/impire-io/soulstream-identity/internal/secrets"
	"github.com/impire-io/soulstream-identity/internal/vault"
)

func b64(v []byte) string { return base64.StdEncoding.EncodeToString(v) }

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func secretsHarness(t *testing.T) (*Service, string) {
	t.Helper()
	firstKP, _ := nkeys.CreateCurveKeys()
	firstSeed, _ := firstKP.Seed()
	v, err := vault.New(vault.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatal(err)
	}
	store, err := secrets.New(sealedstore.NewMemStore(), string(firstSeed))
	if err != nil {
		t.Fatal(err)
	}
	surfaceKP, _ := nkeys.CreateCurveKeys()
	surfaceSeed, _ := surfaceKP.Seed()
	s, err := New(v, string(surfaceSeed), nil, WithSecrets(store))
	if err != nil {
		t.Fatal(err)
	}
	accKP, _ := nkeys.CreateAccount()
	accPub, _ := accKP.PublicKey()
	return s, accPub
}

// TestSecretsOwnTree: the persona in every op is the subject-token user
// — respond() has no other input for it (D36 mirrors D30): the op layer
// cannot be talked into another persona's tree.
func TestSecretsOwnTree(t *testing.T) {
	s, accPub := secretsHarness(t)

	var put secretPutResponse
	if err := call(t, s, accPub, "alice", "secrets.put",
		secretPutRequest{Path: "api/token", Value: b64([]byte("hunter2"))}, &put); err != nil {
		t.Fatalf("put: %v", err)
	}
	var got secretGetResponse
	if err := call(t, s, accPub, "alice", "secrets.get", secretGetRequest{Path: "api/token"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !bytes.Equal(unb64(t, got.Value), []byte("hunter2")) || got.Rev != put.Rev {
		t.Fatalf("round trip: %+v", got)
	}

	// bob's tree is a different tree, same path.
	err := call(t, s, accPub, "bob", "secrets.get", secretGetRequest{Path: "api/token"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no such secret") {
		t.Fatalf("bob's get: want not-found, got %v", err)
	}
	var bobList secretsListResponse
	if err := call(t, s, accPub, "bob", "secrets.list", struct{}{}, &bobList); err != nil || len(bobList.Paths) != 0 {
		t.Fatalf("bob's list: %v %+v", err, bobList)
	}

	// The conditional write (D2): stale rev loses loudly.
	if err := call(t, s, accPub, "alice", "secrets.put",
		secretPutRequest{Path: "api/token", Value: b64([]byte("stale")), ExpectedRev: put.Rev - 1 + 1000}, nil); err == nil {
		t.Fatal("stale conditional write served")
	}
	if err := call(t, s, accPub, "alice", "secrets.delete", secretDeleteRequest{Path: "api/token"}, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := call(t, s, accPub, "alice", "secrets.get", secretGetRequest{Path: "api/token"}, nil); err == nil {
		t.Fatal("get after delete served")
	}
}
