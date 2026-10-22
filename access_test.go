package mpcium

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/jaronnie/mpcium-go/types"
	"strings"
	"testing"
)

func TestAccessRejectsIncompleteConnection(t *testing.T) {
	for _, address := range []string{"nats://localhost:4222", "tls://user:pass@localhost:4222", "tls://"} {
		if _, err := ConnectAccess(context.Background(), address, &Credentials{}); err == nil {
			t.Fatal("invalid connection accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ConnectAccess(ctx, "tls://localhost:4222", nil); err == nil {
		t.Fatal("cancelled connection accepted")
	}
}
func TestAccessResponseValidation(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{"access_error":"denied"}`), []byte(`{}`), []byte(`invalid`), []byte(strings.Repeat("x", 256*1024+1))} {
		if _, err := unwrapAccess(b); err == nil {
			t.Fatal("invalid access response accepted")
		}
	}
	b, _ := json.Marshal(struct {
		Data []byte `json:"data"`
	}{[]byte("authenticated-node-response")})
	data, err := unwrapAccess(b)
	if err != nil || string(data) != "authenticated-node-response" {
		t.Fatal("valid response rejected")
	}
}

func TestAccessRequiresEmbeddedToken(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentials := &Credentials{ProjectID: "project-a", Initiator: &LocalSigner{keyType: types.EventInitiatorKeyTypeEd25519, ed25519Key: key}}
	if _, err := ConnectAccess(context.Background(), "nats://localhost:4222", credentials); err == nil || !strings.Contains(err.Error(), "embedded access token") {
		t.Fatalf("missing token must fail before dial: %v", err)
	}
	credentials.AccessToken = "embedded-token"
	if _, err := ConnectAccess(context.Background(), "nats://localhost:4222", credentials); err == nil || !strings.Contains(err.Error(), "TLS NATS URL") {
		t.Fatalf("embedded token should pass credential validation: %v", err)
	}
}
