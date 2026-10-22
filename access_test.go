package mpcium

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAccessRejectsIncompleteConnection(t *testing.T) {
	for _, address := range []string{"nats://localhost:4222", "tls://user:pass@localhost:4222", "tls://"} {
		if _, err := ConnectAccess(context.Background(), address, "token", &Credentials{}); err == nil {
			t.Fatal("invalid connection accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ConnectAccess(ctx, "tls://localhost:4222", "token", nil); err == nil {
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
