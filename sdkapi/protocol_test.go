package sdkapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSignedEncryptedReplies(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	recipient, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	r := Request{Domain: Domain, ProjectID: "p", ResourceID: "data", RequestID: "request1", Operation: "decrypt-stored", Recipient: recipient.Recipient().String(), Reply: "_INBOX.test", ExpiresAt: time.Now().Add(30 * time.Second).Unix()}
	require.NoError(t, r.Validate(time.Now()))
	encrypted, err := Encrypt(r.Recipient, Result{Error: "test-sensitive-result"})
	require.NoError(t, err)
	require.False(t, bytes.Contains(encrypted, []byte("test-sensitive-result")))
	response := Response{Domain: Domain, NodeID: "node1", Digest: r.Digest(), Ciphertext: encrypted}
	response.Signature = ed25519.Sign(key, response.Raw())
	require.True(t, response.Verify("node1", pub, r.Digest()))
	result, err := Decrypt(recipient, encrypted)
	require.NoError(t, err)
	require.Equal(t, "test-sensitive-result", result.Error)
	other, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	_, err = Decrypt(other, encrypted)
	require.Error(t, err)
	response.Digest = "replayed"
	require.False(t, response.Verify("node1", pub, r.Digest()))
	original := r.Digest()
	r.ResourceID = "other"
	require.NotEqual(t, original, r.Digest())
	r.ExpiresAt = time.Now().Add(-time.Second).Unix()
	require.Error(t, r.Validate(time.Now()))
	r.ExpiresAt = time.Now().Add(time.Hour).Unix()
	require.Error(t, r.Validate(time.Now()))
}
