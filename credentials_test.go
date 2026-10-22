package mpcium

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialsBundle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bundle := CredentialsBundle{Version: 1, NATSToken: "test-only-token", InitiatorAlgorithm: types.EventInitiatorKeyTypeEd25519, InitiatorKey: []byte(hex.EncodeToString(priv.Seed()))}
	path := filepath.Join(t.TempDir(), "credentials.age")
	require.NoError(t, EncryptCredentials(path, "test-only-password", bundle))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	creds, err := UnlockCredentials(path, "test-only-password")
	require.NoError(t, err)
	require.Equal(t, bundle.NATSToken, creds.NATSToken)
	sig, err := creds.Initiator.Sign([]byte("test"))
	require.NoError(t, err)
	require.True(t, ed25519.Verify(pub, []byte("test"), sig))
	creds.Close()
	require.Nil(t, creds.Initiator)
	_, err = UnlockCredentials(path, "wrong-password")
	require.Error(t, err)
	require.Error(t, EncryptCredentials(path, "test-only-password", bundle))
	bundle.InitiatorKey = []byte("00")
	require.Error(t, EncryptCredentials(filepath.Join(t.TempDir(), "invalid.age"), "test-only-password", bundle))
}
