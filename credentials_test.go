package mpcium

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"filippo.io/age"
	"fmt"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialsBundle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	node1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	node2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bundle := CredentialsBundle{Version: CredentialsVersion, ProjectID: "project-a", NodePublicKeys: map[string]ed25519.PublicKey{"node1": node1, "node2": node2}, InitiatorAlgorithm: types.EventInitiatorKeyTypeEd25519, InitiatorKey: []byte(hex.EncodeToString(priv.Seed()))}
	path := filepath.Join(t.TempDir(), "credentials.age")
	require.NoError(t, EncryptCredentials(path, "test-only-password", bundle))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	creds, err := UnlockCredentials(path, "test-only-password")
	require.NoError(t, err)
	require.Equal(t, bundle.ProjectID, creds.ProjectID)
	require.Equal(t, bundle.NodePublicKeys, creds.NodePublicKeys)
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

func TestCredentialsRejectOldFormatsAndMissingTrust(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	first, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	second, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	valid := CredentialsBundle{Version: CredentialsVersion, ProjectID: "project-a", NodePublicKeys: map[string]ed25519.PublicKey{"n1": first, "n2": second}, InitiatorAlgorithm: types.EventInitiatorKeyTypeEd25519, InitiatorKey: []byte(hex.EncodeToString(private.Seed()))}
	for _, version := range []int{0, 1, 2, 3, 5} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			bundle := valid
			bundle.Version = version
			raw, err := json.Marshal(bundle)
			require.NoError(t, err)
			recipient, err := age.NewScryptRecipient("test-password")
			require.NoError(t, err)
			recipient.SetWorkFactor(1)
			var ciphertext bytes.Buffer
			writer, err := age.Encrypt(&ciphertext, recipient)
			require.NoError(t, err)
			_, err = writer.Write(raw)
			require.NoError(t, err)
			require.NoError(t, writer.Close())
			_, err = UnlockCredentialsBytes(ciphertext.Bytes(), "test-password")
			require.ErrorContains(t, err, "only V4")
			_, err = EncryptCredentialsBytes("test-password", bundle)
			require.ErrorContains(t, err, "only V4")
		})
	}
	valid.NodePublicKeys = nil
	_, err = credentialsFromBundle(valid)
	require.ErrorContains(t, err, "trusted nodes")
	valid.ProjectID = ""
	_, err = credentialsFromBundle(valid)
	require.ErrorContains(t, err, "project ID")
}
