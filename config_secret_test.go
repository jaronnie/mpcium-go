package mpcium_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"

	client "github.com/jaronnie/mpcium-go"
	"github.com/jaronnie/mpcium-go/configsecret"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/require"
)

type secretTestSigner struct{ key ed25519.PrivateKey }

func (s secretTestSigner) Sign(b []byte) ([]byte, error) { return ed25519.Sign(s.key, b), nil }
func (s secretTestSigner) PublicKey() (string, error) {
	return hex.EncodeToString(s.key.Public().(ed25519.PublicKey)), nil
}
func (s secretTestSigner) Algorithm() types.EventInitiatorKeyType {
	return types.EventInitiatorKeyTypeEd25519
}
func TestSecretClientPinsPublicPolicyAndProject(t *testing.T) {
	nodes := []configsecret.Node{}
	for _, id := range []string{"n0", "n1", "n2"} {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		nodes = append(nodes, configsecret.Node{ID: id, IdentityKey: pub})
	}
	m, _, err := configsecret.Generate("rebate", "database", 1, 2, nodes)
	require.NoError(t, err)
	// Invalid-name preflight must fail before any use of this disconnected NATS connection.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	opts := client.Options{ProjectID: "collection", NatsConn: &nats.Conn{}, Signer: secretTestSigner{key}}
	_, err = client.NewSecretClient(opts, m)
	require.Error(t, err)
	opts.ProjectID = "rebate"
	sdk, err := client.NewSecretClient(opts, m)
	require.NoError(t, err)
	e, err := sdk.Encrypt("database-password", []byte("temporary-test-value"))
	require.NoError(t, err)
	m.Nodes[0].IdentityKey[0] ^= 1
	m.Commitments[0][0] ^= 1
	_, err = sdk.Decrypt(context.Background(), "different-name", e)
	require.ErrorContains(t, err, "unexpected config secret name")
}
