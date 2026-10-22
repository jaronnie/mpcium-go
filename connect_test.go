package mpcium

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/jaronnie/mpcium-go/types"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectRejectsScopeAndTransportBeforeDial(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	signer := &LocalSigner{keyType: types.EventInitiatorKeyTypeEd25519, ed25519Key: key}
	require.NoError(t, err)
	credentials := &Credentials{ProjectID: "project-a", Initiator: signer}
	_, err = Connect(context.Background(), "tls://example.com:4222", "token", "project-b", credentials)
	require.ErrorContains(t, err, "project ID")
	_, err = Connect(context.Background(), "nats://example.com:4222", "token", "project-a", credentials)
	require.ErrorContains(t, err, "TLS")
	_, err = Connect(context.Background(), "tls://example.com:4222", "", "project-a", credentials)
	require.ErrorContains(t, err, "token")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Connect(ctx, "tls://example.com:4222", "token", "project-a", credentials)
	require.ErrorIs(t, err, context.Canceled)
}
