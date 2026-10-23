package mpcium

import (
	"bytes"
	"crypto/ed25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStandardSolanaKeypairLocalSigning(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	defer clear(private)
	message := []byte("offline transaction message, no broadcast")
	signature, e := SignSolanaKeypair(private, message)
	require.NoError(t, e)
	require.True(t, ed25519.Verify(ed25519.PublicKey(private[32:]), message, signature))
	private[63] ^= 1
	_, e = SignSolanaKeypair(private, message)
	require.Error(t, e)
	_, e = SignSolanaKeypair(private[:32], message)
	require.Error(t, e)
}
