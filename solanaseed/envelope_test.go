package solanaseed

import (
	"bytes"
	"crypto/ed25519"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSeedEnvelopeBindings(t *testing.T) {
	seed := bytes.Repeat([]byte{3}, 32)
	key := bytes.Repeat([]byte{9}, 32)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	raw, e := Seal(seed, key, "w_test", private[32:])
	require.NoError(t, e)
	recovered, e := Open(raw, key, "w_test", private[32:])
	require.NoError(t, e)
	require.Equal(t, []byte(private), recovered)
	clear(recovered)
	_, e = Open(raw, key, "w_other", private[32:])
	require.Error(t, e)
	_, e = Open(raw, bytes.Repeat([]byte{8}, 32), "w_test", private[32:])
	require.Error(t, e)
	raw[len(raw)/2] ^= 1
	_, e = Open(raw, key, "w_test", private[32:])
	require.Error(t, e)
}
