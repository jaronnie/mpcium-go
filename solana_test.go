package mpcium

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/jaronnie/mpcium-go/keyexport"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/stretchr/testify/require"
)

func TestSolanaExportedScalarLocalSigning(t *testing.T) {
	scalar := big.NewInt(123456789).FillBytes(make([]byte, 32))
	defer clear(scalar)
	public := keyexport.PublicKey(types.KeyTypeEd25519, new(big.Int).SetBytes(scalar))
	address, err := SolanaAddress(scalar)
	require.NoError(t, err)
	require.Equal(t, base58.Encode(public), address)
	// A serialized legacy Solana transfer message: signer, destination, system
	// program, recent blockhash and one transfer instruction. No RPC or NATS.
	message := []byte{1, 0, 1, 3}
	message = append(message, public...)
	message = append(message, make([]byte, 32)...)
	message = append(message, make([]byte, 32)...)
	message = append(message, make([]byte, 32)...)
	message = append(message, 1, 2, 2, 0, 1, 12, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0)
	signature, err := SignSolanaMessage(scalar, message)
	require.NoError(t, err)
	require.Len(t, signature, 64)
	require.True(t, ed25519.Verify(public, message, signature))
	message[len(message)-1] ^= 1
	require.False(t, ed25519.Verify(public, message, signature))
	next, err := SignSolanaMessage(scalar, message)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(public, message, next))
	require.False(t, bytes.Equal(signature[:32], next[:32]), "different messages with the same prefix reused nonce")
	repeated, err := SignSolanaMessage(scalar, message)
	require.NoError(t, err)
	require.True(t, ed25519.Verify(public, message, repeated))
	require.False(t, bytes.Equal(next[:32], repeated[:32]), "repeated signing reused nonce")
	b := SolanaScalarBackup{Format: SolanaScalarBackupFormat, WalletID: "wallet", Address: address, PublicKeyHex: hex.EncodeToString(public), PrivateScalarHex: hex.EncodeToString(scalar), ScalarEncoding: "big-endian"}
	encoded, err := json.Marshal(b)
	require.NoError(t, err)
	recovered, err := ParseSolanaScalarBackup(encoded)
	require.NoError(t, err)
	require.Equal(t, scalar, recovered)
	clear(recovered)
	b.Address = "mismatched"
	encoded, _ = json.Marshal(b)
	_, err = ParseSolanaScalarBackup(encoded)
	require.Error(t, err)
	for _, invalid := range [][]byte{nil, make([]byte, 32), make([]byte, 64), keyexport.Curve(types.KeyTypeEd25519).Params().N.FillBytes(make([]byte, 32))} {
		_, err = SignSolanaMessage(invalid, []byte("test"))
		require.Error(t, err)
	}
}
