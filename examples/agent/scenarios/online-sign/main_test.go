package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/jaronnie/mpcium-go/event"
	"github.com/jaronnie/mpcium-go/types"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestVerifySignatures(t *testing.T) {
	key, err := crypto.GenerateKey()
	require.NoError(t, err)
	digest := crypto.Keccak256([]byte("agent"))
	sig, err := crypto.Sign(digest, key)
	require.NoError(t, err)
	r := event.SigningResultEvent{R: sig[:32], S: sig[32:64], SignatureRecovery: sig[64:]}
	pub := crypto.FromECDSAPub(&key.PublicKey)
	got, err := verifiedSignature(types.KeyTypeSecp256k1, pub, digest, r)
	require.NoError(t, err)
	require.Equal(t, sig, got)
	high := new(big.Int).Sub(crypto.S256().Params().N, new(big.Int).SetBytes(sig[32:64]))
	r.S = high.Bytes()
	r.SignatureRecovery = []byte{sig[64] ^ 1}
	got, err = verifiedSignature(types.KeyTypeSecp256k1, pub, digest, r)
	require.NoError(t, err)
	require.Equal(t, sig, got)
	_, err = verifiedSignature(types.KeyTypeSecp256k1, pub, crypto.Keccak256([]byte("wrong")), r)
	require.Error(t, err)
	ep, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	message := []byte("serialized Solana message")
	r = event.SigningResultEvent{Signature: ed25519.Sign(private, message)}
	_, err = verifiedSignature(types.KeyTypeEd25519, ep, message, r)
	require.NoError(t, err)
	_, err = verifiedSignature(types.KeyTypeEd25519, ep, []byte("wrong"), r)
	require.Error(t, err)
}
