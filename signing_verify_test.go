package mpcium

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/jaronnie/mpcium-go/event"
	"github.com/jaronnie/mpcium-go/types"
	"math/big"
	"testing"
)

func TestVerifiedECDSAResult(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	hash := sha256.Sum256([]byte("signing acceptance"))
	pub := hex.EncodeToString(key.PubKey().SerializeUncompressed())
	compact := ecdsa.SignCompact(key, hash[:], false)
	original := event.SigningResultEvent{R: compact[1:33], S: compact[33:], SignatureRecovery: []byte{compact[0] - 27}}
	for _, high := range []bool{false, true} {
		result := original
		if high {
			result.S = new(big.Int).Sub(btcec.S256().Params().N, new(big.Int).SetBytes(result.S)).Bytes()
			result.SignatureRecovery = []byte{original.SignatureRecovery[0] ^ 1}
		}
		if err := verifySigningResult(types.KeyTypeSecp256k1, pub, hash[:], &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Signature) != 65 || new(big.Int).SetBytes(result.S).Cmp(new(big.Int).Rsh(new(big.Int).Set(btcec.S256().Params().N), 1)) > 0 {
			t.Fatal("noncanonical signature")
		}
	}
	for name, alter := range map[string]func(*event.SigningResultEvent){"bad recovery": func(r *event.SigningResultEvent) { r.SignatureRecovery = []byte{3} }, "zero scalar": func(r *event.SigningResultEvent) { r.R = []byte{0} }, "wrong scalar": func(r *event.SigningResultEvent) { r.S = []byte{1} }} {
		t.Run(name, func(t *testing.T) {
			result := original
			alter(&result)
			if verifySigningResult(types.KeyTypeSecp256k1, pub, hash[:], &result) == nil {
				t.Fatal("accepted invalid signature")
			}
		})
	}
	hash[0] ^= 1
	result := original
	if verifySigningResult(types.KeyTypeSecp256k1, pub, hash[:], &result) == nil {
		t.Fatal("accepted different message")
	}
}
func TestVerifiedEd25519Result(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	msg := []byte("ed25519 signing acceptance")
	result := event.SigningResultEvent{Signature: ed25519.Sign(key, msg)}
	if err := verifySigningResult(types.KeyTypeEd25519, hex.EncodeToString(pub), msg, &result); err != nil {
		t.Fatal(err)
	}
	result.Signature[0] ^= 1
	if verifySigningResult(types.KeyTypeEd25519, hex.EncodeToString(pub), msg, &result) == nil {
		t.Fatal("accepted corrupt signature")
	}
}
