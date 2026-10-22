package mpcium

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/jaronnie/mpcium-go/event"
	"github.com/jaronnie/mpcium-go/types"
)

func validateSigningInput(kind types.KeyType, publicHex string, message []byte) error {
	pub, err := hex.DecodeString(publicHex)
	if err != nil {
		return errors.New("invalid wallet public key")
	}
	switch kind {
	case types.KeyTypeSecp256k1:
		if _, err := btcec.ParsePubKey(pub); err != nil || len(message) != 32 {
			return errors.New("secp256k1 requires a wallet public key and 32-byte digest")
		}
	case types.KeyTypeEd25519:
		if len(pub) != ed25519.PublicKeySize {
			return errors.New("invalid Ed25519 wallet public key")
		}
	default:
		return errors.New("unsupported signing key type")
	}
	return nil
}

// verifySigningResult authenticates the signature against the caller-pinned key.
// ECDSA output is normalized to low-S [R || S || recovery] for direct use.
func verifySigningResult(kind types.KeyType, publicHex string, message []byte, result *event.SigningResultEvent) error {
	if err := validateSigningInput(kind, publicHex, message); err != nil {
		return err
	}
	pub, _ := hex.DecodeString(publicHex)
	if kind == types.KeyTypeEd25519 {
		if !ed25519.Verify(pub, message, result.Signature) {
			return errors.New("invalid Ed25519 signature")
		}
		return nil
	}
	if len(result.R) == 0 || len(result.R) > 32 || len(result.S) == 0 || len(result.S) > 32 || len(result.SignatureRecovery) != 1 || result.SignatureRecovery[0] > 1 {
		return errors.New("invalid ECDSA signature format")
	}
	rr, ss := new(big.Int).SetBytes(result.R), new(big.Int).SetBytes(result.S)
	order := btcec.S256().Params().N
	if rr.Sign() <= 0 || rr.Cmp(order) >= 0 || ss.Sign() <= 0 || ss.Cmp(order) >= 0 {
		return errors.New("invalid ECDSA signature values")
	}
	recovery := result.SignatureRecovery[0]
	if ss.Cmp(new(big.Int).Rsh(new(big.Int).Set(order), 1)) > 0 {
		ss.Sub(order, ss)
		recovery ^= 1
	}
	sig := make([]byte, 65)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:64])
	sig[64] = recovery
	compact := append([]byte{27 + recovery}, sig[:64]...)
	recovered, _, err := ecdsa.RecoverCompact(compact, message)
	expected, _ := btcec.ParsePubKey(pub)
	if err != nil || !bytes.Equal(recovered.SerializeCompressed(), expected.SerializeCompressed()) {
		return errors.New("signature does not match wallet public key or message")
	}
	result.Signature = sig
	result.R = append([]byte(nil), sig[:32]...)
	result.S = append([]byte(nil), sig[32:64]...)
	result.SignatureRecovery = []byte{recovery}
	return nil
}
