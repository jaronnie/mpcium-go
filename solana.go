package mpcium

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/jaronnie/mpcium-go/keyexport"
	"github.com/jaronnie/mpcium-go/types"
)

const SolanaScalarBackupFormat = "mpcium-solana-scalar-v1"

// SolanaScalarBackup stores a recovered MPC scalar, NOT a seed or a standard
// Solana CLI/Phantom keypair. Protect it as a full private key.
type SolanaScalarBackup struct {
	Format           string `json:"format"`
	WalletID         string `json:"walletId"`
	Address          string `json:"address"`
	PublicKeyHex     string `json:"publicKeyHex"`
	PrivateScalarHex string `json:"privateScalarHex"`
	ScalarEncoding   string `json:"scalarEncoding"`
	Notice           string `json:"notice"`
}

func solanaScalarKey(scalarBE []byte) (*edwards.PrivateKey, *edwards.PublicKey, error) {
	if len(scalarBE) != 32 {
		return nil, nil, errors.New("expected 32-byte big-endian Ed25519 scalar")
	}
	scalar := new(big.Int).SetBytes(scalarBE)
	defer scalar.SetInt64(0)
	if scalar.Sign() <= 0 || scalar.Cmp(keyexport.Curve(types.KeyTypeEd25519).Params().N) >= 0 {
		return nil, nil, errors.New("Ed25519 scalar out of range")
	}
	key, pub, err := edwards.PrivKeyFromScalar(scalarBE)
	if err != nil {
		return nil, nil, errors.New("invalid Ed25519 scalar")
	}
	return key, pub, nil
}

// SolanaAddress returns the base58 Ed25519 public key for the exported scalar.
func SolanaAddress(scalarBE []byte) (string, error) {
	key, pub, err := solanaScalarKey(scalarBE)
	if err != nil {
		return "", err
	}
	defer key.GetD().SetInt64(0)
	return base58.Encode(pub.Serialize()), nil
}

// SignSolanaMessage signs the serialized Solana transaction MESSAGE bytes, not
// the entire transaction or a prehash. It needs no MPC nodes, NATS, RPC or Consul
// and never broadcasts. scalarBE must be ExportPrivateKey's Ed25519 scalar.
func SignSolanaMessage(scalarBE, message []byte) ([]byte, error) {
	key, pub, err := solanaScalarKey(scalarBE)
	if err != nil {
		return nil, err
	}
	defer key.GetD().SetInt64(0)
	// The library's generic scalar Sign uses an RFC6979 helper that expects a
	// 32-byte prehash. Solana messages are longer and may share a prefix, so
	// choose an independent CSPRNG nonce and sign the FULL message explicitly.
	var nonce *big.Int
	for {
		nonce, err = rand.Int(rand.Reader, keyexport.Curve(types.KeyTypeEd25519).Params().N)
		if err != nil {
			return nil, err
		}
		if nonce.Sign() != 0 {
			break
		}
	}
	defer nonce.SetInt64(0)
	nonceBE := nonce.FillBytes(make([]byte, 32))
	defer clear(nonceBE)
	r, s, err := edwards.SignFromScalar(key, nonceBE, message)
	if err != nil {
		return nil, err
	}
	signature := edwards.NewSignature(r, s).Serialize()
	if !ed25519.Verify(ed25519.PublicKey(pub.Serialize()), message, signature) {
		return nil, errors.New("local Ed25519 signature verification failed")
	}
	return signature, nil
}

// ParseSolanaScalarBackup verifies the format and its public metadata before
// returning secret bytes. The caller must clear the returned bytes after use.
func ParseSolanaScalarBackup(data []byte) ([]byte, error) {
	var b SolanaScalarBackup
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&b) != nil || dec.Decode(new(any)) != io.EOF || b.Format != SolanaScalarBackupFormat || b.ScalarEncoding != "big-endian" {
		return nil, errors.New("unsupported Solana scalar backup")
	}
	scalar, err := hex.DecodeString(b.PrivateScalarHex)
	if err != nil {
		return nil, errors.New("invalid scalar encoding")
	}
	key, pub, err := solanaScalarKey(scalar)
	if err != nil {
		clear(scalar)
		return nil, err
	}
	defer key.GetD().SetInt64(0)
	if hex.EncodeToString(pub.Serialize()) != b.PublicKeyHex || base58.Encode(pub.Serialize()) != b.Address {
		clear(scalar)
		return nil, errors.New("backup scalar does not match its address and public key")
	}
	return scalar, nil
}
