// Package solanaseed binds a standard Ed25519 seed backup to its wallet.
// The encryption key is independent of the signing scalar and is shared 2-of-3.
package solanaseed

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
)

const Domain = "mpcium/solana-seed/v1"

type Envelope struct {
	Domain     string `json:"domain"`
	WalletID   string `json:"walletId"`
	PublicKey  []byte `json:"publicKey"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func Scalar(seed []byte) ([]byte, error) {
	if len(seed) != 32 {
		return nil, errors.New("expected 32-byte Ed25519 seed")
	}
	h := sha512.Sum512(seed)
	defer clear(h[:])
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64
	for i := 0; i < 16; i++ {
		h[i], h[31-i] = h[31-i], h[i]
	}
	n := new(big.Int).SetBytes(h[:32])
	defer n.SetInt64(0)
	n.Mod(n, edwards.Edwards().Params().N)
	return n.FillBytes(make([]byte, 32)), nil
}
func aead(key []byte, wallet string, pub []byte) (cipher.AEAD, error) {
	if len(key) != 32 || wallet == "" || len(pub) != 32 {
		return nil, errors.New("invalid seed envelope binding")
	}
	derived := make([]byte, 32)
	defer clear(derived)
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, pub, []byte(Domain+"/"+wallet)), derived); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func Seal(seed, key []byte, wallet string, pub []byte) ([]byte, error) {
	if len(seed) != 32 {
		return nil, errors.New("invalid seed")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	if !bytes.Equal(priv[32:], pub) {
		return nil, errors.New("seed public key mismatch")
	}
	g, err := aead(key, wallet, pub)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	e := Envelope{Domain: Domain, WalletID: wallet, PublicKey: pub, Nonce: nonce, Ciphertext: g.Seal(nil, nonce, seed, []byte(Domain+"/"+wallet))}
	return json.Marshal(e)
}
func Validate(raw []byte, wallet string, pub []byte) error {
	var e Envelope
	if len(raw) > 1024 || json.Unmarshal(raw, &e) != nil || e.Domain != Domain || e.WalletID != wallet || !bytes.Equal(e.PublicKey, pub) || len(e.Nonce) != 12 || len(e.Ciphertext) != 48 {
		return errors.New("invalid seed envelope")
	}
	return nil
}
func Open(raw, key []byte, wallet string, pub []byte) ([]byte, error) {
	if err := Validate(raw, wallet, pub); err != nil {
		return nil, err
	}
	var e Envelope
	_ = json.Unmarshal(raw, &e)
	g, err := aead(key, wallet, pub)
	if err != nil {
		return nil, err
	}
	seed, err := g.Open(nil, e.Nonce, e.Ciphertext, []byte(Domain+"/"+wallet))
	if err != nil {
		return nil, errors.New("seed recovery failed")
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(private[32:], pub) {
		clear(private)
		return nil, errors.New("recovered seed public key mismatch")
	}
	return private, nil
}
