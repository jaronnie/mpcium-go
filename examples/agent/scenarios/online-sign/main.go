// Requires the mpcium-go release containing ConnectAccess. The token is inside the encrypted credentials.
// Edit the constants below, then run: go run main.go
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	client "github.com/jaronnie/mpcium-go"
	"github.com/jaronnie/mpcium-go/event"
	"github.com/jaronnie/mpcium-go/logger"
	"github.com/jaronnie/mpcium-go/types"
)

const (
	natsURL   = "tls://crypto.blockrazor.xyz:4222"
	projectID = "REPLACE_PROJECT_ID"
	// 粘贴控制台导出的 Base64 凭据。
	credentialsBase64   = "REPLACE_CREDENTIALS_BASE64"
	credentialsPassword = "REPLACE_CREDENTIAL_PASSWORD"
	walletID            = "REPLACE_WALLET_ID"
	walletPublicKeyHex  = "REPLACE_WALLET_PUBLIC_KEY_HEX"
	keyType             = types.KeyTypeSecp256k1 // Or types.KeyTypeEd25519.
	network             = "ethereum-mainnet"
	testMessage         = "mpcium SDK online signing test"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if projectID == "REPLACE_PROJECT_ID" || credentialsBase64 == "REPLACE_CREDENTIALS_BASE64" || credentialsPassword == "REPLACE_CREDENTIAL_PASSWORD" {
		return errors.New("请先填写 main.go 顶部的 项目 ID、凭据 Base64 和解锁密码（访问 token 已包含在凭据中）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// No configuration files, environment variables or interactive prompts.
	encryptedCredentials, err := base64.StdEncoding.DecodeString(credentialsBase64)
	if err != nil {
		return fmt.Errorf("decode credentials: %w", err)
	}
	credentials, err := client.UnlockCredentialsBytes(encryptedCredentials, credentialsPassword)
	clear(encryptedCredentials)
	if err != nil {
		return err
	}
	defer credentials.Close()
	if credentials.ProjectID != projectID {
		return errors.New("项目 ID 与凭据不匹配")
	}
	sdk, err := client.ConnectAccess(ctx, natsURL, credentials)
	if err != nil {
		return err
	}
	defer sdk.Close()
	logger.Init("production", false)
	// Test-only input: no transaction is constructed or broadcast here.
	var message []byte
	switch keyType {
	case types.KeyTypeSecp256k1:
		message = crypto.Keccak256([]byte(testMessage))
	case types.KeyTypeEd25519:
		message = []byte(testMessage)
	default:
		return errors.New("unsupported wallet key type")
	}
	publicKey, err := hex.DecodeString(walletPublicKeyHex)
	if err != nil {
		return err
	}
	if keyType == types.KeyTypeSecp256k1 {
		if _, err = crypto.UnmarshalPubkey(publicKey); err != nil {
			return err
		}
	}
	if keyType == types.KeyTypeEd25519 && len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	result, err := sdk.SignTransaction(ctx, &types.SignTxMessage{WalletID: walletID, KeyType: keyType, NetworkInternalCode: network, TxID: uuid.NewString(), Tx: message})
	if err != nil {
		return err
	}
	if result.ResultType != event.ResultTypeSuccess {
		return errors.New("MPC signing did not succeed")
	}
	signature, err := verifiedSignature(keyType, publicKey, message, result)
	if err != nil {
		return err
	}
	fmt.Printf("在线签名验证通过，未广播\nTxID: %s\nSignature: %x\n", result.TxID, signature)
	return nil
}

func verifiedSignature(kind types.KeyType, pub, message []byte, r event.SigningResultEvent) ([]byte, error) {
	if kind == types.KeyTypeEd25519 {
		if !ed25519.Verify(pub, message, r.Signature) {
			return nil, errors.New("invalid Ed25519 signature")
		}
		return r.Signature, nil
	}
	if kind != types.KeyTypeSecp256k1 || len(r.R) == 0 || len(r.R) > 32 || len(r.S) == 0 || len(r.S) > 32 || len(r.SignatureRecovery) != 1 {
		return nil, errors.New("invalid ECDSA signature format")
	}
	rr, ss := new(big.Int).SetBytes(r.R), new(big.Int).SetBytes(r.S)
	v := r.SignatureRecovery[0]
	if !crypto.ValidateSignatureValues(v, rr, ss, false) {
		return nil, errors.New("invalid ECDSA signature values")
	}
	half := new(big.Int).Rsh(new(big.Int).Set(crypto.S256().Params().N), 1)
	if ss.Cmp(half) > 0 {
		ss.Sub(crypto.S256().Params().N, ss)
		v ^= 1
	}
	sig := make([]byte, 65)
	rr.FillBytes(sig[:32])
	ss.FillBytes(sig[32:64])
	sig[64] = v
	if !crypto.VerifySignature(pub, message, sig[:64]) {
		return nil, errors.New("signature differs from trusted wallet public key")
	}
	recovered, err := crypto.Ecrecover(message, sig)
	if err != nil || hex.EncodeToString(recovered) != hex.EncodeToString(pub) {
		return nil, errors.New("invalid signature recovery")
	}
	return sig, nil
}
