// Requires the mpcium-go release containing ConnectAccess. The token is inside the encrypted credentials.
package main

import (
	"context"

	"encoding/base64"

	"errors"
	"fmt"

	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	client "github.com/jaronnie/mpcium-go"

	"github.com/jaronnie/mpcium-go/logger"
	"github.com/jaronnie/mpcium-go/types"
)

const (
	natsURL   = "tls://crypto.blockrazor.xyz:4222"
	projectID = "REPLACE_PROJECT_ID"
	// 粘贴控制台导出的 Base64 凭据。
	projectCredentialsBase64   = "REPLACE_PROJECT_CREDENTIALS_BASE64"
	projectCredentialsPassword = "REPLACE_PROJECT_CREDENTIALS_PASSWORD"
	walletID                   = "REPLACE_WALLET_ID"
	walletPublicKeyHex         = "REPLACE_WALLET_PUBLIC_KEY_HEX"
	keyType                    = types.KeyTypeSecp256k1 // Or types.KeyTypeEd25519.
	network                    = "ethereum-mainnet"
	testMessage                = "mpcium SDK online signing test"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if projectID == "REPLACE_PROJECT_ID" || projectCredentialsBase64 == "REPLACE_PROJECT_CREDENTIALS_BASE64" || projectCredentialsPassword == "REPLACE_PROJECT_CREDENTIALS_PASSWORD" {
		return errors.New("请提供项目 ID、项目凭据和解锁密码")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	encryptedCredentials, err := base64.StdEncoding.DecodeString(projectCredentialsBase64)
	if err != nil {
		return fmt.Errorf("解析项目凭据失败: %w", err)
	}
	credentials, err := client.UnlockCredentialsBytes(encryptedCredentials, projectCredentialsPassword)
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
	result, err := sdk.SignTransaction(ctx, &types.SignTxMessage{WalletID: walletID, KeyType: keyType, NetworkInternalCode: network, TxID: uuid.NewString(), Tx: message}, walletPublicKeyHex)
	if err != nil {
		return err
	}
	fmt.Printf("在线签名验证通过，未广播\nTxID: %s\nSignature: %x\n", result.TxID, result.Signature)
	return nil
}
