// Requires the mpcium-go release containing ConnectAccess. The token is inside the encrypted credentials.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

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
	keyType                    = types.KeyTypeSecp256k1 // Use KeyTypeEd25519 for Solana wallets.
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if projectID == "" || projectID == "REPLACE_PROJECT_ID" || projectCredentialsBase64 == "" || projectCredentialsBase64 == "REPLACE_PROJECT_CREDENTIALS_BASE64" || projectCredentialsPassword == "" || projectCredentialsPassword == "REPLACE_PROJECT_CREDENTIALS_PASSWORD" {
		return errors.New("请提供项目 ID、项目凭据和解锁密码")
	}
	if walletID == "" || walletID == "REPLACE_WALLET_ID" {
		return errors.New("请提供钱包 ID")
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
		return fmt.Errorf("解锁项目凭据失败: %w", err)
	}
	defer credentials.Close()
	if credentials.ProjectID != projectID {
		return errors.New("项目 ID 与凭据不匹配")
	}
	sdk, err := client.ConnectAccess(ctx, natsURL, credentials)
	if err != nil {
		return fmt.Errorf("连接 MPC 服务失败: %w", err)
	}
	defer sdk.Close()
	logger.Init("production", false)
	privateScalar, err := sdk.ExportWallet(ctx, walletID, keyType)
	if err != nil {
		return err
	}
	defer clear(privateScalar)
	if len(privateScalar) != 32 {
		return fmt.Errorf("unexpected private scalar length: %d", len(privateScalar))
	}
	// Use privateScalar in your own signing code here. For Ed25519 it is an MPC
	// scalar, not a seed. The SDK verifies it against the wallet public key.
	fmt.Printf("钱包私钥导出成功（%d 字节，不打印私钥、不写文件）\n", len(privateScalar))
	return nil
}
