// Requires the mpcium-go release containing ConnectAccess. The token is inside the encrypted credentials.
// Edit the constants below, then run: go run main.go
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
)

const (
	natsURL   = "tls://crypto.blockrazor.xyz:4222"
	natsToken = "REPLACE_NATS_TOKEN"
	projectID = "REPLACE_PROJECT_ID"
	// 粘贴控制台导出的 Base64 凭据。
	credentialsBase64   = "REPLACE_CREDENTIALS_BASE64"
	credentialsPassword = "REPLACE_CREDENTIAL_PASSWORD"
	walletID            = "REPLACE_WALLET_ID"
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
	privateScalar, err := sdk.ExportWallet(ctx, walletID)
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
