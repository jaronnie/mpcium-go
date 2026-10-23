package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	mpcium "github.com/jaronnie/mpcium-go"
	"github.com/jaronnie/mpcium-go/types"
)

const (
	natsURL   = "tls://crypto.blockrazor.xyz:4222"
	projectID = "REPLACE_PROJECT_ID"

	// 使用控制台导出的 Base64 项目凭据及对应的 SDK 私钥密码。
	projectCredentialsBase64   = "REPLACE_PROJECT_CREDENTIALS_BASE64"
	projectCredentialsPassword = "REPLACE_PROJECT_CREDENTIALS_PASSWORD"
	walletID                   = "REPLACE_WALLET_ID"
	keyType                    = types.KeyTypeSecp256k1 // EVM；Solana 使用 types.KeyTypeEd25519。
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if projectID == "" || projectID == "REPLACE_PROJECT_ID" ||
		projectCredentialsBase64 == "" || projectCredentialsBase64 == "REPLACE_PROJECT_CREDENTIALS_BASE64" ||
		projectCredentialsPassword == "" || projectCredentialsPassword == "REPLACE_PROJECT_CREDENTIALS_PASSWORD" {
		return errors.New("请配置项目 ID、Base64 项目凭据和 SDK 私钥密码")
	}
	if walletID == "" || walletID == "REPLACE_WALLET_ID" {
		return errors.New("请配置钱包 ID")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	encryptedCredentials, err := base64.StdEncoding.DecodeString(projectCredentialsBase64)
	if err != nil {
		return fmt.Errorf("解析 Base64 项目凭据失败：%w", err)
	}
	credentials, err := mpcium.UnlockCredentialsBytes(encryptedCredentials, projectCredentialsPassword)
	clear(encryptedCredentials)
	if err != nil {
		return fmt.Errorf("解锁项目凭据失败，请检查 SDK 私钥密码：%w", err)
	}
	defer credentials.Close()
	if credentials.ProjectID != projectID {
		return errors.New("项目 ID 与凭据不匹配")
	}
	sdk, err := mpcium.ConnectAccess(ctx, natsURL, credentials)
	if err != nil {
		return fmt.Errorf("连接 MPC 服务失败，请检查网络、项目凭据及资源 IP 白名单：%w", err)
	}
	defer sdk.Close()

	var privateKey []byte
	expectedLength := 32
	switch keyType {
	case types.KeyTypeEd25519:
		privateKey, err = sdk.ExportSolanaKeypair(ctx, walletID)
		expectedLength = 64
	case types.KeyTypeSecp256k1:
		privateKey, err = sdk.ExportWallet(ctx, walletID, keyType)
	default:
		return errors.New("不支持的钱包类型，请使用 secp256k1（EVM）或 ed25519（Solana）")
	}
	if err != nil {
		return fmt.Errorf("导出钱包私钥失败：%w", err)
	}
	defer clear(privateKey)
	if len(privateKey) != expectedLength {
		return fmt.Errorf("私钥长度异常：收到 %d 字节，期望 %d 字节", len(privateKey), expectedLength)
	}
	// Solana 返回标准 64 字节完整私钥；EVM 返回 32 字节私钥。
	// 在这里将 privateKey 交给业务使用；不要打印或记录私钥。
	fmt.Printf("钱包私钥导出成功（%d 字节）\n", len(privateKey))
	return nil
}
