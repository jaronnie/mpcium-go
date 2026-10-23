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
	walletPublicKeyHex         = "REPLACE_WALLET_PUBLIC_KEY_HEX"
	keyType                    = types.KeyTypeSecp256k1 // EVM；Solana 使用 types.KeyTypeEd25519。
	network                    = "ethereum-mainnet"
	testMessage                = "mpcium SDK online signing test"
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
	if walletPublicKeyHex == "" || walletPublicKeyHex == "REPLACE_WALLET_PUBLIC_KEY_HEX" {
		return errors.New("请配置钱包公钥（walletPublicKeyHex）")
	}
	if network == "" {
		return errors.New("请配置钱包网络（network）")
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
	// 以下仅准备测试消息，不构造或广播交易。
	// 真实交易：EVM 传入业务计算的 32 字节交易签名摘要；
	// Solana 传入序列化的交易 message，不额外做 Keccak256。
	var message []byte
	switch keyType {
	case types.KeyTypeSecp256k1:
		message = crypto.Keccak256([]byte(testMessage))
	case types.KeyTypeEd25519:
		message = []byte(testMessage)
	default:
		return errors.New("不支持的钱包类型，请使用 secp256k1（EVM）或 ed25519（Solana）")
	}
	requestID := uuid.NewString()
	result, err := sdk.SignTransaction(ctx, &types.SignTxMessage{
		WalletID:            walletID,
		KeyType:             keyType,
		NetworkInternalCode: network,
		TxID:                requestID,
		Tx:                  message,
	}, walletPublicKeyHex)
	if err != nil {
		return fmt.Errorf("钱包交易签名失败（请求 ID：%s）：%w", requestID, err)
	}
	// SDK 已验证签名与钱包公钥、请求消息匹配，可直接使用 result.Signature。
	fmt.Printf("钱包交易签名验证通过，未广播\nTxID: %s\nSignature: %x\n", result.TxID, result.Signature)
	return nil
}
