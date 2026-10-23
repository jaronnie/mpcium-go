package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"time"

	mpcium "github.com/jaronnie/mpcium-go"
)

const (
	natsURL                    = "tls://crypto.blockrazor.xyz:4222"
	projectID                  = "REPLACE_PROJECT_ID"
	projectCredentialsBase64   = "REPLACE_PROJECT_CREDENTIALS_BASE64"
	projectCredentialsPassword = "REPLACE_PROJECT_CREDENTIALS_PASSWORD"
	keyDataId                  = "REPLACE_KEY_DATA_ID"
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
	if keyDataId == "" || keyDataId == "REPLACE_KEY_DATA_ID" {
		return errors.New("请配置加密数据 ID（keyDataId）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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
	plaintext, err := sdk.DecryptStoredData(ctx, keyDataId)
	if err != nil {
		return fmt.Errorf("解密数据失败：%w", err)
	}
	defer clear(plaintext)
	// 在这里将 plaintext 交给业务使用；不要将明文写入日志。
	// 返回前清理当前持有的明文字节，业务创建的副本需自行管理。
	fmt.Printf("数据解密成功（%d 字节）\n", len(plaintext))
	return nil
}
