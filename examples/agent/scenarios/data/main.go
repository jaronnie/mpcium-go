// Requires the mpcium-go release containing ConnectAccess. The token is inside the encrypted credentials.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	credentials := must(mpcium.UnlockCredentialsBytes(must(base64.StdEncoding.DecodeString(projectCredentialsBase64)), projectCredentialsPassword))
	defer credentials.Close()
	if credentials.ProjectID != projectID {
		panic("项目 ID 与凭据不匹配")
	}
	sdk := must(mpcium.ConnectAccess(ctx, natsURL, credentials))
	defer sdk.Close()

	plaintext := must(sdk.DecryptStoredData(ctx, keyDataId))
	// 在这里使用 plaintext，不写入文件。
	fmt.Printf("数据解密成功（%d 字节）\n", len(plaintext))
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
