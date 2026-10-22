package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	mpcium "github.com/jaronnie/mpcium-go"
)

const (
	natsURL             = "tls://crypto.blockrazor.xyz:4222"
	natsToken           = "REPLACE_NATS_TOKEN"
	projectID           = "REPLACE_PROJECT_ID"
	credentialsBase64   = "REPLACE_CREDENTIALS_BASE64"
	credentialsPassword = "REPLACE_CREDENTIAL_PASSWORD"
	dataID              = "REPLACE_DATA_ID"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	credentials := must(mpcium.UnlockCredentialsBytes(must(base64.StdEncoding.DecodeString(credentialsBase64)), credentialsPassword))
	defer credentials.Close()
	opts := must(mpcium.Connect(ctx, natsURL, natsToken, projectID, credentials))
	defer opts.NatsConn.Close()

	plaintext := must(mpcium.NewMPCClient(opts).DecryptStoredData(ctx, dataID))
	defer clear(plaintext)
	// 在这里使用 plaintext，不写入文件。
	fmt.Printf("数据解密成功（%d 字节）\n", len(plaintext))
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
