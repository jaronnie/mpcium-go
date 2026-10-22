# mpcium-go

MPCium 的独立 Go SDK。模块路径 `github.com/jaronnie/mpcium-go`，根包名 `mpcium`。

```sh
go get github.com/jaronnie/mpcium-go@v0.1.0
```

无需克隆节点仓库，无需 `replace`。Go 版本要求见 `go.mod`。

## 接入

由集群管理员提供加密的 V4 项目凭据、密码，以及 NATS TLS 地址和 token。V4 凭据包含项目身份和可信节点公钥，连接配置单独提供。不要把凭据或密码提交到 Git。

```go
credentials, err := mpcium.UnlockCredentials("project.age", password)
if err != nil { return err }
defer credentials.Close()

opts, err := mpcium.Connect(ctx, natsURL, natsToken, credentials.ProjectID, credentials)
if err != nil { return err }
defer opts.NatsConn.Close()

client := mpcium.NewMPCClient(opts)
```

完整示例（在此仓库运行）：

```sh
# 设置 NATS_URL（tls:// 域名及端口）、NATS_TOKEN
# 从密码管理器或交互输入设置 MPC_CREDENTIALS_PASSWORD
go run ./examples/create-wallet ./project.age my-new-wallet
```

示例会创建钱包，需要连接已授权的 MPCium 集群。V1 凭据可自行配置 NATS 连接；V2 凭据保留 `credentials.ConnectNATS` 兼容接口。

业务示例见 [examples/agent](examples/agent/README.md)：[仅数据解密](examples/agent/scenarios/data/main.go)、[私钥导出](examples/agent/scenarios/export-wallet/main.go)、[在线签名](examples/agent/scenarios/online-sign/main.go)。这些示例使用已发布的 SDK，单独维护 Go module。

## 能力

- `CreateWallet` / `OnWalletCreationResult`：创建钱包并接收异步结果。
- `SignTransaction` / `OnSignResult`：请求 MPC 签名并接收结果。
- `Resharing` / `OnResharingResult`：请求重新分片。
- `CreateWalletAndExport`、`ExportPrivateKey`、`ExportWallet`：在节点策略允许时导出私钥。
- `EncryptData`、`DecryptData`、`DecryptStoredData`：业务数据加密和门限解密。
- `NewLocalSigner`、`NewKMSSigner`：请求签名身份。
- `SolanaAddress`、`SignSolanaMessage`：导出 Ed25519 scalar 后独立本地签名。

异步操作先注册结果回调，再发送请求。独立客户端应设置唯一 `Options.ClientID`，隔离 JetStream 结果路由；旧版本的空值行为保留。连接和凭据由调用者关闭。

协议类型在 `types`、`event`、`keyexport`、`configsecret` 中。原来的 `github.com/jaronnie/mpcium/pkg/client` 改为根路径；其余客户端协议包从 `github.com/jaronnie/mpcium/pkg/<包名>` 改为 `github.com/jaronnie/mpcium-go/<包名>`。

## 兼容性

从 MPCium 源码提取，保留现有 NATS subjects、JSON 字段、请求签名及响应验证。SDK 不包含节点服务、数据库、Consul 或 TSS 节点计算；私钥恢复采用同一有限域中的 Shamir 插值并校验恢复出的公钥。新增业务接口要求服务端已经部署相应协议。

私钥导出后，调用者拥有完整密钥；使用完毕应清理字节。Ed25519 导出值是 32 字节大端 scalar，**不是**标准 Ed25519 seed 或 Solana keypair；请使用本 SDK 对应的 scalar 接口。

## 开发

```sh
go test ./...
go test -race ./...
go vet ./...
```

单元测试不需要线上集群。真实节点联调与单元测试分开执行。

Apache-2.0，见 LICENSE 和 NOTICE。
