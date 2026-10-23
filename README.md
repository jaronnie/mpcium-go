# mpcium-go

MPCium 的独立 Go SDK。模块路径 `github.com/jaronnie/mpcium-go`，根包名 `mpcium`。

```sh
go get github.com/jaronnie/mpcium-go@v0.5.0
```

无需克隆节点仓库，无需 `replace`。Go 版本要求见 `go.mod`。

## 接入

由集群管理员提供加密的 V4 项目凭据、密码及 NATS TLS 地址。启用 IP 白名单的集群会把专属访问 token 放在 age 密文内；凭据同时包含项目身份和可信节点公钥。不要把凭据或密码提交到 Git。

```go
credentials, err := mpcium.UnlockCredentials("project.age", password)
if err != nil { return err }
defer credentials.Close()

client, err := mpcium.ConnectAccess(ctx, natsURL, credentials)
if err != nil { return err }
defer client.Close()
```

旧共享入口的创建钱包示例（隔离入口由控制台创建资源，业务示例见下方）：

```sh
# 设置 NATS_URL（tls:// 域名及端口）、NATS_TOKEN
# 从密码管理器或交互输入设置 MPC_CREDENTIALS_PASSWORD
go run ./examples/create-wallet ./project.age my-new-wallet
```

示例会创建钱包，需要连接已授权的 MPCium 集群。仅支持 V4 项目凭据；旧文件需从控制台重新导出。旧模式凭据不保存 NATS token、账号密码或客户端证书；IP 白名单模式会在 age 密文中保存专属访问 token。

业务示例见 [examples/agent](examples/agent/README.md)：[仅数据解密](examples/agent/scenarios/data/main.go)、[私钥导出](examples/agent/scenarios/export-wallet/main.go)、[钱包交易签名](examples/agent/scenarios/online-sign/main.go)。这些示例使用已发布的 SDK，单独维护 Go module。

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

## IP 白名单入口（v0.5.0）

启用资源 IP 白名单的集群使用独立 NATS BUSINESS 账号。控制台导出的 age 凭据包含资源访问 token，不能再使用旧的共享 token 或 `NewMPCClient`：

```go
credentials, err := mpcium.UnlockCredentials("project.age", password)
if err != nil { return err }
defer credentials.Close()
client, err := mpcium.ConnectAccess(ctx, natsURL, credentials)
if err != nil { return err }
defer client.Close()
plaintext, err := client.DecryptStoredData(ctx, dataID)
```

支持 `CreateWallet(ctx,id)`、`SignTransaction(ctx,msg,walletPublicKeyHex)`、`EncryptData`、`DecryptData`、`DecryptStoredData`、`ExportWallet`。访问 token 统一从解锁后的 `credentials.AccessToken` 读取，不再提供单独的 token 参数。控制台项目凭据只授权已经登记的资源；资源创建由控制台完成。

连接和重连时检查来源 IP；收紧规则会阻止旧连接继续访问，新增授权需重连。重新导出控制台凭据会轮换 token。超时不代表签名/创建回滚，请先检查状态，不能自动重试。钱包交易签名由 SDK 使用调用方提供的固定钱包公钥验证，验证失败只返回错误。入口重启或来源 IP 改变后应重新建立客户端。

旧版连接方式仅适用于尚未启用隔离入口的集群。以上隔离模式依赖匹配的 `mpcium-access` 与节点版本。

钱包交易签名使用 `SignTransaction(ctx, request, walletPublicKeyHex)`，SDK 内部完成验签、ECDSA low-S 归一化与恢复位校验，成功返回的 `result.Signature` 可直接使用。导出 Solana 钱包使用 `ExportWallet(ctx, walletID, types.KeyTypeEd25519)`，EVM 使用 `types.KeyTypeSecp256k1`。

## Agent skill

[mpcium-sdk](skills/mpcium-sdk/SKILL.md) 以单个 `SKILL.md` 提供三个场景的调用示例、SDK v0.5.0 接入约定和错误排查说明。将该文件放入 agent 技能目录下的 `mpcium-sdk/SKILL.md`，使用 `$mpcium-sdk` 调用；示例不包含真实凭据。


### Standard Solana wallets (v0.6.0)

New console Solana wallets default to `standard` mode: the trusted console server generates a standard seed, encrypts two independent sets of 2-of-3 signing/recovery shares to the pinned nodes, then discards the full secret. Explicit `mpc` mode retains distributed generation and scalar-only export. Existing wallets and addresses are unchanged.

`ExportWallet(ctx, walletID, types.KeyTypeEd25519)` still returns a 32-byte scalar. For a standard-mode wallet, use `ExportSolanaKeypair(ctx, walletID)` to recover a validated 64-byte seed+public-key keypair on the caller's machine. Base58-encode those bytes for private-key import into a compatible Solana wallet. Use `SignSolanaKeypair(privateKey, message)` for local signing; `SignSolanaMessage` retains its scalar-only semantics. Neither helper broadcasts transactions. The encrypted seed requires its independent recovery-share quorum; a single node cannot recover it. Standard-wallet resharing is refused until recovery-share migration is supported.
