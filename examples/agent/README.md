# MPCium Go SDK 业务示例

客户端直接通过 NATS 访问 MPC 节点。控制台负责创建项目、创建资源和交付凭据，不参与 SDK 运行。私钥导出、数据加解密与钱包交易签名复用同一个 `ConnectAccess` 客户端。

## 通过 import 使用

SDK 已提交远端；独立业务项目固定到本次版本：

```sh
go get github.com/jaronnie/mpcium-go@v0.5.0
```

```go
import client "github.com/jaronnie/mpcium-go"
```

本目录固定到独立 SDK 的远端版本，无需克隆节点源码，也无需添加 `replace`。SDK 仓库：https://github.com/jaronnie/mpcium-go 。

## 初始化一次

```go
credentials, err := client.UnlockCredentials(credentialsPath, password)
if err != nil { return err }
defer credentials.Close()

sdk, err := client.ConnectAccess(ctx, natsURL, credentials)
if err != nil { return err }
defer sdk.Close()
```

访问 token 随加密凭据交付。连接使用资源凭据和服务端 TLS，系统 CA 校验域名，不需要客户端证书、私钥、ServerName 或 SSH 隧道。密码只在本地解锁凭据；SDK 自动签署业务请求，节点沿用现有身份签名验证。无需控制台登录、动态码或新的项目授权接口。

## 数据加解密

```go
// 读取创建数据时保存在节点的原始密文并解密。
plain, err := sdk.DecryptStoredData(ctx, keyDataId)
if err != nil { return err }
defer clear(plain)

// 用同一数据密钥保护新的业务内容；密文由业务保存。
ciphertext, err := sdk.EncryptData(ctx, keyDataId, []byte("database password"))
if err != nil { return err }
restored, err := sdk.DecryptData(ctx, keyDataId, ciphertext)
if err != nil { return err }
defer clear(restored)
```

`EncryptData` 在本地加密，明文不发送到 NATS；SDK 内部校验多个节点签名的公钥材料。解密只由节点返回证明绑定的部分结果，在调用方验证并恢复明文。不会将长期数据密钥交给客户端，也不会覆盖原记录。明文为 1–16384 字节，保留任意字节内容。

## 钱包私钥导出

```go
privateScalar, err := sdk.ExportWallet(ctx, walletID)
if err != nil { return err }
defer clear(privateScalar)
```

节点从当前钱包记录读取版本、参与者和门限；客户端不传 policy。恢复材料加密交付给本次调用独有的临时接收者，SDK 验证不同节点签名及钱包公钥后，在本地恢复 32 字节私钥标量。EVM 可交给普通 secp256k1 签名代码；Ed25519 是 MPC 标量，不是钱包 seed，可使用现有 `client.SignSolanaMessage`。

## 钱包交易签名

```go
result, err := sdk.SignTransaction(ctx, &types.SignTxMessage{
    WalletID: walletID,
    KeyType: types.KeyTypeSecp256k1,
    NetworkInternalCode: "ethereum-mainnet",
    TxID: uuid.NewString(),
    Tx: signingDigest,
}, walletPublicKeyHex)
if err != nil { return err }
```

EVM 输入是业务计算的 32 字节摘要；Ed25519 输入是完整消息。SDK 关联请求 ID 并使用固定钱包公钥验证签名；调用成功后直接使用 `result.Signature`，不自动广播。

## 配置和三个 main

[运行说明](scenarios/README.md)及三个完整、可单独阅读和复制的入口（无共享示例包）：

- [数据解密](scenarios/data/main.go)
- [钱包私钥导出](scenarios/export-wallet/main.go)
- [钱包交易签名](scenarios/online-sign/main.go)

三个示例都直接在 `main.go` 顶部填写常量，不读取配置文件、环境变量或终端输入：

```go
const (
    natsURL = "tls://crypto.blockrazor.xyz:4222"
    natsToken = "REPLACE_NATS_TOKEN"
    projectID = "REPLACE_PROJECT_ID"
    projectCredentialsBase64 = "REPLACE_PROJECT_CREDENTIALS_BASE64"
    projectCredentialsPassword = "REPLACE_PROJECT_CREDENTIALS_PASSWORD"
    keyDataId = "REPLACE_KEY_DATA_ID"
)
```

`projectCredentialsBase64` 是完整 V4 `.age` 包的 Base64 文本，示例用 `base64.StdEncoding.DecodeString` 和 `client.UnlockCredentialsBytes` 在内存中解锁。节点验证公钥已封装在凭据里，业务无需填写节点、manifest 或 policy。私钥导出示例只在内存中使用结果；钱包交易签名示例直接对代码中的测试消息签名并验证，不组装或广播交易。

仓库和通用 ZIP 使用占位常量；真实凭据、token 和密码只写入本机专用代码，不提交远端。

## 服务端

节点内的 `pkg/sdkserver` 分为 NATS 传输、业务 Service 和持久化 replay store；身份与资源读取使用节点现有组件。启动入口仅装配依赖。新数据创建时，管理员签名的注册记录包含密文和加密份额，并持久化到各节点；控制台停止后 SDK 仍可运行。请求有签名、有效期和持久化防重放；响应包含节点签名并加密给调用方。

线上节点和控制台已配套更新；本机数据解密示例已直接连接线上节点验证通过。使用 V4 凭据，数据密文须已保存到节点；节点公钥自动封装在凭据中，不要求业务端另行配置。本机已逐项运行数据解密、EVM/Solana 私钥导出和钱包交易签名，且核对解密内容和导出公钥；测试签名未广播。

钱包交易签名使用 `SignTransaction(ctx, request, walletPublicKeyHex)`，SDK 内部完成验签、ECDSA low-S 归一化与恢复位校验，成功返回的 `result.Signature` 可直接使用。导出 Solana 钱包使用 `ExportWallet(ctx, walletID, types.KeyTypeEd25519)`，EVM 使用 `types.KeyTypeSecp256k1`。
