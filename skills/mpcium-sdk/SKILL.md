---
name: mpcium-sdk
description: 使用 MPCium Go SDK 编写或排查加密 Key 数据解密、EVM/Solana 钱包私钥导出和在线 MPC 签名。适用于项目加密凭据、资源 IP 白名单及这三个业务示例的接入，不用于部署 MPC 集群或普通链上 RPC 交易广播。
---

# MPCium SDK 接入

按用户所选业务生成一个独立 Go 示例，保留最少调用代码。固定使用 `github.com/jaronnie/mpcium-go v0.5.0` 和 Go 1.25.8 或更高版本；不要使用本地 `replace`。

```sh
go mod init example.com/mpcium-client
go get github.com/jaronnie/mpcium-go@v0.5.0
```

本文件包含全部接入约定和代码片段，不依赖其他 skill 文件。按所选场景组合连接代码与一个业务调用，补齐实际参数和导入；不要附带执行另外两个敏感操作。

## 项目凭据与连接

使用以下命名：`natsURL`、`projectID`、`projectCredentialsBase64`、`projectCredentialsPassword`。资源参数使用 `keyDataId`、`walletID`、`walletPublicKeyHex`。

`projectCredentialsBase64` 是完整 age 加密项目凭据包的 Base64 文本，包含项目签名身份、可信节点公钥和 NATS 访问 token。Base64 自身不提供加密。凭据与密码由用户指定或从当前任务已授权的秘密来源读取；需要的信息缺失时只询问缺失项。不要把真实秘密写进 skill、版本库、日志或结果报告。

独立程序使用 `main` 调用 `run() error`，错误只在入口输出。`run` 里显式校验参数，再解锁和连接。导入标准库 `context`、`encoding/base64`、`errors`、`fmt`、`os`、`time`，以及 `client "github.com/jaronnie/mpcium-go"`：

```go
func main() {
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func run() error {
    if projectID == "" || projectCredentialsBase64 == "" || projectCredentialsPassword == "" {
        return errors.New("请提供项目 ID、项目凭据和解锁密码")
    }
    ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
    defer cancel()
    encrypted, err := base64.StdEncoding.DecodeString(projectCredentialsBase64)
    if err != nil {
        return fmt.Errorf("解析项目凭据失败: %w", err)
    }
    credentials, err := client.UnlockCredentialsBytes(encrypted, projectCredentialsPassword)
    clear(encrypted)
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

    // 在这里执行下面选定的一项业务调用，然后返回其错误或 nil。
    return nil
}
```

`natsURL` 使用实际集群提供的 `tls://` 地址。生成代码时补齐上述参数的来源，不能将未填写的占位值当成实际输入。

不设置单独的 `natsToken`，不向 `ConnectAccess` 传空 token 参数。不向使用资源 IP 控制的业务客户端暴露内部 NATS 用户、共享 token、JetStream 权限或节点管理凭据。SDK 使用 NATS TLS 地址直接访问节点，不需要业务运行时登录控制台或填写动态码。

每个钱包或 Key 独立检查 SDK 来源 IP，白名单为空表示拒绝；项目没有 IP 白名单或继承规则。使用服务端实际看到的公网出口 IP。拿到项目凭据不代表可以访问该项目所有资源。SDK 凭据只授权已登记资源，钱包和 Key 的创建属于控制台管理流程。

## 业务调用

把所选片段放入已连接的 `run` 中；校验对应资源 ID 不为空。

### 数据解密

```go
plaintext, err := sdk.DecryptStoredData(ctx, keyDataId)
if err != nil {
    return fmt.Errorf("解密数据失败: %w", err)
}
defer clear(plaintext)
// 在内存中使用 plaintext；不打印其内容。
```

### 钱包私钥导出

额外导入 `"github.com/jaronnie/mpcium-go/types"`。EVM 的 `keyType` 为 `types.KeyTypeSecp256k1`，Solana 为 `types.KeyTypeEd25519`。

```go
privateScalar, err := sdk.ExportWallet(ctx, walletID, keyType)
if err != nil {
    return fmt.Errorf("导出钱包私钥失败: %w", err)
}
defer clear(privateScalar)
// 在内存中使用 privateScalar；不打印私钥。
```

### 在线签名

额外导入 `"github.com/google/uuid"` 和 `"github.com/jaronnie/mpcium-go/types"`。`message` 是按下文规则准备的真实业务输入。EVM 测试消息可通过 `crypto.Keccak256([]byte(testMessage))` 准备；此时添加 `github.com/ethereum/go-ethereum/crypto` 导入及 `github.com/ethereum/go-ethereum@v1.16.5` 依赖。Solana 使用 `[]byte(testMessage)`，无需该依赖。

```go
result, err := sdk.SignTransaction(ctx, &types.SignTxMessage{
    WalletID: walletID,
    KeyType: keyType,
    NetworkInternalCode: network,
    TxID: uuid.NewString(),
    Tx: message,
}, walletPublicKeyHex)
if err != nil {
    return fmt.Errorf("在线签名失败: %w", err)
}
// result.Signature 已由 SDK 验证，可交给后续业务使用；不自动广播。
```

- 在线签名由 SDK 检查请求/结果关联、固定钱包公钥与消息，完成验签和 ECDSA low-S、恢复位校验。成功后直接使用 `result.Signature`，不在业务示例再实现 `verifiedSignature` 或手动拼接 R/S。
- 公钥来自用户指定钱包的可信元数据，不能从待验证的签名结果里取得。签名 API 的第三个参数是钱包公钥，不是 NATS token。
- EVM 使用 `types.KeyTypeSecp256k1`，签名输入是业务构造的 32 字节摘要；测试示例仅对测试消息计算 Keccak256 摘要。Solana 使用 `types.KeyTypeEd25519`，输入是完整消息。为真实交易签名时保留用户指定的链、编码和交易内容，不把测试消息摘要当成交易。
- 导出时明确传 `keyType`，尤其是 Solana。同一钱包 ID 的节点存储可能同时存在两种曲线数据。Ed25519 导出值是 32 字节 MPC 标量，不是 seed，不能直接当作 Phantom 或 solana-keygen keypair。EVM 导出值是 secp256k1 私钥标量。
- `defer credentials.Close()`、`defer sdk.Close()`；使用完明文和私钥后 `clear`。默认不打印、保存明文或私钥。用户明确请求导出文件时，使用受保护的目标文件而不是日志或版本库。

## 示例写法和验证

使用 `main` 调用 `run() error`；在操作处返回带上下文的错误，由入口输出错误并退出。不要使用 `must`、`panic` 或“请填写 main.go 顶部”这样的错误提示。对缺失参数说明参数名称即可。实际产品可改用用户已有的配置或秘密管理方式，不强制使用常量配置。

先编译验证代码；用户要求真实验证时，再使用已授权的线上或测试资源执行所选场景。编译通过不能报告为真实操作成功。解密应核对实际内容；导出不能只检查长度，应核对对应曲线的固定钱包公钥；签名直接检查 SDK 调用成功，不再在业务入口复制验签实现。报告使用的 SDK 版本、实际验证结果及是否广播。

复用用户已授权的测试范围。不要为了通过测试擅自修改资源白名单、轮换凭据、创建或销毁用户资源。用户授权使用临时资源时，清理自己创建的资源，并保留期间新增的其他用户资源。在线签名不自动代表获准广播交易。

## 错误边界（v0.5.0）

- 连接返回 `authorization violation`：核对凭据、token 是否轮换、是否存在有效资源，以及来源 IP 是否获准；不能仅凭错误认定唯一原因。
- 已连接但发布出现 `Permissions Violation`：其他资源允许连接，不代表目标资源获准。核对目标 `walletID` / `keyDataId`，不要通过扩大白名单或内部账号绕过。
- 权限拒绝后可能等 45–60 秒才返回：NATS 通过异步回调报告发布权限错误，当前 SDK 仍等待业务回复，未关联该错误提前结束。数据/导出通常约 45 秒，签名示例约 60 秒；服务端已经拒绝，不是在继续执行请求。升级 SDK 后应重新核对这一限制。
- 单看 `context deadline exceeded` 不能认定权限拒绝或操作已回滚。签名可能已经开始，不自动重新提交签名或创建请求。
- TLS `EOF` 或证书错误不是 IP 拒绝证据。保持 TLS 验证，核对地址与网络；确认发生在提交前，才按授权重连。
- 签名与固定公钥不匹配时只处理错误，不交付签名，不用返回数据替换可信公钥。
- Solana 导出不能只核对 32 字节长度；必须明确指定 Ed25519，入口和节点也需支持导出请求的 `key_type`。
- 凭据解锁失败时区分 Base64 格式与密码/age 错误。重新导出会轮换 token，不是无副作用的默认排查步骤。

报告时区分“服务端何时拒绝”和“调用方何时收到错误”。不要给签名或创建操作添加隐式重试。
