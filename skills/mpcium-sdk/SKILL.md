---
name: mpcium-sdk
description: 使用 MPCium Go SDK 编写或排查加密 Key 数据解密、EVM/Solana 钱包私钥导出和在线 MPC 签名。适用于项目加密凭据、资源 IP 白名单及这三个业务示例的接入，不用于部署 MPC 集群或普通链上 RPC 交易广播。
---

# MPCium SDK 接入

按用户所选业务复制一个独立示例，保留最少调用代码。示例固定使用 `github.com/jaronnie/mpcium-go v0.5.0`，不是上游同名项目的任意版本。使用 Go 1.25.8 或更高版本；保留随附 module 的依赖约束，勿在生成的业务代码中使用本地 `replace`。

## 选择示例

只读取当前业务需要的模板：

- 解密已保存数据：[assets/examples/data/main.go](assets/examples/data/main.go)。参数是 `keyDataId`，不是钱包 ID 或项目 ID。
- 钱包私钥导出：[assets/examples/export-wallet/main.go](assets/examples/export-wallet/main.go)。填写 `walletID` 和 `keyType`。
- 在线签名：[assets/examples/online-sign/main.go](assets/examples/online-sign/main.go)。填写 `walletID`、固定的 `walletPublicKeyHex`、`keyType`、`network` 和待签名内容。

三个模板都可独立使用；共享的 [go.mod](assets/examples/go.mod) 和 [go.sum](assets/examples/go.sum) 只提供依赖，不存在共享业务初始化代码。复制对应目录及 module 到用户工作区，再按实际任务调整。未经填写的占位参数不能当成真实测试输入。

## 项目凭据与连接

使用以下命名：`natsURL`、`projectID`、`projectCredentialsBase64`、`projectCredentialsPassword`。资源参数使用 `keyDataId`、`walletID`、`walletPublicKeyHex`。

`projectCredentialsBase64` 是完整 age 加密项目凭据包的 Base64 文本，包含项目签名身份、可信节点公钥和 NATS 访问 token。Base64 自身不提供加密。凭据与密码由用户指定或从当前任务已授权的秘密来源读取；需要的信息缺失时只询问缺失项。不要把真实秘密写进 skill、版本库、日志或结果报告。

按模板完成 Base64 解码、`UnlockCredentialsBytes` 和项目 ID 校验，再连接：

```go
sdk, err := client.ConnectAccess(ctx, natsURL, credentials)
```

不设置单独的 `natsToken`，不向 `ConnectAccess` 传空 token 参数。不向使用资源 IP 控制的业务客户端暴露内部 NATS 用户、共享 token、JetStream 权限或节点管理凭据。SDK 使用 NATS TLS 地址直接访问节点，不需要业务运行时登录控制台或填写动态码。

每个钱包或 Key 独立检查 SDK 来源 IP，白名单为空表示拒绝；项目没有 IP 白名单或继承规则。使用服务端实际看到的公网出口 IP。拿到项目凭据不代表可以访问该项目所有资源。SDK 凭据只授权已登记资源，钱包和 Key 的创建属于控制台管理流程。

## 业务调用

```go
plaintext, err := sdk.DecryptStoredData(ctx, keyDataId)
privateScalar, err := sdk.ExportWallet(ctx, walletID, keyType)
result, err := sdk.SignTransaction(ctx, request, walletPublicKeyHex)
```

三个调用分别对应不同场景，不要为了完成一个场景附带执行其他敏感操作。

- 在线签名由 SDK 检查请求/结果关联、固定钱包公钥与消息，完成验签和 ECDSA low-S、恢复位校验。成功后直接使用 `result.Signature`，不在业务示例再实现 `verifiedSignature` 或手动拼接 R/S。
- 公钥来自用户指定钱包的可信元数据，不能从待验证的签名结果里取得。签名 API 的第三个参数是钱包公钥，不是 NATS token。
- EVM 使用 `types.KeyTypeSecp256k1`，签名输入是业务构造的 32 字节摘要；模板仅演示测试消息的 Keccak256 摘要。Solana 使用 `types.KeyTypeEd25519`，输入是完整消息。为真实交易签名时保留用户指定的链、编码和交易内容，不把测试消息摘要当成交易。
- 导出时明确传 `keyType`，尤其是 Solana。同一钱包 ID 的节点存储可能同时存在两种曲线数据。Ed25519 导出值是 32 字节 MPC 标量，不是 seed，不能直接当作 Phantom 或 solana-keygen keypair。EVM 导出值是 secp256k1 私钥标量。
- `defer credentials.Close()`、`defer sdk.Close()`；使用完明文和私钥后 `clear`。默认不打印、保存明文或私钥。用户明确请求导出文件时，使用受保护的目标文件而不是日志或版本库。

## 示例写法和验证

使用 `main` 调用 `run() error`；在操作处返回带上下文的错误，由入口输出错误并退出。不要使用 `must`、`panic` 或“请填写 main.go 顶部”这样的错误提示。对缺失参数说明参数名称即可。实际产品可改用用户已有的配置或秘密管理方式，不强制沿用模板的常量配置。

先编译验证代码；用户要求真实验证时，再使用已授权的线上或测试资源执行所选场景。编译通过不能报告为真实操作成功。解密应核对实际内容；导出不能只检查长度，应核对对应曲线的固定钱包公钥；签名直接检查 SDK 调用成功，不再在业务入口复制验签实现。报告使用的 SDK 版本、实际验证结果及是否广播。

复用用户已授权的测试范围。不要为了通过测试擅自修改资源白名单、轮换凭据、创建或销毁用户资源。用户授权使用临时资源时，清理自己创建的资源，并保留期间新增的其他用户资源。在线签名不自动代表获准广播交易。

权限拒绝、超时、TLS 连接错误、错误公钥等情况，按 [references/errors.md](references/errors.md) 处理。不要给签名或创建操作添加隐式重试。
