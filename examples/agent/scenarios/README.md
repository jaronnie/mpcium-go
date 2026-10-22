# 三个硬编码入口

每个目录只有一个独立的 `main.go`。编辑顶部常量即可运行，不读取配置文件、环境变量、消息文件，也不弹出密码输入。

```sh
cd examples/agent/scenarios/data
go run main.go
```

共同参数：`natsURL`、`projectID`、`projectCredentialsBase64`、`projectCredentialsPassword`。其中 `projectCredentialsBase64` 为完整 V4 age 凭据包的 Base64 文本，直接在内存中解锁。

| 目录 | 额外常量 | 行为 |
| --- | --- | --- |
| `data` | `keyDataId` | 仅解密节点保存的数据；不打印明文、不改原记录。 |
| `export-wallet` | `walletID` | 将 32 字节私钥标量返回到本地变量，验证长度；不打印私钥、不写文件。 |
| `online-sign` | `walletID`、`walletPublicKeyHex`、`keyType`、`network`、`testMessage` | EVM 对测试消息的 Keccak256 摘要签名；Ed25519 对完整消息签名。验证并显示签名，不广播。 |

示例无需节点配置、manifest、policy、SSH 隧道或客户端证书。Ed25519 导出值是 MPC 标量，不是普通钱包 seed。

SDK 固定使用远端版本 `v0.5.0`。复制单个 main.go 时，一并保留 `go.mod` 与 `go.sum`；不需要其他示例源码。本目录包含三个 main、文档和 Go module，不包含真实秘密。

线上节点和控制台已配套更新；Mac 上已直接通过公网 NATS 验证解密成功。使用当前项目导出的 V4 凭据及节点上保存的密文。数据解密入口为 `data/main.go`，明文只保留在内存变量中。

启用 IP 白名单后请重新导出凭据。示例使用 ConnectAccess，访问 token 在 age 密文内，不需要再填写共享 NATS token。

钱包交易签名使用 `SignTransaction(ctx, request, walletPublicKeyHex)`，SDK 内部完成验签、ECDSA low-S 归一化与恢复位校验，成功返回的 `result.Signature` 可直接使用。导出 Solana 钱包使用 `ExportWallet(ctx, walletID, types.KeyTypeEd25519)`，EVM 使用 `types.KeyTypeSecp256k1`。
