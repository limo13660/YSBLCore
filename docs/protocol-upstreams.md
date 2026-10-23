# 协议上游同步记录

本文记录 YSBLCore 中 Naive、Brook 和 Juicity 协议适配层对应的官方上游版本。同步时应保留 Mihomo 的 outbound 接口和 YSBLCore 的客户端扩展，不要直接把完整的官方客户端仓库复制到核心中。

## Naive

- 上游封装：`https://github.com/SagerNet/cronet-go`
- 分支：`main`
- 当前提交：`049f2909701ca088c9569f6b303bba5376a2b2ff`
- Go module：`github.com/sagernet/cronet-go v0.0.0-20260912091555-049f2909701c`
- NaiveProxy 原始项目：`https://github.com/klzgrad/naiveproxy`

YSBLCore 使用 Cronet Go wrapper 连接 Naive，不直接编译或嵌入 NaiveProxy 的完整 C++ 客户端。更新 wrapper 后需要同时检查 `with_naive` 构建和各平台 Cronet 动态库加载。

## Brook

- 官方仓库：`https://github.com/txthinking/brook`
- 分支：`master`
- 当前上游提交：`5ad0c40c361437dc9d8c4407e09c647d9b7b0e47`
- 当前最新发布标签：`v20270101` (`3dae422429a65df8421aa4537167c5151d045f0f`)

核心中的 `transport/brook` 是 Mihomo 需要的轻量协议适配层，不是官方 Brook 完整程序。当前 TCP/UDP 帧、AES-GCM、HKDF、nonce 和时间戳规则已按官方 `protocol/brook-server-protocol.md` 核对；更新官方协议后应继续运行 `transport/brook` 测试，并保持 `adapter/outbound/brook.go` 的接口不变。

## Juicity

- 官方仓库：`https://github.com/juicity/juicity`
- 分支：`main`
- 当前上游提交：`412dbe43e091788c5464eb2d6e9c169bdf39f19c`
- 当前最新稳定标签：`v0.5.0` (`88dbf4f8efc54d70caf319ec79d0b7f12d70faf1`)

核心中的 `transport/juicity` 是 Mihomo 专用传输适配层。认证使用 UUID、密码和 TLS ExportKeyingMaterial，TCP/UDP network 类型及 UDP-over-stream 帧格式与官方 `docs/spec.md` 一致。由于 quic-go 不暴露对端动态 stream 上限，客户端每条 QUIC 连接最多复用 30 条请求 stream，达到上限后为新请求建立连接；旧连接保留到已有 stream 关闭。

## 同步检查

同步任一上游后至少运行：

```sh
go test ./transport/brook ./transport/juicity ./adapter/...
go test ./...
go test -tags with_naive ./...
```

客户端 GitHub Actions 每次构建会从 `YSBL_CORE_REPOSITORY` 的 `YSBL_CORE_REF`（当前为 `main`）强制 fetch 最新远程分支，并以该提交构建，不使用仓库中固定的子模块指针。
