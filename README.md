# vl-core — 精简 VLESS 核心

[![CI](https://github.com/purepoorx/vl-core/actions/workflows/ci.yml/badge.svg)](https://github.com/purepoorx/vl-core/actions/workflows/ci.yml) [![Release](https://github.com/purepoorx/vl-core/actions/workflows/release.yml/badge.svg)](https://github.com/purepoorx/vl-core/actions/workflows/release.yml)

从 [XTLS/Xray-core](https://github.com/XTLS/Xray-core) 的 `proxy/vless` 中把 **VLESS 协议**单独抽出来，用纯 Go 标准库重写成一个可独立编译、可运行、零第三方依赖的核心。

实现时逐行对照了官方源码的字节语义：`proxy/vless/encoding/encoding.go`、`encoding/addons.go`、`validator.go`、`common/protocol/address.go`、`inbound/inbound.go`、`outbound/outbound.go`。

**互通已实测**：用源码编译的官方 Xray `26.10.31` 做了 8 组双向交叉验证（raw TCP、UDP、WebSocket × 客户端/服务端两个方向，以及 WebSocket 0-RTT 双向），全部通过。

---

## 为什么不是直接复制目录

官方 `proxy/vless/` 约 3600 行，但真正的协议编解码只有 `encoding/` 下约 400 行，其余全部是对 Xray 框架的胶水：`common/buf`、`common/net`、`common/session`、`common/protocol`、`proxy.Vision`、REALITY、dispatcher、policy、statistics……单独把目录拎出来根本编译不了。

所以这里做的是**协议层重新实现 + 最小运行时重写**：

| 目录 | 内容 | 依赖 |
|---|---|---|
| `protocol/` | VLESS v0 全部 wire format：请求/响应头、UUID、Addons protobuf 子集、地址端口、UDP 分包 | 仅标准库，零外部依赖 |
| `transport/` | 外层传输：raw TCP、TLS、WebSocket（含 WSS），握手/帧编解码手写 | 仅标准库 |
| `core/` | 服务端（VLESS 入站 → 直连）、客户端（SOCKS5 / HTTP CONNECT 入站 → VLESS 出站）、UDP 会话 | 仅标准库 |
| `cmd/vl-core/` | 单二进制 CLI | — |
| `examples/` | 配置示例，含官方 Xray 互通配置 | — |

`protocol` 包完全不碰 socket，可以直接嵌进别的项目。

---

## 协议规范（VLESS v0）

**请求头**（一次性写出，payload 紧随其后）

```
+--------+---------------------------------------------+
| 1 byte | Version = 0x00                              |
|16 bytes| UUID                                        |
| 1 byte | Addons 长度 (0..255)                        |
| N bytes| Addons（protobuf）                          |
| 1 byte | Command                                     |
| 2 bytes| Port，大端                                  |  \ Mux / Rvs
| 1 byte | AddressType                                 |  / 时省略
| N bytes| Address                                     |
+--------+---------------------------------------------+
```

| 字段 | 取值 |
|---|---|
| Command | `0x01` TCP、`0x02` UDP、`0x03` Mux(`v1.mux.cool`)、`0x04` Rvs(`v1.rvs.cool`) |
| AddressType | `0x01` IPv4(4B)、`0x02` 域名(1B 长度 + 内容)、`0x03` IPv6(16B) |
| Addons | proto3 `message Addons { string Flow = 1; bytes Seed = 2; }`；无内容时长度写 `0x00`。未知字段原样保留 |

**响应头**：`Version(1) + AddonsLen(1) + Addons`，之后立刻是 payload。

**UDP**：双向都用 `长度(2B, 大端) + 数据报` 分包；请求头里带目标地址，一条连接对应一个目标。

**UUID 校验**：官方 `vless.ProcessUUID` 会把 UUID 的 `id[6]`、`id[7]` 清零后再查用户表（这两字节被客户端用来携带 `VlessRoute`）。本项目完整复刻了这个行为，否则部分客户端会被误拒。

---

## 快速开始

```bash
go build -o vl-core ./cmd/vl-core

# 生成一个 UUID
./vl-core -gen-uuid

# 终端 A：服务端
./vl-core -c examples/server.json

# 终端 B：客户端（本地 SOCKS5 在 127.0.0.1:1080）
./vl-core -c examples/client.json

# 验证
curl -x socks5h://127.0.0.1:1080 https://example.com
```

常用参数：`-c <配置>`、`-role server|client`、`-listen <地址>`、`-log debug|info|warn|error`、`-gen-uuid`、`-v`。

传输层可切换：`examples/server-tls.json` / `client-tls.json`（TLS）、`server-ws-tls.json` / `client-ws-tls.json`（WebSocket、WSS）。

---

## 与官方 Xray 互通

`examples/xray-server.json` 是官方 Xray 的 VLESS 入站配置，`examples/xray-client.json` 是官方 Xray 的 VLESS 出站配置。

```bash
# 场景 1：官方 Xray 服务端 ← vl-core 客户端
xray run -c examples/xray-server.json
./vl-core -c examples/client.json

# 场景 2：vl-core 服务端 ← 官方 Xray 客户端
./vl-core -c examples/server.json
xray run -c examples/xray-client.json
```

**前提：用户的 `flow` 必须留空**（见下方能力边界）。TCP、TLS、WebSocket/WSS 传输均可互通。

---

## WebSocket 0-RTT

兼容官方 Xray 的 `?ed=2048`：把 VLESS 请求头用 `base64.RawURLEncoding` 放进握手请求的 `Sec-WebSocket-Protocol`，服务端在返回 101 之前就能拿到目标地址，省掉「等握手响应才能发首包」的一个 RTT。**这是 WS 层的 0-RTT，不是 TLS 1.3 的 0-RTT**；TCP / TLS 握手照常。

客户端开启（两种写法等价）：

```json
"transport": {
  "network": "ws",
  "ws": {"path": "/ray", "ed": 2048}
}
```

```json
"ws": {"path": "/ray?ed=2048"}
```

服务端**无需配置**：会自动接收并解析 `Sec-WebSocket-Protocol`（兼容老版 V2Ray 的标准 base64 写法），在 101 中回显，并把解码结果作为连接读流的前缀交给 VLESS 入站。因此现在可以对接开了 `?ed=` 的官方 Xray 客户端；不开 `?ed=` 的客户端照常工作。

行为细节：

- 仅当 `ed > 0` 且 VLESS 请求头长度不超过 `ed` 时启用，否则自动退化为普通握手。
- 只把 VLESS 请求头放进握手，业务首包仍走正常 WS 帧，避免为「服务端先说话」的协议引入等待。
- 解码上限 8192 字节；非法或超长的 header 被忽略，连接退化为普通 WebSocket。
- `Sec-WebSocket-Protocol` 是 HTTP 头：WSS 下虽在 TLS 内，CDN 仍可见且可能改写/记录，也没有 TLS 1.3 early data 的重放保护。CDN 常有 8KB 头长度限制，`ed` 建议 2048。

---

## 作为协议库使用

```go
import "github.com/purepoorx/vl-core/protocol"

// 编码
h := &protocol.RequestHeader{
    Version: protocol.Version,
    UUID:    uuid,                       // protocol.ParseUUID("...")
    Addons:  &protocol.Addons{},         // 空 addons -> 单字节 0x00
    Command: protocol.CommandTCP,
    Address: protocol.ParseAddress("www.example.com", 443),
}
err := protocol.WriteRequestHeader(conn, h)

// 解码（v 是 protocol.Validator，可为 nil 表示不校验用户）
req, err := protocol.ReadRequestHeader(reader, v)
fmt.Println(req.Command, req.Address.String(), req.Addons.Flow)
```

UDP 用 `protocol.WritePacket` / `protocol.ReadPacket`；`protocol.MarshalAddons` / `UnmarshalAddons` 单独可用来处理 `xtls-rprx-vision` 等 Flow 字段。module path 是 `github.com/purepoorx/vl-core`，可以直接 `go get` 后按上面的 import 使用。

---

## 超时与清理

配置里的 `timeouts`，单位都是秒：

| 字段 | 默认 | 作用 |
|---|---|---|
| `handshake` | 15 | 握手阶段的总 deadline |
| `idle` | 0（不限） | 流式会话的空闲 deadline |
| `udpIdle` | 60 | UDP 会话无包即回收，每次收发成功顺延 |
| `halfClose` | 60 | 半关闭后对端完全静默的兜底，每读到数据顺延；负数表示关闭该兜底 |

`halfClose` 只对**无法传播 TCP 半关闭的传输**（WebSocket / WSS）生效，语义见下面能力边界。

---

## 能力边界（重要）

| 已实现 | 未实现 |
|---|---|
| VLESS v0 请求/响应头完整编解码 | **XTLS-RPRX-Vision 数据面**（TLS 记录过滤、splice copy、`proxy.NewVision*`） |
| Addons protobuf（含未知字段保真） | **REALITY**、uTLS 指纹伪装 |
| UUID 校验 + 官方 `ProcessUUID` 规范化 | **VLESS Encryption**（ML-KEM-768 握手、XOR 模式） |
| TCP / UDP 命令；IPv4 / IPv6 / 域名 | Mux、XUDP、Reverse proxy 数据面（仅能解析命令码） |
| UDP 长度分包、多目标会话 | Fallback / 伪装站点、PROXY protocol |
| raw TCP / TLS / WebSocket / WSS | gRPC、QUIC、HTTP/2、mkcp 等传输 |
| SOCKS5（CONNECT + UDP ASSOCIATE）、HTTP CONNECT | 路由、策略、流量统计、DNS 内部解析、UDP full-cone |
| 多用户、握手/会话超时、完整测试 | TLS 1.3 0-RTT、XHTTP H2/H3 |
| WebSocket 0-RTT（`?ed=N` / `ed`，双向互通官方 Xray） | **WS/WSS 传播 TCP 半关闭**（RFC 6455 无此原语） |
| WS 半关闭兜底（`timeouts.halfClose`，默认 60s） | — |

**关键限制**：`Addons.Flow` 可以正确编解码（例如 `xtls-rprx-vision`），但**数据面按普通字节流透传**，没有实现 Vision 的 TLS 握手识别与填充逻辑。因此只能对接 **`flow` 留空** 的官方 Xray 节点；如果服务端用户配置了 `flow: "xtls-rprx-vision"`，官方 Xray 会要求客户端配合 Vision，本项目无法互通。REALITY 节点同理不支持。要连这类节点请直接用官方 Xray。

这几块之所以砍掉，是因为它们深度耦合 Xray 的 TLS 内部 buffer（靠反射访问 `crypto/tls.Conn.input/rawInput`）、REALITY 自定义 TLS 栈和 dispatcher，硬搬到独立核心里既不"精简"也不稳。

另外几个刻意的行为差异：

- 官方把响应头与首个下行包合并 flush 做性能优化；本项目**立即 flush 响应头**，语义等价且更不易踩坑。
- 客户端**上行不等待响应头**（两个方向并发启动），避免与延迟 flush 的服务端实现死锁。
- UDP 采用「每个目标一条 VLESS 连接」，覆盖 DNS 等常见场景，但不做 XUDP 多路复用。
- 每个 SOCKS5 UDP ASSOCIATE 都有自己的 UDP relay socket（端口唯一），并绑定首个合法来源地址，同机多个客户端不会互相读到回包。
- TCP 用会话级 deadline 兜底（`timeouts.idle`，默认不限）；UDP 可能长时间无包，默认 `timeouts.udpIdle=60` 秒回收会话，有流量则顺延。
- **WS/WSS 不支持 TCP 半关闭**。RFC 6455 只有「整个连接关闭」的 Close 帧，没有「我不再发了」的原语，把 `CloseWrite` 映射成 Close 帧会连带掐掉反向数据。因此依赖 FIN 判定结束的协议（FTP 数据连接、HTTP/1.0 无 `Content-Length` 的响应、`nc -N` 之类的管道）在 WS 下拿不到结束信号 —— 这类场景请改用 raw TCP 或 TLS（`*tls.Conn` 实现了 `CloseWrite`）。为避免永久挂起，WS 下单向结束后由 `timeouts.halfClose`（默认 60s，持续有数据则顺延）兜底收尾，官方 Xray 的 WS 传输同样没有半关闭能力。

---

## 测试

```bash
go test ./...
```

覆盖内容：

- `protocol/`：UUID、Addons wire format（含与 `proto.Marshal` 一致的黄金字节、未知字段按 varint/fixed32/fixed64/length-delimited 各 wire type 跳过并保真）、IPv4/IPv6/域名地址 round-trip、**与官方 `EncodeRequestHeader` 等价的请求头黄金向量**、Vision/Mux/Rvs 头、用户校验与路由字节、各类畸形输入、响应头、UDP 分包。
- `transport/`：WebSocket 握手、客户端掩码、大包与部分读、分片消息、ping/pong，以及协议违规拒绝（控制帧 >125 字节、分片控制帧、未掩码客户端帧、RSV 位、非法 close 状态码）。
- `core/`：端到端 TCP echo、HTTP CONNECT、TLS、WebSocket、WSS、SOCKS5 UDP ASSOCIATE、未知 UUID 拒绝，WS 0-RTT 的 TCP / UDP 链路，**同机两个 UDP ASSOCIATE 互不串流**，服务端 UDP 会话按 `udpIdle` 回收，以及 raw TCP 正常传播半关闭 / WS 下由 `halfClose` 兜底收尾。
- `core/xray_interop_test.go`（env-gated，`VL_CORE_XRAY_BIN`）：与官方 Xray 的 8 组交叉互通，含 `?ed=2048` 0-RTT 双向。CI 里有独立的 `interop` job 自动跑这一组。

---

## CI 与发布

两个 GitHub Actions workflow：

- `.github/workflows/ci.yml`：两个 job。
  - `test`：每次 push / PR 跑 `gofmt -l .`、`go build ./...`、`go vet ./...`、`go test ./... -count=1`。
  - `interop`：下载固定版本 `Xray-linux-64.zip`（`XRAY_VERSION`，当前 `v26.10.31`），以 `VL_CORE_XRAY_BIN` 指向它跑 `TestInterop`，保证 8 组官方互通不会只在本地被验证。
- `.github/workflows/release.yml`：推送 `v*` tag（或在 Actions 页手动指定已有 tag）触发。交叉编译 6 个目标（linux / windows / darwin × amd64 / arm64，`CGO_ENABLED=0`、`-trimpath`、`-ldflags "-s -w"`），打包为 `.tar.gz`（Windows 为 `.zip`），生成 SHA256 校验和，并上传到 GitHub Release。手动指定 tag 时 checkout 会用 `ref: inputs.tag || github.ref`，避免拿默认分支 HEAD 构建却发布成旧 tag。

发一个版本：

```bash
git tag -a v0.1.2 -m "v0.1.2"
git push origin v0.1.2
```

Release 资产命名 `vl-core-v0.1.2-<os>-<arch>.tar.gz` / `.zip`，每个资产附带同名 `.sha256`；压缩包内含二进制、`README.md` 和 `examples/`。重复执行 workflow 会用 `--clobber` 覆盖同名资产，不会因 release 已存在而失败。

---

## 许可证

[MIT](LICENSE) © 2026 purepoorx

---

## 来源

协议定义与实现参考 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)（`proxy/vless/`）。本项目是独立的协议学习/嵌入用实现，不是 Xray 的替代品。
