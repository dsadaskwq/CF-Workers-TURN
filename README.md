# CF-Workers-TURN

基于 Cloudflare Workers 的 TURN 中继实验项目。它利用 Workers `cloudflare:sockets` 连接公开 TURN Server，通过 TURN TCP relay 或 TURN UDP relay 把 VLESS/WebSocket 流量转发到目标地址。

核心突破点：**Cloudflare Workers 没有原生 UDP socket，但 TURN 本身就是为中继 UDP/TCP 流量设计的协议。** 通过 TURN UDP relay，Worker 可以把客户端的 UDP/XUDP 流量封装成 STUN `SendIndication`，交给 TURN Server 从公网发出，再用 `DataIndication` 收回响应。

也就是说，Workers 仍然没有直接获得 UDP socket；但可以借助 TURN Server 的标准中继能力，构造出一条可用的 UDP 出口路径，用于 DNS、UDP ping、QUIC 等原本 Workers 无法直接处理的场景。

> 这是协议研究和验证代码，用来探索 STUN/TURN 作为 TCP/UDP 出口的可行性。实际可用性取决于 TURN Server 配置、认证方式、网络质量和 Cloudflare Workers 运行时限制。

## 功能特性

- 支持 VLESS over WebSocket 入口。
- 支持 TURN TCP relay：`Allocate → CreatePermission → Connect → ConnectionBind`。
- 支持 TURN UDP relay：`SendIndication / DataIndication`。
- 支持 XUDP 帧解析，用一条 WebSocket 复用 UDP 会话。
- 支持扫描公网 TURN/STUN 服务并验证中继能力。
- 支持弱凭据检测和无认证 TURN 识别。

## 文件结构

| 文件 | 说明 |
| --- | --- |
| [Turn.js](./Turn.js) | Worker 版 TURN TCP relay，面向 VLESS `cmd=1` TCP 流量。 |
| [Turn_XUDP.js](./Turn_XUDP.js) | Worker 版 TURN TCP + UDP relay，增加 XUDP / FakeIP / UDP 场景支持。 |
| [turn_scan.go](./turn_scan.go) | TURN/STUN 批量扫描与中继验证工具。 |
| [turn_results.txt](./turn_results.txt) | 扫描结果样例或本地输出文件。 |

## 协议背景

STUN 用于让 NAT 后客户端发现自己的公网映射地址。TURN 在 STUN 基础上增加中继能力：当直连或打洞不可用时，客户端可以让 TURN Server 代为转发流量。

本项目主要使用 TURN 的 relay 能力，而不是只做 STUN 地址探测。

## 为什么 TURN 对 Workers 特别关键

Cloudflare Workers 的 `connect()` 提供 TCP 出站能力，但没有原生 UDP socket。普通 Worker 代码无法直接发起 DNS/QUIC/UDP ping 这类 UDP 流量。

TURN 的价值在这里被放大：

```text
客户端 UDP/XUDP
  → WebSocket/VLESS
  → Cloudflare Worker
  → TURN UDP allocation
  → SendIndication(peer, payload)
  → TURN Server 从公网向目标发送 UDP
  ← DataIndication(peer, payload)
  ← Worker 回传给客户端
```

这不是绕过协议，而是复用 TURN 的标准 relay 语义：Worker 只需要能用 TCP 连接 TURN Server，真正的 UDP 发送和接收由 TURN Server 完成。

因此 `Turn_XUDP.js` 的意义不只是“多支持了 UDP”，而是把 Workers 原本缺失的 UDP 出口能力转化为：

- 客户端侧仍然走 WebSocket；
- Worker 内部仍然只使用可用的网络能力；
- UDP 出口由 TURN Server 承担；
- XUDP 在单条 WebSocket 内复用多个 UDP 目标。

这个路径让 Workers 可以实验 DNS、UDP ping、部分 QUIC/UDP 场景。实际效果取决于 TURN Server 是否允许 UDP relay、网络质量和目标协议本身。

### RFC 来源

| RFC | 内容 |
| --- | --- |
| [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) | STUN：Session Traversal Utilities for NAT。 |
| [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) | TURN 原始规范，定义 relay allocations。 |
| [RFC 6062](https://datatracker.ietf.org/doc/html/rfc6062) | TURN TCP allocations，定义 `Connect` / `ConnectionBind`。 |
| [RFC 6156](https://datatracker.ietf.org/doc/html/rfc6156) | TURN IPv6 扩展。 |
| [RFC 7065](https://datatracker.ietf.org/doc/html/rfc7065) | STUN/TURN URI scheme。 |
| [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489) | STUN bis，更新 RFC 5389。 |
| [RFC 8656](https://datatracker.ietf.org/doc/html/rfc8656) | TURN bis，更新 RFC 5766。 |

## TURN TCP relay 流程

`Turn.js` 实现的是 TURN TCP allocations，也就是 RFC 6062 路径：

```text
Client --TCP control--> TURN Server
  1. Allocate(REQUESTED-TRANSPORT=TCP)
  2. 401 Unauthorized + REALM + NONCE
  3. Allocate + MESSAGE-INTEGRITY
  4. CreatePermission(peer address)
  5. Connect(peer address)

Client --TCP data--> TURN Server --TCP--> Peer
  6. ConnectionBind(CONNECTION-ID)
  7. 数据连接变成透明 TCP 管道
```

对应代码中的核心 STUN/TURN 消息：

```text
Allocate Request / Success / Error
CreatePermission Request / Success
Connect Request / Success
ConnectionBind Request / Success
```

## TURN UDP relay 与 XUDP

`Turn_XUDP.js` 在 `Turn.js` 基础上扩展 UDP 中继和 XUDP 复用。

TURN UDP relay 路径：

```text
Allocate(REQUESTED-TRANSPORT=UDP)
CreatePermission(peer address)
SendIndication(peer, data)     -> 发送 UDP payload
DataIndication(peer, data)     <- 接收 UDP payload
```

XUDP 帧用于在单条 WebSocket 内承载多个 UDP 目标：

```text
[MetaLen 2B][Meta: flags + network + port + addr][PayLen 2B][Payload]
```

地址类型：

```text
0/1 = IPv4
2   = Domain
3   = IPv6
```

## 认证机制

TURN 长期凭据机制使用 `REALM` / `NONCE` / `MESSAGE-INTEGRITY`：

1. 首次 `Allocate` 可能返回 `401 Unauthorized`。
2. 响应中携带 `REALM` 和 `NONCE`。
3. 客户端使用：

```text
MD5(username:realm:password)
```

生成 HMAC key。

4. 后续 STUN/TURN 消息附加 `MESSAGE-INTEGRITY`，使用 HMAC-SHA1 签名。

`turn_scan.go` 会识别无认证 TURN，也会尝试常见弱凭据，并复用已命中的凭据做 TCP/UDP 中继验证。

## Worker 节点格式

TURN Worker 的 WebSocket path 使用：

```text
/turn://[user:pass@]turn_host:port?ed=2560
```

无认证 TURN：

```text
/turn://turn_host:3478?ed=2560
```

长期凭据 TURN：

```text
/turn://username:password@turn_host:3478?ed=2560
```

VLESS 分享链接模板：

```text
vless://<uuid>@<front-host>:<front-port>/?type=ws&encryption=none&host=<worker-host>&path=%2Fturn%3A%2F%2F%5Buser%3Apass%40%5Dturn_host%3A3478%3Fed%3D2560&security=tls&sni=<worker-host>&fp=chrome&packetEncoding=xudp#TURN
```

## 扫描器

`turn_scan.go` 用于批量发现和验证 TURN/STUN 服务。

工作流程：

```text
TCPing 探活 → STUN/TURN 协议识别 → 认证检测 → TCP/UDP 中继验证 → 输出结果
```

能力：

- 自动识别 STUN/TURN 响应。
- 检测无认证 TURN。
- 尝试常见弱凭据。
- 验证 TURN TCP relay 能否访问 HTTPS 目标并获取出口信息。
- 验证 TURN UDP relay 能否转发 UDP 查询。
- 支持高并发 TCPing 和扫描。
- 输出命中结果到 `turn_results.txt`。

用法：

```bash
./turn_scan [参数] <ip_list.txt | ->
```

参数：

| 参数 | 说明 |
| --- | --- |
| `-c` | 扫描并发数，默认 `100`。 |
| `-p` | TCPing 并发数，默认 `500`。 |
| `-pt` | TCPing 超时秒数，默认 `3`。 |
| `-t` | 扫描超时秒数，默认 `5`。 |
| `-ct` | TURN Connect 超时秒数，默认 `8`。 |

输入格式：

```text
1.2.3.4
1.2.3.4:3478
1.2.3.4:3479
1.2.3.4:5349
```

常见扫描端口：

```text
3478 / 3479 / 5349
```

## FOFA 查询参考

```text
(app="Coturn-Server" || app="coturn-TURN-Server" || header="coturn" || banner="coturn" || port="3479" || port="3478" || port="5349" || server="Citrix" || server="Coturn" || title="TURN Server" || body_hash="-558802108" || body_hash="753498134" || protocol="stun" || "XOR-MAPPED-ADDRESS") && is_domain=false && tls.version="" && protocol!="unknown" && protocol!="ssh"
```

## Turn.js 与 Turn_XUDP.js 对比

| 能力 | Turn.js | Turn_XUDP.js |
| --- | --- | --- |
| VLESS TCP (`cmd=1`) | ✅ | ✅ |
| TURN TCP relay | ✅ | ✅ |
| VLESS UDP (`cmd=3`) | ❌ | ✅ |
| TURN UDP relay | ❌ | ✅ |
| XUDP 复用 | ❌ | ✅ |
| FakeIP 映射 | ❌ | ✅ |
| DNS / QUIC 等 UDP 场景 | ❌ | ✅ |

## 已知限制

- Cloudflare Workers 没有原生 UDP socket；本项目通过 TURN UDP relay 构造 UDP 出口路径。
- 免费或弱认证 TURN Server 随时可能失效。
- TURN Server 是否允许 TCP/UDP relay 取决于服务端配置。
- 扫描结果只能代表当时可用性，不代表长期稳定。
- 本项目是协议研究和验证工具，不保证代理体验。

## 相关链接

- 开源协议：[GPL-3.0](./LICENSE)
- 频道 / 交流群组：<https://t.me/Enkelte_notif>
- STUN RFC 5389: <https://datatracker.ietf.org/doc/html/rfc5389>
- TURN RFC 5766: <https://datatracker.ietf.org/doc/html/rfc5766>
- TURN TCP RFC 6062: <https://datatracker.ietf.org/doc/html/rfc6062>
- TURN bis RFC 8656: <https://datatracker.ietf.org/doc/html/rfc8656>
