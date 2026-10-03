# FlutifyPS 客户端接入

普通使用者请从 [README](README.md#接入-flutify) 开始。本页用于实现或调试兼容客户端。[Flutify](https://github.com/is-hp-is-mad/Flutify) 已内置接入支持。

## 入口和认证

客户端保存 HTTPS 基础地址，例如 `https://music.example.com/assets-example`，以及独立的网关用户名和密码。每个 HTTP 请求、WebSocket 握手和 TCP 隧道握手都必须包含：

```http
X-Proxy-User: <网关用户名>
X-Proxy-Pass: <网关密码>
```

网关在发送上游请求前移除这些头。Spotify 的 `Authorization` 保留，用于 Spotify 自身的认证。不要把网关密码放到查询参数、Cookie 或 Basic Authorization 中。

## 请求映射

| 流量 | 原地址 | 网关地址 |
|---|---|---|
| API | `https://api.spotify.com/v1/me` | `https://music.example.com/assets-example/api.spotify.com/v1/me` |
| 封面 / 音频 | `https://i.scdn.co/image/…` | `https://music.example.com/assets-example/i.scdn.co/image/…` |
| Connect WebSocket | `wss://dealer.spotify.com/?access_token=…` | `wss://music.example.com/assets-example/dealer.spotify.com/?access_token=…` |
| 健康检查 | — | `https://music.example.com/assets-example/__ping` |

只映射客户端已确认需要经过网关的 Spotify 请求，保留编码后的路径与查询参数。创建新的请求对象，不要尝试修改 Dart `http.Request.url` 等不可变属性。上游域名仍须通过服务端白名单；响应中的 URL 不会被自动改写。

API 和媒体走 HTTPS，支持 Range / 206。默认不开放任意 IP 或自定义端口。`open.spotify.com` 仅有 token/server-time 的窄路径例外，Google provisioning 也仅有专用路径例外；这不意味着允许代理这些站点的网页。登录页面仍走客户端的官方授权流程。

## WebSocket 和 TCP 接入点

普通 WebSocket 反代使用标准 RFC 6455 握手。服务端校验上游升级响应和 `Sec-WebSocket-Accept`，过滤逐跳头、改写 Cookie 后转发握手；升级后的帧字节直接双向转发。

TCP 接入点通过以下地址建立：

```text
/<入口路径>/__tunnel/<接入点域名>:<端口>
```

目标由独立的 `tunnel.hosts` 和 `tunnel.allowedPorts` 控制。默认允许 Spotify 接入点域名形态和 4070、443、80 端口，连接仍需执行上游协议本身的认证。

直接连接网关可发送 `Connection: Upgrade`、`Upgrade: tcp-tunnel`。网关返回 `HTTP/1.1 200 Connection Established` 后，按原始 TCP 字节流读写。

通过 CDN 使用 `Upgrade: websocket`，带标准的版本 13 与随机 `Sec-WebSocket-Key`。收到 101 后：

- 客户端将 TCP 数据封装为带掩码的二进制帧；服务端返回不带掩码的二进制帧。
- 帧边界不是上游协议消息边界，收到的数据应作为连续字节流处理。
- 支持二进制分片及 ping/pong/close，拒绝文本、未掩码客户端帧及不合法控制帧。
- 默认单帧及分片消息总量不超过 1 MiB；大数据应分批发送。
- 转发有背压；空闲连接受 `wsIdleMs` / `tunnelIdleMs` 超时限制。

## Cookie、错误和重连

Cookie 默认剥离 `Domain`，将 `Path` 限定到入口路径及上游域名段。路径区分只便于路由，不能作为浏览器安全隔离；请使用客户端独立 Cookie 容器，不要把不同用户的会话混用。

鉴权失败、路径或目标被拒绝通常返回 404 伪装页；不合法 HTTP framing 可在 Node 解析阶段返回 400。上游业务错误按原状态返回。响应开始前的连接错误可返回 502/504；响应开始后的故障终止流，不向媒体字节后追加错误文本。

客户端应区分认证失败、业务限流与短暂网络中断，遵循 Spotify 的重试提示。重建 WebSocket/隧道时需重新带网关鉴权头。关闭请求时一并释放底层连接，避免后台残留下载。

## 证书和日志

生产环境验证网关证书与主机名，不能因反代而全局关闭证书校验。不要将访问 token、网关密码、完整授权 URL 或 Cookie 写入日志及 Issue。`__ping` 成功仅说明网关可达且凭据有效，实际连通性需再验证 API、媒体和长连接。
