# FlutifyPS

[Flutify](https://github.com/is-hp-is-mad/Flutify) 的可选自建反代服务。将它部署在能够连接 Spotify 的服务器上，再把入口地址和凭据填入 Flutify，即可让受支持的 Spotify 请求通过该服务器转发。

**能直接使用 Flutify 的用户无需部署本项目。** FlutifyPS 适合需要自建 Spotify 网络入口、或集中管理服务器出口的用户。它不包含播放器，不提供音乐资源，也不替代 Spotify 账号、订阅或设备 DRM 能力。

[部署](#部署) · [接入 Flutify](#接入-flutify) · [常见问题](#常见问题) · [客户端开发文档](INTEGRATION.md)

## 可以做什么

- 转发 Spotify API、封面与音频等媒体请求，支持 Range 分段下载。
- 转发 Spotify Connect 使用的 WebSocket 和接入点连接。
- 使用同一组用户名、密码和入口路径鉴权，限制可访问的上游域名。
- 服务器可直接出站，也可使用 HTTP CONNECT、HTTPS CONNECT 或 SOCKS5 出口。
- 零第三方运行依赖，支持 Node.js 22 / 24 与 Docker 部署。

网页登录和授权仍由 Flutify 的官方登录流程完成。FlutifyPS 不是通用网页代理；默认拒绝上游标记为 HTML 的响应。

## 部署

准备一台能够连接 Spotify 的服务器、一个域名及其 HTTPS 证书。新用户推荐 Docker；已有 Node.js 和 systemd 环境也可直接运行。

以下命令从项目源码目录执行。普通部署与 Docker 二选一；暂不提供预构建镜像，Docker 使用源码构建。

### 方式一：Docker Compose

安装 [Docker Engine 与 Compose](https://docs.docker.com/engine/install/)，将源码放到服务器后执行：

```bash
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -w /work flutifyps:local node scripts/gen-env.js
mkdir -p cert
```

生成器会创建 `.env`，且不会覆盖已有文件。把证书链放入 `cert/server.crt`，私钥放入 `cert/server.key`，然后允许容器中的非 root 用户读取：

```bash
sudo chown root:10001 .env cert cert/server.key cert/server.crt
sudo chmod 640 .env cert/server.key
sudo chmod 750 cert
sudo chmod 644 cert/server.crt
docker compose up -d
docker compose logs --tail=50 flutifyps
```

默认将宿主机 `443` 映射到容器的 HTTPS `8443`。配置与证书以只读文件挂载，镜像中不包含凭据；修改它们后运行 `docker compose restart flutifyps`。证书目录整体挂载，续期后重启服务即可加载新证书。

如果服务器的 443 已被 Nginx/Caddy 占用，修改 `compose.yaml` 的端口映射为 `127.0.0.1:18443:8443`，再让前置服务转发至该 HTTPS 端口，并启用 WebSocket 升级。前置服务在容器内时，需要使用共同的 Docker 网络或可访问的宿主机地址。

### 方式二：Node.js + systemd

安装受支持的 Node.js 22 或 24（`node --version` 检查版本），将源码放到 `/opt/flutifyps`。无须执行 `npm install`。

```bash
cd /opt/flutifyps
node scripts/gen-env.js
sudo useradd --system --user-group --home-dir /nonexistent --shell /usr/sbin/nologin flutifyps
```

放入 `cert/server.crt` 和 `cert/server.key` 后，设置权限并安装服务：

```bash
sudo chown -R root:flutifyps /opt/flutifyps
sudo chmod 750 /opt/flutifyps /opt/flutifyps/cert
sudo chmod 640 /opt/flutifyps/.env /opt/flutifyps/cert/server.key
sudo install -m 644 deploy/flutifyps.service /etc/systemd/system/flutifyps.service
sudo systemctl daemon-reload
sudo systemctl enable --now flutifyps
sudo systemctl status flutifyps
```

模板使用 `/usr/bin/node`；如果 `command -v node` 返回其他路径，请先修改服务的 `ExecStart`。服务以 `flutifyps` 用户运行，仅授予绑定低端口的能力。日志使用 `journalctl -u flutifyps -n 50` 查看。

证书续期后，将新证书复制到上述路径，恢复所有者及权限，再执行 `sudo systemctl restart flutifyps`。不要给服务用户整个证书管理目录的读权限。

### 本地试运行

安装 Node.js 22 / 24 和 OpenSSL 后：

```bash
node scripts/gen-env.js
bash scripts/gen-cert.sh
```

Windows 生成证书使用 `powershell -ExecutionPolicy Bypass -File scripts/gen-cert.ps1`。生成器仅创建 localhost 开发证书，拒绝覆盖已有证书。

在 `.env` 中加入以下两行，再执行 `node server.js`：

```dotenv
PROXY_LISTEN_HOST=127.0.0.1
PROXY_LISTEN_PORT=8443
```

自签证书只适合本地验证；Flutify 正式连接应使用设备信任的 HTTPS 证书。

## 接入 Flutify

打开 Flutify 的 **设置 → 网络 → Spotify 反代**，按下面的对应关系填写：

| Flutify 中的选项 | 填写内容 |
|---|---|
| 反代地址（包含路径） | `https://你的域名/入口路径`，非 443 端口时带上端口 |
| 反代用户名 | `.env` 中 `PROXY_AUTH_USERNAME` 的值 |
| 反代密码 | `.env` 中 `PROXY_AUTH_PASSWORD` 的值 |

入口路径是 `.env` 中的 `PROXY_DISGUISE_PATH`。例如值为 `assets-example`，地址就是 `https://music.example.com/assets-example`，不要额外加上 Spotify 域名或 `__ping`。

保存后可手动开启反代，也可启用自动切换：Flutify 使用 Cloudflare trace 的 `loc` 判断当前网络出口国家/地区。允许直连的国家/地区代码留空时，CN 开启反代，其余直连；填写 `US,JP,HK` 等代码后，仅列表中的国家/地区直连，其余开启反代。查询失败时保持当前线路。此判断发生在客户端，与服务器出口的国家/地区是两回事。

部署者可以把入口地址和凭据交给需要使用它的用户；请通过可信渠道分享，不要写入公开 README、Issue 或截图。

## 配置与出口

配置优先级为 **进程环境变量 → `.env` → `config.json` → 内置默认值**。相对文件路径以配置文件所在目录为基准。修改配置后需重启服务。

通常只需修改 `.env`，完整模板见 [.env.example](.env.example)：

| 配置项 | 用途 |
|---|---|
| `PROXY_AUTH_USERNAME`、`PROXY_AUTH_PASSWORD` | 必填；密码至少 8 个字符且不能是纯数字 |
| `PROXY_DISGUISE_PATH` | 入口路径的第一段，推荐随机值 |
| `PROXY_LISTEN_HOST`、`PROXY_LISTEN_PORT` | 监听地址、HTTPS 端口 |
| `PROXY_TLS_KEY`、`PROXY_TLS_CERT` | 私钥和证书链路径 |
| `PROXY_UPSTREAM_PROXY` | 可选服务器出口代理，留空时直连 |
| `PROXY_LOG_LEVEL` | `error` / `warn` / `info` / `debug`，默认 `warn` |

例如服务器本机已有 SOCKS5 出口：

```dotenv
PROXY_UPSTREAM_PROXY=socks5://127.0.0.1:40000
```

也支持 `http://代理地址:端口`、`https://代理地址:端口`，以及 URL 编码的 `用户名:密码@`。HTTP 和 SOCKS5 本身不加密代理认证及隧道外层；跨主机使用时应放在可信网络或加密通道内。HTTPS CONNECT 会校验代理证书。

**Docker 中的 `127.0.0.1` 指向容器自身。** 要连接宿主机出口，使用可达的宿主机地址，并限制出口监听及防火墙范围。WARP 是可选出口，是否能连接 Spotify 取决于实际网络与账号国家/地区，不保证解除访问限制。

并发、超时、域名白名单和隧道配置见 [config.json](config.json)。默认配置即可支持 Flutify 的常用请求；不要为方便而开放任意域名、IP 或端口。

### 前置反代 / CDN

- 前置服务需保留请求路径、查询参数和两项鉴权头，并支持 WebSocket；关闭该入口的缓存，避免缓存账号或媒体响应。
- 前置服务到 FlutifyPS 也使用 HTTPS，并验证源站证书。仅通过 CDN 访问时，限制源站端口的入站来源。
- 默认以直接连接的 IP 作为来源。确需使用转发 IP 时，在 `security.trustedProxies` 填入可信前置服务的 IP/CIDR，并设置 `realIpHeader`（`cf-connecting-ip`、`x-real-ip` 或 `x-forwarded-for`）。前置服务必须覆盖客户端传入的对应头。
- CDN 通常只能转发 WebSocket 升级，Flutify 的 TCP 接入点应使用 WebSocket 载体。其他客户端的握手格式见 [INTEGRATION.md](INTEGRATION.md)。

## 常见问题

**如何确认已经启动？**

请求 `https://你的域名/入口路径/__ping`，携带 `X-Proxy-User` 和 `X-Proxy-Pass` 请求头。成功返回 `{"ok":true}`。直接在浏览器打开地址没有鉴权头，看到 404 是正常行为。健康检查只验证入口与凭据，不能证明服务器已能访问 Spotify。

**一直是 404？**

先核对路径、用户名、密码以及前置服务是否传递鉴权头。目标不在白名单、HTML 被拦截也会返回伪装页；Spotify 自身的业务接口同样可能返回真正的 404。不要仅凭状态码判断故障位置。

**入口可用但仍播放失败？**

检查服务器出口、Spotify 账号状态和客户端日志。FlutifyPS 不改变订阅权限或解密能力。502/504 通常需要排查服务器到上游的连接；媒体传输中断应由客户端重试。

**升级会改变入口和密码吗？**

保留原 `.env`、证书和部署配置，不要重新生成凭据。先备份代码、配置与服务文件，在独立端口验证新版，再替换并重启；失败时恢复备份。Docker 部署重新执行 `docker compose build` 和 `docker compose up -d`，systemd 部署更新代码后重启服务。

**数据会保存到服务器吗？**

本项目不持久化音频、账号 token 或请求体；音频缓存由 Flutify 客户端管理。服务转发时会在内存中处理数据；日志、CDN 和前置服务的记录策略由部署者管理。HTTPS 在网关终止，部署者能够接触转发数据，因此只连接自己信任的网关。

## 开发与反馈

```bash
npm test
npm run check:public
```

测试需要 OpenSSL，使用本地临时证书和模拟上游，不需要真实 Spotify 账号。协议说明见 [INTEGRATION.md](INTEGRATION.md)，贡献流程见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全边界及报告方式见 [SECURITY.md](SECURITY.md)。

## 许可证与致谢

[MIT License](LICENSE)。FlutifyPS 是社区项目，与 Spotify AB 无关联；使用时遵守相关服务条款及当地法律。

感谢 [LINUX DO](https://linux.do) 社区的支持。
