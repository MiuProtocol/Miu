<p align="center">
  <img src="assets/miu-logo.svg" width="112" alt="Miu">
</p>

<h1 align="center">Miu</h1>

<p align="center"><a href="README.md">English</a> | 简体中文</p>

<p align="center">
  跑在 TLS 1.3 / REALITY 之上的代理协议:连接池代替多路复用,内层已经是 TLS 1.3 密文的数据不再加密第二遍。
</p>

本仓库是 Miu 的独立 Go 实现:一个库、一个服务端程序 `miu-server`、一个客户端程序 `miu-client`(本地 SOCKS5)。

线上格式与行为要求见 [PROTOCOL.zh-CN.md](PROTOCOL.zh-CN.md)。

## 特点

- **通道池**。一条通道 = 一条 TCP + 外层 TLS + 一次认证,同一时间只跑一条流,流结束后回池给下一条用。
  热通道上开流不握手、不等回包:OPEN 与应用的首批数据在同一个包里发出。没有多路复用,也就没有流控窗口、
  没有流与流之间的队头阻塞,背压完全交给 TCP。
- **内层 TLS 1.3 原样转发**。沿途跟踪内层 TLS 的记录边界,握手过后,内层的密文记录不再套外层加密:
  一条只含 RAW 帧的记录声明字节数,其后原样写在 TCP 上。明文、内层握手的明文部分、TLS 1.2 仍然留在外层加密里。
  Linux 上服务端的下行用 splice,数据不进用户态。
- **中止不废通道**。应用关掉连接时客户端发 RESET,把剩下的下行丢到服务端的 END 为止,通道照样回池。
- 每条流开头的几个包按 padding scheme 整形(AnyTLS 的方案格式,服务端可下发);UDP 走流里的 UoT v2,每个会话独占一条通道。
- 池里取到的通道已经死了(NAT 过期之类)时,还没收到下行、发得不多的流会在新通道上自动重放一次。

## 构建

需要 Go 1.24 或更新的版本。

```sh
go build -o bin/ ./cmd/...
```

得到 `bin/miu-server` 与 `bin/miu-client`。交叉编译照常用 `GOOS` / `GOARCH`(Linux、macOS、Windows 都能编)。

依赖只有两个:[uTLS](https://github.com/refraction-networking/utls)(客户端的浏览器指纹与 REALITY 握手)和
[xtls/reality](https://github.com/xtls/reality)(服务端的 REALITY 握手)。只用 `miu` 这个库包、外层用标准库 TLS 的程序两个都不会链接进去。

## 本机试一下

```sh
# 一个 PSK(任意字符串,至少 16 个字符;两端必须逐字符相同)
openssl rand -base64 32

# 一张自签证书(只为试用;正式使用请换成受信任的证书)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com"
```

`server.json`:

```json
{
  "listen": "127.0.0.1:8443",
  "cert": "cert.pem",
  "key": "key.pem",
  "users": [{"name": "alice", "psk": "<上面生成的 PSK>"}]
}
```

```sh
bin/miu-server -c server.json
# 另开一个终端(自签证书,所以要 -insecure)
bin/miu-client -server 127.0.0.1:8443 -sni example.com -psk '<上面生成的 PSK>' -insecure
# 再开一个终端
curl -x socks5h://127.0.0.1:1080 https://example.com/
```

服务端每开一条流打印一行访问日志:`用户名 客户端地址 -> tcp|udp 目标`。

## 服务端

```sh
miu-server -c server.json [-listen 地址] [-v]
miu-server keygen            # 生成一对 REALITY 密钥
```

外层二选一:证书(TLS 1.3)或 `reality`。示例见 [examples/](examples/)。

外层 TLS 1.3:

```json
{
  "listen": ":443",
  "cert": "/etc/miu/cert.pem",
  "key": "/etc/miu/key.pem",
  "users": [
    {"name": "alice", "psk": "..."},
    {"name": "bob", "psk": "..."}
  ],
  "idleTimeout": 180
}
```

外层 REALITY:

```json
{
  "listen": ":443",
  "reality": {
    "dest": "www.example.com:443",
    "serverNames": ["www.example.com"],
    "privateKey": "<miu-server keygen 输出的 privateKey>",
    "shortIds": ["0123456789abcdef"]
  },
  "users": [{"name": "alice", "psk": "..."}]
}
```

| 字段 | 说明 |
|---|---|
| `listen` | 监听地址,默认 `:443`;命令行 `-listen` 覆盖 |
| `cert` / `key` | 外层 TLS 的证书与私钥(PEM 文件)。只接受 TLS 1.3 |
| `reality.dest` | 伪装目标 `host:port`,必须支持 TLS 1.3。没通过认证的连接原样转发给它 |
| `reality.serverNames` | 客户端可以用的 SNI,应当是伪装目标证书覆盖的名字 |
| `reality.privateKey` | X25519 私钥,base64url 无填充 |
| `reality.shortIds` | 客户端可以出示的 short id,每个是最多 16 位十六进制;可以包含空串 `""` |
| `users` | 用户列表:`name` 只用于日志,`psk` 是凭据(至少 16 个字符,按字符串原样使用,不做 base64 解码) |
| `idleTimeout` | 没有流的通道保留多少秒,默认 180。会下发给客户端 |
| `paddingScheme` | 可选,覆盖内建的包长整形方案,每行一个数组元素,如 `["stop=8", "0=30-30", "1=100-400"]` |

`-v` 额外打印诊断信息(目标连不上、握手失败、认证失败),并在每条流结束时打印一行它搬了多少字节、其中多少走了裸段:

```
alice 198.51.100.7:53124 -> tcp example.org:443 closed: up 496 (raw 0), down 8401247 (raw 8397151)
```

`raw` 不为 0 说明这个方向的发送方认出了内层 TLS 1.3、并且接收方能收裸段——对接别的客户端实现时,这是确认裸段生效最直接的办法。

REALITY 服务端启动后会先探测一次伪装目标(握手之后它还会发些什么,以便照着发),大约需要 5 秒;这期间到达的连接会等它。

不是每个站点都能当伪装目标:个别站点在 REALITY 库照着它握手时会失败(与 miu 无关,同一目标换成别的基于该库的协议一样连不上)。
换目标之后先用 `miu-client` 实际连一次确认。

## 客户端

```sh
miu-client -c client.json [-v]
miu-client -server example.com:443 -psk '...' [-sni 名字] [-insecure] [-fingerprint chrome] [-listen 127.0.0.1:1080]
miu-client keygen            # 同 miu-server keygen
```

本地开一个 SOCKS5 代理(无认证;支持 CONNECT 与 UDP ASSOCIATE),默认 `127.0.0.1:1080`。命令行参数覆盖配置文件里的同名项。

外层 TLS 1.3:

```json
{
  "listen": "127.0.0.1:1080",
  "server": "example.com:443",
  "sni": "example.com",
  "psk": "...",
  "insecure": false,
  "fingerprint": "chrome"
}
```

外层 REALITY:

```json
{
  "listen": "127.0.0.1:1080",
  "server": "203.0.113.10:443",
  "psk": "...",
  "reality": {
    "serverName": "www.example.com",
    "publicKey": "<miu-server keygen 输出的 publicKey>",
    "shortId": "0123456789abcdef"
  }
}
```

| 字段 | 说明 |
|---|---|
| `listen` | 本地 SOCKS5 地址,默认 `127.0.0.1:1080` |
| `server` | 服务端地址 `host:port` |
| `psk` | 与服务端某个用户相同的字符串 |
| `sni` | 外层 TLS 的 SNI,默认取 `server` 的主机名 |
| `insecure` | `true` 时不校验服务端证书(只应在试用自签证书时打开) |
| `fingerprint` | `"chrome"`:ClientHello 换成 Chrome 的(uTLS);不写则是 Go 标准库的 |
| `reality.serverName` | SNI,必须是服务端 `serverNames` 里的一个(不写则取 `sni`) |
| `reality.publicKey` | 服务端的 X25519 公钥,base64url 无填充 |
| `reality.shortId` | 服务端 `shortIds` 里的一个,可以是空串 |

用了 `reality` 时 ClientHello 固定是 Chrome 的,`insecure` 不适用:服务端的身份由握手里的认证确定,
认证不过(公钥、short id 或 SNI 不对)握手直接失败。

## 作为库使用

```go
import "github.com/MiuProtocol/Miu/miu"

// 服务端:自己监听、做完外层握手,把连接交给 Serve。
srv, err := miu.NewServer(miu.ServerConfig{
	Users:    []miu.User{{Name: "alice", PSK: psk}},
	OnAccess: func(a miu.Access) { log.Printf("%s -> %s %s", a.User, a.Network, a.Target) },
})
ln, _ := tls.Listen("tcp", ":443", tlsConfig) // MinVersion: tls.VersionTLS13
for {
	conn, err := ln.Accept()
	if err != nil { break }
	go srv.Serve(ctx, conn)
}

// 客户端:一个 Client 就是到一台服务端的通道池。
client, err := miu.NewClient(miu.ClientConfig{
	PSK:  psk,
	Dial: miu.TLSDialer("example.com:443", &tls.Config{}),
})
conn, err := client.DialContext(ctx, "tcp", "example.org:443") // net.Conn,另有 CloseWrite
pc, err := client.ListenPacket()                               // net.PacketConn(UDP)
```

- `conn.Close()` 在两个方向都结束之前调用就是中止(发 RESET),通道仍然回池;`CloseWrite()` 是半关闭。
- 外层换成别的:`miu/fingerprint`(`fingerprint.Dialer`,uTLS)、`miu/reality`(`reality.Dialer`)提供另外两种 `Dial`;
  服务端的 REALITY 握手在 `miu/realityserver`。任何 `net.Conn` 都可以当外层,但只有直接架在 TCP 上的 Go TLS 连接
  (crypto/tls、uTLS、xtls/reality)才有裸段。
- 裸段要用反射取 Go TLS 连接的两个内部缓冲。`miu.SelfTest`(以及 `fingerprint.SelfTest`、`realityserver.SelfTest`)
  在内存里实际跑一遍来确认这在当前的 Go 版本上可用;两个命令行程序启动时都会跑,不通过就打印错误并关掉裸段
  (settings 里声明 `raw=0`),其余功能不受影响。自己写程序时建议照做,失败时设 `DisableRaw`。
- 网络切换之后调 `client.CloseIdle()` 把池清掉。
- 服务端的 `ServerConfig.OnAccess` 在每条流开始时回调,`OnClose` 在结束时回调并带上 `Traffic`(两个方向的字节数与其中走裸段的部分)。
- 核心包 `miu` 只用标准库,并且只用到 Go 1.20 的语法与标准库:宿主工程的 Go 版本低于本模块 `go.mod` 的要求时,
  可以把 `miu/` 目录下的非测试文件原样拷进去用(保留 LICENSE)。

把 Miu 出站接进 mihomo(或它的分支)的完整步骤见 [docs/mihomo.zh-CN.md](docs/mihomo.zh-CN.md),那份文档是写给 AI 编码助手照着做的。
已经照这份文档接好的 mihomo 在 [MiuProtocol/mihomo](https://github.com/MiuProtocol/mihomo)(`Alpha` 分支)。

## 目前支持

- TCP;UDP(UoT v2,服务端每个会话一个 UDP socket,full-cone)
- 外层 TLS 1.3(标准库,或 Chrome 指纹)与 REALITY(客户端 Chrome 指纹)
- 裸段(两个方向),Linux 上服务端下行走 splice + TCP_CORK,其它平台走用户态拷贝
- 通道池:后进先出、分两档保留、连续开流时预热、取用前探活、死通道重放
- 包长整形与服务端下发方案;RESET 中止;半关闭
- 多用户;访问日志

## 目前不支持

- 多路复用、心跳、会话恢复:协议里就没有
- 外层为 WebSocket / gRPC,或经反向代理终结 TLS(库可以接受任何 `net.Conn` 当外层,只是没有裸段;两个程序没有做这些传输)
- 客户端指纹只有 `chrome`
- REALITY 的附加项:ML-DSA-65 验证、PROXY protocol(`xver`)、客户端版本与时间差限制
- SOCKS5 的用户名密码认证、BIND、UDP 分片;HTTP 代理入站;透明代理 / TUN
- 服务端的路由与出站策略、流量统计、限速、运行中增删用户(目标一律由服务端直接拨出;库里可以用 `ServerConfig.Dial` 换掉拨号)
- Windows 上「取用前探活」没有实现,死通道靠重放兜底

## 测试

```sh
go test -race ./...
```

回环测试覆盖四种外层(明文、TLS、uTLS、REALITY)下的小包、大包、并发、内层真实 TLS 1.3(断言两个方向都走了裸段)、
UDP、中止后通道复用、死通道重放等。`miu/live_test.go` 里另有两项对着别的实现跑的互通测试,由环境变量开启,说明在文件开头。

## 标志

标志是一个带猫耳的 μ(读作 miu)。[assets/](assets/) 里有两份:

| 文件 | 用途 |
|---|---|
| [miu-logo.svg](assets/miu-logo.svg) | 橙底圆角方形图标,用作应用图标、头像 |
| [miu-mark.svg](assets/miu-mark.svg) | 单色标记,颜色跟随 `currentColor`,用在协议徽标、列表里的小图标 |

## 许可证

[MIT](LICENSE)。
