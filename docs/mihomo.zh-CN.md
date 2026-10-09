# 把 Miu 出站接进 mihomo

[English](mihomo.md) | 简体中文

这份文档写给 AI 编码助手:使用者把本仓库的链接交给你,让你给 mihomo(或它的某个分支)加上 `type: miu` 的出站。
照着做即可,不需要别的资料;协议本身的线上格式在 [PROTOCOL.zh-CN.md](../PROTOCOL.zh-CN.md)。

## 0. 给 AI 的任务说明

**目标**:让 mihomo 能解析并使用下面 [§3](#3-节点配置格式) 那种格式的节点,TCP 与 UDP 都能走,外层支持普通 TLS、带浏览器指纹的 TLS、REALITY 三种。

**完成标准**(都满足才算完成):

1. 带 `type: miu` 节点的配置能通过 `mihomo -t -f config.yaml`。
2. 工程在它原本支持的每个 Go 版本上都还能 `go build`(见 [§2](#2-选路线))。
3. [§6.4](#64-验收清单) 的验收清单逐项通过——实际起服务端、实际发请求,不是「看代码应该能行」。
4. 除了 [§4](#4-路线-a引用本仓库的库) 列出的文件,没有改动 mihomo 的其它文件。

**不要做的事**:

- 不要改节点配置的键名、含义或必填项:已有的客户端和面板在用这套格式。
- 不要对 `psk` 做 base64 解码或别的变换:认证 token 是 `sha256(psk 字符串)`,字符串原样参与(只去掉首尾空白)。
- 不要给外层 TLS 连接再套一层会缓冲、改写或拦截读写的包装;不要用 `bufio` 之类带缓冲的读取器去读通道(原因见 [§4.8](#48-裸段对连接类型的要求与实测结果))。
- 不要把「中止一条流」实现成关掉外层连接。
- 不要引入本仓库的 `miu/fingerprint`、`miu/reality`、`miu/realityserver` 三个子包:mihomo 自带 uTLS 与 REALITY 客户端,
  用它自己的就行;引入这三个会把另一份 uTLS 和 REALITY 服务端链接进来。
- 不要顺手重构 mihomo 的其它出站、TLS 组件或依赖。
- 没有实际验证过的项,不要报告为「已完成」;做不了的验证如实说明卡在哪。

## 1. 核对过的版本,以及「名字以你手上的源码为准」

本文里出现的 mihomo 类型名、函数名、文件路径,都是对着下面这个版本的源码逐个核对过、并且实际编译运行过的:

| | 版本 |
|---|---|
| mihomo | 分支 `Alpha`,提交 `e4dd968de9e10ecc6770acfafd306edeb578eb52`(2026-10-08),`go.mod` 写的是 `go 1.20` |
| TLS 组件 | `github.com/metacubex/tls v0.1.8`、`github.com/metacubex/utls v1.8.8` |
| Miu | 路线 A2 与 [§6](#6-验证) 里的服务端日志需要**包含本文档的版本或更新的版本**(更早的版本里核心包用了 Go 1.21 以后的语法,服务端也没有 `closed:` 日志);路线 A1 对版本没有要求 |

克隆 mihomo 时确认检出的分支里有 `go.mod` 与 `adapter/outbound/` 目录(开发分支是 `Alpha`)。

**mihomo 上游一直在变,分支之间也有出入。动手之前先用下面的命令确认这些名字在你手上的源码里还在;对不上时以你手上的源码为准,
照同一个文件里别的出站(本文拿 `anytls` 当参照物)的写法调整,不要硬套本文的代码。**

```sh
# Run in the root of the mihomo source tree. The comments say what the verified version shows.
grep -n "AnyTLS" constant/adapters.go            # two places: one line in the AdapterType enum, one case in String()
grep -n '"anytls"' adapter/parser.go             # the case "anytls": in the switch of ParseProxy
grep -n "func NewConn\|func NewPacketConn\|func NewBase\|type BaseOption struct\|type BasicOption struct\|func (b \*BasicOption) NewDialer\|func (b \*Base) DialOptions\|func (b \*Base) ResolveUDP" adapter/outbound/base.go
grep -n "type RealityOptions struct\|func (o RealityOptions) Parse" adapter/outbound/reality.go
grep -n "type TLSConfig struct\|func StreamTLSConn" transport/vmess/tls.go
grep -n "func GetFingerprint\|func UClient\|^type Config\|VersionTLS13" component/tls/utls.go
grep -n "func GetRealityConn" component/tls/reality.go
grep -n "func OnceValue" common/once/*.go
grep -n "func (m \*Metadata) RemoteAddress" constant/metadata.go
grep -n "# anytls" docs/config.yaml
head -5 go.mod                                   # module path and go version
```

本文用到的签名(核对版本):

```go
// adapter/outbound/base.go
func NewBase(opt BaseOption) *Base
func (b *BasicOption) NewDialer(opts []dialer.Option) C.Dialer
func (b *Base) DialOptions() (opts []dialer.Option)
func (b *Base) ResolveUDP(ctx context.Context, metadata *C.Metadata) error
func NewConn(c net.Conn, a C.ProxyAdapter) C.Conn
func NewPacketConn(pc net.PacketConn, a ProxyAdapter) C.PacketConn
// adapter/outbound/reality.go
func (o RealityOptions) Parse() (*tlsC.RealityConfig, error)   // nil, nil when public-key is empty
// transport/vmess/tls.go
func StreamTLSConn(ctx context.Context, conn net.Conn, cfg *TLSConfig) (net.Conn, error)
// component/tls/utls.go
func GetFingerprint(clientFingerprint string) (UClientHelloID, bool)
func UClient(c net.Conn, config *utls.Config, fingerprint UClientHelloID) *UConn
// constant/metadata.go
func (m *Metadata) RemoteAddress() string                      // "host:port"; host is the domain name when there is one
```

## 2. 选路线

| 路线 | 做法 | 什么时候选 |
|---|---|---|
| **A1** | `go get` 本仓库,`import "github.com/MiuProtocol/Miu/miu"` | 工程的 `go.mod` 可以升到 `go 1.24.0`,所有构建都用 Go 1.24 或更新的工具链 |
| **A2** | 把本仓库 `miu/` 目录的源码拷进工程(`transport/miu/`) | 工程还要用低于 1.24 的 Go 构建,或者不想动 `go.mod` |
| **B** | 照协议文档在工程里自己实现 | 不想引入也不想拷贝外部代码,或需要做库没有提供的取舍 |

A1 与 A2 写出来的适配器代码完全一样,只差一行 import。**优先 A;A1 还是 A2 由下面两条命令的结果决定**:

```sh
head -5 go.mod                                                      # the go version
grep -rn "goversion\|go-version" .github/workflows/ 2>/dev/null     # the Go versions CI builds with
```

核对的那版 mihomo:`go.mod` 是 `go 1.20`,CI 用 Go 1.20 到 1.26 各构建一遍(`GOTOOLCHAIN=local`)。**这样的工程选 A2**;
选 A1 的话,低于 1.24 的那些构建会全部失败。只用新工具链构建、也接受下面这些副作用的分支可以选 A1。

A1 的副作用(在核对的版本上实测,`go get github.com/MiuProtocol/Miu@main` 之后):

- `go.mod` 的 `go 1.20` 变成 `go 1.24.0`(本模块的 `go.mod` 要求 1.24.0,Go 会自动抬高宿主的)。
- 这些依赖被抬高:`golang.org/x/crypto` 0.33.0 → 0.48.0、`x/net` 0.35.0 → 0.49.0、`x/sync` 0.11.0 → 0.19.0、`x/sys` 0.30.0 → 0.41.0,
  间接依赖 `x/mod`、`x/term`、`x/text`、`x/tools`、`github.com/pires/go-proxyproto` 也跟着升。原因:本模块的 `go.mod` 里
  为 REALITY 服务端子包记了这些版本,Go 取各模块要求的最大值,不管那个子包有没有被用到。
- `go.sum` 多出几十行(含 `refraction-networking/utls`、`xtls/reality` 的 `go.mod` 校验行)。这是模块图需要的,**并没有**把它们编进去:
  `go list -deps . | grep -i "MiuProtocol\|refraction\|xtls"` 只会列出 `github.com/MiuProtocol/Miu/miu` 一个包,这个包只依赖标准库。
- `go` 行到了 1.24,`go test` 自带的 vet 会对 mihomo 里几处既有代码报 `non-constant format string`,
  `adapter/provider`、`common/structure`、`component/trie` 三个包的测试因此编不过(与 Miu 无关;`go test -vet=off` 可过,或者改掉那几处)。
- 二进制大约大 0.3 MB。升完之后用 Go 1.24.0 和 1.27.0 都能编出 mihomo。

A2 不碰 `go.mod` / `go.sum`,用 Go 1.20.14 实测能编、能通过下面全部验证。代价是以后要手工同步上游的修正。

路线 B 见 [§5](#5-路线-b照协议文档自己实现)。

## 3. 节点配置格式

```yaml
proxies:
  - name: n
    type: miu
    server: example.com
    port: 443
    psk: "<string>"
    udp: true
    tls: true
    sni: www.example.com          # servername is accepted too
    skip-cert-verify: false
    client-fingerprint: chrome    # required for REALITY
    reality-opts: {public-key: "...", short-id: "..."}   # present: REALITY; absent: plain TLS
    # optional: alpn, fingerprint (certificate pin), idle-session-timeout, min-idle-session
```

| 键 | 类型 | 缺省 | 含义 | 映射到 |
|---|---|---|---|---|
| `name` | 字符串 | 必填 | 节点名 | `BaseOption.Name` |
| `type` | `miu` | 必填 | | `adapter/parser.go` 里的 `case "miu"` |
| `server` | 字符串 | 必填 | 服务端主机名或 IP | 拨号地址;没写 `sni` 时也当 SNI |
| `port` | 整数 | 必填 | 服务端端口 | 拨号地址 |
| `psk` | 字符串 | 必填 | 与服务端某个用户逐字符相同的字符串,至少 16 个字符。原样使用,不做 base64 解码 | `miu.ClientConfig.PSK` |
| `udp` | 布尔 | `false` | 是否允许 UDP(走流里的 UoT v2) | `BaseOption.UDP` |
| `tls` | 布尔 | — | 兼容字段。Miu 始终跑在 TLS 之上,这个键读进来但不起作用(写 `false` 也不会变成明文) | 不映射 |
| `sni` | 字符串 | `server` 的值 | 外层 TLS 的 SNI;REALITY 时必须是服务端 `serverNames` 里的一个 | `vmess.TLSConfig.Host` |
| `servername` | 字符串 | — | `sni` 的别名;两个都写时用 `sni` | 同上 |
| `skip-cert-verify` | 布尔 | `false` | 不校验服务端证书。REALITY 时不起作用(身份由握手里的认证确定) | `vmess.TLSConfig.SkipCertVerify` |
| `client-fingerprint` | 字符串 | 空 | 空:Go 自己的 ClientHello;`chrome` 等:uTLS 浏览器指纹(名字表在 `component/tls/utls.go` 的 `fingerprints`)。写了 `reality-opts` 就必须写它 | `vmess.TLSConfig.ClientFingerprint` |
| `reality-opts.public-key` | 字符串 | — | 服务端的 X25519 公钥(base64url 无填充)。有它外层就是 REALITY | `RealityOptions.Parse()` → `vmess.TLSConfig.Reality` |
| `reality-opts.short-id` | 字符串 | 空 | 服务端 `shortIds` 里的一个,最多 16 位十六进制 | 同上 |
| `alpn` | 字符串数组 | 空 | 外层 TLS 的 ALPN。REALITY 时不起作用 | `vmess.TLSConfig.NextProtos` |
| `fingerprint` | 字符串 | 空 | 服务端证书的 SHA-256 指纹(十六进制),写了就按指纹校验而不看证书链 | `vmess.TLSConfig.FingerPrint` |
| `idle-session-timeout` | 整数(秒) | `0` = 用库的缺省 30 | 空闲通道保留多久。库固定把最新放回的 4 条至少留 120 秒,这个值管的是其余的;两者都不会超过服务端下发的 `idle` − 5 秒 | `miu.ClientConfig.LaneIdle` |
| `min-idle-session` | 整数 | `0` = 用库的缺省 2 | 连续开流(10 秒内)时把空闲通道预热到几条 | `miu.ClientConfig.MinIdle` |

`tfo`、`mptcp`、`interface-name`、`routing-mark`、`ip-version`、`dialer-proxy` 这些通用键来自内嵌的 `BasicOption`,不用另外处理。

解码器的规矩(核对版本的 `common/structure`):结构体标签是 `proxy:"键名"`;标签里没有 `omitempty` 的键是必填的,缺了会报
`'' has unset fields: psk` 这样的错;配置里多出来的、结构体没有的键会被忽略。

## 4. 路线 A:引用本仓库的库

要改的文件一共五处(A1 另有 `go.mod` / `go.sum`,A2 另有拷进来的 `transport/miu/`):

| 文件 | 改动 |
|---|---|
| `constant/adapters.go` | 加出站类型常量 `Miu` 和它的名字 |
| `adapter/outbound/miu.go` | 新文件:选项结构体与适配器 |
| `adapter/outbound/miu_test.go` | 新文件:两个单元测试 |
| `adapter/parser.go` | `ParseProxy` 里加 `case "miu"` |
| `docs/config.yaml` | 加一段示例节点 |

### 4.1 把库放进工程

**A1**:

```sh
go get github.com/MiuProtocol/Miu@main
```

此时 `go.mod` 里它带着 `// indirect`;写完 [§4.3](#43-出站适配器) 的文件之后执行一次 `go mod tidy`,它会挪到直接依赖里。
`go mod tidy` 改动的只应该是 [§2](#2-选路线) 列的那些行,检查一下 diff。

**A2**:

```sh
git clone --depth 1 https://github.com/MiuProtocol/Miu /tmp/Miu
mkdir -p transport/miu
cp /tmp/Miu/miu/*.go transport/miu/
rm transport/miu/*_test.go          # the tests depend on other packages of the Miu repository
cp /tmp/Miu/LICENSE transport/miu/LICENSE
```

- 只拷 `miu/` 这一层的 `.go` 文件,不要拷它下面的 `fingerprint/`、`reality/`、`realityserver/` 目录。
- 文件原样使用,不用改:包名是 `miu`,只依赖标准库,只用到 Go 1.20 的语法与标准库。里面带着服务端的代码(`server.go` 等),
  用不到,链接器会丢掉;不要为了「精简」去删,它和客户端共用一些定义。
- import 路径是「你的模块路径 + `/transport/miu`」,模块路径看 `go.mod` 第一行(上游是 `github.com/metacubex/mihomo`)。
- 保留 `LICENSE`(MIT 要求保留版权与许可声明)。

### 4.2 出站类型常量

`constant/adapters.go` 有两处要加,**都加在最后**,不要插在中间(这个枚举是 `iota`,插在中间会改变后面所有类型的数值):

1. `AdapterType` 的常量块(以 `Direct AdapterType = iota` 开头的那个 `const (...)`)末尾加一行 `Miu`。
2. `func (at AdapterType) String() string` 的 `switch` 里,在最后一个代理类型的 `case` 后面加:

```go
	case Miu:
		return "Miu"
```

这个字符串会出现在 API 的 `type` 字段和面板上。

### 4.3 出站适配器

新建 `adapter/outbound/miu.go`,内容如下(A1 的写法;A2 把 `"github.com/MiuProtocol/Miu/miu"` 换成
`"<你的模块路径>/transport/miu"`,并把这一行挪到上面 mihomo 自己那组 import 里)。这段代码是本仓库的,MIT 许可;放进 mihomo 之后的许可见 [§8](#8-许可证)。

```go
package outbound

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/common/once"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/MiuProtocol/Miu/miu"
	"github.com/metacubex/tls"
)

type Miu struct {
	*Base
	client    *miu.Client
	option    *MiuOption
	tlsConfig *vmess.TLSConfig
}

type MiuOption struct {
	BasicOption
	Name               string         `proxy:"name"`
	Server             string         `proxy:"server"`
	Port               int            `proxy:"port"`
	PSK                string         `proxy:"psk"`
	UDP                bool           `proxy:"udp,omitempty"`
	TLS                bool           `proxy:"tls,omitempty"` // accepted for compatibility: Miu always runs over TLS
	SNI                string         `proxy:"sni,omitempty"`
	ServerName         string         `proxy:"servername,omitempty"` // alias of sni
	ALPN               []string       `proxy:"alpn,omitempty"`
	SkipCertVerify     bool           `proxy:"skip-cert-verify,omitempty"`
	Fingerprint        string         `proxy:"fingerprint,omitempty"`
	ClientFingerprint  string         `proxy:"client-fingerprint,omitempty"`
	RealityOpts        RealityOptions `proxy:"reality-opts,omitempty"`
	IdleSessionTimeout int            `proxy:"idle-session-timeout,omitempty"`
	MinIdleSession     int            `proxy:"min-idle-session,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (m *Miu) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	// The destination goes to the server as it is: a domain name is resolved there.
	c, err := m.client.DialContext(ctx, "tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(c, m), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (m *Miu) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := m.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	// One UoT stream, on a lane of its own, opened by the first packet written.
	pc, err := m.client.ListenPacket()
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, m), nil
}

// SupportUOT implements C.ProxyAdapter
func (m *Miu) SupportUOT() bool {
	return true
}

// ProxyInfo implements C.ProxyAdapter
func (m *Miu) ProxyInfo() C.ProxyInfo {
	info := m.Base.ProxyInfo()
	info.DialerProxy = m.option.DialerProxy
	return info
}

// Close implements C.ProxyAdapter
func (m *Miu) Close() error {
	return m.client.Close()
}

// dialLane opens the outer connection of a lane: TCP through the proxy's dialer, then TLS, uTLS or
// REALITY. The TLS connection is returned as it is, without any wrapper around it: the library needs
// to reach into it for raw segments.
func (m *Miu) dialLane(ctx context.Context) (net.Conn, error) {
	conn, err := m.dialer.DialContext(ctx, "tcp", m.addr)
	if err != nil {
		return nil, err
	}
	tlsConn, err := vmess.StreamTLSConn(ctx, conn, m.tlsConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// miuRawUsable checks, once, that the library's raw segments work on the two kinds of TLS connection
// vmess.StreamTLSConn can return here: *tls.Conn of metacubex/tls and *utls.UConn of metacubex/utls
// (the latter is also what a REALITY handshake yields).
var miuRawUsable = once.OnceValue(func() bool {
	err := miu.SelfTest(func(conn net.Conn, cfg *stdtls.Config) net.Conn {
		return tls.Client(conn, &tls.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	})
	if err == nil {
		err = miu.SelfTest(func(conn net.Conn, cfg *stdtls.Config) net.Conn {
			chrome, _ := tlsC.GetFingerprint("chrome")
			return tlsC.UClient(conn, &tlsC.Config{ServerName: cfg.ServerName, InsecureSkipVerify: true, MinVersion: tlsC.VersionTLS13}, chrome)
		})
	}
	if err != nil {
		log.Warnln("Miu: raw segments are not usable with this build, continuing without them: %v", err)
		return false
	}
	return true
})

func NewMiu(option MiuOption) (*Miu, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Miu{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Miu,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	realityConfig, err := option.RealityOpts.Parse()
	if err != nil {
		return nil, err
	}
	if realityConfig != nil && option.ClientFingerprint == "" {
		return nil, errors.New("miu: reality-opts needs client-fingerprint")
	}
	sni := option.SNI
	if sni == "" {
		sni = option.ServerName
	}
	if sni == "" {
		sni = option.Server
	}
	outbound.tlsConfig = &vmess.TLSConfig{
		Host:              sni,
		SkipCertVerify:    option.SkipCertVerify,
		FingerPrint:       option.Fingerprint,
		NextProtos:        option.ALPN,
		ClientFingerprint: option.ClientFingerprint,
		Reality:           realityConfig,
	}

	outbound.client, err = miu.NewClient(miu.ClientConfig{
		PSK:        option.PSK,
		Dial:       outbound.dialLane,
		LaneIdle:   time.Duration(option.IdleSessionTimeout) * time.Second,
		MinIdle:    option.MinIdleSession,
		DisableRaw: !miuRawUsable(),
	})
	if err != nil {
		return nil, err
	}
	return outbound, nil
}
```

逐块说明,改写时别丢掉这些要点:

- **`MiuOption`**:键与 [§3](#3-节点配置格式) 的表一一对应。`TLS` 字段只是为了让 `tls: true` 有地方落(没有它也不会报错,多余的键本来就被忽略;留着是为了让读代码的人知道这个键是有意不处理的)。
- **`DialContext`**:目标地址用 `metadata.RemoteAddress()`,有域名时把域名原样交给服务端解析。`client.DialContext` 拿到一条通道就返回,
  **不等服务端确认目标**(协议里服务端不回应 OPEN):目标连不上表现为第一次 `Read` 立刻读到 EOF,而不是 `DialContext` 报错。
  返回的 `net.Conn` 另有 `CloseWrite()`(半关闭);在两个方向都结束之前 `Close()` 就是「中止」,库会发 RESET 并把通道留在池里。
  用 `NewConn(c, m)` 包成 `C.Conn`——这是 mihomo 记录代理链的那一层;流量统计与连接跟踪由 `tunnel` 在外面再包(`statistic.NewTCPTracker`),适配器不用管。
- **`ListenPacketContext`**:先 `ResolveUDP`(与 `anytls` 等出站一致,把域名目标解析成 IP),再 `client.ListenPacket()`。它返回一个 `net.PacketConn`:
  `WriteTo` 的地址接受 `*net.UDPAddr`,`ReadFrom` 带回每个包的来源地址;第一次 `WriteTo` 才真正开流,所以这里不会因为网络问题失败。
  每个 UDP 会话独占一条通道,`Close()` 时中止这条流、通道回池。用 `NewPacketConn(pc, m)` 包成 `C.PacketConn`。
- **`SupportUOT`** 返回 `true`:UDP 是装在 TCP 流里的。核对的版本里它只用于 API 输出(`adapter/adapter.go` 的 `uot` 字段)和 `singmux` 的透传。
- **`ProxyInfo`** 补上 `DialerProxy`,**`Close`** 关掉通道池——照 `anytls` 的做法。节点被删除、配置重载时 mihomo 会调 `Close`。
- **`dialLane`** 是库的 `Dial` 回调:用节点自己的拨号器(`m.dialer`,它已经带上了 `interface-name`、`routing-mark`、`dialer-proxy` 等)连 TCP,
  再用 `vmess.StreamTLSConn` 握外层。**握完手的连接原样返回,外面不要再包任何东西**。失败时自己关掉 TCP 连接(`StreamTLSConn` 不替你关)。
  这个回调会被并发调用,也会在后台被调用(预热、重放),不要在里面依赖某一次请求的状态。
- **`miuRawUsable`**:进程里只跑一次的自检,确认裸段在 mihomo 用的两种 TLS 连接上可用;不通过就关掉裸段(其余照常工作)并打一条警告。见 [§4.8](#48-裸段对连接类型的要求与实测结果)。
- **`NewMiu`**:`reality-opts` 用 mihomo 现成的 `RealityOptions.Parse()`;写了 REALITY 却没写 `client-fingerprint` 在这里就报错(否则要等到第一次拨号才报)。
  SNI 的取值顺序是 `sni` → `servername` → `server`。`idle-session-timeout` / `min-idle-session` 为 0 时库用自己的缺省值,不用在这里判断。

### 4.4 配置解析入口

`adapter/parser.go` 的 `ParseProxy` 里,`switch proxyType` 中加一个 case(放在任意两个 case 之间,比如 `case "anytls":` 那一段的后面):

```go
	case "miu":
		miuOption := &outbound.MiuOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, miuOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMiu(*miuOption)
```

没有这个 case 时,mihomo 启动会报 `unsupport proxy type: miu`。

### 4.5 文档示例

`docs/config.yaml` 的 `proxies:` 下,在 `# anytls` 那个示例节点之后加一段(注意缩进与相邻节点一致):

```yaml
  # miu
  - name: miu
    type: miu
    server: 1.2.3.4
    port: 443
    psk: "<your psk>" # 与服务端逐字符相同的字符串,至少 16 个字符
    udp: true
    tls: true # 可省略,miu 始终跑在 TLS 之上
    # sni: "example.com" # 也可以写成 servername
    # skip-cert-verify: true
    # fingerprint: xxxx # 证书指纹
    # client-fingerprint: chrome
    # alpn:
    #   - h2
    #   - http/1.1
    # reality-opts: # 写了它外层就是 REALITY,此时必须同时写 client-fingerprint
    #   public-key: xxxx
    #   short-id: xxxx
    # idle-session-timeout: 30 # seconds
    # min-idle-session: 2
```

### 4.6 单元测试

新建 `adapter/outbound/miu_test.go`:

```go
package outbound

import (
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
)

// Raw segments reach into the TLS connections of metacubex/tls and metacubex/utls. If this fails after
// one of them has been upgraded, Miu still works, but without raw segments.
func TestMiuRawSegmentsUsable(t *testing.T) {
	if !miuRawUsable() {
		t.Fatal("the Miu self-test failed: raw segments would be disabled")
	}
}

func TestMiuOption(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	parse := func(mapping map[string]any) (*Miu, error) {
		option := &MiuOption{}
		if err := decoder.Decode(mapping, option); err != nil {
			return nil, err
		}
		return NewMiu(*option)
	}
	base := func() map[string]any {
		return map[string]any{"name": "n", "type": "miu", "server": "example.com", "port": 443, "psk": "0123456789abcdef0123456789abcdef", "udp": true, "tls": true}
	}

	m, err := parse(base())
	if err != nil {
		t.Fatal(err)
	}
	if m.Type() != C.Miu || m.Type().String() != "Miu" || !m.SupportUDP() || m.Addr() != "example.com:443" || m.tlsConfig.Host != "example.com" {
		t.Fatalf("type %v, udp %v, addr %s, sni %s", m.Type(), m.SupportUDP(), m.Addr(), m.tlsConfig.Host)
	}
	_ = m.Close()

	for _, key := range []string{"sni", "servername"} {
		mapping := base()
		mapping[key] = "www.example.com"
		m, err := parse(mapping)
		if err != nil || m.tlsConfig.Host != "www.example.com" {
			t.Fatalf("%s: %v", key, err)
		}
		_ = m.Close()
	}

	reality := base()
	reality["reality-opts"] = map[string]any{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "0123456789abcdef"}
	if _, err := parse(reality); err == nil {
		t.Fatal("reality-opts without client-fingerprint was accepted")
	}
	reality["client-fingerprint"] = "chrome"
	m, err = parse(reality)
	if err != nil || m.tlsConfig.Reality == nil {
		t.Fatalf("reality: %v", err)
	}
	_ = m.Close()

	short := base()
	short["psk"] = "short"
	if _, err := parse(short); err == nil {
		t.Fatal("a psk shorter than 16 characters was accepted")
	}
	missing := base()
	delete(missing, "psk")
	if _, err := parse(missing); err == nil {
		t.Fatal("a proxy without psk was accepted")
	}
}
```

```sh
go test -count=1 -run TestMiu ./adapter/outbound/
```

期望 `ok`。`TestMiuRawSegmentsUsable` 失败说明裸段在这份 mihomo 的 TLS 连接上不可用(见 [§4.8](#48-裸段对连接类型的要求与实测结果)),
功能不受影响但要如实报告。A1 下如果这条命令因为 vet 报 `non-constant format string` 而编不过,那是 [§2](#2-选路线) 说的既有问题,加 `-vet=off`。

### 4.7 构建

```sh
gofmt -l adapter/ constant/        # expect no output
go build -o mihomo .
./mihomo -v
```

A2 且工程支持旧版 Go 的,用最低的那个版本再编一次,例如 `GOTOOLCHAIN=go1.20.14 go build -o mihomo-go120 .`。

### 4.8 裸段:对连接类型的要求与实测结果

**裸段是什么**:内层(被代理的连接)已经是 TLS 1.3 密文时,库不再用外层 TLS 加密它,而是在一条只含 RAW 帧的记录后面把字节直接写到 TCP 上。
这要求库能越过外层 TLS 连接直接读写它底下的连接,并且能看到 TLS 连接「已经从 socket 读进来、还没解析」的缓冲。

**库怎么拿到这些**(`miu/tlsbuf.go`):对 `Dial` 返回的连接,

1. 它必须有 `NetConn() net.Conn` 方法——返回值就是裸段读写用的底层连接;
2. 它必须是指向结构体的指针,并且能按名字找到两个字段:`input`(类型 `bytes.Reader`)和 `rawInput`(类型 `bytes.Buffer`),
   直接字段或经内嵌指针提升上来的都行。

Go 标准库的 `*crypto/tls.Conn` 以及保持同样结构的分支都满足。取不到时库不会出错,只是这条通道不用裸段(向服务端声明 `raw=0`)。

**在核对的 mihomo 版本上的实测结果**——`vmess.StreamTLSConn` 在 Miu 用到的三种写法下返回的连接:

| 节点写法 | 返回的类型 | 取到缓冲 | 自检 | 实际流量里的裸段(8 MiB 文件经内层 TLS 1.3) |
|---|---|---|---|---|
| 不写 `client-fingerprint` | `*tls.Conn`(`github.com/metacubex/tls`) | 是 | 通过 | 下行 8401250 / 8397800;上行 8400388 / 8398010 |
| `client-fingerprint: chrome` | `*utls.UConn`(`github.com/metacubex/utls`) | 是 | 通过 | 下行 8401250 / 8396013;上行 8400388 / 8397996 |
| 再加 `reality-opts` | 同上,`*utls.UConn`(`tlsC.GetRealityConn` 返回的就是它) | 是 | 同一种类型 | 下行 8401249 / 8397134;上行 8400388 / 8399002 |

(数字是服务端 `-v` 日志里的「总字节数 / 其中走裸段的字节数」,差的那一点是内层握手。A1 用 Go 1.27.0 编译、A2 用 Go 1.20.14 编译,结果相同。)

`StreamTLSConn` 的另外几个分支(ShadowTLS、Restls、JLS、TLSMirror)返回的不是这种连接;本文的 `MiuOption` 没有开放它们。
如果你的分支要给 Miu 加这些外层,能用,但没有裸段。

**自检**:`miu.SelfTest(client)` 在内存里建一条真的 TLS 1.3 连接,两个方向各发一组帧与裸段——其中一段特意以 `15 03 03` 开头,
这是 Go 的 TLS 读逻辑会误判成 alert 记录的情形——逐字节核对。参数 `client` 用来指定「客户端这一头用哪种 TLS 连接」,
所以适配器里对 `metacubex/tls` 和 `metacubex/utls` 各跑一遍。升级这两个依赖之后只要字段改了名或读逻辑变了,自检会失败,
`miuRawUsable()` 返回 `false`,适配器把 `DisableRaw` 设成 `true`。

**`DisableRaw: true` 的后果**:一切功能照常,只是内层 TLS 流量会被外层再加密一遍(多一倍加解密的 CPU,大流量下吞吐下降);
服务端 `-v` 日志里 `raw` 一直是 0。不影响与服务端的互通。

**包装的禁忌**——`Dial` 返回值必须是 TLS 连接本身:

- 在 TLS 连接**外面**套一层普通包装(例如统计、引用计数、超时包装):库认不出它是 TLS 连接,裸段自动关闭。能用,但白白丢了裸段。
- 包装类型**内嵌**了 TLS 连接又改写了 `Read` / `Write`(例如内嵌 `*tls.Conn` 再加缓冲):库能找到缓冲字段、于是启用裸段,
  而读写却经过了你的改写——只要它缓冲或多读,裸段的字节就会错位,表现为内层 TLS 报 `bad record MAC`、连接随机断。**这种不要做。**
- 在 TLS 连接**下面**的包装(TFO 的延迟连接、`dialer-proxy` 链上的另一个代理连接)没有问题:TLS 和库读写的是同一个对象。
  底层连接不是系统 socket 时,库做不了「取用前探活」,死通道靠重放兜底。

### 4.9 没有接、也不需要接的地方

- **网络切换时清池**:库有 `client.CloseIdle()`,用于网络切换后丢掉池里的通道。核对的 mihomo 版本没有给出站用的「网络变化」通知
  (默认网卡变化时只通知了 DNS 解析器:`grep -rn "resolver.ResetConnection()" --include="*.go" .`),所以没有接。不接也能用:池里取到死通道时库会探活、
  必要时在新通道上把请求重放一次。你的分支如果有这样的钩子,在里面对每个 Miu 节点调一次 `CloseIdle()`。
- **分享链接转换**(`common/convert/converter.go`):Miu 没有定义分享链接格式,不用加。
- **入站**(`listener/`):本文只做出站。服务端用本仓库的 `miu-server`。
- **TCP keep-alive**:由 mihomo 的拨号器按全局配置(`keep-alive-interval` 等)设置,适配器不管。
- **`metadata` 的入站类型常量**(`constant/metadata.go`):那是给入站用的,不用加。

## 5. 路线 B:照协议文档自己实现

先完整读一遍 [PROTOCOL.zh-CN.md](../PROTOCOL.zh-CN.md)。下面的「§」都指它的章节。

### 5.1 目标形态

- 协议代码放在 `transport/miu/`,对外提供与路线 A 的库同样的四个入口,这样 [§4.2](#42-出站类型常量)–[§4.6](#46-单元测试) 的适配器、解析入口、测试可以原样使用:
  `NewClient(ClientConfig{PSK, Dial, LaneIdle, MinIdle, DisableRaw})`、`DialContext(ctx, "tcp", "host:port") (net.Conn, error)`(返回值带 `CloseWrite()`)、
  `ListenPacket() (net.PacketConn, error)`、`Close()`。
- 外层握手仍然用 `vmess.StreamTLSConn`,在 `Dial` 回调里做;协议代码只面对一条握完手的 `net.Conn`。
- 裸段需要的两个缓冲在 `github.com/metacubex/tls` 的 `Conn` 与 `github.com/metacubex/utls` 的 `Conn`(`UConn` 内嵌它)里都叫
  `input`(`bytes.Reader`)与 `rawInput`(`bytes.Buffer`),是未导出字段,只能用 `reflect` 按名字取地址再转成指针;底层连接用 `NetConn()` 取。
  取之前核对字段类型,取不到就当作不支持裸段(`raw=0`),不要 panic。

### 5.2 实现顺序与每一步的自测

每一步都用本仓库的 `miu-server -v` 当对端([§6.1](#61-起对端) 的搭法),做完一步验一步,不要攒到最后。

| 步 | 做什么 | 自测 |
|---|---|---|
| 1 | 编解码:帧、`socksAddr` / `uotAddr`、settings 文本、padding scheme 解析与 md5 | 单元测试,对下面的测试向量 |
| 2 | 一条流一条连接、全走 DATA、声明 `raw=0`、不整形、不入池:握手 → 一次写出「认证头 · padding · Settings」→ OPEN · DATA → 读帧到 END;`CloseWrite` 发 END | [§6.3](#63-逐项检查) 的小请求通过;服务端日志出现访问行和 `closed:` 行,字节数对得上;故意写错 psk,服务端日志是 `auth failed: unknown token` |
| 3 | 读侧补全:任何位置的 PAD / ServerSettings / UpdatePaddingScheme;记下 `raw` 与 `idle`;END 才是流的结束,连接断开是错误 | 服务端配置里加 `"paddingScheme": ["stop=3","0=40-60","1=200-300","2=300-400"]` 重启,请求照常(这时每条新连接都会收到 UpdatePaddingScheme) |
| 4 | 整形:每条流每个方向的包序号从 1 起;END 不整形 | 单元测试:抓每次写的长度。默认方案下,第 1 个包(OPEN 加不到 90 字节的数据)是一次 100–399 字节的写;END 是单独一次 3 字节的写,而且是这个方向的最后一次写 |
| 5 | 通道池:流的两个方向都 END 之后放回;后进先出;保留时长;预热;OPEN 等首批数据最多 10 ms | 连发 10 个小请求,到服务端的连接数稳定在 3 条以内([§6.3](#63-逐项检查) 的数法) |
| 6 | 中止:RESET、限时把下行丢到 END、回池 | 「下载中止」那一项:连接数不涨 |
| 7 | 收裸段:声明 `raw=1`,RAW 帧体的读法、裸字节的取法 | 经内层 TLS 下载大文件,哈希一致;服务端日志 `down N (raw 接近 N)` |
| 8 | 发裸段:沿上行跟踪内层 TLS 记录边界(需要从下行的 DATA 里认 ServerHello),条件满足后大块数据走 RAW | 经内层 TLS 上传大文件,哈希一致;服务端日志 `up N (raw 接近 N)` |
| 9 | UDP:UoT v2 | UDP 那一项 |
| 10 | 取用前探活、死通道重放 | 「服务端重启」那一项 |
| 11 | 读超时可续读;`Close` 能打断阻塞中的 `Read`;并发 | 半关闭那一项;`go test -race`;32 个并发下载哈希都对 |

测试向量(十六进制):

```
token = sha256("0123456789abcdef0123456789abcdef")
      = 3eb1bd439947eb762998e566ccc2e099c791118b2f40579cc4f7da2b5061b7f9
md5 of the default padding scheme text (the 9 lines of §6 joined by \n, no trailing newline, 137 bytes)
      = 75cff2ad89aadf5e257059ee571ebe11
OPEN example.com:443               04 000f 03 0b 6578616d706c652e636f6d 01bb
OPEN 1.2.3.4:80                    04 0007 01 01020304 0050
DATA "hi"                          05 0002 6869
RAW, 70000 raw bytes follow        06 0004 00011170
END / RESET                        07 0000 / 08 0000
payload of the Settings frame      "v=2\nraw=1\npadding-md5=75cff2ad89aadf5e257059ee571ebe11" (54 bytes; frame header 01 0036)
OPEN of a UoT stream               04 001b 03 17 "sp.v2.udp-over-tcp.arpa" 0000
UoT request (not connected, destination 8.8.8.8:53)    00 01 08080808 0035
one UoT packet (to 8.8.8.8:53, payload "abc")          00 08080808 0035 0003 616263
```

### 5.3 最容易错的点

按出错的频率排。每条后面是协议文档里的出处。

1. **读帧不能多读**(§9)。帧头 3 字节、帧体 len 字节,要多少读多少。任何带缓冲的读取器(`bufio.Reader`、一次读一大块自己再切)
   都会把 RAW 帧后面的裸字节当成 TLS 明文读走。
2. **Go 的 TLS 连接读空一条记录后会偷看下一个字节**(§9)。`Read` 返回前,如果这条记录读完了、`rawInput` 里还有数据且首字节是 `0x15`,
   它会去解析一条 alert 记录;RAW 帧后面的首个裸字节可能恰好是 `0x15`。所以 RAW 帧体(4 字节)的前 3 个用 `Read` 读,最后 1 个直接从 `input`
   里 `ReadByte()` 取走,取完检查 `input.Len() == 0`(否则 RAW 不是所在记录的最后一帧,按协议错误关通道)。
   `metacubex/tls` 与 `metacubex/utls` 都有这个行为。自检办法:发一段以 `15 03 03 00 02` 开头的裸段,看能否原样收到。
3. **裸字节先从 `rawInput` 取,再读底层连接**(§5.2、§9)。TLS 层读 socket 时会多读,RAW 记录后面的裸字节常常已经在 `rawInput` 里。
   读底层连接时一次最多读「这一段还剩的字节数」,多读的那部分属于下一条 TLS 记录,读走了就错位。
4. **RAW 帧独占一条 TLS 记录**(§3、§5.2)。发送:对 TLS 连接做一次只有 7 字节(`06 0004` + u32)的 `Write`,然后把 N 个字节直接写到 `NetConn()`
   返回的连接上。这两步以及别的写操作必须在同一把写锁里,中间不能插进别的帧。
5. **END 不整形,而且是这个方向的最后一个字节**(§6)。END 之后再写 PAD,它会在通道回池之后才到服务端 / 客户端,
   被当成下一条流的数据或「对端在关通道」。OPEN 还没发出去就要结束上行时,OPEN 与 END 一起、不整形地写出去。
6. **RESET 的两种时机**(§5.3)。上行还没 END:发 RESET 代替 END。上行已经 END、下行还没收到 END:补发一帧 RESET。
   OPEN 还没发出去:什么都不发,通道原样回池。下行已经收到 END 而上行没 END:发 END 即可。发完 RESET 要把下行读到 END 为止并丢弃,
   期限 3 秒,等到了通道回池,等不到才关。
7. **通道回池的条件**(§5、§5.3、§8)。必须同时满足:本方已发 END 或 RESET;已读到对端的 END;读写都没出过错;读游标停在帧边界上;
   这条流设过的读写期限已经清掉。少一条就关掉,不要回池——带着半条流的状态回池,下一条流会读到上一条的数据。
8. **服务端不回应 OPEN**(§5)。不要等任何确认;目标连不上时服务端直接发 END,客户端这边是「立刻读到流结束」。
   流的结束(END)与连接断开(EOF)要分开:前者对上层是 `io.EOF`,后者是错误。
9. **走裸段的条件**(§5.1)。按字节流跟踪内层 TLS 的记录边界,不是「某一次写恰好是一条记录」;含有那个 `0x17` 记录头的一批数据本身仍走 DATA,
   下一批才开始;对端没声明 `raw=1` 不能发;裸段阶段里小于 4 KiB 的一批仍走 DATA;看过 64 KiB 还没等到就永远走 DATA。
   客户端的上行要等「内层是 TLS 1.3」这个结论,它只能从**下行**的 DATA 里的 ServerHello 得到。
10. **认证头**(§2)。`token(32) · padlen(u16) · padding`,token 是 psk 字符串去掉首尾空白之后的 SHA-256,不解 base64;
    认证头、padding、Settings 帧一次写出;之后不等 ServerSettings 就可以开流。
11. **包序号是「每条流、每个方向」各自从 1 数**(§6),不是每条通道。OPEN 与首批数据是第 1 个包。
12. **ServerSettings 可能在任何时候到**(§4)。新通道上它排在第一条流的下行之前;预热出来还没用过的通道,它一直留在 socket 里没人读——
    所以「空闲通道上有数据待读 = 对端在关它」这条判断只对**用过的**通道成立。
13. **死通道重放的条件**(§8)。四条都满足才重放,且只重放一次:通道是从池里取的(不是为这条流新拨的);还没收到这条流的任何下行帧;
    已发的上行不超过 64 KiB;流没有被本地关掉。重放 = 清空池、新拨一条、把 OPEN 与已发的上行原样重发(上行已 END 的连 END)。
    为此要在满足条件期间留一份已发上行的拷贝。
14. **UoT 的两套地址编码**(§3、§7)。OPEN 与 UoT 请求头用 socksAddr(IPv4 `01`、域名 `03`、IPv6 `04`),逐包地址用 uotAddr(IPv4 `00`、IPv6 `01`、域名 `02`)。
    OPEN 的目标固定是 `sp.v2.udp-over-tcp.arpa:0`;请求头的 `isConnect` 写 0;每个包带地址;包可以跨 DATA 帧,要按字节流切。UDP 流不走裸段。
15. **读超时要能续读,写超时只能关通道**(§9)。mihomo 会给连接设读期限;帧头读到一半超时,进度要留着下次接着读。
16. **`Close` 不能在调用者的 goroutine 里做完所有事**。中止要发帧、要读到 END,而另一个 goroutine 可能正阻塞在 `Read` 或 `Write` 上。
    先让阻塞的 `Read` 立刻返回(把读期限设成现在),再在后台完成 RESET 与丢弃。

## 6. 验证

下面的步骤在一台机器上完成,路线 A 与路线 B 通用。需要:Go 1.24+(编译本仓库的 `miu-server`)、OpenSSL 1.1.1+ 的 `openssl` 命令、`python3`、`curl`。
端口都是随手挑的,被占用就换。

**curl 的写法**:本机 shell 如果带着代理环境变量,curl 会把请求发给那个代理而不是你的 mihomo。一律这样调用,**不要用 `--noproxy`**(它会让 `-x` 一起失效):

```sh
c() { env -u http_proxy -u https_proxy -u all_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u no_proxy -u NO_PROXY curl -sS "$@"; }
```

### 6.1 起对端

```sh
mkdir -p miu-verify/www && cd miu-verify

# the server program
git clone --depth 1 https://github.com/MiuProtocol/Miu src
(cd src && go build -o ../bin/ ./cmd/miu-server)

# a PSK, a self-signed certificate, a REALITY key pair, the test files
openssl rand -base64 32 > psk.txt
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.com"
bin/miu-server keygen > keys.txt        # two lines: privateKey: … / publicKey: …
head -c 8388608 /dev/urandom > www/big.bin
echo "hello from the target" > www/index.html
shasum -a 256 www/big.bin | cut -d' ' -f1 > big.sha     # sha256sum on Linux

PSK=$(cat psk.txt)
PRIV=$(awk '/privateKey/{print $2}' keys.txt)
PUB=$(awk '/publicKey/{print $2}' keys.txt)

cat > server-tls.json <<EOF
{
  "listen": "127.0.0.1:28443",
  "cert": "cert.pem",
  "key": "key.pem",
  "users": [{"name": "alice", "psk": "$PSK"}]
}
EOF
cat > server-reality.json <<EOF
{
  "listen": "127.0.0.1:28444",
  "reality": {
    "dest": "127.0.0.1:27444",
    "serverNames": ["www.example.com"],
    "privateKey": "$PRIV",
    "shortIds": ["0123456789abcdef"]
  },
  "users": [{"name": "alice", "psk": "$PSK"}]
}
EOF
```

被代理的目标(都在本机,这样结果不受外网影响):

```sh
# plain HTTP file server, :27080
python3 -m http.server 27080 --bind 127.0.0.1 --directory www > httpd.log 2>&1 &
# TLS 1.3 file server, :27443 (inner TLS: shows raw segments on the downlink)
(cd www && openssl s_server -accept 127.0.0.1:27443 -cert ../cert.pem -key ../key.pem -tls1_3 -WWW -quiet > ../tls.log 2>&1) &
# TLS 1.3 sink, :27445 (writes the plaintext it receives to received.bin: shows raw segments on the uplink)
(tail -f /dev/null | openssl s_server -accept 127.0.0.1:27445 -cert cert.pem -key key.pem -tls1_3 -quiet > received.bin 2> sink.log) &
# the site the REALITY server looks like, :27444 (an ordinary TLS 1.3 server)
(cd www && openssl s_server -accept 127.0.0.1:27444 -cert ../cert.pem -key ../key.pem -tls1_3 -www -quiet > ../dest.log 2>&1) &
# UDP echo, :27053
cat > udpecho.py <<'EOF'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
EOF
python3 udpecho.py 27053 &
```

两个服务端(`-v` 是必须的,后面靠它的日志确认裸段):

```sh
bin/miu-server -c server-tls.json -v > server-tls.log 2>&1 &
bin/miu-server -c server-reality.json -v > server-reality.log 2>&1 &
sleep 6      # a REALITY server probes its site after starting, about 5 seconds; connections arriving meanwhile wait
cat server-tls.log server-reality.log
```

期望:

```
… listening on 127.0.0.1:28443 (TLS 1.3), 1 user(s)
… listening on 127.0.0.1:28444 (REALITY, looking like 127.0.0.1:27444), 1 user(s)
```

### 6.2 mihomo 配置

三个节点各配一个本地入口(`listeners` 里的 `proxy` 把这个入口的流量固定交给某个节点),这样可以逐个节点测,不用切换分组:

```sh
FP=$(openssl x509 -in cert.pem -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
mkdir -p mihomo-home
cat > mihomo.yaml <<EOF
mixed-port: 17890
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: 127.0.0.1:19090
proxies:
  # plain TLS, Go's own ClientHello
  - name: miu-tls
    type: miu
    server: 127.0.0.1
    port: 28443
    psk: "$PSK"
    udp: true
    tls: true
    sni: example.com
    skip-cert-verify: true
  # plain TLS with Chrome's ClientHello; also exercises servername, fingerprint, alpn and the two pool settings
  - name: miu-chrome
    type: miu
    server: 127.0.0.1
    port: 28443
    psk: "$PSK"
    udp: true
    tls: true
    servername: example.com
    fingerprint: "$FP"
    client-fingerprint: chrome
    alpn: [h2, http/1.1]
    idle-session-timeout: 30
    min-idle-session: 2
  # REALITY
  - name: miu-reality
    type: miu
    server: 127.0.0.1
    port: 28444
    psk: "$PSK"
    udp: true
    tls: true
    sni: www.example.com
    client-fingerprint: chrome
    reality-opts: {public-key: "$PUB", short-id: "0123456789abcdef"}
listeners:
  - {name: in-tls, type: mixed, listen: 127.0.0.1, port: 17891, udp: true, proxy: miu-tls}
  - {name: in-chrome, type: mixed, listen: 127.0.0.1, port: 17892, udp: true, proxy: miu-chrome}
  - {name: in-reality, type: mixed, listen: 127.0.0.1, port: 17893, udp: true, proxy: miu-reality}
rules:
  - MATCH,miu-tls
EOF

/path/to/your/mihomo -t -d mihomo-home -f mihomo.yaml        # last line: configuration file … test is successful
/path/to/your/mihomo -d mihomo-home -f mihomo.yaml > mihomo.log 2>&1 &
sleep 2; grep -i "warn\|error\|fatal" mihomo.log             # expect no output
```

如果 `mihomo.log` 里有 `Miu: raw segments are not usable with this build`,裸段被自检关掉了,后面「裸段」两项会不通过,其余项仍应通过。

### 6.3 逐项检查

对三个入口各做一遍:`PORT=17891`(对应服务端 28443)、`PORT=17892`(28443)、`PORT=17893`(28444)。下面以 17891 为例。

```sh
PORT=17891; SPORT=28443; SLOG=server-tls.log     # the REALITY node: PORT=17893 SPORT=28444 SLOG=server-reality.log
WANT=$(cat big.sha)
# how many connections (lanes) mihomo has to the server. Without lsof: ss -Htn state established "( dport = :$SPORT )" | wc -l
lanes() { lsof -nP -iTCP:$SPORT -sTCP:ESTABLISHED | grep -c "^mihomo"; }
```

**① 小请求**

```sh
c -x socks5h://127.0.0.1:$PORT --max-time 10 http://127.0.0.1:27080/index.html
```

期望输出 `hello from the target`。`$SLOG` 里多出两行(用户名、客户端地址、目标;结束时的字节数):

```
… alice 127.0.0.1:53124 -> tcp 127.0.0.1:27080
… alice 127.0.0.1:53124 -> tcp 127.0.0.1:27080 closed: up 88 (raw 0), down 206 (raw 0)
```

(字节数随 curl 版本略有出入,下同。)

**② 大文件哈希(明文内层)**

```sh
c -x socks5h://127.0.0.1:$PORT --max-time 60 http://127.0.0.1:27080/big.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
```

期望两行相同。日志里这条流是 `down 8388812 (raw 0)`:明文不走裸段。

**③ 内层 TLS 的下行走裸段**

```sh
c -x socks5h://127.0.0.1:$PORT -k --max-time 60 https://127.0.0.1:27443/big.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
grep "27443 closed" $SLOG | tail -1
```

期望哈希相同,并且日志是这个样子——`down` 的 `raw` 接近总数(差的几 KB 是内层握手):

```
… -> tcp 127.0.0.1:27443 closed: up 496 (raw 0), down 8401247 (raw 8397151)
```

`raw 0` 表示这种外层连接没有用上裸段,去看 [§7](#7-常见错误与现象对照)。

**④ 内层 TLS 的上行走裸段**

```sh
c -x socks5h://127.0.0.1:$PORT -k --max-time 4 -H 'Expect:' -T www/big.bin https://127.0.0.1:27445/up -o /dev/null
tail -c 8388608 received.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
grep "27445 closed" $SLOG | tail -1
```

那个接收端只收不答,所以 curl 会在 4 秒后以超时(退出码 28)结束,这是预期的。期望哈希相同,日志里 `up` 的 `raw` 接近总数:

```
… -> tcp 127.0.0.1:27445 closed: up 8400388 (raw 8399312), down 1308 (raw 0)
```

**⑤ 下载到一半中止,连接数不涨**

```sh
sleep 1; before=$(lanes)
for i in 1 2 3 4 5; do
  c -x socks5h://127.0.0.1:$PORT -k --limit-rate 500k --max-time 1 -o /dev/null https://127.0.0.1:27443/big.bin; sleep 0.3
done
sleep 1; echo "lanes: $before -> $(lanes)"
c -x socks5h://127.0.0.1:$PORT -k --max-time 60 https://127.0.0.1:27443/big.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
```

每个 curl 都以超时结束(预期)。期望连接数前后相同,之后的完整下载哈希仍然正确。数值本身不重要(一个节点通常是 3:用过的一条加预热的两条;
`miu-tls` 与 `miu-chrome` 连的是同一个服务端端口,数出来是两个节点的合计),看的是前后有没有变。每中止一次就涨 1,说明中止被做成了关连接。

**⑥ UDP**

```sh
cat > udp_via_socks.py <<'EOF'
# usage: udp_via_socks.py <socks5 port> <udp echo port>
import socket, struct, sys
proxy_port, target_port = int(sys.argv[1]), int(sys.argv[2])
c = socket.create_connection(("127.0.0.1", proxy_port)); c.settimeout(10)
c.sendall(b"\x05\x01\x00"); assert c.recv(2) == b"\x05\x00"
c.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
r = c.recv(10); assert r[1] == 0, r
relay = ("127.0.0.1", struct.unpack(">H", r[8:10])[0])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(10)
ok = 0
for i, size in enumerate([5, 600, 1400, 4000]):
    msg = bytes([65 + i]) * size
    u.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", target_port) + msg, relay)
    d, _ = u.recvfrom(65535)
    ok += d[10:] == msg
print("udp: %d/4 datagrams echoed" % ok)
sys.exit(0 if ok == 4 else 1)
EOF
python3 udp_via_socks.py $PORT 27053
grep " udp " $SLOG | tail -2
```

期望 `udp: 4/4 datagrams echoed`,日志里有 `-> udp 127.0.0.1:27053` 的访问行(对应的 `closed:` 行在会话结束后片刻才出现)。

**⑦ 半关闭**

```sh
cat > halfclose.py <<'EOF'
# usage: halfclose.py <socks5 port>
# Starts a target that answers only after it has seen the end of the request, then talks to it through
# the proxy: send 1 MiB, half-close, read the answer (the SHA-256 of what was sent).
import hashlib, os, socket, struct, sys, threading
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
def target():
    c, _ = srv.accept(); h = hashlib.sha256()
    while True:
        b = c.recv(65536)
        if not b: break
        h.update(b)
    c.sendall(h.hexdigest().encode()); c.close()
threading.Thread(target=target, daemon=True).start()
data = os.urandom(1 << 20)
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); s.settimeout(10)
s.sendall(b"\x05\x01\x00"); assert s.recv(2) == b"\x05\x00"
s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", srv.getsockname()[1]))
assert s.recv(10)[1] == 0
s.sendall(data); s.shutdown(socket.SHUT_WR)
got = b""
while True:
    b = s.recv(4096)
    if not b: break
    got += b
ok = got.decode() == hashlib.sha256(data).hexdigest()
print("half-close:", "ok" if ok else "FAILED (%d bytes back)" % len(got))
sys.exit(0 if ok else 1)
EOF
python3 halfclose.py $PORT
```

期望 `half-close: ok`。失败说明「应用关闭写方向」被当成了整条流的结束或中止。

**⑧ 延迟测试接口**(mihomo 的健康检查走的就是这条路)

```sh
c "http://127.0.0.1:19090/proxies/miu-tls/delay?url=http%3A%2F%2F127.0.0.1%3A27080%2Findex.html&timeout=3000"
```

三个节点名各测一次。期望 `{"delay":N}`。**本机回环太快时会看到另一种结果**:请求不到 1 毫秒就完成,延迟取整为 0,
而 mihomo 的这个接口把 0 当失败,返回 `{"message":"An error occurred in the delay test"}`(`hub/route/proxies.go` 里的 `delay == 0`)。
这不是出站的问题。遇到时以服务端日志为准:每调用一次,`$SLOG` 里应当多出一对访问行与 `closed: up 84 (raw 0), down 184 (raw 0)` 这样的行。

**⑨ 服务端重启后的第一个请求**

```sh
pkill -f "miu-server -c server-tls.json"; pkill -f "miu-server -c server-reality.json"; sleep 0.5
bin/miu-server -c server-tls.json -v >> server-tls.log 2>&1 &
bin/miu-server -c server-reality.json -v >> server-reality.log 2>&1 &
sleep 6
for PORT in 17891 17892 17893; do
  c -x socks5h://127.0.0.1:$PORT --max-time 10 -o /dev/null -w "$PORT: %{http_code}\n" http://127.0.0.1:27080/index.html
done
```

此时 mihomo 的池里留着连到旧进程的通道。期望三行都是 `200`,第一个请求就成功(库在取用时发现通道已断,或在写入失败后换一条新通道重放)。

收尾:`kill` 掉 mihomo、两个 `miu-server` 和上面起的几个目标进程(`pkill -f "s_server -accept 127.0.0.1:274"`、`pkill -f udpecho.py`、`pkill -f "http.server 27080"`、`pkill -f "tail -f /dev/null"`)。

### 6.4 验收清单

对 `miu-tls`、`miu-chrome`、`miu-reality` 三个节点各打一遍勾:

| # | 项 | 怎么算通过 |
|---|---|---|
| 1 | 配置能解析 | `mihomo -t` 成功;日志没有 warning / error |
| 2 | 小请求 | ① 输出正确,服务端有访问行与 `closed:` 行 |
| 3 | 大文件哈希 | ② 哈希一致 |
| 4 | 内层 TLS 下行走裸段 | ③ 哈希一致,且 `down N (raw 接近 N)` |
| 5 | 内层 TLS 上行走裸段 | ④ 哈希一致,且 `up N (raw 接近 N)` |
| 6 | 中止后连接数不涨 | ⑤ 前后连接数相同,其后的下载哈希一致 |
| 7 | UDP | ⑥ 4/4 |
| 8 | 半关闭 | ⑦ ok |
| 9 | 延迟测试 | ⑧ 返回 delay;或者(本机太快时)返回那条报错,而服务端日志里每次调用都有完整的一对行 |
| 10 | 服务端重启后首个请求 | ⑨ 三个都是 200 |
| 11 | 单元测试 | `go test -run TestMiu ./adapter/outbound/` 通过 |
| 12 | 支持的每个 Go 版本都能编译 | 逐个版本 `go build` |

第 4、5 项不通过而其余都通过,是「能用但没有裸段」——如实报告,并按 [§7](#7-常见错误与现象对照) 找原因。

核对版本上的实测结果:路线 A1(分别用 Go 1.27.0 与 1.24.0 编译)和路线 A2(用 Go 1.20.14 编译)在三个节点上全部通过;
第 9 项在本机属于上面说的「太快」的情形,三个节点各自既出现过 `{"delay":1}` 也出现过那条报错,服务端日志里每次调用都是完整的。

## 7. 常见错误与现象对照

| 现象 | 原因 | 改法 |
|---|---|---|
| 启动报 `unsupport proxy type: miu` | `adapter/parser.go` 没加 `case "miu"`,或运行的不是新编出来的二进制 | [§4.4](#44-配置解析入口);`mihomo -v` 确认 |
| 启动报 `'' has unset fields: psk` | 节点缺 `psk`(必填键缺失时解码器的报法) | 补上;键名是 `psk`,不是 `password` |
| 启动报 `miu: psk too short (need at least 16 characters)` | `psk` 不足 16 个字符 | 换成更长的字符串,两端一致 |
| 启动报 `invalid REALITY public key` | `reality-opts.public-key` 不是 43 个字符的 base64url | 用 `miu-server keygen` 输出的 `publicKey` |
| 启动报 `miu: reality-opts needs client-fingerprint` | 写了 `reality-opts` 没写 `client-fingerprint` | 加 `client-fingerprint: chrome` |
| `go build` 报 `go.mod requires go >= 1.24.0`,或 CI 里旧版 Go 的任务全红 | 走了 A1,而工具链低于 1.24 | 换 A2,或确认可以放弃旧版 Go 的构建 |
| `go test` 报 `non-constant format string`,若干包 `[build failed]` | A1 把 `go` 行抬到 1.24 之后,vet 对 mihomo 既有代码的新检查 | `-vet=off`,或改那几处;与 Miu 无关 |
| 请求全部失败(curl `Empty reply`),mihomo 日志没有明显错误;服务端 `-v` 日志是 `miu: auth failed: unknown token` | 两端 psk 不同:多了引号 / 空格以外的字符、被做了 base64 解码、或填的是别的用户的 | psk 按字符串原样使用;对比两端配置里的值 |
| mihomo 日志 `tls: failed to verify certificate: x509: certificate signed by unknown authority`;服务端是 `handshake: remote error: tls: bad certificate` | 服务端用自签证书,客户端在校验 | 测试时 `skip-cert-verify: true` 或写 `fingerprint`;正式环境用受信任的证书并让 `sni` 与证书一致 |
| REALITY 节点连不上:mihomo 日志 `REALITY authentication failed` 或 `x509: certificate signed by unknown authority`;服务端是 `REALITY: processed invalid connection … authentication failed or validation criteria not met` | `public-key`、`short-id`、`sni` 三者之一与服务端不符(服务端把这条连接转给了伪装目标,客户端拿到的是伪装目标的证书) | 公钥用 `keygen` 的 `publicKey`(不是 `privateKey`);`short-id` 在服务端 `shortIds` 里;`sni` 在 `serverNames` 里 |
| REALITY 服务端刚启动时第一条连接要等约 5 秒 | 服务端在探测伪装目标 | 正常;等它探测完 |
| mihomo 日志 `REALITY is based on uTLS, please set a client-fingerprint` | 同「needs client-fingerprint」,但绕过了 `NewMiu` 的检查 | 加 `client-fingerprint` |
| 能用,但服务端日志里内层 TLS 的流 `raw` 一直是 0 | (a) mihomo 日志有 `Miu: raw segments are not usable`:自检没过;(b) `Dial` 返回的连接外面套了包装;(c) 目标不是 TLS 1.3(TLS 1.2 与明文不走裸段);(d) 数据量太小(握手之后每批不足 4 KiB) | (a) 看自检报的错,多半是 TLS 依赖升级后字段变了;(b) [§4.8](#48-裸段对连接类型的要求与实测结果);(c)(d) 属正常 |
| HTTP 目标正常,HTTPS 目标随机失败:内层报 `bad record MAC` / `decryption failed`,或下载的哈希不对 | 裸段的字节错位:`Dial` 返回的连接读写被改写或加了缓冲;路线 B 里则是 [§5.3](#53-最容易错的点) 的第 1–4 条 | 先设 `DisableRaw: true` 确认(问题消失即是裸段处理的问题),再照 [§4.8](#48-裸段对连接类型的要求与实测结果) / [§5.3](#53-最容易错的点) 排查 |
| 每中止一次下载,到服务端的连接就多一条(或少一条再新建一条) | 中止被实现成关连接;路线 A 里通常是适配器把 `client.DialContext` 返回的连接换成了别的东西再交给 `NewConn`,或者每次请求都新建了 `miu.Client` | 一个节点一个 `miu.Client`,在 `NewMiu` 里建;`DialContext` 返回的连接直接交给 `NewConn` |
| 请求偶尔卡住几秒后失败,服务端日志是 `miu: OPEN before the previous stream ended` 或 `data outside of a stream` | 路线 B:通道带着没结束的流回了池,或 END 之后又写了东西 | [§5.3](#53-最容易错的点) 第 5、7 条 |
| 服务端重启(或网络切换)后头一两个请求失败,之后恢复 | 路线 B:没做取用前探活与死通道重放 | [§5.3](#53-最容易错的点) 第 12、13 条 |
| UDP 不通,TCP 正常 | 节点没写 `udp: true`;或入口没开 UDP(本文配置里 `listeners` 的 `udp: true`) | 补上 |
| 上传后等不到应答(客户端半关闭之后连接被整个关掉) | `CloseWrite` 没有传到 Miu 的流上,被降级成了 `Close` | 路线 A 不会出现(`NewConn` 之后 mihomo 的中继能找到流上的 `CloseWrite`);路线 B 给流实现 `CloseWrite() error` |
| 节点很多时内存 / 连接数偏高 | 每个节点最多保留 32 条空闲通道,连续使用时预热 2 条 | 调小 `min-idle-session` / `idle-session-timeout`;空闲通道最久 120 秒后自行关闭 |

## 8. 许可证

- 本仓库(包括本文里的示例代码)是 MIT 许可。A2 拷贝源码时保留 `LICENSE` 文件。
- mihomo 是 GPL-3.0。**放进 mihomo 源码树的文件——不论是照本文新写的适配器,还是拷进去的 `transport/miu/`——随 mihomo 一起分发时受 GPL-3.0 约束**
  (MIT 与 GPL-3.0 兼容,可以这样合并;反过来,不要把 mihomo 的代码拷回本仓库)。
- 路线 B 里参照协议文档自己写的实现,版权归写的人,同样随所在工程的许可证分发。
