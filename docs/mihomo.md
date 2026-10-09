# Adding the Miu outbound to mihomo

English | [简体中文](mihomo.zh-CN.md)

This document is written for an AI coding assistant: someone has handed you a link to this repository and asked you to add
a `type: miu` outbound to mihomo (or to a fork of it). Follow it and you need nothing else; the wire format of the protocol
itself is in [PROTOCOL.md](../PROTOCOL.md).

## 0. Task brief for the AI

**Goal**: mihomo parses and uses proxies written in the format of [§3](#3-proxy-configuration-format), for TCP and UDP,
with all three outer layers: plain TLS, TLS with a browser fingerprint, and REALITY.

**Done means** (all of these, not some):

1. A configuration with a `type: miu` proxy passes `mihomo -t -f config.yaml`.
2. The project still builds with every Go version it built with before (see [§2](#2-choosing-a-route)).
3. Every item of the acceptance checklist in [§6.4](#64-acceptance-checklist) passes — with a server actually running and
   requests actually sent, not "the code looks like it should work".
4. No mihomo file has been changed other than those listed in [§4](#4-route-a-use-the-library-from-this-repository).

**Do not**:

- Do not rename configuration keys, change what they mean, or change which are required: existing clients and panels emit
  this format.
- Do not base64-decode or otherwise transform `psk`: the authentication token is `sha256(the psk string)`, the string taken
  as written (only surrounding whitespace is removed).
- Do not put another wrapper around the outer TLS connection that buffers, rewrites or intercepts reads and writes, and do
  not read a lane through `bufio` or any other buffered reader (why: [§4.8](#48-raw-segments-what-they-need-from-the-connection-and-what-was-measured)).
- Do not implement "abort a stream" as closing the outer connection.
- Do not import the `miu/fingerprint`, `miu/reality` or `miu/realityserver` packages of this repository: mihomo has its own
  uTLS and its own REALITY client, use those. Importing these three would link in a second uTLS and a REALITY server.
- Do not refactor mihomo's other outbounds, its TLS components or its dependencies while you are at it.
- Do not report an item as done unless you have verified it; where a check cannot be run, say exactly what stopped you.

## 1. Verified versions, and "trust the source in front of you"

Every mihomo type name, function name and file path in this document was checked against the source of the version below,
which was then compiled and run:

| | Version |
|---|---|
| mihomo | branch `Alpha`, commit `e4dd968de9e10ecc6770acfafd306edeb578eb52` (2026-10-08); its `go.mod` says `go 1.20` |
| TLS components | `github.com/metacubex/tls v0.1.8`, `github.com/metacubex/utls v1.8.8` |
| Miu | Route A2 and the server log used in [§6](#6-verification) need **the version that contains this document, or a later one** (earlier versions use post-Go-1.20 syntax in the core package, and their server has no `closed:` log line); route A1 works with any version |

When you clone mihomo, make sure the branch you have checked out contains `go.mod` and `adapter/outbound/` (the development
branch is `Alpha`).

**Upstream mihomo keeps changing, and forks differ. Before touching anything, run the commands below to confirm that these
names still exist in the source you actually have. Where they do not match, the source in front of you wins: adapt by
following how another outbound in the same file does it (this document uses `anytls` as the reference), rather than forcing
the code from this document in.**

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

Signatures this document relies on (verified version):

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

## 2. Choosing a route

| Route | What you do | Choose it when |
|---|---|---|
| **A1** | `go get` this repository and `import "github.com/MiuProtocol/Miu/miu"` | the project's `go.mod` can move to `go 1.24.0` and every build uses a Go 1.24 or newer toolchain |
| **A2** | copy the source of this repository's `miu/` directory into the project (`transport/miu/`) | the project still has to build with a Go older than 1.24, or `go.mod` should stay untouched |
| **B** | implement the protocol inside the project from the protocol document | you want neither an import nor a copy of outside code, or you need trade-offs the library does not offer |

A1 and A2 produce exactly the same adapter code; a single import line differs. **Prefer A; these two commands decide
between A1 and A2**:

```sh
head -5 go.mod                                                      # the go version
grep -rn "goversion\|go-version" .github/workflows/ 2>/dev/null     # the Go versions CI builds with
```

For the verified mihomo: `go.mod` says `go 1.20`, and CI builds with every Go from 1.20 to 1.26 (`GOTOOLCHAIN=local`).
**A project like that takes A2**; with A1 every build below Go 1.24 fails. A fork that builds only with recent toolchains and
accepts the side effects below can take A1.

Side effects of A1 (measured on the verified version, after `go get github.com/MiuProtocol/Miu@main`):

- `go 1.20` in `go.mod` becomes `go 1.24.0` (this module's `go.mod` requires 1.24.0, and Go raises the host's to match).
- These dependencies are raised: `golang.org/x/crypto` 0.33.0 → 0.48.0, `x/net` 0.35.0 → 0.49.0, `x/sync` 0.11.0 → 0.19.0,
  `x/sys` 0.30.0 → 0.41.0, and with them the indirect `x/mod`, `x/term`, `x/text`, `x/tools` and
  `github.com/pires/go-proxyproto`. The reason: this module's `go.mod` records those versions for its REALITY server
  package, and Go takes the maximum any module asks for, whether or not that package is used.
- `go.sum` grows by a few dozen lines (among them the `go.mod` checksums of `refraction-networking/utls` and
  `xtls/reality`). The module graph needs them; they are **not** compiled in:
  `go list -deps . | grep -i "MiuProtocol\|refraction\|xtls"` lists the single package `github.com/MiuProtocol/Miu/miu`,
  which depends on the standard library only.
- With the `go` line at 1.24, the vet pass built into `go test` reports `non-constant format string` for a few existing
  places in mihomo, and the tests of `adapter/provider`, `common/structure` and `component/trie` no longer build (nothing to
  do with Miu; `go test -vet=off` passes, or fix those places).
- The binary grows by about 0.3 MB. After the upgrade mihomo builds with both Go 1.24.0 and Go 1.27.0.

A2 leaves `go.mod` and `go.sum` alone; it was built with Go 1.20.14 and passed everything in this document. The price is
that later fixes in this repository have to be carried over by hand.

Route B is [§5](#5-route-b-implement-the-protocol-yourself).

## 3. Proxy configuration format

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

| Key | Type | Default | Meaning | Maps to |
|---|---|---|---|---|
| `name` | string | required | name of the proxy | `BaseOption.Name` |
| `type` | `miu` | required | | the `case "miu"` in `adapter/parser.go` |
| `server` | string | required | host name or IP of the server | the address dialed; also the SNI when `sni` is absent |
| `port` | integer | required | port of the server | the address dialed |
| `psk` | string | required | the same string, character for character, as one of the server's users has; at least 16 characters. Used as it is, never base64-decoded | `miu.ClientConfig.PSK` |
| `udp` | boolean | `false` | whether UDP is allowed (it travels as UoT v2 inside a stream) | `BaseOption.UDP` |
| `tls` | boolean | — | compatibility key. Miu always runs over TLS; the key is read and has no effect (`false` does not turn the outer layer into plaintext) | not mapped |
| `sni` | string | the value of `server` | SNI of the outer TLS; with REALITY it must be one of the server's `serverNames` | `vmess.TLSConfig.Host` |
| `servername` | string | — | alias of `sni`; `sni` wins when both are present | same |
| `skip-cert-verify` | boolean | `false` | do not verify the server's certificate. No effect with REALITY (the handshake's own authentication establishes identity) | `vmess.TLSConfig.SkipCertVerify` |
| `client-fingerprint` | string | empty | empty: Go's own ClientHello; `chrome` and the like: a uTLS browser fingerprint (the names are in `fingerprints` in `component/tls/utls.go`). Required when `reality-opts` is present | `vmess.TLSConfig.ClientFingerprint` |
| `reality-opts.public-key` | string | — | the server's X25519 public key (base64url, no padding). Its presence makes the outer layer REALITY | `RealityOptions.Parse()` → `vmess.TLSConfig.Reality` |
| `reality-opts.short-id` | string | empty | one of the server's `shortIds`, up to 16 hex digits | same |
| `alpn` | list of strings | empty | ALPN of the outer TLS. No effect with REALITY | `vmess.TLSConfig.NextProtos` |
| `fingerprint` | string | empty | SHA-256 fingerprint (hex) of the server's certificate; when set, the certificate is checked against it instead of against a chain | `vmess.TLSConfig.FingerPrint` |
| `idle-session-timeout` | integer (seconds) | `0` = the library's default, 30 | how long idle lanes are kept. The library always keeps the 4 most recently returned ones for at least 120 seconds; this value governs the rest. Neither exceeds the `idle` announced by the server minus 5 seconds | `miu.ClientConfig.LaneIdle` |
| `min-idle-session` | integer | `0` = the library's default, 2 | how many idle lanes to keep warm while streams are being opened in a row (within 10 seconds) | `miu.ClientConfig.MinIdle` |

The common keys `tfo`, `mptcp`, `interface-name`, `routing-mark`, `ip-version` and `dialer-proxy` come from the embedded
`BasicOption` and need no handling of their own.

How the decoder behaves (`common/structure` in the verified version): struct tags are `proxy:"key"`; a key whose tag lacks
`omitempty` is required, and leaving it out fails with an error like `'' has unset fields: psk`; keys present in the
configuration but absent from the struct are ignored.

## 4. Route A: use the library from this repository

Five files change (plus `go.mod` / `go.sum` for A1, or the copied `transport/miu/` for A2):

| File | Change |
|---|---|
| `constant/adapters.go` | add the adapter type constant `Miu` and its name |
| `adapter/outbound/miu.go` | new file: the option struct and the adapter |
| `adapter/outbound/miu_test.go` | new file: two unit tests |
| `adapter/parser.go` | add `case "miu"` to `ParseProxy` |
| `docs/config.yaml` | add an example proxy |

### 4.1 Bringing the library in

**A1**:

```sh
go get github.com/MiuProtocol/Miu@main
```

At this point `go.mod` lists it with `// indirect`; once the file of [§4.3](#43-the-outbound-adapter) is in place, run
`go mod tidy` once and it moves to the direct requirements. `go mod tidy` should touch nothing but the lines listed in
[§2](#2-choosing-a-route) — check the diff.

**A2**:

```sh
git clone --depth 1 https://github.com/MiuProtocol/Miu /tmp/Miu
mkdir -p transport/miu
cp /tmp/Miu/miu/*.go transport/miu/
rm transport/miu/*_test.go          # the tests depend on other packages of the Miu repository
cp /tmp/Miu/LICENSE transport/miu/LICENSE
```

- Copy only the `.go` files directly in `miu/`; leave out the `fingerprint/`, `reality/` and `realityserver/` directories
  below it.
- Use the files as they are, without edits: the package is named `miu`, depends on the standard library only, and keeps
  to the language and library of Go 1.20. The server's code comes along (`server.go` and others); it is unused and the
  linker drops it. Do not delete it to "slim down" — it shares definitions with the client.
- The import path is your module path plus `/transport/miu`; the module path is the first line of `go.mod` (upstream:
  `github.com/metacubex/mihomo`).
- Keep `LICENSE` (MIT asks for the copyright and permission notice to be kept).

### 4.2 The adapter type constant

`constant/adapters.go` needs two additions, **both at the end**, never in the middle (the enum is an `iota`; inserting in
the middle renumbers every type after it):

1. At the end of the `AdapterType` constant block (the `const (...)` that starts with `Direct AdapterType = iota`), add a
   line `Miu`.
2. In the `switch` of `func (at AdapterType) String() string`, after the `case` of the last proxy type, add:

```go
	case Miu:
		return "Miu"
```

That string is what shows up in the `type` field of the API and in dashboards.

### 4.3 The outbound adapter

Create `adapter/outbound/miu.go` with the content below (as written for A1; for A2 replace
`"github.com/MiuProtocol/Miu/miu"` with `"<your module path>/transport/miu"` and move that line up into the group of mihomo's
own imports). This code belongs to this repository and is MIT-licensed; for what applies once it sits inside mihomo, see
[§8](#8-licensing).

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

What each part is for — keep these points if you rewrite it:

- **`MiuOption`**: one field per key of the table in [§3](#3-proxy-configuration-format). The `TLS` field exists only to give
  `tls: true` somewhere to land (leaving it out would not fail, unknown keys are ignored anyway; it is there so that a
  reader sees the key is deliberately not acted on).
- **`DialContext`**: the destination is `metadata.RemoteAddress()`, so a domain name is passed to the server as a name and
  resolved there. `client.DialContext` returns as soon as it has a lane; **it does not wait for the server to confirm the
  destination** (the server never acknowledges an OPEN). A destination that cannot be reached shows up as an immediate EOF
  on the first `Read`, not as an error from `DialContext`. The returned `net.Conn` also has `CloseWrite()` (half-close);
  calling `Close()` before both directions have ended is an abort — the library sends RESET and keeps the lane in the
  pool. Wrap it with `NewConn(c, m)` to get a `C.Conn`; that is the layer where mihomo records the proxy chain. Traffic
  statistics and connection tracking are added outside by `tunnel` (`statistic.NewTCPTracker`), the adapter has nothing to
  do for them.
- **`ListenPacketContext`**: `ResolveUDP` first (as `anytls` and others do, turning a domain destination into an IP), then
  `client.ListenPacket()`. It returns a `net.PacketConn`: `WriteTo` takes a `*net.UDPAddr`, `ReadFrom` reports the source
  of every packet. The stream is opened by the first `WriteTo`, so nothing here can fail because of the network. Every UDP
  session has a lane to itself; `Close()` aborts the stream and returns the lane to the pool. Wrap it with
  `NewPacketConn(pc, m)` to get a `C.PacketConn`.
- **`SupportUOT`** returns `true`: UDP is carried inside a TCP stream. In the verified version the value is used only for
  API output (the `uot` field in `adapter/adapter.go`) and passed through by `singmux`.
- **`ProxyInfo`** fills in `DialerProxy` and **`Close`** closes the lane pool, both as `anytls` does. mihomo calls `Close`
  when a proxy is removed or the configuration is reloaded.
- **`dialLane`** is the library's `Dial` callback: TCP through the proxy's own dialer (`m.dialer`, which already carries
  `interface-name`, `routing-mark`, `dialer-proxy` and so on), then the outer handshake with `vmess.StreamTLSConn`. **The
  connection is returned exactly as the handshake produced it, with nothing wrapped around it.** On failure close the TCP
  connection yourself (`StreamTLSConn` does not). The callback is invoked concurrently and also in the background (warm-up,
  replay); it must not depend on the state of any one request.
- **`miuRawUsable`**: a self-test that runs once per process and confirms that raw segments work on the two kinds of TLS
  connection mihomo uses. If it fails, raw segments are switched off (everything else keeps working) and a warning is
  logged. See [§4.8](#48-raw-segments-what-they-need-from-the-connection-and-what-was-measured).
- **`NewMiu`**: `reality-opts` goes through mihomo's existing `RealityOptions.Parse()`. REALITY without
  `client-fingerprint` is rejected right here (otherwise the error would wait for the first dial). The SNI is taken from
  `sni`, then `servername`, then `server`. When `idle-session-timeout` / `min-idle-session` are 0 the library applies its
  own defaults; there is nothing to decide here.

### 4.4 The config parser

In `ParseProxy` in `adapter/parser.go`, add a case to `switch proxyType` (between any two cases — for instance right
after the `case "anytls":` block):

```go
	case "miu":
		miuOption := &outbound.MiuOption{BasicOption: basicOption}
		err = decoder.Decode(mapping, miuOption)
		if err != nil {
			break
		}
		proxy, err = outbound.NewMiu(*miuOption)
```

Without this case mihomo fails at start-up with `unsupport proxy type: miu`.

### 4.5 The documentation example

In `docs/config.yaml`, under `proxies:`, add an example after the `# anytls` one (match the indentation of its
neighbours; that file is written in Chinese, so the comments are too):

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

### 4.6 Unit tests

Create `adapter/outbound/miu_test.go`:

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

Expect `ok`. A failing `TestMiuRawSegmentsUsable` means raw segments are not available on the TLS connections of this
mihomo (see [§4.8](#48-raw-segments-what-they-need-from-the-connection-and-what-was-measured)); the outbound still works,
but report it as it is. Under A1, if this command fails to build because vet reports `non-constant format string`, that is
the existing issue from [§2](#2-choosing-a-route): add `-vet=off`.

### 4.7 Building

```sh
gofmt -l adapter/ constant/        # expect no output
go build -o mihomo .
./mihomo -v
```

With A2 on a project that supports older Go versions, build once more with the lowest of them, for example
`GOTOOLCHAIN=go1.20.14 go build -o mihomo-go120 .`.

### 4.8 Raw segments: what they need from the connection, and what was measured

**What a raw segment is**: when the inner connection (the one being proxied) already is TLS 1.3 ciphertext, the library
does not encrypt it again with the outer TLS. It writes a record holding nothing but a RAW frame and then the bytes
straight onto TCP. For that the library has to read and write the connection *underneath* the outer TLS connection, and
it has to see what the TLS connection has already read off the socket but not yet parsed.

**How the library gets at those** (`miu/tlsbuf.go`) — of the connection that `Dial` returns it requires:

1. a `NetConn() net.Conn` method, whose result is the underlying connection used for raw segments;
2. that it is a pointer to a struct in which two fields can be found by name: `input` (of type `bytes.Reader`) and
   `rawInput` (of type `bytes.Buffer`), either directly or promoted through an embedded pointer.

`*crypto/tls.Conn` of the standard library qualifies, and so does every fork that keeps its layout. When the fields cannot
be reached nothing breaks: that lane simply goes without raw segments (it declares `raw=0` to the server).

**Measured on the verified mihomo** — the connection `vmess.StreamTLSConn` returns for the three ways a Miu proxy can be
written:

| Proxy | Type returned | Buffers reachable | Self-test | Raw segments in real traffic (an 8 MiB file through inner TLS 1.3) |
|---|---|---|---|---|
| no `client-fingerprint` | `*tls.Conn` (`github.com/metacubex/tls`) | yes | passes | downlink 8401250 / 8397800; uplink 8400388 / 8398010 |
| `client-fingerprint: chrome` | `*utls.UConn` (`github.com/metacubex/utls`) | yes | passes | downlink 8401250 / 8396013; uplink 8400388 / 8397996 |
| plus `reality-opts` | the same, `*utls.UConn` (it is what `tlsC.GetRealityConn` returns) | yes | same type | downlink 8401249 / 8397134; uplink 8400388 / 8399002 |

(The numbers are "total bytes / bytes sent as raw segments" from the server's `-v` log; the small difference is the inner
handshake. A1 built with Go 1.27.0 and A2 built with Go 1.20.14 gave the same picture.)

The other branches of `StreamTLSConn` (ShadowTLS, Restls, JLS, TLSMirror) return something else; the `MiuOption` of this
document does not expose them. If your fork adds those outer layers to Miu they will work, without raw segments.

**The self-test**: `miu.SelfTest(client)` sets up a real TLS 1.3 connection in memory and sends a mix of frames and raw
segments in both directions — one segment deliberately starting with `15 03 03`, the case that Go's TLS read logic would
mistake for an alert record — and compares every byte. The `client` argument says which kind of TLS connection the client
end uses, which is why the adapter runs it once for `metacubex/tls` and once for `metacubex/utls`. After an upgrade of
either dependency that renames the fields or changes the read logic, the self-test fails, `miuRawUsable()` returns `false`
and the adapter sets `DisableRaw` to `true`.

**What `DisableRaw: true` costs**: everything keeps working; inner TLS traffic is encrypted a second time by the outer
layer (twice the cipher work, lower throughput on bulk transfers), and `raw` stays 0 in the server's `-v` log.
Interoperation with the server is unaffected.

**Wrappers** — what `Dial` returns has to be the TLS connection itself:

- An ordinary wrapper *around* the TLS connection (statistics, reference counting, a deadline shim): the library no longer
  recognizes a TLS connection and raw segments switch themselves off. It works, and raw segments are lost for nothing.
- A wrapper type that *embeds* the TLS connection and overrides `Read` / `Write` (say, embeds `*tls.Conn` and adds
  buffering): the library finds the buffer fields and enables raw segments, while reads and writes pass through your
  override. As soon as that buffers or reads ahead, the bytes of a raw segment end up misaligned — inner TLS reports
  `bad record MAC`, connections drop at random. **Do not do this.**
- Wrappers *below* the TLS connection (the lazy connection of TFO, another proxy's connection in a `dialer-proxy` chain)
  are fine: TLS and the library read and write the very same object. When the underlying connection is not a system
  socket the library cannot probe a lane before taking it from the pool; dead lanes are then caught by the replay.

### 4.9 What is not wired up, and does not need to be

- **Clearing the pool on a network change**: the library has `client.CloseIdle()` for dropping pooled lanes after the
  network has changed. The verified mihomo has no "network changed" notification for outbounds (on a change of the default
  interface only the DNS resolver is told: `grep -rn "resolver.ResetConnection()" --include="*.go" .`), so nothing is
  wired. It works without: when a dead lane comes out of the pool the library probes it, and if needed replays the request
  once on a fresh lane. If your fork has such a hook, call `CloseIdle()` on every Miu proxy from it.
- **Share-link conversion** (`common/convert/converter.go`): Miu defines no share-link format; nothing to add.
- **Inbound** (`listener/`): this document covers the outbound only. The server is this repository's `miu-server`.
- **TCP keep-alive**: set by mihomo's dialer from the global configuration (`keep-alive-interval` and friends); not the
  adapter's business.
- **The inbound type constants of `metadata`** (`constant/metadata.go`): those are for inbounds; nothing to add.

## 5. Route B: implement the protocol yourself

Read [PROTOCOL.md](../PROTOCOL.md) from start to finish first. Every "§" below refers to its sections.

### 5.1 Target shape

- Put the protocol code in `transport/miu/` and give it the same four entry points as the library of route A, so that the
  adapter, the parser case and the tests of [§4.2](#42-the-adapter-type-constant)–[§4.6](#46-unit-tests) can be used
  unchanged: `NewClient(ClientConfig{PSK, Dial, LaneIdle, MinIdle, DisableRaw})`,
  `DialContext(ctx, "tcp", "host:port") (net.Conn, error)` (the result also has `CloseWrite()`),
  `ListenPacket() (net.PacketConn, error)`, `Close()`.
- The outer handshake still goes through `vmess.StreamTLSConn`, inside the `Dial` callback; the protocol code only ever
  sees a `net.Conn` on which the handshake is done.
- The two buffers raw segments need are called `input` (`bytes.Reader`) and `rawInput` (`bytes.Buffer`) both in the `Conn`
  of `github.com/metacubex/tls` and in the `Conn` of `github.com/metacubex/utls` (which `UConn` embeds). They are
  unexported: take their addresses by name with `reflect` and convert to pointers; get the underlying connection from
  `NetConn()`. Check the field types before using them, and when they cannot be reached treat the lane as having no raw
  segments (`raw=0`) — do not panic.

### 5.2 Order of implementation, with a check for every step

Use this repository's `miu-server -v` as the peer at every step (set up as in [§6.1](#61-start-the-peers)), and check each
step when it is done instead of saving the checks for the end.

| Step | What to build | How to check it |
|---|---|---|
| 1 | Codecs: frames, `socksAddr` / `uotAddr`, the settings text, parsing a padding scheme and its md5 | unit tests against the vectors below |
| 2 | One stream per connection, DATA only, `raw=0`, no shaping, no pool: handshake → "token · padding · Settings" in one write → OPEN · DATA → read frames up to END; `CloseWrite` sends END | the small request of [§6.3](#63-the-checks) works; the server log shows the access line and a `closed:` line with matching byte counts; with a deliberately wrong psk the server logs `auth failed: unknown token` |
| 3 | The whole read side: PAD / ServerSettings / UpdatePaddingScheme anywhere; remember `raw` and `idle`; only END ends a stream, a dropped connection is an error | add `"paddingScheme": ["stop=3","0=40-60","1=200-300","2=300-400"]` to the server configuration and restart it: requests still work (every new connection now receives an UpdatePaddingScheme) |
| 4 | Shaping: packets numbered from 1 per stream and per direction; END is not shaped | unit test recording the length of every write. With the default scheme the first packet (OPEN plus less than 90 bytes of data) is one write of 100–399 bytes; END is a write of 3 bytes on its own, and the last write of its direction |
| 5 | The lane pool: back into it once both directions have seen END; last in, first out; retention; warm-up; OPEN waits up to 10 ms for the first payload | ten small requests in a row leave no more than 3 connections to the server (counted as in [§6.3](#63-the-checks)) |
| 6 | Abort: RESET, a bounded discard of the downlink up to END, back to the pool | the "aborted downloads" check: the connection count does not grow |
| 7 | Receiving raw segments: declare `raw=1`; reading the body of a RAW frame, fetching the raw bytes | a large download through inner TLS has the right hash; the server logs `down N (raw close to N)` |
| 8 | Sending raw segments: follow the inner TLS record boundaries along the uplink (this needs the ServerHello, recognized in the DATA of the downlink) and send large batches as RAW once the condition holds | a large upload through inner TLS has the right hash; the server logs `up N (raw close to N)` |
| 9 | UDP: UoT v2 | the UDP check |
| 10 | Probing a lane before reuse; replay on a dead lane | the "server restart" check |
| 11 | Reads that resume after a timeout; `Close` interrupting a blocked `Read`; concurrency | the half-close check; `go test -race`; 32 concurrent downloads all with the right hash |

Test vectors (hexadecimal):

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

### 5.3 What goes wrong most often

Most frequent first. Each item names its place in the protocol document.

1. **Reading ahead while parsing frames** (§9). A frame header is 3 bytes and a body is `len` bytes: read exactly what is
   needed. Any buffered reader (`bufio.Reader`, or reading a large chunk and slicing it yourself) swallows the raw bytes
   after a RAW frame as if they were TLS plaintext.
2. **A Go TLS connection peeks at the next byte after emptying a record** (§9). Before `Read` returns, if the record is
   used up, `rawInput` holds more data and its first byte is `0x15`, it goes and parses an alert record — and the first raw
   byte after a RAW frame may well be `0x15`. So read the first 3 bytes of the RAW frame's body (4 bytes) with `Read` and
   take the last one straight out of `input` with `ReadByte()`; then check `input.Len() == 0` (otherwise RAW was not the
   last frame of its record: a protocol error, close the lane). Both `metacubex/tls` and `metacubex/utls` behave this way.
   To test it: send a raw segment that starts with `15 03 03 00 02` and see whether it arrives intact.
3. **Raw bytes come from `rawInput` first, then from the underlying connection** (§5.2, §9). The TLS layer reads more off
   the socket than it needs, so the raw bytes after a RAW record are often already in `rawInput`. When reading the
   underlying connection, never ask for more than is left of the segment: anything beyond belongs to the next TLS record,
   and once taken the stream is misaligned.
4. **A RAW frame has a TLS record to itself** (§3, §5.2). To send: one `Write` of exactly 7 bytes (`06 0004` + u32) on the
   TLS connection, then the N bytes written directly to the connection `NetConn()` returns. Both steps, and every other
   write, belong under one write lock; no other frame may slip in between.
5. **END is not shaped, and it is the last byte of its direction** (§6). A PAD written after END reaches the peer after
   the lane is back in a pool, where it is taken for data of the next stream or for "the peer is closing this lane". When
   the uplink has to end before OPEN has gone out, write OPEN and END together, unshaped.
6. **The two moments for RESET** (§5.3). Uplink not yet ended: send RESET instead of END. Uplink ended, downlink END not
   yet received: send a RESET after the END. OPEN never sent: send nothing, the lane goes back as it is. Downlink END
   already received and uplink still open: a plain END is enough. After a RESET, read the downlink up to END and throw it
   away, with a 3 second limit: reached END, the lane returns to the pool; limit hit, close it.
7. **When a lane may go back to the pool** (§5, §5.3, §8). All of these at once: END or RESET has been sent; the peer's END
   has been read; neither reading nor writing has failed; the read cursor is on a frame boundary; the deadlines set for
   this stream have been cleared. One missing — close it instead. A lane that returns carrying half a stream makes the
   next stream read the previous one's data.
8. **The server never answers an OPEN** (§5). Do not wait for any acknowledgement; when the destination cannot be reached
   the server simply sends END, which the client sees as "the stream ended at once". Keep the end of a stream (END) apart
   from a dropped connection (EOF): the first is `io.EOF` to the caller, the second is an error.
9. **When to switch to raw segments** (§5.1). Record boundaries of the inner TLS are followed over the byte stream, not
   assumed to coincide with writes; the batch containing that `0x17` record header still goes as DATA and raw segments
   start with the next one; nothing raw may be sent to a peer that has not declared `raw=1`; within the raw phase a batch
   under 4 KiB still goes as DATA; after 64 KiB without getting there the stream stays on DATA for good. The client's
   uplink has to wait for "the inner connection is TLS 1.3", which it can only learn from the ServerHello in the DATA of
   the **downlink**.
10. **The authentication header** (§2). `token(32) · padlen(u16) · padding`; the token is the SHA-256 of the psk string
    with surrounding whitespace removed, not base64-decoded; token, padding and the Settings frame leave in one write;
    after that streams may be opened without waiting for ServerSettings.
11. **Packets are numbered "per stream, per direction", from 1** (§6) — not per lane. OPEN plus the first payload is
    packet 1.
12. **ServerSettings can arrive at any time** (§4). On a new lane it precedes the downlink of the first stream; on a lane
    that was warmed up and never used it stays unread in the socket. So "data waiting on an idle lane means the peer is
    closing it" holds only for lanes that **have carried a stream**.
13. **When a dead lane is replayed** (§8). Only when all four hold, and only once: the lane came from the pool (it was not
    dialed for this stream); no downlink frame of this stream has arrived; no more than 64 KiB of uplink has been sent; the
    stream has not been closed locally. To replay: empty the pool, dial a new lane, resend OPEN and the uplink sent so far
    (and END, if the uplink had ended). This needs a copy of the uplink kept for as long as the conditions hold.
14. **UoT has two address encodings** (§3, §7). OPEN and the UoT request use socksAddr (IPv4 `01`, domain `03`, IPv6 `04`);
    the per-packet address uses uotAddr (IPv4 `00`, IPv6 `01`, domain `02`). The destination in OPEN is always
    `sp.v2.udp-over-tcp.arpa:0`; `isConnect` in the request is 0; every packet carries an address; packets may span DATA
    frames and must be cut out of the byte stream. UDP streams never use raw segments.
15. **A read that times out must be resumable; a write that times out ends the lane** (§9). mihomo sets read deadlines on
    connections; when one passes in the middle of a frame header the progress has to be kept for the next read.
16. **`Close` cannot do all its work in the caller's goroutine.** An abort has to send a frame and read up to END while
    another goroutine may be blocked in `Read` or `Write`. First make the blocked `Read` return at once (set the read
    deadline to now), then finish the RESET and the discard in the background.

## 6. Verification

Everything here happens on one machine and applies to route A and route B alike. You need Go 1.24+ (to build this
repository's `miu-server`), the `openssl` command of OpenSSL 1.1.1 or later, `python3` and `curl`. The ports are arbitrary;
pick others if they are taken.

**How to call curl**: if the shell carries proxy environment variables, curl sends its requests to that proxy rather than
to your mihomo. Always call it like this, and **do not use `--noproxy`** (it disables `-x` as well):

```sh
c() { env -u http_proxy -u https_proxy -u all_proxy -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u no_proxy -u NO_PROXY curl -sS "$@"; }
```

### 6.1 Start the peers

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

The destinations to proxy to (all local, so that results do not depend on the outside network):

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

The two servers (`-v` is required: its log is how raw segments are confirmed later):

```sh
bin/miu-server -c server-tls.json -v > server-tls.log 2>&1 &
bin/miu-server -c server-reality.json -v > server-reality.log 2>&1 &
sleep 6      # a REALITY server probes its site after starting, about 5 seconds; connections arriving meanwhile wait
cat server-tls.log server-reality.log
```

Expect:

```
… listening on 127.0.0.1:28443 (TLS 1.3), 1 user(s)
… listening on 127.0.0.1:28444 (REALITY, looking like 127.0.0.1:27444), 1 user(s)
```

### 6.2 mihomo configuration

Each of the three proxies gets a local entry of its own (`proxy` in `listeners` pins an entry's traffic to one proxy), so
they can be tested one by one without switching groups:

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

If `mihomo.log` contains `Miu: raw segments are not usable with this build`, the self-test has switched raw segments off:
the two "raw segments" checks below will fail, everything else should still pass.

### 6.3 The checks

Run all of them for each of the three entries: `PORT=17891` (server at 28443), `PORT=17892` (28443), `PORT=17893` (28444).
The examples use 17891.

```sh
PORT=17891; SPORT=28443; SLOG=server-tls.log     # the REALITY node: PORT=17893 SPORT=28444 SLOG=server-reality.log
WANT=$(cat big.sha)
# how many connections (lanes) mihomo has to the server. Without lsof: ss -Htn state established "( dport = :$SPORT )" | wc -l
lanes() { lsof -nP -iTCP:$SPORT -sTCP:ESTABLISHED | grep -c "^mihomo"; }
```

**① A small request**

```sh
c -x socks5h://127.0.0.1:$PORT --max-time 10 http://127.0.0.1:27080/index.html
```

Expect `hello from the target`. Two more lines appear in `$SLOG` (user, client address, destination; byte counts at the
end):

```
… alice 127.0.0.1:53124 -> tcp 127.0.0.1:27080
… alice 127.0.0.1:53124 -> tcp 127.0.0.1:27080 closed: up 88 (raw 0), down 206 (raw 0)
```

(Byte counts vary a little with the curl version, here and below.)

**② Hash of a large file (plaintext inside)**

```sh
c -x socks5h://127.0.0.1:$PORT --max-time 60 http://127.0.0.1:27080/big.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
```

Expect two identical lines. In the log this stream ends with `down 8388812 (raw 0)`: plaintext does not use raw segments.

**③ Inner TLS, downlink in raw segments**

```sh
c -x socks5h://127.0.0.1:$PORT -k --max-time 60 https://127.0.0.1:27443/big.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
grep "27443 closed" $SLOG | tail -1
```

Expect identical hashes and a log line like this one — the `raw` of `down` close to the total (the few KB of difference
are the inner handshake):

```
… -> tcp 127.0.0.1:27443 closed: up 496 (raw 0), down 8401247 (raw 8397151)
```

`raw 0` means this kind of outer connection is not getting raw segments; go to [§7](#7-symptoms-and-causes).

**④ Inner TLS, uplink in raw segments**

```sh
c -x socks5h://127.0.0.1:$PORT -k --max-time 4 -H 'Expect:' -T www/big.bin https://127.0.0.1:27445/up -o /dev/null
tail -c 8388608 received.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
grep "27445 closed" $SLOG | tail -1
```

That sink receives and never answers, so curl ends with a timeout (exit code 28) after 4 seconds; that is expected. Expect
identical hashes and, in the log, the `raw` of `up` close to the total:

```
… -> tcp 127.0.0.1:27445 closed: up 8400388 (raw 8399312), down 1308 (raw 0)
```

**⑤ Downloads aborted midway do not cost connections**

```sh
sleep 1; before=$(lanes)
for i in 1 2 3 4 5; do
  c -x socks5h://127.0.0.1:$PORT -k --limit-rate 500k --max-time 1 -o /dev/null https://127.0.0.1:27443/big.bin; sleep 0.3
done
sleep 1; echo "lanes: $before -> $(lanes)"
c -x socks5h://127.0.0.1:$PORT -k --max-time 60 https://127.0.0.1:27443/big.bin | shasum -a 256 | cut -d' ' -f1; echo $WANT
```

Every curl ends with a timeout (expected). Expect the same connection count before and after, and a correct hash for the
full download that follows. The number itself does not matter (one proxy usually has 3: the lane that was used plus two
warmed up; `miu-tls` and `miu-chrome` connect to the same server port, so there the count covers both) — what matters is
that it does not change. A count that grows by one per abort means an abort is being implemented as closing the
connection.

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

Expect `udp: 4/4 datagrams echoed`, and an access line `-> udp 127.0.0.1:27053` in the log (its `closed:` line follows a
moment after the session has ended).

**⑦ Half-close**

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

Expect `half-close: ok`. A failure means "the application closed its write side" was treated as the end, or an abort, of
the whole stream.

**⑧ The delay-test API** (the path mihomo's health checks take)

```sh
c "http://127.0.0.1:19090/proxies/miu-tls/delay?url=http%3A%2F%2F127.0.0.1%3A27080%2Findex.html&timeout=3000"
```

Test each of the three proxy names. Expect `{"delay":N}`. **On loopback you may see something else**: the request
completes in under a millisecond, the delay rounds to 0, and this API treats 0 as a failure and answers
`{"message":"An error occurred in the delay test"}` (`delay == 0` in `hub/route/proxies.go`). That is not the outbound's
doing. When it happens, go by the server log: every call should add an access line and a line like
`closed: up 84 (raw 0), down 184 (raw 0)` to `$SLOG`.

**⑨ The first request after a server restart**

```sh
pkill -f "miu-server -c server-tls.json"; pkill -f "miu-server -c server-reality.json"; sleep 0.5
bin/miu-server -c server-tls.json -v >> server-tls.log 2>&1 &
bin/miu-server -c server-reality.json -v >> server-reality.log 2>&1 &
sleep 6
for PORT in 17891 17892 17893; do
  c -x socks5h://127.0.0.1:$PORT --max-time 10 -o /dev/null -w "$PORT: %{http_code}\n" http://127.0.0.1:27080/index.html
done
```

mihomo's pool now holds lanes to processes that no longer exist. Expect `200` three times, the very first request included
(the library notices on reuse that the lane is gone, or, after a failed write, replays on a new lane).

To clean up, `kill` mihomo, the two `miu-server` processes and the destinations started above
(`pkill -f "s_server -accept 127.0.0.1:274"`, `pkill -f udpecho.py`, `pkill -f "http.server 27080"`,
`pkill -f "tail -f /dev/null"`).

### 6.4 Acceptance checklist

Tick every item for each of `miu-tls`, `miu-chrome` and `miu-reality`:

| # | Item | Passes when |
|---|---|---|
| 1 | The configuration parses | `mihomo -t` succeeds; no warning or error in the log |
| 2 | A small request | ① prints the right text; the server has the access line and the `closed:` line |
| 3 | Hash of a large file | ② hashes match |
| 4 | Inner TLS, downlink in raw segments | ③ hashes match and `down N (raw close to N)` |
| 5 | Inner TLS, uplink in raw segments | ④ hashes match and `up N (raw close to N)` |
| 6 | Aborts do not cost connections | ⑤ same count before and after, and the download after it has the right hash |
| 7 | UDP | ⑥ 4/4 |
| 8 | Half-close | ⑦ ok |
| 9 | Delay test | ⑧ returns a delay; or (when the machine is too fast) returns that error while the server log has the complete pair of lines for every call |
| 10 | First request after a server restart | ⑨ three times 200 |
| 11 | Unit tests | `go test -run TestMiu ./adapter/outbound/` passes |
| 12 | Builds with every supported Go version | `go build` with each of them |

Items 4 and 5 failing while everything else passes is "works, without raw segments" — report it as that, and look for the
cause in [§7](#7-symptoms-and-causes).

Measured on the verified version: route A1 (built with Go 1.27.0 and with Go 1.24.0) and route A2 (built with Go 1.20.14)
pass everything on all three proxies. Item 9 was the "too fast" case on the test machine: each proxy returned
`{"delay":1}` on some calls and that error on others, and the server log was complete for every call.

## 7. Symptoms and causes

| Symptom | Cause | Fix |
|---|---|---|
| Start-up fails with `unsupport proxy type: miu` | `adapter/parser.go` has no `case "miu"`, or the binary being run is not the one just built | [§4.4](#44-the-config-parser); check with `mihomo -v` |
| Start-up fails with `'' has unset fields: psk` | the proxy has no `psk` (this is how the decoder reports a missing required key) | add it; the key is `psk`, not `password` |
| Start-up fails with `miu: psk too short (need at least 16 characters)` | `psk` is shorter than 16 characters | use a longer string, the same on both sides |
| Start-up fails with `invalid REALITY public key` | `reality-opts.public-key` is not 43 characters of base64url | use the `publicKey` printed by `miu-server keygen` |
| Start-up fails with `miu: reality-opts needs client-fingerprint` | `reality-opts` without `client-fingerprint` | add `client-fingerprint: chrome` |
| `go build` says `go.mod requires go >= 1.24.0`, or every CI job with an older Go turns red | route A1 with a toolchain below 1.24 | switch to A2, or confirm that builds with older Go can be dropped |
| `go test` reports `non-constant format string` and several packages `[build failed]` | A1 raised the `go` line to 1.24, which enables a newer vet check on existing mihomo code | `-vet=off`, or fix those places; unrelated to Miu |
| Every request fails (curl: `Empty reply`), nothing telling in mihomo's log; the server's `-v` log says `miu: auth failed: unknown token` | the psk differs between the two sides: stray characters, a base64 decode somewhere, or another user's key | psk is used as a string, as written; compare the values in the two configurations |
| mihomo logs `tls: failed to verify certificate: x509: certificate signed by unknown authority`; the server logs `handshake: remote error: tls: bad certificate` | the server has a self-signed certificate and the client verifies | for testing, `skip-cert-verify: true` or a `fingerprint`; in production use a trusted certificate and an `sni` that matches it |
| A REALITY proxy does not connect: mihomo logs `REALITY authentication failed` or `x509: certificate signed by unknown authority`; the server logs `REALITY: processed invalid connection … authentication failed or validation criteria not met` | one of `public-key`, `short-id`, `sni` does not match the server (the server passed the connection on to the site it imitates, and the client received that site's certificate) | the public key is the `publicKey` from `keygen` (not `privateKey`); `short-id` is in the server's `shortIds`; `sni` is in its `serverNames` |
| The first connection to a freshly started REALITY server takes about 5 seconds | the server is probing the site it imitates | normal; wait for the probe |
| mihomo logs `REALITY is based on uTLS, please set a client-fingerprint` | the same as "needs client-fingerprint", reached past the check in `NewMiu` | add `client-fingerprint` |
| It works, but in the server log streams with TLS inside always show `raw 0` | (a) mihomo's log has `Miu: raw segments are not usable`: the self-test failed; (b) the connection returned by `Dial` is wrapped; (c) the destination is not TLS 1.3 (TLS 1.2 and plaintext never use raw segments); (d) too little data (batches under 4 KiB after the handshake) | (a) read the error the self-test reports — most likely a TLS dependency was upgraded and its fields changed; (b) [§4.8](#48-raw-segments-what-they-need-from-the-connection-and-what-was-measured); (c) and (d) are normal |
| HTTP destinations work, HTTPS destinations fail at random: `bad record MAC` / `decryption failed` from the inner connection, or a download with the wrong hash | the bytes of raw segments are misaligned: reads or writes of the connection returned by `Dial` are rewritten or buffered; in route B, items 1–4 of [§5.3](#53-what-goes-wrong-most-often) | set `DisableRaw: true` to confirm (if the problem disappears, it is the handling of raw segments), then work through [§4.8](#48-raw-segments-what-they-need-from-the-connection-and-what-was-measured) / [§5.3](#53-what-goes-wrong-most-often) |
| Each aborted download adds a connection to the server (or drops one and dials another) | an abort is implemented as closing the connection; in route A usually because the adapter swaps the connection returned by `client.DialContext` for something else before `NewConn`, or creates a new `miu.Client` per request | one `miu.Client` per proxy, created in `NewMiu`; hand the result of `DialContext` straight to `NewConn` |
| Requests occasionally hang for a few seconds and fail; the server logs `miu: OPEN before the previous stream ended` or `data outside of a stream` | route B: a lane went back to the pool with an unfinished stream on it, or something was written after END | items 5 and 7 of [§5.3](#53-what-goes-wrong-most-often) |
| After a server restart (or a network change) the first request or two fail, then things recover | route B: no probe before reuse, no replay on a dead lane | items 12 and 13 of [§5.3](#53-what-goes-wrong-most-often) |
| UDP does not work, TCP does | the proxy lacks `udp: true`; or the entry does not accept UDP (`udp: true` in the `listeners` of this document's configuration) | add it |
| No answer after an upload (the connection is closed entirely once the client half-closes) | `CloseWrite` did not reach the Miu stream and was downgraded to `Close` | cannot happen in route A (through `NewConn`, mihomo's relay finds `CloseWrite` on the stream); in route B implement `CloseWrite() error` on the stream |
| Memory or connection count runs high with many proxies | every proxy keeps up to 32 idle lanes and warms up 2 while in use | lower `min-idle-session` / `idle-session-timeout`; idle lanes close by themselves after 120 seconds at most |

## 8. Licensing

- This repository, the example code of this document included, is MIT-licensed. When copying source for A2, keep the
  `LICENSE` file.
- mihomo is GPL-3.0. **Files placed in the mihomo source tree — the adapter written from this document as much as a copied
  `transport/miu/` — are subject to GPL-3.0 when distributed as part of mihomo** (MIT is compatible with GPL-3.0, so the
  combination is allowed; the other way round, do not copy mihomo code back into this repository).
- An implementation written for route B from the protocol document belongs to whoever writes it, and is likewise
  distributed under the license of the project it lives in.
