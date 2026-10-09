<p align="center">
  <img src="assets/miu-logo.svg" width="112" alt="Miu">
</p>

<h1 align="center">Miu</h1>

<p align="center">English | <a href="README.zh-CN.md">简体中文</a></p>

<p align="center">
  A proxy protocol on top of TLS 1.3 / REALITY: a connection pool instead of multiplexing, and data that is already TLS 1.3 ciphertext is not encrypted a second time.
</p>

This repository is the standalone Go implementation of Miu: a library, a server program `miu-server`, and a client program `miu-client` (local SOCKS5).

The wire format and the required behaviour are specified in [PROTOCOL.md](PROTOCOL.md).

## Features

- **Lane pool.** A lane is one TCP connection + outer TLS + one authentication. It carries one stream at a time and goes
  back to the pool when the stream ends. Opening a stream on a warm lane needs no handshake and waits for no reply:
  OPEN and the application's first bytes leave in the same packet. There is no multiplexing, so there are no
  flow-control windows and no head-of-line blocking between streams; back-pressure is left entirely to TCP.
- **Inner TLS 1.3 forwarded as is.** The record boundaries of the inner TLS are tracked along the way. After the inner
  handshake, inner ciphertext records are no longer wrapped in the outer encryption: one record holding only a RAW frame
  declares a byte count, and that many bytes follow directly on TCP. Plaintext, the plaintext part of the inner
  handshake, and TLS 1.2 stay inside the outer encryption. On Linux the server's downlink uses splice, so the data never
  enters user space.
- **Aborting does not waste the lane.** When the application closes a connection the client sends RESET, discards the
  rest of the downlink up to the server's END, and the lane goes back to the pool.
- The first few packets of each stream are shaped by a padding scheme (AnyTLS's scheme format; the server can push its
  own). UDP runs as UoT v2 inside a stream, one lane per session.
- If a lane taken from the pool turns out to be dead (an expired NAT entry and the like), a stream that has not received
  any downlink yet and has not sent much is replayed once on a fresh lane.

## Build

Go 1.24 or newer is required.

```sh
go build -o bin/ ./cmd/...
```

This produces `bin/miu-server` and `bin/miu-client`. Cross-compile with `GOOS` / `GOARCH` as usual (Linux, macOS and
Windows all build).

There are only two dependencies: [uTLS](https://github.com/refraction-networking/utls) (browser fingerprint and the
REALITY handshake on the client) and [xtls/reality](https://github.com/xtls/reality) (the REALITY handshake on the
server). A program that uses only the `miu` library package with the standard library's TLS links neither of them.

## Try it locally

```sh
# A PSK (any string of at least 16 characters; both ends must use exactly the same characters)
openssl rand -base64 32

# A self-signed certificate (for trying it out only; use a trusted certificate in production)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=example.com" -addext "subjectAltName=DNS:example.com"
```

`server.json`:

```json
{
  "listen": "127.0.0.1:8443",
  "cert": "cert.pem",
  "key": "key.pem",
  "users": [{"name": "alice", "psk": "<the PSK generated above>"}]
}
```

```sh
bin/miu-server -c server.json
# In another terminal (the certificate is self-signed, hence -insecure)
bin/miu-client -server 127.0.0.1:8443 -sni example.com -psk '<the PSK generated above>' -insecure
# In a third terminal
curl -x socks5h://127.0.0.1:1080 https://example.com/
```

The server prints one access-log line per stream: `user client-address -> tcp|udp target`.

## Server

```sh
miu-server -c server.json [-listen address] [-v]
miu-server keygen            # generate a REALITY key pair
```

The outer layer is one of: a certificate (TLS 1.3) or `reality`. Examples are in [examples/](examples/).

Outer TLS 1.3:

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

Outer REALITY:

```json
{
  "listen": ":443",
  "reality": {
    "dest": "www.example.com:443",
    "serverNames": ["www.example.com"],
    "privateKey": "<privateKey printed by miu-server keygen>",
    "shortIds": ["0123456789abcdef"]
  },
  "users": [{"name": "alice", "psk": "..."}]
}
```

| Field | Meaning |
|---|---|
| `listen` | Listen address, `:443` by default; overridden by `-listen` on the command line |
| `cert` / `key` | Certificate and private key of the outer TLS (PEM files). Only TLS 1.3 is accepted |
| `reality.dest` | The cover target, `host:port`. It must support TLS 1.3. Connections that fail authentication are forwarded to it unchanged |
| `reality.serverNames` | SNI values the client may use; they should be names covered by the cover target's certificate |
| `reality.privateKey` | X25519 private key, base64url without padding |
| `reality.shortIds` | Short ids the client may present, each up to 16 hex digits; the empty string `""` is allowed |
| `users` | User list: `name` is used in logs only, `psk` is the credential (at least 16 characters, used as the string it is, not base64-decoded) |
| `idleTimeout` | How many seconds a lane without a stream is kept, 180 by default. Sent to the client |
| `paddingScheme` | Optional; overrides the built-in packet-length shaping scheme, one array element per line, e.g. `["stop=8", "0=30-30", "1=100-400"]` |

`-v` additionally prints diagnostics (target unreachable, handshake failure, authentication failure) and, when a stream
ends, one line with how many bytes it carried and how many of them went as raw segments:

```
alice 198.51.100.7:53124 -> tcp example.org:443 closed: up 496 (raw 0), down 8401247 (raw 8397151)
```

A non-zero `raw` means the sender of that direction recognised the inner TLS 1.3 and the receiver can take raw
segments. When you are bringing up another client implementation, this is the most direct way to confirm that raw
segments work.

After it starts, a REALITY server first probes the cover target once (to learn what it sends after the handshake, so
it can send the same). This takes about 5 seconds, and connections that arrive in the meantime wait for it.

Not every site works as a cover target: with a few sites the handshake fails when the REALITY library imitates them
(this is unrelated to miu; other protocols built on the same library fail with the same target). After changing the
target, connect once with `miu-client` to make sure it works.

## Client

```sh
miu-client -c client.json [-v]
miu-client -server example.com:443 -psk '...' [-sni name] [-insecure] [-fingerprint chrome] [-listen 127.0.0.1:1080]
miu-client keygen            # same as miu-server keygen
```

It opens a local SOCKS5 proxy (no authentication; CONNECT and UDP ASSOCIATE are supported), `127.0.0.1:1080` by
default. Command-line flags override the same settings in the configuration file.

Outer TLS 1.3:

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

Outer REALITY:

```json
{
  "listen": "127.0.0.1:1080",
  "server": "203.0.113.10:443",
  "psk": "...",
  "reality": {
    "serverName": "www.example.com",
    "publicKey": "<publicKey printed by miu-server keygen>",
    "shortId": "0123456789abcdef"
  }
}
```

| Field | Meaning |
|---|---|
| `listen` | Local SOCKS5 address, `127.0.0.1:1080` by default |
| `server` | Server address, `host:port` |
| `psk` | The same string as one of the server's users |
| `sni` | SNI of the outer TLS; defaults to the host name in `server` |
| `insecure` | `true` skips verification of the server certificate (only for trying out a self-signed certificate) |
| `fingerprint` | `"chrome"`: use Chrome's ClientHello (uTLS); if omitted, the Go standard library's |
| `reality.serverName` | SNI; must be one of the server's `serverNames` (defaults to `sni`) |
| `reality.publicKey` | The server's X25519 public key, base64url without padding |
| `reality.shortId` | One of the server's `shortIds`; may be the empty string |

With `reality` the ClientHello is always Chrome's and `insecure` does not apply: the server's identity is established
by the authentication inside the handshake, and the handshake simply fails when that authentication does not pass
(wrong public key, short id or SNI).

## Using it as a library

```go
import "github.com/MiuProtocol/Miu/miu"

// Server: listen and complete the outer handshake yourself, then hand the connection to Serve.
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

// Client: one Client is the lane pool to one server.
client, err := miu.NewClient(miu.ClientConfig{
	PSK:  psk,
	Dial: miu.TLSDialer("example.com:443", &tls.Config{}),
})
conn, err := client.DialContext(ctx, "tcp", "example.org:443") // net.Conn, plus CloseWrite
pc, err := client.ListenPacket()                               // net.PacketConn (UDP)
```

- Calling `conn.Close()` before both directions have ended aborts the stream (sends RESET); the lane still goes back to
  the pool. `CloseWrite()` is a half-close.
- Other outer layers: `miu/fingerprint` (`fingerprint.Dialer`, uTLS) and `miu/reality` (`reality.Dialer`) provide two
  more `Dial` functions; the server side of the REALITY handshake is in `miu/realityserver`. Any `net.Conn` can serve as
  the outer layer, but only a Go TLS connection sitting directly on TCP (crypto/tls, uTLS, xtls/reality) gets raw
  segments.
- Raw segments need two internal buffers of the Go TLS connection, reached by reflection. `miu.SelfTest` (and
  `fingerprint.SelfTest`, `realityserver.SelfTest`) actually runs an exchange in memory to confirm this works with the
  current Go version. Both command-line programs run it at startup; if it fails they print an error and turn raw
  segments off (declaring `raw=0` in settings), and everything else keeps working. Do the same in your own program and
  set `DisableRaw` on failure.
- After a network change, call `client.CloseIdle()` to empty the pool.
- On the server, `ServerConfig.OnAccess` is called when a stream starts and `OnClose` when it ends, with a `Traffic`
  value (bytes in each direction and how many of them were raw segments).
- The core package `miu` uses only the standard library, and only Go 1.20 syntax and APIs. If the host project's Go
  version is lower than what this module's `go.mod` requires, copy the non-test files of the `miu/` directory into it
  as they are (keep the LICENSE).

For the complete steps to add a Miu outbound to mihomo (or one of its forks), see [docs/mihomo.md](docs/mihomo.md).
That document is written for an AI coding assistant to follow. A fork of mihomo with those steps already applied is at
[MiuProtocol/mihomo](https://github.com/MiuProtocol/mihomo) (branch `Alpha`).

## Supported

- TCP; UDP (UoT v2, one UDP socket per session on the server, full-cone)
- Outer TLS 1.3 (standard library, or Chrome fingerprint) and REALITY (Chrome fingerprint on the client)
- Raw segments in both directions; on Linux the server's downlink uses splice + TCP_CORK, other platforms copy in user space
- Lane pool: last in first out, two retention tiers, pre-warming while streams are being opened in quick succession, a liveness check before use, replay on a dead lane
- Packet-length shaping, with the scheme pushed by the server; RESET abort; half-close
- Multiple users; access log

## Not supported

- Multiplexing, heartbeats, session resumption: the protocol does not have them
- WebSocket / gRPC as the outer layer, or TLS terminated by a reverse proxy (the library accepts any `net.Conn` as the outer layer, only without raw segments; the two programs do not implement these transports)
- Client fingerprints other than `chrome`
- REALITY extras: ML-DSA-65 verification, PROXY protocol (`xver`), limits on client version and clock difference
- SOCKS5 username/password authentication, BIND, UDP fragmentation; an HTTP proxy inbound; transparent proxy / TUN
- Routing and outbound policy on the server, traffic statistics, rate limiting, adding or removing users at run time (the server always dials the target directly; in the library the dialing can be replaced with `ServerConfig.Dial`)
- The liveness check before use is not implemented on Windows; dead lanes are covered by replay

## Tests

```sh
go test -race ./...
```

The loopback tests cover small and large payloads, concurrency, a real inner TLS 1.3 (asserting that both directions
used raw segments), UDP, lane reuse after an abort, replay on a dead lane and more, under four outer layers
(plaintext, TLS, uTLS, REALITY). `miu/live_test.go` additionally holds two interoperability tests that run against
another implementation; they are enabled by environment variables described at the top of the file.

## Logo

The logo is a μ (read "miu") with cat ears. [assets/](assets/) holds two versions:

| File | Use |
|---|---|
| [miu-logo.svg](assets/miu-logo.svg) | Rounded square icon on orange, for app icons and avatars |
| [miu-mark.svg](assets/miu-mark.svg) | Single-colour mark that follows `currentColor`, for protocol badges and small icons in lists |

## License

[MIT](LICENSE).
