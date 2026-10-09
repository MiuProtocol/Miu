package miu_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MiuProtocol/Miu/miu"
	"github.com/MiuProtocol/Miu/miu/fingerprint"
	"github.com/MiuProtocol/Miu/miu/reality"
	"github.com/MiuProtocol/Miu/miu/realityserver"
)

// End-to-end loopback: Client → Server → target, all in this process. The outer layer is plaintext TCP
// (no raw segments, everything in DATA), crypto/tls, uTLS with a browser fingerprint, or REALITY (uTLS
// on the client, github.com/xtls/reality on the server, a local TLS 1.3 server as the site). With a real
// TLS 1.3 connection inside, raw segments are used — and the inner TLS's integrity check is the referee:
// one byte lost or misplaced on the way in or out of a raw segment and the inner connection fails.

const testPSK = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ="

func testCert(t testing.TB, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// collectEvents gathers what the test hook reports (lanes dialed and reused, raw segments sent, …).
func collectEvents(t *testing.T) func(string) int {
	t.Helper()
	var mu sync.Mutex
	events := map[string]int{}
	miu.SetTestObserver(func(e string) {
		mu.Lock()
		events[e]++
		mu.Unlock()
	})
	t.Cleanup(func() { miu.SetTestObserver(nil) })
	return func(e string) int {
		mu.Lock()
		defer mu.Unlock()
		return events[e]
	}
}

const realityShortID = "0123456789abcdef"

type pairOptions struct {
	outer string // "" (plaintext), "tls", "utls" or "reality"
	psk   string // the client's; the server always has testPSK
	// REALITY: what the client presents instead of the server's real public key and short id.
	realityKey     string
	realityShortID *string
	server         miu.ServerConfig
	client         miu.ClientConfig
	wrapDial       func(dial func(ctx context.Context) (net.Conn, error)) func(ctx context.Context) (net.Conn, error)
	serveErrs      chan error
}

// realitySite starts the site a REALITY server looks like: a plain TLS 1.3 server. It does not keep
// connections around, so that the probe the REALITY library runs against it finishes quickly.
func realitySite(t *testing.T) string {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t, "localhost")}, MinVersion: tls.VersionTLS13}
	return listen(t, func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(300 * time.Millisecond))
		tc := tls.Server(c, cfg)
		if tc.Handshake() == nil {
			_, _ = tc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	})
}

// startServer runs a server on a loopback port and returns its address (and, for REALITY, its public key).
func startServer(t *testing.T, o pairOptions) (addr, realityPublicKey string) {
	t.Helper()
	cfg := o.server
	cfg.Users = []miu.User{{Name: "u@test", PSK: testPSK}}
	srv, err := miu.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); ln.Close() })
	var tlsCfg *tls.Config
	var rs *realityserver.Server
	switch o.outer {
	case "":
	case "reality":
		private, public, err := reality.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		realityPublicKey = public
		rs, err = realityserver.New(realityserver.Config{
			Dest:        realitySite(t),
			ServerNames: []string{"localhost"},
			PrivateKey:  private,
			ShortIDs:    []string{realityShortID, ""},
		})
		if err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(10 * time.Second); !rs.Ready(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the REALITY probe of the site did not finish")
			}
		}
	default:
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{testCert(t, "localhost")}, MinVersion: tls.VersionTLS13}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				switch {
				case rs != nil:
					outer, err := rs.Handshake(ctx, conn)
					if err != nil {
						return
					}
					conn = outer
				case tlsCfg != nil:
					tc := tls.Server(conn, tlsCfg)
					if err := tc.Handshake(); err != nil {
						conn.Close()
						return
					}
					conn = tc
				}
				err := srv.Serve(ctx, conn)
				if o.serveErrs != nil {
					o.serveErrs <- err
				}
			}()
		}
	}()
	return ln.Addr().String(), realityPublicKey
}

// pair starts a server and returns a client for it.
func pair(t *testing.T, o pairOptions) *miu.Client {
	t.Helper()
	addr, realityKey := startServer(t, o)
	cfg := o.client
	cfg.PSK = testPSK
	if o.psk != "" {
		cfg.PSK = o.psk
	}
	tlsCfg := &tls.Config{ServerName: "localhost", InsecureSkipVerify: true}
	switch o.outer {
	case "":
		cfg.Dial = func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
	case "tls":
		cfg.Dial = miu.TLSDialer(addr, tlsCfg)
	case "utls":
		dial, err := fingerprint.Dialer(addr, "chrome", tlsCfg)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Dial = dial
	case "reality":
		rc := reality.ClientConfig{ServerName: "localhost", PublicKey: realityKey, ShortID: realityShortID}
		if o.realityKey != "" {
			rc.PublicKey = o.realityKey
		}
		if o.realityShortID != nil {
			rc.ShortID = *o.realityShortID
		}
		dial, err := reality.Dialer(addr, rc)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Dial = dial
	}
	if o.wrapDial != nil {
		cfg.Dial = o.wrapDial(cfg.Dial)
	}
	c, err := miu.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func listen(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return ln.Addr().String()
}

func echoTCP(t *testing.T) string {
	return listen(t, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(c, c) })
}

// innerTLS returns a TLS 1.3 server config and the matching client wrapper for the inner connection.
func innerTLS(t *testing.T) (*tls.Config, func(net.Conn) net.Conn) {
	t.Helper()
	server := &tls.Config{Certificates: []tls.Certificate{testCert(t, "inner")}, MinVersion: tls.VersionTLS13}
	return server, func(raw net.Conn) net.Conn {
		return tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "inner", MinVersion: tls.VersionTLS13})
	}
}

// innerTLSEcho starts a real TLS 1.3 echo server; wrap is the inner TLS client for it.
func innerTLSEcho(t *testing.T) (string, func(net.Conn) net.Conn) {
	t.Helper()
	cfg, wrap := innerTLS(t)
	return listen(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		defer tc.Close()
		_, _ = io.Copy(tc, tc)
	}), wrap
}

func random(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// roundTrip sends payload to an echo target and reads the same bytes back, then ends the stream in an
// orderly way so that its lane goes back to the pool. wrap, if not nil, puts the inner TLS on top.
func roundTrip(t *testing.T, c *miu.Client, target string, payload []byte, wrap func(net.Conn) net.Conn) {
	t.Helper()
	roundTripVia(t, func(target string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return c.DialContext(ctx, "tcp", target)
	}, target, payload, wrap)
}

// roundTripVia is roundTrip over any way of reaching the target.
func roundTripVia(t *testing.T, dial func(target string) (net.Conn, error), target string, payload []byte, wrap func(net.Conn) net.Conn) {
	t.Helper()
	raw, err := dial(target)
	if err != nil {
		t.Error(err)
		return
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(30 * time.Second))
	conn := raw
	if wrap != nil {
		conn = wrap(raw)
	}
	go func() { _, _ = conn.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Errorf("read echo (%d bytes): %v", len(payload), err)
		return
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("echo mismatch (%d bytes)", len(payload))
		return
	}
	// Half-close, read the other direction to its end: both directions END, the lane is pooled.
	if tc, ok := conn.(*tls.Conn); ok {
		_ = tc.CloseWrite()
		_, _ = io.Copy(io.Discard, tc)
	}
	if err := raw.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v", err)
		return
	}
	if n, err := io.Copy(io.Discard, raw); err != nil || n != 0 {
		t.Errorf("after the echo: %d stray bytes, %v", n, err)
	}
}

// exercise: a small payload, a large one, concurrent streams, then a few one after another (those
// should reuse lanes the earlier ones put back).
func exercise(t *testing.T, c *miu.Client, target string, wrap func(net.Conn) net.Conn) {
	t.Helper()
	roundTrip(t, c, target, []byte("hello miu"), wrap)
	roundTrip(t, c, target, random(3<<20), wrap)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			roundTrip(t, c, target, random(64<<10+i), wrap)
		}(i)
	}
	wg.Wait()
	for i := 0; i < 6; i++ {
		roundTrip(t, c, target, random(1000+i), wrap)
	}
}

// Plaintext outer layer: neither side can use raw segments, everything travels in DATA frames.
func TestLoopbackPlain(t *testing.T) {
	count := collectEvents(t)
	exercise(t, pair(t, pairOptions{}), echoTCP(t), nil)
	if n := count("client:raw") + count("server:raw"); n != 0 {
		t.Fatalf("raw segments on a plaintext outer transport: %d", n)
	}
	if count("client:reuse") == 0 {
		t.Fatalf("lanes were never reused (dial=%d)", count("client:dial"))
	}
}

// Outer TLS, inner data that is not TLS: the plaintext has to stay inside the outer encryption.
func TestLoopbackTLSPlainInner(t *testing.T) {
	count := collectEvents(t)
	exercise(t, pair(t, pairOptions{outer: "tls"}), echoTCP(t), nil)
	if n := count("client:raw") + count("server:raw"); n != 0 {
		t.Fatalf("non-TLS inner data left the outer TLS: %d raw segments", n)
	}
	if count("client:reuse") == 0 {
		t.Fatalf("lanes were never reused (dial=%d)", count("client:dial"))
	}
}

// Outer TLS, inner real TLS 1.3: after the inner handshake both directions use raw segments, and lanes
// are reused between streams (the same outer connection goes in and out of raw segments again and again).
func TestRawSegmentsInnerTLS(t *testing.T) {
	for _, outer := range []string{"tls", "utls", "reality"} {
		for _, segmented := range []bool{false, true} {
			if segmented && !miu.CanSegment() {
				continue
			}
			t.Run(fmt.Sprintf("%s/segmented=%v", outer, segmented), func(t *testing.T) {
				defer miu.SetSegmentedCopy(miu.SetSegmentedCopy(segmented))
				count := collectEvents(t)
				target, wrap := innerTLSEcho(t)
				exercise(t, pair(t, pairOptions{outer: outer}), target, wrap)
				if count("client:raw") == 0 {
					t.Fatal("the uplink never used raw segments")
				}
				if count("server:raw") == 0 {
					t.Fatal("the downlink never used raw segments")
				}
				if count("client:reuse") == 0 {
					t.Fatalf("lanes were never reused (dial=%d)", count("client:dial"))
				}
				if segmented != (count("server:splice") > 0) {
					t.Fatalf("segmented=%v but %d segments were moved socket to socket", segmented, count("server:splice"))
				}
			})
		}
	}
}

// Streams one after another run on the same lane: after the first handshake (and the two lanes warmed
// up in the background) nothing is dialed any more, raw segments or not.
func TestSequentialStreamsShareLane(t *testing.T) {
	for _, outer := range []string{"tls", "reality"} {
		t.Run(outer, func(t *testing.T) {
			count := collectEvents(t)
			target, wrap := innerTLSEcho(t)
			c := pair(t, pairOptions{outer: outer})
			const streams = 12
			for i := 0; i < streams; i++ {
				roundTrip(t, c, target, random(200<<10), wrap)
			}
			if dials, reuse := count("client:dial"), count("client:reuse"); dials > 3 || reuse < streams-1 {
				t.Fatalf("dials=%d reuse=%d for %d consecutive streams", dials, reuse, streams)
			}
			if count("client:raw") < streams || count("server:raw") < streams {
				t.Fatalf("raw segments: up %d, down %d", count("client:raw"), count("server:raw"))
			}
		})
	}
}

// A REALITY client with the wrong public key or an unknown short id is not let in — the server passes
// it on to the site — and the client, seeing a certificate that is not the server's, fails the handshake.
func TestRealityRejects(t *testing.T) {
	_, otherKey, err := reality.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	unknown, empty := "ffff", ""
	for name, o := range map[string]pairOptions{
		"wrong public key": {outer: "reality", realityKey: otherKey},
		"unknown short id": {outer: "reality", realityShortID: &unknown},
	} {
		c := pair(t, o)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := c.DialContext(ctx, "tcp", "192.0.2.1:80")
		cancel()
		if err == nil {
			conn.Close()
			t.Fatalf("%s: the handshake succeeded", name)
		}
		if !errors.Is(err, reality.ErrNotReality) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// The empty short id is an id like any other when the server lists it.
	c := pair(t, pairOptions{outer: "reality", realityShortID: &empty})
	roundTrip(t, c, echoTCP(t), []byte("hello"), nil)

	if _, err := reality.Dialer("example.com:443", reality.ClientConfig{ServerName: "example.com", PublicKey: "AAAA", ShortID: ""}); err == nil {
		t.Fatal("a truncated public key was accepted")
	}
	if _, err := reality.Dialer("example.com:443", reality.ClientConfig{ServerName: "example.com", PublicKey: otherKey, ShortID: "xyz"}); err == nil {
		t.Fatal("a short id that is not hex was accepted")
	}
	if _, err := realityserver.New(realityserver.Config{Dest: "example.com:443", ServerNames: []string{"example.com"}, PrivateKey: "AAAA", ShortIDs: []string{""}}); err == nil {
		t.Fatal("a truncated private key was accepted")
	}
}

// With raw segments disabled on either side, the same traffic goes through DATA frames only.
func TestRawDisabled(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			count := collectEvents(t)
			o := pairOptions{outer: "tls"}
			if side == "client" {
				o.client.DisableRaw = true
			} else {
				o.server.DisableRaw = true
			}
			target, wrap := innerTLSEcho(t)
			c := pair(t, o)
			roundTrip(t, c, target, random(1<<20), wrap)
			roundTrip(t, c, target, random(1<<20), wrap)
			// The side that cannot receive raw segments gets none; the other direction is unaffected.
			if side == "client" && count("server:raw") != 0 || side == "server" && count("client:raw") != 0 {
				t.Fatalf("raw segments sent to a side that declared raw=0 (up %d, down %d)", count("client:raw"), count("server:raw"))
			}
			if count("client:raw")+count("server:raw") != 0 {
				// A side with raw=0 does not send raw segments either: it has no access to the socket.
				t.Fatalf("raw segments with %s raw disabled (up %d, down %d)", side, count("client:raw"), count("server:raw"))
			}
		})
	}
}

func TestLoopbackUDP(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(b[:n], from)
		}
	}()
	count := collectEvents(t)
	c := pair(t, pairOptions{outer: "tls"})

	for round := 0; round < 3; round++ {
		pc, err := c.ListenPacket()
		if err != nil {
			t.Fatal(err)
		}
		_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
		// Up to what a loopback datagram may carry on every platform.
		for i, size := range []int{1, 500, 1400, 9000} {
			msg := append([]byte(fmt.Sprintf("udp packet %d.%d ", round, i)), random(size)...)
			if _, err := pc.WriteTo(msg, echo.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 65535)
			n, from, err := pc.ReadFrom(got)
			if err != nil {
				t.Fatalf("udp echo %d.%d: %v", round, i, err)
			}
			if !bytes.Equal(got[:n], msg) {
				t.Fatalf("udp echo %d.%d mismatch (%d bytes of %d)", round, i, n, len(msg))
			}
			if from.String() != echo.LocalAddr().String() {
				t.Fatalf("source %v, want %v", from, echo.LocalAddr())
			}
		}
		// A name is resolved by the server.
		port := echo.LocalAddr().(*net.UDPAddr).Port
		if _, err := pc.WriteTo([]byte("by name"), miu.HostPort(fmt.Sprintf("localhost:%d", port))); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 100)
		if n, _, err := pc.ReadFrom(got); err != nil || string(got[:n]) != "by name" {
			t.Fatalf("udp by name: %q %v", got[:n], err)
		}
		// A read deadline that passes is not the end of the session.
		_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		if _, _, err := pc.ReadFrom(got); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read past the deadline: %v", err)
		}
		pc.Close()
		time.Sleep(200 * time.Millisecond) // the abort returns the lane in the background
	}
	// The session ends by abort; its lane is used again by the next one.
	if count("client:reset") != 3 || count("client:reuse") < 2 || count("client:raw")+count("server:raw") != 0 {
		t.Fatalf("resets=%d reuse=%d dials=%d", count("client:reset"), count("client:reuse"), count("client:dial"))
	}
}

func TestRejectBadCredential(t *testing.T) {
	// Garbage instead of a token: the server closes the connection.
	errs := make(chan error, 4)
	addr, _ := startServer(t, pairOptions{serveErrs: errs})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(random(120))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("server should close on a bad credential")
	}
	if err := <-errs; !errors.Is(err, miu.ErrAuth) {
		t.Fatalf("Serve returned %v", err)
	}

	// A client with the wrong PSK: the stream fails, it does not look like an orderly end.
	for _, outer := range []string{"", "tls"} {
		c := pair(t, pairOptions{outer: outer, psk: "this-is-not-the-right-psk"})
		conn, err := c.DialContext(context.Background(), "tcp", echoTCP(t))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("hello"))
		if n, err := conn.Read(make([]byte, 16)); err == nil || err == io.EOF {
			t.Fatalf("outer %q: read with a wrong psk: %d bytes, %v", outer, n, err)
		}
		conn.Close()
	}
	if _, err := miu.NewClient(miu.ClientConfig{PSK: "short", Dial: miu.TLSDialer(addr, nil)}); err == nil {
		t.Fatal("a short psk was accepted")
	}
	if _, err := miu.NewServer(miu.ServerConfig{Users: []miu.User{{Name: "a", PSK: testPSK}, {Name: "b", PSK: " " + testPSK}}}); err == nil {
		t.Fatal("two users with the same psk were accepted")
	}
}

// foreverTCP starts a server that keeps writing for as long as the peer reads. With withTLS it speaks
// TLS 1.3. conns counts the connections that are still open.
func foreverTCP(t *testing.T, withTLS bool) (addr string, wrap func(net.Conn) net.Conn, open *atomic.Int32) {
	t.Helper()
	open = new(atomic.Int32)
	wrap = func(c net.Conn) net.Conn { return c }
	var cfg *tls.Config
	if withTLS {
		cfg, wrap = innerTLS(t)
	}
	chunk := random(64 << 10)
	addr = listen(t, func(c net.Conn) {
		open.Add(1)
		defer open.Add(-1)
		defer c.Close()
		if cfg != nil {
			c = tls.Server(c, cfg)
		}
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
	})
	return addr, wrap, open
}

// Aborting a stream in the middle of a download: the client sends RESET, the server stops the downlink
// and closes it with END, and the lane goes back to the pool for the next stream — an abort must not
// cost a lane. This has to hold over a plaintext outer layer (all DATA) and over TLS with TLS inside
// (raw segments; with the segmented downlink the abort arrives while a segment is being moved).
func TestAbortKeepsLane(t *testing.T) {
	cases := []struct {
		name      string
		outer     string
		innerTLS  bool
		segmented bool
	}{
		{"plain", "", false, false}, {"raw", "tls", true, false}, {"raw-utls", "utls", true, false}, {"raw-segmented", "tls", true, true},
		{"raw-reality", "reality", true, false}, {"raw-reality-segmented", "reality", true, true},
	}
	for _, tc := range cases {
		if tc.segmented && !miu.CanSegment() {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			defer miu.SetSegmentedCopy(miu.SetSegmentedCopy(tc.segmented))
			count := collectEvents(t)
			target, wrap, open := foreverTCP(t, tc.innerTLS)
			c := pair(t, pairOptions{outer: tc.outer})
			const rounds = 8
			for i := 0; i < rounds; i++ {
				raw, err := c.DialContext(context.Background(), "tcp", target)
				if err != nil {
					t.Fatal(err)
				}
				_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
				if _, err := io.ReadFull(wrap(raw), make([]byte, 2<<20)); err != nil {
					t.Fatalf("round %d: %v", i, err)
				}
				raw.Close() // leave in the middle of the download
				time.Sleep(300 * time.Millisecond)
			}
			// Every round was an abort, and the lanes are the same few throughout (the first one and the
			// two warmed up in the background), not a new one per round.
			if resets, dials := count("client:reset"), count("client:dial"); resets != rounds || dials > 3 {
				t.Fatalf("resets=%d dials=%d reuse=%d: aborted streams are burning lanes", resets, dials, count("client:reuse"))
			}
			if tc.innerTLS && count("server:raw") == 0 {
				t.Fatal("inner TLS data never went out as raw segments")
			}
			if tc.segmented && count("server:splice") == 0 {
				t.Fatal("the segmented downlink was not used")
			}
			if n := open.Load(); n != 0 {
				t.Fatalf("%d target connections left open after the aborts", n)
			}
			// The lanes are clean: ordinary streams work on them afterwards.
			echo := echoTCP(t)
			for i := 0; i < 4; i++ {
				roundTrip(t, c, echo, random(100<<10), nil)
			}
			if dials := count("client:dial"); dials > 3 {
				t.Fatalf("dials=%d after the aborts", dials)
			}
		})
	}
}

// The other ways a stream gets aborted: closed before anything was sent, closed right after the request,
// closed after a half-close, closed while the target is still being dialed. None of them costs a lane.
func TestAbortVariants(t *testing.T) {
	count := collectEvents(t)
	target, _, open := foreverTCP(t, false)
	blackhole := "192.0.2.1:9" // TEST-NET-1: the dial neither succeeds nor fails quickly
	c := pair(t, pairOptions{outer: "tls"})
	dial := func(addr string) net.Conn {
		conn, err := c.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}
	settle := func() { time.Sleep(250 * time.Millisecond) }

	conn := dial(target) // closed before OPEN went out: nothing is sent at all
	conn.Close()
	settle()
	if count("client:reset") != 0 {
		t.Fatal("RESET for a stream that was never opened")
	}

	conn = dial(target) // closed right after the first write
	_, _ = conn.Write([]byte("x"))
	conn.Close()
	settle()

	conn = dial(target) // half-closed, then closed: RESET follows END
	_, _ = conn.Write([]byte("x"))
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	_, _ = io.ReadFull(conn, make([]byte, 100<<10))
	conn.Close()
	settle()

	conn = dial(blackhole) // closed while the server is dialing the target
	_, _ = conn.Write([]byte("x"))
	time.Sleep(50 * time.Millisecond)
	conn.Close()
	settle()

	conn = dial(target)      // closed after OPEN went out on its own, without a byte written or read
	conn2 := dial(blackhole) // closed from another goroutine while a Read is blocked
	_, _ = conn2.Write([]byte("x"))
	done := make(chan error, 1)
	go func() { _, err := conn2.Read(make([]byte, 1)); done <- err }()
	time.Sleep(50 * time.Millisecond)
	conn2.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a Read interrupted by Close returned %v", err)
	}
	conn.Close()
	settle()

	if resets, dials := count("client:reset"), count("client:dial"); resets != 5 || dials > 4 {
		t.Fatalf("resets=%d dials=%d", resets, dials)
	}
	if n := open.Load(); n != 0 {
		t.Fatalf("%d target connections left open", n)
	}
	roundTrip(t, c, echoTCP(t), random(10<<10), nil)
}

// flakyConn is a connection that can be made to die without its owner noticing — which is what a pooled
// lane that went dead looks like to the client: alive when it is taken from the pool (flakyConn offers
// nothing to probe), gone once the stream has been written to it.
type flakyConn struct {
	net.Conn
	gen int32
	f   *flaky
}

type flaky struct {
	gen atomic.Int32
	// Connections made before killBefore are dead: with swallow their writes vanish and the next read
	// fails, otherwise the write itself fails.
	killBefore atomic.Int32
	swallow    atomic.Bool
}

func (f *flaky) killAll(swallow bool) {
	f.swallow.Store(swallow)
	f.killBefore.Store(f.gen.Load() + 1)
}

func (c *flakyConn) Write(p []byte) (int, error) {
	if c.gen < c.f.killBefore.Load() {
		c.Conn.Close()
		if c.f.swallow.Load() {
			return len(p), nil
		}
		return 0, errors.New("flaky: connection is gone")
	}
	return c.Conn.Write(p)
}

// dialer returns an outer dialer to addr: TCP, the flaky layer, TLS on top.
func (f *flaky) dialer(addr string) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(&flakyConn{Conn: conn, gen: f.gen.Add(1), f: f}, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tc, nil
	}
}

// A stream that lands on a dead pooled lane is replayed once on a new lane, and the application does not
// notice. Not so once it has sent more than the replay limit, or when the lane was not from the pool.
func TestReplayOnDeadLane(t *testing.T) {
	count := collectEvents(t)
	f := &flaky{}
	addr, _ := startServer(t, pairOptions{outer: "tls"})
	c, err := miu.NewClient(miu.ClientConfig{PSK: testPSK, Dial: f.dialer(addr)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	target, wrap := innerTLSEcho(t)
	echo := echoTCP(t)

	// Detected by the reader (the write seemed to work), then by the writer.
	for i, swallow := range []bool{true, false} {
		roundTrip(t, c, target, random(300<<10), wrap) // leaves a lane in the pool
		f.killAll(swallow)
		roundTrip(t, c, target, random(300<<10), wrap)
		if n := count("client:replay"); n != i+1 {
			t.Fatalf("swallow=%v: %d replays", swallow, n)
		}
	}
	if count("client:raw") == 0 || count("server:raw") == 0 {
		t.Fatal("no raw segments after a replay")
	}

	// The uplink had already ended when the lane turned out to be dead: END is replayed too.
	roundTrip(t, c, echo, []byte("warm"), nil)
	f.killAll(true)
	conn, err := c.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = conn.Write([]byte("ping"))
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	if got, err := io.ReadAll(conn); err != nil || string(got) != "ping" {
		t.Fatalf("after the replay of a half-closed stream: %q %v", got, err)
	}
	conn.Close()
	if n := count("client:replay"); n != 3 {
		t.Fatalf("%d replays", n)
	}

	// More than the limit already sent: no replay, the stream fails.
	sink := listen(t, func(c net.Conn) { defer c.Close(); _, _ = io.Copy(io.Discard, c) })
	roundTrip(t, c, echo, []byte("warm"), nil)
	conn, err = c.DialContext(context.Background(), "tcp", sink)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(random(100 << 10)); err != nil {
		t.Fatal(err)
	}
	f.killAll(false)
	if _, err := conn.Write([]byte("more")); err == nil {
		t.Fatal("a write on a dead lane succeeded past the replay limit")
	}
	conn.Close()

	// A lane that was dialed for this stream: no replay either.
	c.CloseIdle()
	time.Sleep(100 * time.Millisecond) // let background warm-up dials land, then drop them as well
	c.CloseIdle()
	conn, err = c.DialContext(context.Background(), "tcp", sink)
	if err != nil {
		t.Fatal(err)
	}
	f.killAll(false)
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("a write on a dead fresh lane succeeded")
	}
	conn.Close()
	if n := count("client:replay"); n != 3 {
		t.Fatalf("%d replays, want 3", n)
	}
	// And the client recovers.
	roundTrip(t, c, echo, random(10<<10), nil)
}

// A target that cannot be reached: the downlink ends at once, and the lane stays usable.
func TestUnreachableTarget(t *testing.T) {
	count := collectEvents(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	ln.Close()
	c := pair(t, pairOptions{outer: "tls"})
	for i := 0; i < 3; i++ {
		conn, err := c.DialContext(context.Background(), "tcp", closed)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		if n, err := conn.Read(make([]byte, 16)); n != 0 || err != io.EOF {
			t.Fatalf("read from an unreachable target: %d %v", n, err)
		}
		_ = conn.(interface{ CloseWrite() error }).CloseWrite()
		conn.Close()
	}
	if dials := count("client:dial"); dials > 3 || count("client:reuse") < 2 {
		t.Fatalf("dials=%d reuse=%d", dials, count("client:reuse"))
	}
	roundTrip(t, c, echoTCP(t), random(10<<10), nil)
}

// A protocol in which the server speaks first: OPEN must not wait for the client's first bytes.
// And a half-close: the target answers only after it has seen the end of the request.
func TestServerFirstAndHalfClose(t *testing.T) {
	c := pair(t, pairOptions{outer: "tls"})
	greeter := listen(t, func(c net.Conn) {
		defer c.Close()
		_, _ = c.Write([]byte("220 hello\r\n"))
		_, _ = io.Copy(io.Discard, c)
	})
	conn, err := c.DialContext(context.Background(), "tcp", greeter)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 11)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "220 hello\r\n" {
		t.Fatalf("greeting: %q %v", got, err)
	}
	conn.Close()

	summer := listen(t, func(c net.Conn) {
		defer c.Close()
		h := sha256.New()
		_, _ = io.Copy(h, c) // reads to the end of the request
		_, _ = c.Write(h.Sum(nil))
	})
	payload := random(1 << 20)
	conn, err = c.DialContext(context.Background(), "tcp", summer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	sum, err := io.ReadAll(conn)
	if want := sha256.Sum256(payload); err != nil || !bytes.Equal(sum, want[:]) {
		t.Fatalf("digest after the half-close: %x %v", sum, err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("write after CloseWrite succeeded")
	}
}

// retryConn reads with a short deadline and retries when it passes.
type retryConn struct {
	net.Conn
	timeouts *atomic.Int32
}

func (r retryConn) Read(p []byte) (int, error) {
	for {
		_ = r.Conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, err := r.Conn.Read(p)
		if n == 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			r.timeouts.Add(1)
			continue
		}
		return n, err
	}
}

// A read deadline that passes leaves the stream intact: the read is simply retried. The inner TLS
// connection reads through deadlines that keep expiring, in the DATA phase and in raw segments alike,
// and still verifies every record.
func TestReadDeadlineIsResumable(t *testing.T) {
	cfg, _ := innerTLS(t)
	payload := random(600 << 10)
	target := listen(t, func(c net.Conn) {
		tc := tls.Server(c, cfg)
		defer tc.Close()
		// In pieces, with pauses that let the client's deadline pass in between.
		for i := 0; i < len(payload); i += 50 << 10 {
			time.Sleep(30 * time.Millisecond)
			if _, err := tc.Write(payload[i:min(i+50<<10, len(payload))]); err != nil {
				return
			}
		}
	})
	count := collectEvents(t)
	c := pair(t, pairOptions{outer: "tls"})
	raw, err := c.DialContext(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var timeouts atomic.Int32
	conn := tls.Client(retryConn{raw, &timeouts}, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("after %d timeouts: %v", timeouts.Load(), err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if timeouts.Load() < 5 || count("server:raw") == 0 {
		t.Fatalf("timeouts=%d raw=%d: the test did not exercise what it is for", timeouts.Load(), count("server:raw"))
	}
}

// Many streams at once: each has a lane to itself, and afterwards the pool holds them for reuse.
func TestConcurrentStreams(t *testing.T) {
	count := collectEvents(t)
	target, wrap := innerTLSEcho(t)
	c := pair(t, pairOptions{outer: "tls"})
	for round := 0; round < 2; round++ {
		var wg sync.WaitGroup
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				roundTrip(t, c, target, random(256<<10+i), wrap)
			}(i)
		}
		wg.Wait()
	}
	if dials, reuse := count("client:dial"), count("client:reuse"); dials > 40 || reuse < 24 {
		t.Fatalf("dials=%d reuse=%d", dials, reuse)
	}
}

// The server closes a lane that has been idle for too long; the client notices when it next reaches for
// it and dials a new one, without the application seeing anything.
func TestServerIdleTimeout(t *testing.T) {
	count := collectEvents(t)
	echo := echoTCP(t)
	c := pair(t, pairOptions{outer: "tls", server: miu.ServerConfig{IdleTimeout: time.Second}})
	roundTrip(t, c, echo, []byte("one"), nil)
	time.Sleep(1500 * time.Millisecond)
	roundTrip(t, c, echo, []byte("two"), nil)
	if dials := count("client:dial"); dials < 2 {
		t.Fatalf("dials=%d: the idle lane was not closed by the server", dials)
	}
}

// The server tells the client how long it keeps idle lanes, and pushes its padding scheme when the
// client's differs; the stream works either way.
func TestServerPaddingScheme(t *testing.T) {
	c := pair(t, pairOptions{outer: "tls", server: miu.ServerConfig{PaddingScheme: "stop=3\n0=40-60\n1=200-300\n2=300-400,c,600-700"}})
	echo := echoTCP(t)
	for i := 0; i < 3; i++ {
		roundTrip(t, c, echo, random(5000), nil)
	}
	if _, err := miu.NewServer(miu.ServerConfig{Users: []miu.User{{Name: "a", PSK: testPSK}}, PaddingScheme: "nonsense"}); err == nil {
		t.Fatal("a bad padding scheme was accepted")
	}
}

// The server reports every stream when it opens, and when it ends what it carried — including how much
// of it travelled as raw segments, which is how an operator (or someone integrating another client)
// can tell whether raw segments are in use.
func TestAccessAndTraffic(t *testing.T) {
	var mu sync.Mutex
	var opened []string
	closed := map[string]miu.Traffic{}
	c := pair(t, pairOptions{outer: "tls", server: miu.ServerConfig{
		OnAccess: func(a miu.Access) {
			mu.Lock()
			opened = append(opened, a.User+" "+a.Network+" "+a.Target)
			mu.Unlock()
		},
		OnClose: func(a miu.Access, tr miu.Traffic) {
			mu.Lock()
			closed[a.Network+" "+a.Target] = tr
			mu.Unlock()
		},
	}})
	wait := func(key string) miu.Traffic {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			mu.Lock()
			tr, ok := closed[key]
			mu.Unlock()
			if ok {
				return tr
			}
			if time.Now().After(deadline) {
				t.Fatalf("no close report for %s", key)
			}
		}
	}

	// Plain inner data: counted, none of it raw.
	echo := echoTCP(t)
	roundTrip(t, c, echo, random(100<<10), nil)
	if tr := wait("tcp " + echo); tr.Up != 100<<10 || tr.Down != 100<<10 || tr.RawUp != 0 || tr.RawDown != 0 {
		t.Fatalf("plain stream: %+v", tr)
	}
	mu.Lock()
	if len(opened) != 1 || opened[0] != "u@test tcp "+echo {
		t.Fatalf("access log: %q", opened)
	}
	mu.Unlock()

	// Inner TLS 1.3: after the handshake nearly everything is raw, in both directions.
	target, wrap := innerTLSEcho(t)
	roundTrip(t, c, target, random(1<<20), wrap)
	if tr := wait("tcp " + target); tr.Up < 1<<20 || tr.Down < 1<<20 || tr.RawUp < 900<<10 || tr.RawDown < 900<<10 || tr.RawUp > tr.Up || tr.RawDown > tr.Down {
		t.Fatalf("inner TLS stream: %+v", tr)
	}

	// UDP: the UoT bytes of the session.
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 2000)
		for {
			n, from, err := udp.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(b[:n], from)
		}
	}()
	pc, err := c.ListenPacket()
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := pc.WriteTo(random(1000), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if n, _, err := pc.ReadFrom(make([]byte, 2000)); err != nil || n != 1000 {
		t.Fatalf("udp echo: %d %v", n, err)
	}
	pc.Close()
	// request header (1 + 7) + packet (7 + 2 + 1000) up; one packet (7 + 2 + 1000) down
	if tr := wait("udp " + udp.LocalAddr().String()); tr.Up != 8+1009 || tr.Down != 1009 || tr.RawUp+tr.RawDown != 0 {
		t.Fatalf("udp session: %+v", tr)
	}
}
