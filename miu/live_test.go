package miu_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MiuProtocol/Miu/miu"
	"github.com/MiuProtocol/Miu/miu/fingerprint"
	"github.com/MiuProtocol/Miu/miu/reality"
	"github.com/MiuProtocol/Miu/miu/realityserver"
)

// Interoperability tests against another implementation of the protocol. They are skipped unless the
// environment says where the other side is. The targets (echo servers and the like) are started by the
// test on 127.0.0.1, so the other implementation has to run on this machine.
//
// TestLiveClient — this client against another server:
//
//	MIU_LIVE_SERVER=host:port  MIU_LIVE_PSK=...  MIU_LIVE_OUTER=tls|utls|reality
//	MIU_LIVE_SNI=name                     (tls, utls and reality; the certificate is not verified for tls / utls)
//	MIU_LIVE_REALITY_PBK=...  MIU_LIVE_REALITY_SID=...
//
// TestLiveServer — this server against another client, which must be configured to connect to
// MIU_LIVE_LISTEN and offer a SOCKS5 proxy at MIU_LIVE_SOCKS:
//
//	MIU_LIVE_LISTEN=127.0.0.1:port  MIU_LIVE_SOCKS=127.0.0.1:port  MIU_LIVE_PSK=...
//	MIU_LIVE_CERT=cert.pem MIU_LIVE_KEY=key.pem                                  (outer TLS), or
//	MIU_LIVE_REALITY_DEST=host:port MIU_LIVE_SNI=name MIU_LIVE_REALITY_PRIVATE=... MIU_LIVE_REALITY_SID=...
//	MIU_LIVE_SEGMENTED=1                 (use the segmented downlink where the platform has it but does not default to it)

func TestLiveClient(t *testing.T) {
	server, psk := os.Getenv("MIU_LIVE_SERVER"), os.Getenv("MIU_LIVE_PSK")
	if server == "" {
		t.Skip("MIU_LIVE_SERVER is not set")
	}
	cfg := miu.ClientConfig{PSK: psk}
	tlsCfg := &tls.Config{ServerName: os.Getenv("MIU_LIVE_SNI"), InsecureSkipVerify: true}
	var err error
	switch outer := os.Getenv("MIU_LIVE_OUTER"); outer {
	case "", "tls":
		cfg.Dial = miu.TLSDialer(server, tlsCfg)
	case "utls":
		cfg.Dial, err = fingerprint.Dialer(server, "chrome", tlsCfg)
	case "reality":
		cfg.Dial, err = reality.Dialer(server, reality.ClientConfig{
			ServerName: os.Getenv("MIU_LIVE_SNI"), PublicKey: os.Getenv("MIU_LIVE_REALITY_PBK"), ShortID: os.Getenv("MIU_LIVE_REALITY_SID"),
		})
	default:
		t.Fatalf("MIU_LIVE_OUTER=%q", outer)
	}
	if err != nil {
		t.Fatal(err)
	}
	c, err := miu.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	count := collectEvents(t)

	// Streams one after another, inner TLS 1.3: raw segments both ways, on the same few lanes.
	target, wrap := innerTLSEcho(t)
	const streams = 12
	for i := 0; i < streams; i++ {
		roundTrip(t, c, target, random(300<<10), wrap)
	}
	if t.Failed() {
		t.FailNow()
	}
	if dials, reuse := count("client:dial"), count("client:reuse"); dials > 3 || reuse < streams-1 {
		t.Fatalf("dials=%d reuse=%d for %d consecutive streams", dials, reuse, streams)
	}
	if up, down := count("client:raw"), count("client:rawin"); up < streams || down < streams {
		t.Fatalf("raw segments: %d sent, %d received", up, down)
	}
	t.Logf("%d streams: %d lanes dialed, %d reused, raw segments %d sent / %d received", streams, count("client:dial"), count("client:reuse"), count("client:raw"), count("client:rawin"))

	// Plain inner data stays inside the outer TLS; the large and the concurrent case.
	rawBefore := count("client:raw") + count("client:rawin")
	exercise(t, c, echoTCP(t), nil)
	if n := count("client:raw") + count("client:rawin") - rawBefore; n != 0 {
		t.Fatalf("%d raw segments for plaintext inner data", n)
	}
	exercise(t, c, target, wrap)
	if t.Failed() {
		t.FailNow()
	}

	// Aborts in the middle of a download do not cost lanes.
	forever, fwrap, open := foreverTCP(t, true)
	dialsBefore, resetsBefore := count("client:dial"), count("client:reset")
	const rounds = 8
	for i := 0; i < rounds; i++ {
		raw, err := c.DialContext(context.Background(), "tcp", forever)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.ReadFull(fwrap(raw), make([]byte, 2<<20)); err != nil {
			t.Fatalf("abort round %d: %v", i, err)
		}
		raw.Close()
		time.Sleep(300 * time.Millisecond)
	}
	if resets, dials := count("client:reset")-resetsBefore, count("client:dial")-dialsBefore; resets != rounds || dials > 2 {
		t.Fatalf("%d aborts: %d lanes kept, %d new lanes dialed", rounds, resets, dials)
	}
	if n := open.Load(); n != 0 {
		t.Fatalf("%d target connections left open after the aborts", n)
	}
	t.Logf("%d aborts: %d lanes returned to the pool, %d new lanes dialed", rounds, count("client:reset")-resetsBefore, count("client:dial")-dialsBefore)
	roundTrip(t, c, target, random(300<<10), wrap)

	// UDP.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
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
	pc, err := c.ListenPacket()
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
	// Sizes an implementation with 8 KiB packet buffers can take too.
	for i, size := range []int{1, 500, 1400, 4000} {
		msg := random(size)
		if _, err := pc.WriteTo(msg, echo.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 65535)
		n, from, err := pc.ReadFrom(got)
		if err != nil || string(got[:n]) != string(msg) || from.String() != echo.LocalAddr().String() {
			t.Fatalf("udp echo %d (%d bytes): %d bytes from %v, %v", i, size, n, from, err)
		}
	}
	t.Logf("UDP: 4 datagrams echoed")
}

// socksDial opens a CONNECT through a SOCKS5 proxy.
func socksDial(proxy, target string) (net.Conn, error) {
	host, p, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(p)
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		return nil, err
	}
	req := []byte{5, 1, 0, 5, 1, 0, 3, byte(len(host))}
	req = binary.BigEndian.AppendUint16(append(req, host...), uint16(port))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	reply := make([]byte, 2+4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, err
	}
	if reply[1] != 0 || reply[3] != 0 {
		conn.Close()
		return nil, fmt.Errorf("socks: %x", reply)
	}
	n := map[byte]int{1: 4 + 2, 4: 16 + 2}[reply[5]]
	if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil || n == 0 {
		conn.Close()
		return nil, fmt.Errorf("socks: bad reply %x", reply)
	}
	return conn, nil
}

func TestLiveServer(t *testing.T) {
	listenAddr, socks := os.Getenv("MIU_LIVE_LISTEN"), os.Getenv("MIU_LIVE_SOCKS")
	if listenAddr == "" {
		t.Skip("MIU_LIVE_LISTEN is not set")
	}
	var handshake func(net.Conn) (net.Conn, error)
	if dest := os.Getenv("MIU_LIVE_REALITY_DEST"); dest != "" {
		rs, err := realityserver.New(realityserver.Config{
			Dest: dest, ServerNames: []string{os.Getenv("MIU_LIVE_SNI")},
			PrivateKey: os.Getenv("MIU_LIVE_REALITY_PRIVATE"), ShortIDs: []string{os.Getenv("MIU_LIVE_REALITY_SID")},
		})
		if err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(15 * time.Second); !rs.Ready() && time.Now().Before(deadline); {
			time.Sleep(100 * time.Millisecond)
		}
		handshake = func(c net.Conn) (net.Conn, error) { return rs.Handshake(context.Background(), c) }
	} else {
		cert, err := tls.LoadX509KeyPair(os.Getenv("MIU_LIVE_CERT"), os.Getenv("MIU_LIVE_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		handshake = func(c net.Conn) (net.Conn, error) {
			tc := tls.Server(c, tlsCfg)
			if err := tc.Handshake(); err != nil {
				c.Close()
				return nil, err
			}
			return tc, nil
		}
	}
	srv, err := miu.NewServer(miu.ServerConfig{Users: []miu.User{{Name: "live", PSK: os.Getenv("MIU_LIVE_PSK")}}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lanes atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				outer, err := handshake(conn)
				if err != nil {
					t.Logf("handshake: %v", err)
					return
				}
				lanes.Add(1)
				if err := srv.Serve(ctx, outer); err != nil {
					t.Errorf("Serve: %v", err)
				}
			}()
		}
	}()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if c, err := net.DialTimeout("tcp", socks, time.Second); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no SOCKS5 proxy at %s", socks)
		}
	}
	dial := func(target string) (net.Conn, error) { return socksDial(socks, target) }
	count := collectEvents(t)
	if os.Getenv("MIU_LIVE_SEGMENTED") != "" && miu.CanSegment() {
		defer miu.SetSegmentedCopy(miu.SetSegmentedCopy(true))
	}

	target, wrap := innerTLSEcho(t)
	const streams = 12
	for i := 0; i < streams; i++ {
		roundTripVia(t, dial, target, random(300<<10), wrap)
		time.Sleep(50 * time.Millisecond) // let the other client put its lane back
	}
	if t.Failed() {
		t.FailNow()
	}
	if down, up := count("server:raw"), count("server:rawin"); down < streams || up < streams {
		t.Fatalf("raw segments: %d sent, %d received", down, up)
	}
	if n := lanes.Load(); n > 4 {
		t.Fatalf("%d lanes for %d consecutive streams", n, streams)
	}
	t.Logf("%d streams on %d lanes, raw segments %d sent / %d received, %d moved socket to socket", streams, lanes.Load(), count("server:raw"), count("server:rawin"), count("server:splice"))

	rawBefore := count("server:raw") + count("server:rawin")
	roundTripVia(t, dial, echoTCP(t), random(1<<20), nil)
	if n := count("server:raw") + count("server:rawin") - rawBefore; n != 0 {
		t.Fatalf("%d raw segments for plaintext inner data", n)
	}

	forever, fwrap, open := foreverTCP(t, true)
	lanesBefore := lanes.Load()
	const rounds = 8
	for i := 0; i < rounds; i++ {
		raw, err := dial(forever)
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.ReadFull(fwrap(raw), make([]byte, 2<<20)); err != nil {
			t.Fatalf("abort round %d: %v", i, err)
		}
		raw.Close()
		time.Sleep(400 * time.Millisecond)
	}
	if n := open.Load(); n != 0 {
		t.Fatalf("%d target connections left open after the aborts", n)
	}
	if n := lanes.Load() - lanesBefore; n > 2 {
		t.Fatalf("%d new lanes for %d aborted streams", n, rounds)
	}
	t.Logf("%d aborts: %d new lanes", rounds, lanes.Load()-lanesBefore)
	roundTripVia(t, dial, target, random(300<<10), wrap)
}
