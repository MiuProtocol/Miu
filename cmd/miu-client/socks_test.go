package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/MiuProtocol/Miu/miu"
)

const testPSK = "0123456789abcdef0123456789abcdef"

// startProxy runs a miu server, a client for it and the SOCKS5 front end; it returns the proxy's address.
func startProxy(t *testing.T) string {
	t.Helper()
	cert, err := miu.SelfSignedCert("localhost")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := miu.NewServer(miu.ServerConfig{Users: []miu.User{{Name: "test", PSK: testPSK}}})
	if err != nil {
		t.Fatal(err)
	}
	sln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := sln.Accept()
			if err != nil {
				return
			}
			go srv.Serve(ctx, conn)
		}
	}()
	client, err := miu.NewClient(miu.ClientConfig{PSK: testPSK, Dial: miu.TLSDialer(sln.Addr().String(), &tls.Config{InsecureSkipVerify: true})})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go (&socksServer{client: client}).serve(ln)
	t.Cleanup(func() { cancel(); ln.Close(); sln.Close(); client.Close() })
	return ln.Addr().String()
}

// socksRequest performs the greeting and one request, and returns the reply code and bound address.
func socksRequest(t *testing.T, conn net.Conn, cmd byte, host string, port int) (byte, *net.UDPAddr) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := []byte{5, 1, 0, 5, cmd, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(append(req, 1), ip.To4()...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2+3)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("greeting reply %x", reply[:2])
	}
	host2, port2, err := readSocksAddr(conn)
	if err != nil {
		t.Fatal(err)
	}
	return reply[3], &net.UDPAddr{IP: net.ParseIP(host2), Port: int(port2)}
}

func TestSocksConnect(t *testing.T) {
	proxy := startProxy(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	port := echo.Addr().(*net.TCPAddr).Port
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB
	for _, host := range []string{"127.0.0.1", "localhost"} {
		conn, err := net.Dial("tcp", proxy)
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := socksRequest(t, conn, socksConnect, host, port); code != socksOK {
			t.Fatalf("%s: reply %d", host, code)
		}
		go func() {
			_, _ = conn.Write(payload)
			_ = conn.(*net.TCPConn).CloseWrite()
		}()
		got, err := io.ReadAll(conn)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("%s: %d bytes back, %v", host, len(got), err)
		}
		conn.Close()
	}

	// BIND is not supported.
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if code, _ := socksRequest(t, conn, 2, "127.0.0.1", 1); code != socksCmdUnsupported {
		t.Fatalf("BIND: reply %d", code)
	}
}

func TestSocksUDPAssociate(t *testing.T) {
	proxy := startProxy(t)
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
	port := echo.LocalAddr().(*net.UDPAddr).Port

	ctrl, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	code, relay := socksRequest(t, ctrl, socksUDPAssociate, "0.0.0.0", 0)
	if code != socksOK || relay.Port == 0 {
		t.Fatalf("UDP ASSOCIATE: reply %d, relay %v", code, relay)
	}
	app, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	_ = app.SetDeadline(time.Now().Add(10 * time.Second))
	for i, host := range []string{"127.0.0.1", "localhost", "127.0.0.1"} {
		msg := []byte(fmt.Sprintf("datagram %d", i))
		if _, err := app.Write(append(appendSocksAddr([]byte{0, 0, 0}, host, uint16(port)), msg...)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		n, err := app.Read(buf)
		if err != nil {
			t.Fatalf("datagram %d: %v", i, err)
		}
		// RSV(2) · FRAG · ATYP(IPv4) · 127.0.0.1 · port · data
		want := append(append([]byte{0, 0, 0, 1, 127, 0, 0, 1}, byte(port>>8), byte(port)), msg...)
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d: %x, want %x (%s)", i, buf[:n], want, strconv.Quote(string(msg)))
		}
	}
	// The association ends with its control connection.
	ctrl.Close()
	time.Sleep(200 * time.Millisecond)
	_ = app.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = app.Write(append(appendSocksAddr([]byte{0, 0, 0}, "127.0.0.1", uint16(port)), "late"...))
	if n, err := app.Read(make([]byte, 100)); err == nil {
		t.Fatalf("%d bytes relayed after the association ended", n)
	}
}
