package miu_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/MiuProtocol/Miu/miu"
)

// webBackend is the fallback: a minimal HTTP server that answers whatever it gets with a fixed page and
// reports what it received.
func webBackend(t *testing.T) (string, chan string) {
	got := make(chan string, 8)
	addr := listen(t, func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		// Collect what arrives until it goes quiet: the request may come in pieces.
		var req []byte
		b := make([]byte, 4096)
		for {
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, err := c.Read(b)
			req = append(req, b[:n]...)
			if err != nil {
				break
			}
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		got <- string(req)
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	})
	return addr, got
}

// probe connects to the TLS outer layer, sends what, and returns what came back and when the connection
// ended.
func probe(t *testing.T, addr string, what string) (string, time.Duration) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if what != "" {
		if _, err := io.WriteString(c, what); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := io.ReadAll(c)
	return string(b), time.Since(start)
}

// A connection that is not a client goes to the fallback web server, with the bytes already read: an
// HTTP request gets the web server's answer, and so does a first record too short to be a header — at
// once, without waiting for more. Clients are not affected.
func TestFallback(t *testing.T) {
	back, got := webBackend(t)
	addr, _ := startServer(t, pairOptions{outer: "tls", server: miu.ServerConfig{Fallback: back}})

	for _, what := range []string{"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n", "hello"} {
		resp, d := probe(t, addr, what)
		if !strings.HasPrefix(resp, "HTTP/1.1 400") {
			t.Fatalf("probe %q: got %q", what, resp)
		}
		if d > 2*time.Second {
			t.Fatalf("probe %q: answered after %v", what, d)
		}
		if b := <-got; b != what {
			t.Fatalf("probe %q: the backend got %q", what, b)
		}
	}

	// A client on the same server still works.
	c, err := miu.NewClient(miu.ClientConfig{PSK: testPSK, Dial: miu.TLSDialer(addr, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialContext(context.Background(), "tcp", echoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(conn, b); err != nil || string(b) != "ping" {
		t.Fatalf("client through the server: %q %v", b, err)
	}
	select {
	case b := <-got:
		t.Fatalf("the client's lane reached the fallback: %q", b)
	default:
	}
}
