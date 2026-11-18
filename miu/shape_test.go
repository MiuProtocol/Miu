package miu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

const shapeTestPSK = "shape-test-psk-0123456789"

func inTable(t []smallLen, n int) bool {
	for _, e := range t {
		if int(e.n) == n {
			return true
		}
	}
	return false
}

// Lengths are drawn from the table, at or above the minimum, in proportion to the counts.
func TestLengthSampler(t *testing.T) {
	for _, tc := range []struct {
		name  string
		s     *lengthSampler
		table []smallLen
	}{{"up", samplerUp, smallUp}, {"down", samplerDown, smallDown}} {
		total := 0
		for _, e := range tc.table {
			total += int(e.count)
		}
		for _, min := range []int{0, 20, 26, 27, 100, 250, 299} {
			for i := 0; i < 500; i++ {
				n := tc.s.pick(min)
				if n == 0 && tc.s.lens[len(tc.s.lens)-1] >= min {
					t.Fatalf("%s: nothing picked at or above %d", tc.name, min)
				}
				if n != 0 && (n < min || !inTable(tc.table, n)) {
					t.Fatalf("%s: picked %d for min %d", tc.name, n, min)
				}
			}
		}
		if tc.s.pick(smallLimit) != 0 {
			t.Fatalf("%s: picked a length at or above the limit", tc.name)
		}
		// The commonest length comes out about as often as its count says.
		top := tc.table[0]
		for _, e := range tc.table {
			if e.count > top.count {
				top = e
			}
		}
		hits := 0
		const draws = 20000
		for i := 0; i < draws; i++ {
			if tc.s.pick(0) == int(top.n) {
				hits++
			}
		}
		want := float64(top.count) / float64(total)
		if got := float64(hits) / draws; got < want-0.03 || got > want+0.03 {
			t.Fatalf("%s: length %d drawn %.3f of the time, its share is %.3f", tc.name, top.n, got, want)
		}
	}
}

// A small record is padded in front to a length from the table; what it carries is unchanged and stays
// last; the prefix counts towards the length; a record that is not small is left alone.
func TestPadSmall(t *testing.T) {
	for _, server := range []bool{false, true} {
		table := smallUp
		if server {
			table = smallDown
		}
		l := newLane(nil, server, true)
		end := []byte{frEnd, 0, 0}
		for i := 0; i < 200; i++ {
			out := l.padSmall(end)
			if n := len(out) + recordOverhead; !inTable(table, n) || !bytes.HasSuffix(out, end) {
				t.Fatalf("server=%v: END padded to a %d-byte record: %x", server, n, out)
			}
			if !bytes.Equal(stripPad([][]byte{out}), end) {
				t.Fatalf("server=%v: frames changed: %x", server, out)
			}
		}
		l.prefix = make([]byte, 60)
		for i := 0; i < 200; i++ {
			if n := len(l.prefix) + len(l.padSmall(end)) + recordOverhead; !inTable(table, n) {
				t.Fatalf("server=%v: with a prefix, a %d-byte record", server, n)
			}
		}
		l.prefix = nil
		big := appendData(nil, make([]byte, smallLimit))
		if out := l.padSmall(big); !bytes.Equal(out, big) {
			t.Fatal("a record that is not small was padded")
		}
	}
}

// pipeClient returns a client whose lanes are the near ends of net.Pipes, handed to the test on peers.
func pipeClient(t *testing.T) (*Client, chan net.Conn) {
	t.Helper()
	peers := make(chan net.Conn, 8)
	c, err := NewClient(ClientConfig{PSK: shapeTestPSK, Dial: func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		t.Cleanup(func() { a.Close(); b.Close() })
		peers <- b
		return a, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, peers
}

// readHello reads one write from peer and splits it into the authentication header (checked against the
// client's token) and the frames that follow it in the same write.
func readHello(t *testing.T, c *Client, peer net.Conn) (frames []byte) {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 70000)
	n, err := peer.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	b = b[:n]
	if len(b) < authHead || !bytes.Equal(b[:32], c.token[:]) {
		t.Fatalf("the write does not start with the authentication header: %x", b[:min(len(b), 40)])
	}
	pad := int(binary.BigEndian.Uint16(b[32:]))
	return b[authHead+pad:]
}

// frameTypes lists the frame types in b, PAD included.
func frameTypes(b []byte) []byte {
	var out []byte
	for len(b) >= frameHead {
		n := int(binary.BigEndian.Uint16(b[1:]))
		out = append(out, b[0])
		if len(b) < frameHead+n {
			break
		}
		b = b[frameHead+n:]
	}
	return out
}

func withoutPad(types []byte) []byte {
	return bytes.ReplaceAll(types, []byte{frPad}, nil)
}

// A lane dialed for a stream writes nothing until the stream's first write, which then starts with the
// authentication header and Settings: OPEN and the first payload in the same write. Without payload the
// OPEN that follows firstPayloadWait carries them.
func TestColdLaneMergesHello(t *testing.T) {
	c, peers := pipeClient(t)
	ctx := context.Background()

	conn, err := c.DialContext(ctx, "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	peer := <-peers
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	if n, err := peer.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the lane wrote before the stream did: %d %v", n, err)
	}
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); done <- err }()
	if got := withoutPad(frameTypes(readHello(t, c, peer))); !bytes.HasPrefix(got, []byte{frSettings, frOpen, frData}) {
		t.Fatalf("first write after the header: frames %v, want Settings OPEN DATA", got)
	}
	go func() {
		for { // drain the rest of the packet
			if _, err := peer.Read(make([]byte, 70000)); err != nil {
				return
			}
		}
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	conn.Close()

	// The server speaks first: OPEN goes alone after firstPayloadWait, with the header in front.
	c2, peers2 := pipeClient(t)
	conn2, err := c2.DialContext(ctx, "tcp", "example.com:25")
	if err != nil {
		t.Fatal(err)
	}
	if got := withoutPad(frameTypes(readHello(t, c2, <-peers2))); !bytes.HasPrefix(got, []byte{frSettings, frOpen}) {
		t.Fatalf("server-first: frames %v, want Settings OPEN", got)
	}
	conn2.Close()
}

// A lane that goes back to the pool before anything was written sends its authentication then, so that
// the server does not time it out and the next stream can use it.
func TestColdLaneAbortedBeforeWriting(t *testing.T) {
	c, peers := pipeClient(t)
	l, err := c.dial(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	peer := <-peers
	got := make(chan []byte, 1)
	go func() { got <- readHello(t, c, peer) }()
	c.put(l, false)
	if f := withoutPad(frameTypes(<-got)); !bytes.Equal(f, []byte{frSettings}) {
		t.Fatalf("frames after the header: %v, want Settings", f)
	}
	c.mu.Lock()
	pooled := len(c.idle)
	c.mu.Unlock()
	if pooled != 1 {
		t.Fatalf("%d lanes in the pool", pooled)
	}
}

// A lane dialed to warm the pool sends its header at once.
func TestWarmLaneSendsHelloAtOnce(t *testing.T) {
	c, peers := pipeClient(t)
	got := make(chan []byte, 1)
	go func() { got <- readHello(t, c, <-peers) }()
	if _, err := c.dial(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if f := withoutPad(frameTypes(<-got)); !bytes.Equal(f, []byte{frSettings}) {
		t.Fatalf("frames after the header: %v", f)
	}
}

// recConn keeps a copy of every Write.
type recConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recConn) first() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.writes) == 0 {
		return nil
	}
	return c.writes[0]
}

// ServerSettings goes out with the server's first downlink write, or alone after settingsWait.
func TestServerSettingsDeferred(t *testing.T) {
	srv, err := NewServer(ServerConfig{Users: []User{{Name: "u", PSK: shapeTestPSK}}})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := pskToken(shapeTestPSK)
	hello := append(append([]byte(nil), token[:]...), 0, 0)
	hello = appendFrame(hello, frSettings, []byte("v=2\nraw=0\npadding-md5=x"))

	// No stream: alone, after settingsWait.
	a, b := net.Pipe()
	defer a.Close()
	rc := &recConn{Conn: b}
	go func() { _ = srv.Serve(context.Background(), rc) }()
	start := time.Now()
	go func() { _, _ = a.Write(hello) }()
	_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := a.Read(make([]byte, 70000)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < settingsWait-100*time.Millisecond || d > settingsWait+time.Second {
		t.Fatalf("ServerSettings alone after %v, want about %v", d, settingsWait)
	}
	if f := withoutPad(frameTypes(rc.first())); len(f) == 0 || f[0] != frServerSettings {
		t.Fatalf("first write: frames %v", f)
	}

	// A stream whose target answers at once: ServerSettings leads the first downlink write.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		c, err := target.Accept()
		if err == nil {
			_, _ = c.Write([]byte("220 hello\r\n"))
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	open, _ := socksAddr.append(nil, "127.0.0.1", uint16(target.Addr().(*net.TCPAddr).Port))
	a2, b2 := net.Pipe()
	defer a2.Close()
	rc2 := &recConn{Conn: b2}
	go func() { _ = srv.Serve(context.Background(), rc2) }()
	go func() { _, _ = a2.Write(appendFrame(append([]byte(nil), hello...), frOpen, open)) }()
	_ = a2.SetReadDeadline(time.Now().Add(3 * time.Second))
	start = time.Now()
	if _, err := a2.Read(make([]byte, 70000)); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > settingsWait/2 {
		t.Fatal("ServerSettings waited for settingsWait although the downlink had data")
	}
	// The md5 sent above is not the server's, so UpdatePaddingScheme comes along.
	if f := withoutPad(frameTypes(rc2.first())); !bytes.Equal(f, []byte{frServerSettings, frUpdatePadding, frData}) {
		t.Fatalf("first write: frames %v, want ServerSettings UpdatePaddingScheme DATA", f)
	}
}
