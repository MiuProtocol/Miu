package miu_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/MiuProtocol/Miu/miu"
	"github.com/MiuProtocol/Miu/miu/reality"
)

// What a passive observer sees: the bytes of a lane, read as TLS records by their headers. Outer records
// and raw segments alternate on the wire, and the raw segments are inner TLS records, so the whole byte
// stream has to read as one well-formed sequence of TLS records — in both directions, however the
// application and the target cut their data, and whether or not a record's rest is late.

// wireCapture is a TCP relay between client and server that keeps a copy of both directions.
type wireCapture struct {
	mu    sync.Mutex
	conns []*capturedConn
	wg    sync.WaitGroup
}

type capturedConn struct {
	mu       sync.Mutex
	up, down []byte
}

func captureRelay(t *testing.T, target string) (string, *wireCapture) {
	t.Helper()
	w := &wireCapture{}
	addr := listen(t, func(c net.Conn) {
		s, err := net.Dial("tcp", target)
		if err != nil {
			c.Close()
			return
		}
		cc := &capturedConn{}
		w.mu.Lock()
		w.conns = append(w.conns, cc)
		w.wg.Add(2)
		w.mu.Unlock()
		pump := func(dst, src net.Conn, up bool) {
			defer w.wg.Done()
			buf := make([]byte, 64<<10)
			for {
				n, err := src.Read(buf)
				if n > 0 {
					cc.mu.Lock()
					if up {
						cc.up = append(cc.up, buf[:n]...)
					} else {
						cc.down = append(cc.down, buf[:n]...)
					}
					cc.mu.Unlock()
					if _, werr := dst.Write(buf[:n]); werr != nil {
						break
					}
				}
				if err != nil {
					break
				}
			}
			_ = dst.(*net.TCPConn).CloseWrite()
		}
		go pump(s, c, true)
		go pump(c, s, false)
	})
	return addr, w
}

func (w *wireCapture) wait() []*capturedConn {
	w.wg.Wait()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.conns
}

type recordStats struct {
	records  int
	desyncAt int // -1: every byte belongs to a well-formed record
	bad      string
	tail     int // bytes of an incomplete record at the end
	sizes    map[int]int
}

func parseTLSRecords(b []byte) recordStats {
	st := recordStats{desyncAt: -1, sizes: map[int]int{}}
	pos := 0
	for pos+5 <= len(b) {
		typ, ver, n := b[pos], binary.BigEndian.Uint16(b[pos+1:]), int(binary.BigEndian.Uint16(b[pos+3:]))
		if typ < 20 || typ > 23 || !(ver == 0x0303 || pos == 0 && ver == 0x0301) || n > 16384+256 {
			st.desyncAt, st.bad = pos, fmt.Sprintf("% x", b[pos:pos+5])
			return st
		}
		if pos+5+n > len(b) {
			break
		}
		st.records++
		st.sizes[n]++
		pos += 5 + n
	}
	st.tail = len(b) - pos
	return st
}

// splitConn cuts every write into pieces of random length and now and then pauses between two pieces
// for longer than a held record tail may wait — like a relay reading a socket, or a slow sender.
type splitConn struct {
	net.Conn
	mu  sync.Mutex
	rnd *mrand.Rand
}

func (c *splitConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		c.mu.Lock()
		k := 1 + c.rnd.Intn(20000)
		pause := c.rnd.Intn(40) == 0
		c.mu.Unlock()
		if k > len(p) {
			k = len(p)
		}
		n, err := c.Conn.Write(p[:k])
		total += n
		if err != nil {
			return total, err
		}
		p = p[k:]
		if pause && len(p) > 0 {
			time.Sleep(30 * time.Millisecond)
		}
	}
	return total, nil
}

func patternBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(seed)).Read(b)
	return b
}

// transferTarget is the inner TLS 1.3 server: it reads an 8-byte header (download size, upload size) and
// the upload, answers with the upload's SHA-256, then sends the download (patternBytes(down)). Its TCP
// writes are cut up by a splitConn, so the Miu server reads inner records in pieces.
func transferTarget(t *testing.T) string {
	cfg, _ := innerTLS(t)
	var seed int64
	var mu sync.Mutex
	return listen(t, func(c net.Conn) {
		defer c.Close()
		mu.Lock()
		seed++
		s := seed
		mu.Unlock()
		tc := tls.Server(&splitConn{Conn: c, rnd: mrand.New(mrand.NewSource(s))}, cfg)
		var h [8]byte
		if _, err := io.ReadFull(tc, h[:]); err != nil {
			return
		}
		down, up := int(binary.BigEndian.Uint32(h[:4])), int64(binary.BigEndian.Uint32(h[4:]))
		sum := sha256.New()
		if _, err := io.CopyN(sum, tc, up); err != nil {
			return
		}
		if _, err := tc.Write(sum.Sum(nil)); err != nil {
			return
		}
		data := patternBytes(int64(down), down)
		r := mrand.New(mrand.NewSource(s))
		for len(data) > 0 {
			k := 1 + r.Intn(96<<10)
			if k > len(data) {
				k = len(data)
			}
			if _, err := tc.Write(data[:k]); err != nil {
				return
			}
			data = data[k:]
		}
	})
}

func TestWireReadsAsTLSRecords(t *testing.T) {
	for _, outer := range []string{"tls", "reality"} {
		for _, segmented := range []bool{false, true} {
			if segmented && !miu.CanSegment() {
				continue
			}
			t.Run(fmt.Sprintf("%s/segmented=%v", outer, segmented), func(t *testing.T) {
				old := miu.SetSegmentedCopy(segmented)
				defer miu.SetSegmentedCopy(old)
				events := collectEvents(t)
				wireTransfers(t, outer, events)
			})
		}
	}
}

func wireTransfers(t *testing.T, outer string, events func(string) int) {
	addr, realityKey := startServer(t, pairOptions{outer: outer})
	relay, capture := captureRelay(t, addr)
	cfg := miu.ClientConfig{PSK: testPSK}
	switch outer {
	case "tls":
		cfg.Dial = miu.TLSDialer(relay, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	case "reality":
		dial, err := reality.Dialer(relay, reality.ClientConfig{ServerName: "localhost", PublicKey: realityKey, ShortID: realityShortID})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Dial = dial
	}
	c, err := miu.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	target := transferTarget(t)
	_, wrap := innerTLS(t)
	const down, up = 3 << 20, 2 << 20
	for i := 0; i < 2; i++ { // the second stream runs on the lane the first one returned
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		conn, err := c.DialContext(ctx, "tcp", target)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		tc := wrap(&splitConn{Conn: conn, rnd: mrand.New(mrand.NewSource(int64(100 + i)))})
		var h [8]byte
		binary.BigEndian.PutUint32(h[:4], down)
		binary.BigEndian.PutUint32(h[4:], up)
		upload := patternBytes(int64(7+i), up)
		if _, err := tc.Write(append(h[:], upload...)); err != nil {
			t.Fatal(err)
		}
		var sum [32]byte
		if _, err := io.ReadFull(tc, sum[:]); err != nil {
			t.Fatal(err)
		}
		if want := sha256.Sum256(upload); sum != want {
			t.Fatal("the upload arrived damaged")
		}
		got, err := io.ReadAll(io.LimitReader(tc, down))
		if err != nil || !bytes.Equal(got, patternBytes(down, down)) {
			t.Fatalf("the download arrived damaged: %d bytes, %v", len(got), err)
		}
		tc.Close()
	}
	time.Sleep(100 * time.Millisecond)
	c.Close()

	for _, e := range []string{"client:raw", "server:raw", "client:holdflush", "server:holdflush"} {
		if events(e) == 0 {
			t.Errorf("%s never happened: the test does not exercise that path", e)
		}
	}
	small, fixed := 0, 0
	for i, cc := range capture.wait() {
		for _, d := range []struct {
			name string
			b    []byte
		}{{"up", cc.up}, {"down", cc.down}} {
			st := parseTLSRecords(d.b)
			if st.desyncAt >= 0 || st.tail != 0 {
				t.Errorf("conn %d %s (%d bytes): not a sequence of TLS records at %d (%s), %d bytes left over",
					i, d.name, len(d.b), st.desyncAt, st.bad, st.tail)
			}
			for n, k := range st.sizes {
				if n <= 7+16+3+300 {
					small += k
				}
			}
			fixed += st.sizes[7+16+1] // a RAW frame alone: the old fixed-size announcement
		}
	}
	// The announcing records vary in length; the bare RAW frame is now rare.
	if raw := events("client:raw") + events("server:raw"); fixed*10 > raw {
		t.Errorf("%d of %d raw segments announced by a fixed-size record", fixed, raw)
	}
	t.Logf("raw segments: client %d, server %d (splice %d); hold flushed: client %d, server %d; small records %d",
		events("client:raw"), events("server:raw"), events("server:splice"),
		events("client:holdflush"), events("server:holdflush"), small)
}
