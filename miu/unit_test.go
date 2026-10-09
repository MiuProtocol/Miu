package miu

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestAddrCodecRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port uint16
	}{
		{"1.2.3.4", 80},
		{"2001:db8::1", 443},
		{"example.com", 8443},
		{uotMagicDomain, 0},
	}
	for _, codec := range []addrCodec{socksAddr, uotAddr} {
		for _, c := range cases {
			b, err := codec.append(nil, c.host, c.port)
			if err != nil {
				t.Fatalf("append %v: %v", c.host, err)
			}
			host, port, n, err := codec.parse(b)
			if err != nil || n != len(b) || host != c.host || port != c.port {
				t.Fatalf("parse %v:%d → %v:%d (n=%d of %d, err=%v)", c.host, c.port, host, port, n, len(b), err)
			}
			host, port, err = codec.read(bytes.NewReader(b))
			if err != nil || host != c.host || port != c.port {
				t.Fatalf("read %v:%d → %v:%d (%v)", c.host, c.port, host, port, err)
			}
			// every proper prefix is "short", never a different address
			for i := 0; i < len(b); i++ {
				if _, _, _, err := codec.parse(b[:i]); err != errShort {
					t.Fatalf("prefix %d of %v: %v", i, c.host, err)
				}
			}
		}
	}
	// The family bytes are part of the wire format.
	b, _ := socksAddr.append(nil, "1.2.3.4", 1)
	if !bytes.Equal(b, []byte{0x01, 1, 2, 3, 4, 0, 1}) {
		t.Fatalf("socks ipv4 = %x", b)
	}
	b, _ = uotAddr.append(nil, "1.2.3.4", 1)
	if b[0] != 0x00 {
		t.Fatalf("uot ipv4 family = %#x", b[0])
	}
	b, _ = socksAddr.append(nil, "example.com", 443)
	if !bytes.Equal(b, append([]byte{0x03, 11}, "example.com\x01\xbb"...)) {
		t.Fatalf("socks domain = %x", b)
	}
	b, _ = uotAddr.append(nil, "::ffff:9.9.9.9", 53) // an IPv4-mapped address is IPv4 on the wire
	if !bytes.Equal(b, []byte{0x00, 9, 9, 9, 9, 0, 53}) {
		t.Fatalf("mapped ipv4 = %x", b)
	}
	if _, err := socksAddr.append(nil, "", 1); err == nil {
		t.Fatal("empty host accepted")
	}
	if _, _, _, err := socksAddr.parse([]byte{9, 1, 2, 3}); err == nil || err == errShort {
		t.Fatalf("unknown family: %v", err)
	}
}

func TestFrames(t *testing.T) {
	if b := appendFrame(nil, frOpen, []byte{1, 2, 3}); !bytes.Equal(b, []byte{frOpen, 0, 3, 1, 2, 3}) {
		t.Fatalf("frame = %x", b)
	}
	if b := appendFrame(nil, frEnd, nil); !bytes.Equal(b, []byte{7, 0, 0}) {
		t.Fatalf("END = %x", b)
	}
	// Payload larger than one frame is split; every frame fits a TLS record.
	p := bytes.Repeat([]byte{0xab}, 2*maxData+10)
	b := appendData(nil, p)
	var got []byte
	frames := 0
	for len(b) > 0 {
		n := int(b[1])<<8 | int(b[2])
		if b[0] != frData || n > maxData {
			t.Fatalf("frame type %d len %d", b[0], n)
		}
		got = append(got, b[frameHead:frameHead+n]...)
		b = b[frameHead+n:]
		frames++
	}
	if frames != 3 || !bytes.Equal(got, p) {
		t.Fatalf("%d frames, %d bytes", frames, len(got))
	}
	kv := parseKV("v=2\nraw=1\n  idle=180 \n\njunk\npadding-md5=ab=cd")
	if kv["v"] != "2" || kv["raw"] != "1" || kv["padding-md5"] != "ab=cd" {
		t.Fatalf("kv = %v", kv)
	}
	if n, ok := kvInt(kv, "idle"); !ok || n != 180 {
		t.Fatalf("idle = %d %v", n, ok)
	}
	if _, ok := kvInt(kv, "raw-missing"); ok {
		t.Fatal("missing key parsed")
	}
}

func TestUoTPacketCodec(t *testing.T) {
	a, _ := appendUoTPacket(nil, "9.9.9.9", 53, []byte("hello"))
	b, _ := appendUoTPacket(nil, "dns.example", 5353, bytes.Repeat([]byte("x"), 1000))
	flat := append(append([]byte(nil), a...), b...)
	// Packets may be cut anywhere: a prefix is "short" until the whole packet is there.
	for i := 0; i < len(a); i++ {
		if _, _, _, _, err := parseUoTPacket(flat[:i], true); err != errShort {
			t.Fatalf("prefix %d: %v", i, err)
		}
	}
	host, port, payload, n, err := parseUoTPacket(flat, true)
	if err != nil || host != "9.9.9.9" || port != 53 || string(payload) != "hello" || n != len(a) {
		t.Fatalf("first packet: %v %v %q %d %v", host, port, payload, n, err)
	}
	host, port, payload, n, err = parseUoTPacket(flat[n:], true)
	if err != nil || host != "dns.example" || port != 5353 || len(payload) != 1000 || n != len(b) {
		t.Fatalf("second packet: %v %v %d %d %v", host, port, len(payload), n, err)
	}
	// A connected stream's packets carry no address.
	_, _, payload, n, err = parseUoTPacket([]byte{0, 2, 'o', 'k', 0xff}, false)
	if err != nil || string(payload) != "ok" || n != 4 {
		t.Fatalf("connected packet: %q %d %v", payload, n, err)
	}
	if _, err := appendUoTPacket(nil, "9.9.9.9", 53, make([]byte, 70000)); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestPaddingScheme(t *testing.T) {
	p := defaultScheme
	if p == nil || p.stop != 8 {
		t.Fatal("default scheme")
	}
	// The md5 is what the two sides compare; it is the md5 of the text as written.
	if sum := md5.Sum([]byte(DefaultPaddingScheme)); p.md5 != hex.EncodeToString(sum[:]) {
		t.Fatalf("md5 %q", p.md5)
	}
	if s := p.sizesFor(0); len(s) != 1 || s[0] != 30 {
		t.Fatalf("pkt0 sizes %v", s)
	}
	for i := 0; i < 50; i++ {
		for _, s := range p.sizesFor(2) {
			if s != checkMark && (s < 400 || s >= 1000) {
				t.Fatalf("pkt2 size %d out of range", s)
			}
		}
	}
	if p.sizesFor(8) != nil {
		t.Fatal("sizes past the end of the scheme")
	}
	if parsePaddingScheme("garbage") != nil || parsePaddingScheme("") != nil || parsePaddingScheme("1=2-3") != nil {
		t.Fatal("bad scheme should not parse")
	}
	if p.padding0() != 30 || (*paddingScheme)(nil).padding0() != 30 {
		t.Fatal("padding0")
	}
	if q := parsePaddingScheme("stop=2\n0=77-77\n1=50-60"); q == nil || q.padding0() != 77 || q.md5 == p.md5 {
		t.Fatal("custom scheme")
	}
}

func TestPSKToken(t *testing.T) {
	const psk = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ="
	tok, err := pskToken("  " + psk + "\n")
	if err != nil {
		t.Fatal(err)
	}
	// The token is the hash of the string itself, not of the bytes it would decode to.
	if tok != sha256.Sum256([]byte(psk)) {
		t.Fatal("token is not sha256(psk string)")
	}
	if _, err := pskToken("short"); err == nil {
		t.Fatal("short psk accepted")
	}
	if _, err := pskToken(""); err == nil {
		t.Fatal("empty psk accepted")
	}
}

// pipeLane makes a lane over an in-memory connection (a plaintext outer layer: no raw segments) and
// returns it with the peer's end.
func pipeLane(t *testing.T) (*lane, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return newLane(a, false, true), b
}

// collect runs write on the lane and returns the individual writes the peer saw. Over net.Pipe every
// Write of the lane arrives as one Read, which is what a TLS record would be.
func collect(t *testing.T, l *lane, peer net.Conn, write func() error) [][]byte {
	t.Helper()
	var writes [][]byte
	done := make(chan error, 1)
	go func() {
		err := write()
		_ = l.write([]byte{0xff}) // sentinel
		done <- err
	}()
	for {
		b := make([]byte, 70000)
		n, err := peer.Read(b)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 && b[0] == 0xff {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			return writes
		}
		writes = append(writes, b[:n])
	}
}

// stripPad joins the writes and removes the PAD frames.
func stripPad(writes [][]byte) []byte {
	all := bytes.Join(writes, nil)
	var out []byte
	for len(all) > 0 {
		n := int(all[1])<<8 | int(all[2])
		if all[0] != frPad {
			out = append(out, all[:frameHead+n]...)
		}
		all = all[frameHead+n:]
	}
	return out
}

// Shaping: with the default scheme packet 1 is padded to one record of 100–400 bytes; packet 2 is cut
// into several, each within its range; without the PAD frames the original frames are back. A packet
// past stop goes out whole.
func TestWritePacketShaping(t *testing.T) {
	l, peer := pipeLane(t)
	open := appendFrame(appendFrame(nil, frOpen, []byte{1, 127, 0, 0, 1, 1, 187}), frData, bytes.Repeat([]byte{7}, 20))
	w := collect(t, l, peer, func() error { return l.writePacket(1, open) })
	if len(w) != 1 || len(w[0]) < 100 || len(w[0]) >= 400 {
		t.Fatalf("packet 1: %d writes, first %d bytes", len(w), len(w[0]))
	}
	if !bytes.Equal(stripPad(w), open) {
		t.Fatal("packet 1: frames changed")
	}

	data := appendFrame(nil, frData, bytes.Repeat([]byte{9}, 3000))
	w = collect(t, l, peer, func() error { return l.writePacket(2, data) })
	if len(w) < 3 || len(w[0]) < 400 || len(w[0]) >= 500 {
		t.Fatalf("packet 2: %d writes, first %d bytes", len(w), len(w[0]))
	}
	// The ones in between are 500–1000; what is left when the scheme runs out follows in one piece.
	for _, x := range w[1 : len(w)-1] {
		if len(x) < 500 || len(x) >= 1000 {
			t.Fatalf("packet 2: a record of %d bytes", len(x))
		}
	}
	if !bytes.Equal(stripPad(w), data) {
		t.Fatal("packet 2: frames changed")
	}

	if w = collect(t, l, peer, func() error { return l.writePacket(l.scheme.Load().stop, data) }); len(w) != 1 || !bytes.Equal(w[0], data) {
		t.Fatalf("a packet past stop was shaped: %d writes", len(w))
	}
}

// A stream's END is never shaped and is the last byte of its direction — also when the stream ends
// within the first packets, where everything else is padded, and when OPEN has not even gone out yet.
func TestEndIsNotShaped(t *testing.T) {
	for _, withData := range []bool{true, false} {
		l, peer := pipeLane(t)
		s := &stream{c: &Client{}, open: appendFrame(nil, frOpen, []byte{1, 127, 0, 0, 1, 0, 80}), pkt: 1}
		s.lane.Store(l)
		s.upScan = recScan{st: &s.state, dead: true}
		s.timer = time.NewTimer(time.Hour)
		w := collect(t, l, peer, func() error {
			if withData {
				if _, err := s.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
					return err
				}
			}
			return s.CloseWrite()
		})
		last := w[len(w)-1]
		if withData {
			// packet 1 (OPEN · DATA, padded), then END alone
			if len(w) != 2 || len(w[0]) < 100 || !bytes.Equal(last, []byte{frEnd, 0, 0}) {
				t.Fatalf("with data: %d writes, last %x", len(w), last)
			}
		} else if len(w) != 1 || !bytes.Equal(last, append(append([]byte(nil), s.open...), frEnd, 0, 0)) {
			// OPEN · END in one unpadded write
			t.Fatalf("without data: %d writes, last %x", len(w), last)
		}
	}
}

// Following the inner handshake's record boundaries: after a TLS 1.3 ServerHello, the first
// application_data record header on a boundary means raw segments may begin — however the data is cut
// into chunks. A stream that is not TLS, or is TLS 1.2, never gets there.
func TestRecScan(t *testing.T) {
	rec := func(typ byte, body []byte) []byte {
		return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
	}
	serverHello := func(tls13 bool) []byte {
		b := []byte{2, 0, 0, 0, 3, 3}
		b = append(b, make([]byte, 32)...)    // random
		b = append(b, 0)                      // session id
		b = append(b, 0x13, 0x01, 0)          // cipher, compression
		ext := []byte{0, 0x33, 0, 2, 0, 0x1d} // some other extension
		if tls13 {
			ext = append(ext, 0, 0x2b, 0, 2, 3, 4)
		}
		return append(append(b, byte(len(ext)>>8), byte(len(ext))), ext...)
	}
	down13 := bytes.Join([][]byte{rec(0x16, serverHello(true)), rec(0x14, []byte{1}), rec(0x17, make([]byte, 100))}, nil)

	for _, chunk := range []int{1, 3, 7, 64, len(down13)} {
		st := &streamState{}
		s := &recScan{st: st}
		sw, at := false, 0
		for i := 0; i < len(down13) && !sw; i += chunk {
			end := min(i+chunk, len(down13))
			sw, at = s.feed(down13[i:end]), end
		}
		// the chunk that completes the application_data record header (5 bytes) is where it switches
		if want := len(down13) - 100; !sw || at < want || at >= want+chunk {
			t.Fatalf("chunk %d: switch=%v at %d, want within [%d,%d)", chunk, sw, at, want, want+chunk)
		}
		if !st.tls13.Load() {
			t.Fatalf("chunk %d: TLS 1.3 not recognised", chunk)
		}
		if !s.feed([]byte{1, 2, 3}) {
			t.Fatalf("chunk %d: the result does not latch", chunk)
		}
	}

	// The uplink learns about TLS 1.3 from the other direction: no switch on ClientHello or CCS, a
	// switch on Finished (application_data).
	st := &streamState{}
	up := &recScan{st: st}
	if up.feed(rec(0x16, []byte{1, 0, 0, 0})) {
		t.Fatal("switched on ClientHello")
	}
	st.tls13.Store(true)
	if up.feed(rec(0x14, []byte{1})) || !up.feed(rec(0x17, make([]byte, 40))) {
		t.Fatal("uplink should switch at the first application_data record after TLS 1.3 is known")
	}

	s12 := &recScan{st: &streamState{}}
	if s12.feed(bytes.Join([][]byte{rec(0x16, serverHello(false)), rec(0x14, []byte{1}), rec(0x17, make([]byte, 100))}, nil)) {
		t.Fatal("switched on a TLS 1.2 handshake")
	}
	plain := &recScan{st: &streamState{}}
	if plain.feed([]byte("GET / HTTP/1.1\r\n\r\n")) || !plain.dead {
		t.Fatal("plaintext HTTP should be given up on")
	}
	// Past the sniff limit the search is abandoned.
	slow := &recScan{st: &streamState{}}
	for i := 0; i < sniffLimit/16384+1; i++ {
		slow.feed(rec(0x16, make([]byte, 16384-5)))
	}
	if !slow.dead {
		t.Fatal("no give-up after the sniff limit")
	}
}

// Idle lanes are kept in two tiers: the newest warmLanes ones for longer, the rest until LaneIdle;
// neither beyond what the server announced minus 5s.
func TestLaneTTL(t *testing.T) {
	c := &Client{cfg: ClientConfig{LaneIdle: defaultLaneIdle}}
	l, _ := pipeLane(t)
	if c.ttl(l, 0) != warmLaneIdle || c.ttl(l, warmLanes-1) != warmLaneIdle || c.ttl(l, warmLanes) != defaultLaneIdle {
		t.Fatalf("ttl by rank: %v %v %v", c.ttl(l, 0), c.ttl(l, warmLanes-1), c.ttl(l, warmLanes))
	}
	l.peerIdle.Store(60)
	if c.ttl(l, 0) != 55*time.Second || c.ttl(l, warmLanes) != defaultLaneIdle {
		t.Fatalf("server idle 60s: %v %v", c.ttl(l, 0), c.ttl(l, warmLanes))
	}
	l.peerIdle.Store(20)
	if c.ttl(l, 0) != 15*time.Second || c.ttl(l, warmLanes) != 15*time.Second {
		t.Fatalf("server idle 20s: %v %v", c.ttl(l, 0), c.ttl(l, warmLanes))
	}
}

// The pool hands out the newest lane first, drops the oldest when it is full, and sweeps by tier.
func TestPoolOrder(t *testing.T) {
	c := &Client{cfg: ClientConfig{LaneIdle: defaultLaneIdle, MinIdle: defaultMinIdle}}
	var lanes []*lane
	for i := 0; i < maxIdleLanes+1; i++ {
		l, _ := pipeLane(t)
		lanes = append(lanes, l)
		c.put(l, true)
	}
	if len(c.idle) != maxIdleLanes || !lanes[0].closed.Load() || lanes[1].closed.Load() {
		t.Fatalf("pool of %d, oldest closed=%v", len(c.idle), lanes[0].closed.Load())
	}
	if l, _ := c.takeIdle(time.Now()); l != lanes[maxIdleLanes] {
		t.Fatal("not last in, first out")
	}
	// 40s on: only the newest warmLanes survive a sweep.
	for i := range c.idle {
		c.idle[i].since = time.Now().Add(-40 * time.Second)
	}
	c.sweep()
	if len(c.idle) != warmLanes || c.idle[len(c.idle)-1].l != lanes[maxIdleLanes-1] {
		t.Fatalf("after the sweep: %d lanes", len(c.idle))
	}
	// A lane past its time is not handed out.
	for i := range c.idle {
		c.idle[i].since = time.Now().Add(-130 * time.Second)
	}
	if l, _ := c.takeIdle(time.Now()); l != nil {
		t.Fatal("an expired lane was handed out")
	}
	c.Close()
	l, _ := pipeLane(t)
	c.put(l, true)
	if !l.closed.Load() {
		t.Fatal("a closed client pooled a lane")
	}
}

func TestSelfTest(t *testing.T) {
	if err := SelfTest(nil); err != nil {
		t.Fatal(err)
	}
}

// A connection that is not a Go TLS connection simply has no raw segments.
func TestTLSBuffersFallback(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if _, _, _, ok := tlsBuffers(a); ok {
		t.Fatal("a pipe is not a TLS connection")
	}
	if l := newLane(a, false, true); l.canRaw || string(l.settingsText("")) != "v=2\nraw=0" {
		t.Fatal("lane over a pipe claims raw segments")
	}
	// Same field names, wrong types: must be refused, not reinterpreted.
	if _, _, _, ok := tlsBuffers(&fakeTLS{Conn: a}); ok {
		t.Fatal("a look-alike struct was accepted")
	}
}

type fakeTLS struct {
	net.Conn
	input    []byte
	rawInput int
}

func (f *fakeTLS) NetConn() net.Conn { return f.Conn }

// The lane's read cursor survives a read that times out, wherever in a frame that happens.
func TestLaneReadResumable(t *testing.T) {
	l, peer := pipeLane(t)
	var wire []byte
	wire = appendFrame(wire, frPad, make([]byte, 10))
	wire = appendFrame(wire, frServerSettings, []byte("v=2\nraw=0\nidle=77"))
	wire = appendFrame(wire, frData, []byte("hello, lane"))
	wire = appendFrame(wire, frEnd, nil)
	go func() {
		for i := range wire { // one byte at a time, slower than the reader's deadline
			time.Sleep(3 * time.Millisecond)
			if _, err := peer.Write(wire[i : i+1]); err != nil {
				return
			}
		}
	}()
	timeouts := 0
	retry := func(f func() error) {
		for {
			_ = l.conn.SetReadDeadline(time.Now().Add(time.Millisecond))
			err := f()
			if err == nil {
				return
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
			timeouts++
		}
	}
	var typ byte
	var payload []byte
	next := func() error {
		var err error
		typ, payload, err = l.next()
		return err
	}
	retry(next)
	if typ != frServerSettings || l.control(typ, payload) != nil || l.peerIdle.Load() != 77 {
		t.Fatalf("first frame: type %d %q", typ, payload)
	}
	retry(next)
	if typ != frData || !l.pending() {
		t.Fatalf("second frame: type %d", typ)
	}
	var got []byte
	for l.pending() {
		retry(func() error {
			b := make([]byte, 4)
			n, err := l.readPayload(b)
			got = append(got, b[:n]...)
			return err
		})
	}
	retry(next)
	if typ != frEnd || string(got) != "hello, lane" || timeouts < 10 {
		t.Fatalf("type %d, data %q, %d timeouts", typ, got, timeouts)
	}
}
