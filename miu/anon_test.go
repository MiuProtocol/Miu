package miu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// A lane's scheme comes from the PSK-derived family: deterministic for a nonce, different across nonces,
// within the generator's bounds; the PSK-derived scheme itself is untouched.
func TestLanePaddingScheme(t *testing.T) {
	token := sha256.Sum256([]byte("anon-test-psk-0123456789"))
	base, err := derivePaddingScheme(token)
	if err != nil {
		t.Fatal(err)
	}
	a1, err := deriveLanePaddingScheme(token, []byte("nonce-a"))
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := deriveLanePaddingScheme(token, []byte("nonce-a"))
	if a1.md5 != a2.md5 {
		t.Fatal("the same nonce gave two schemes")
	}
	seen := map[string]bool{base.md5: true}
	for i := 0; i < 200; i++ {
		p := newLaneScheme(token, base)
		if p == base {
			t.Fatal("no lane scheme drawn")
		}
		if p.stop < 5 || p.stop > 11 {
			t.Fatalf("stop %d: %q", p.stop, p.raw)
		}
		if s := p.sizesFor(0); len(s) != 1 || s[0] < 24 || s[0] > 64 {
			t.Fatalf("item 0 %v: %q", s, p.raw)
		}
		seen[p.md5] = true
	}
	if len(seen) < 150 {
		t.Fatalf("only %d distinct schemes in 200 lanes", len(seen))
	}
	if again, _ := derivePaddingScheme(token); again.md5 != base.md5 {
		t.Fatal("the PSK-derived scheme changed")
	}
}

// Two lanes of one client shape with different schemes but announce the same, PSK-derived md5.
func TestClientLanesDrawTheirOwnScheme(t *testing.T) {
	c, peers := pipeClient(t)
	go func() {
		for p := range peers {
			go func(p net.Conn) { // swallow the hellos of the warm lanes below
				for {
					if _, err := p.Read(make([]byte, 70000)); err != nil {
						return
					}
				}
			}(p)
		}
	}()
	var lanes []*lane
	for i := 0; i < 4; i++ {
		l, err := c.dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		lanes = append(lanes, l)
	}
	base := c.currentPadding()
	md5s := map[string]bool{}
	for _, l := range lanes {
		if l.base != base {
			t.Fatal("a lane's base is not the client's scheme")
		}
		md5s[l.scheme.Load().md5] = true
	}
	if len(md5s) < 3 {
		t.Fatalf("4 lanes shaped with %d schemes", len(md5s))
	}

	// A configured scheme is used as it is, on every lane.
	c2, err := NewClient(ClientConfig{PSK: shapeTestPSK, PaddingScheme: "stop=3\n0=40-40\n1=300-400",
		Dial: func(context.Context) (net.Conn, error) { a, _ := net.Pipe(); return a, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	l2, err := c2.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l2.scheme.Load() != l2.base || string(l2.base.raw) != "stop=3\n0=40-40\n1=300-400" {
		t.Fatalf("configured scheme not used as is: %q", l2.scheme.Load().raw)
	}
	if !strings.Contains(string(l2.prefix), "padding-md5="+l2.base.md5) {
		t.Fatal("Settings does not carry the base md5")
	}
}

// Only the lane's first packets are shaped, whichever stream they belong to.
func TestShapingCoversTheLaneStart(t *testing.T) {
	l, peer := pipeLane(t)
	l.scheme.Store(parsePaddingScheme("stop=3\n0=30-30\n1=200-200\n2=300-300"))
	data := appendData(nil, []byte("x"))
	var lens []int
	for i := 0; i < 5; i++ {
		w := collect(t, l, peer, func() error { return l.writeLanePacket(data) })
		for _, x := range w {
			lens = append(lens, len(x))
		}
	}
	// packets 1 and 2 padded to 200 and 300; the third and later go as they are
	if want := []int{200, 300, len(data), len(data), len(data)}; fmt.Sprint(lens) != fmt.Sprint(want) {
		t.Fatalf("record lengths %v, want %v", lens, want)
	}
}

// The server compares the client's md5 with the lane's base, not with its own draw: a client on the
// PSK-derived scheme gets no UpdatePaddingScheme.
func TestServerComparesWithBase(t *testing.T) {
	srv, err := NewServer(ServerConfig{Users: []User{{Name: "u", PSK: shapeTestPSK}}})
	if err != nil {
		t.Fatal(err)
	}
	token, _ := pskToken(shapeTestPSK)
	base, _ := derivePaddingScheme(token)
	hello := append(append([]byte(nil), token[:]...), 0, 0)
	hello = appendFrame(hello, frSettings, []byte("v=2\nraw=0\npadding-md5="+base.md5))
	a, b := net.Pipe()
	defer a.Close()
	rc := &recConn{Conn: b}
	go func() { _ = srv.Serve(context.Background(), rc) }()
	go func() { _, _ = a.Write(hello) }()
	_ = a.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := a.Read(make([]byte, 70000)); err != nil {
		t.Fatal(err)
	}
	if f := withoutPad(frameTypes(rc.first())); !bytes.Equal(f, []byte{frServerSettings}) {
		t.Fatalf("frames %v, want ServerSettings alone", f)
	}
}

// The first inner record of a raw segment rides in the announcing record when it fits (DATA, then the
// RAW frame for the rest, last); a full-size one does not, and the announcement stands alone.
func TestRawSegmentCarriesFirstRecord(t *testing.T) {
	rec := func(n int) []byte {
		return append([]byte{0x17, 3, 3, byte(n >> 8), byte(n)}, bytes.Repeat([]byte{byte(n)}, n)...)
	}
	for _, tc := range []struct {
		first int
		carry bool
	}{{120, true}, {4000, true}, {16384 - 40, true}, {16380, false}, {16401, false}} {
		l, peer := pipeLane(t)
		a := rec(tc.first)
		b := append(rec(16401), rec(300)...)
		w := collect(t, l, peer, func() error { return l.writeRawRecords(a, b) })
		head := w[0]
		types := withoutPad(frameTypes(head))
		if tc.carry {
			if !bytes.Equal(types, []byte{frData, frRaw}) {
				t.Fatalf("first %d: announcing record frames %v, want DATA RAW", tc.first, types)
			}
			if got := stripPad([][]byte{head[:len(head)-frameHead-4]}); !bytes.Equal(got, appendFrame(nil, frData, a)) {
				t.Fatalf("first %d: the carried record changed", tc.first)
			}
			if !bytes.Equal(bytes.Join(w[1:], nil), b) {
				t.Fatalf("first %d: the raw bytes are not the rest", tc.first)
			}
		} else {
			if !bytes.Equal(types, []byte{frRaw}) {
				t.Fatalf("first %d: announcing record frames %v, want RAW alone", tc.first, types)
			}
			if !bytes.Equal(bytes.Join(w[1:], nil), append(append([]byte(nil), a...), b...)) {
				t.Fatalf("first %d: the raw bytes changed", tc.first)
			}
		}
		if n := int(binary.BigEndian.Uint32(head[len(head)-4:])); n != len(bytes.Join(w[1:], nil)) {
			t.Fatalf("first %d: RAW announces %d bytes", tc.first, n)
		}
	}
}
