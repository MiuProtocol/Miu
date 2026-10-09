package miu

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"
)

// SelfTest checks that raw segments work with the TLS implementation linked into the program.
//
// Raw segments rely on two unexported buffers of Go's TLS connection (see PROTOCOL.md, implementation
// notes). The fields are looked up by name at run time, so a Go release that reshapes the connection
// cannot crash the program — but it can make raw segments unavailable, or wrong. SelfTest runs a TLS 1.3
// connection over an in-memory pipe, sends frames and raw segments both ways (including a segment whose
// first bytes look like a TLS alert record, the case the buffer handling exists for) and verifies every
// byte. A program should call it once at start-up and set DisableRaw when it fails.
//
// client builds the client side of the test connection; nil means crypto/tls. Pass a constructor for
// another TLS stack (uTLS) to test that one against a crypto/tls server. For stacks that need a
// handshake of their own on both sides, see SelfTestPair.
func SelfTest(client func(conn net.Conn, cfg *tls.Config) net.Conn) error {
	if client == nil {
		client = func(conn net.Conn, cfg *tls.Config) net.Conn { return tls.Client(conn, cfg) }
	}
	return SelfTestPair(func(pipe func() (net.Conn, net.Conn)) (net.Conn, net.Conn, error) {
		cert, err := SelfSignedCert("miu.test")
		if err != nil {
			return nil, nil, err
		}
		a, b := pipe()
		cc := client(a, &tls.Config{ServerName: "miu.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		sc := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
		hs := make(chan error, 1)
		go func() { hs <- sc.Handshake() }()
		h, ok := cc.(interface{ Handshake() error })
		if !ok {
			return nil, nil, errors.New("the client connection has no Handshake method")
		}
		if err := h.Handshake(); err != nil {
			return nil, nil, err
		}
		return cc, sc, <-hs
	})
}

// SelfTestPair is SelfTest for any pair of outer connections. handshake creates the two ends of the
// outer layer — the client's connection and the server's, handshake completed — on top of in-memory
// pipes obtained from pipe (it may ask for more than one, for instance to stand in for a third party).
// The pipes are torn down when the test is over, or after five seconds.
func SelfTestPair(handshake func(pipe func() (net.Conn, net.Conn)) (client, server net.Conn, err error)) error {
	var mu sync.Mutex
	var pipes []*memPipe
	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, p := range pipes {
			p.Close()
		}
	}
	defer closeAll()
	watchdog := time.AfterFunc(5*time.Second, closeAll)
	defer watchdog.Stop()

	cc, sc, err := handshake(func() (net.Conn, net.Conn) {
		a, b := newMemPipe()
		mu.Lock()
		pipes = append(pipes, a, b)
		mu.Unlock()
		return a, b
	})
	if err != nil {
		return fmt.Errorf("miu: self-test: handshake: %w", err)
	}
	cl, sl := newLane(cc, false, true), newLane(sc, true, true)
	if !cl.canRaw || !sl.canRaw {
		return fmt.Errorf("miu: the read buffers of the TLS connection are not reachable (client %T: %v, server %T: %v)", cc, cl.canRaw, sc, sl.canRaw)
	}
	if err := selfTestDirection(sl, cl); err != nil {
		return fmt.Errorf("miu: raw segments, server to client: %w", err)
	}
	if err := selfTestDirection(cl, sl); err != nil {
		return fmt.Errorf("miu: raw segments, client to server: %w", err)
	}
	return nil
}

// selfTestDirection writes a mix of frames and raw segments on from, then reads it all back on to.
// Everything is written before anything is read, so that the reader's TLS connection finds raw bytes
// already sitting behind the RAW record — the situation that needs care.
func selfTestDirection(from, to *lane) error {
	// The first segment starts like a TLS alert record header.
	alert := append([]byte{0x15, 0x03, 0x03, 0x00, 0x02}, bytes.Repeat([]byte{0x15}, rawMin)...)
	big := make([]byte, 70000)
	_, _ = rand.Read(big)
	parts := []struct {
		raw  bool
		data []byte
	}{{false, []byte("head")}, {true, alert}, {true, big}, {false, []byte("middle")}, {true, alert}, {false, []byte("tail")}}

	var want []byte
	for _, p := range parts {
		var err error
		if p.raw {
			err = from.writeRaw(p.data)
		} else {
			err = from.writeFrame(frData, p.data)
		}
		if err != nil {
			return err
		}
		want = append(want, p.data...)
	}
	if err := from.writeFrame(frEnd, nil); err != nil {
		return err
	}

	var got []byte
	buf := make([]byte, 4096)
	for {
		for to.pending() {
			n, err := to.readPayload(buf)
			if err != nil {
				return err
			}
			got = append(got, buf[:n]...)
		}
		typ, _, err := to.next()
		if err != nil {
			return err
		}
		if typ == frEnd {
			break
		}
		if typ != frData && typ != frRaw {
			return fmt.Errorf("unexpected frame type %d", typ)
		}
	}
	if !bytes.Equal(got, want) {
		return errors.New("data mismatch")
	}
	return nil
}

// SelfSignedCert makes a throw-away certificate for name. It exists for self-tests and tests.
func SelfSignedCert(name string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// memPipe is one end of an in-memory, buffered, full-duplex connection. Unlike net.Pipe a write does not
// wait for the reader, and a read returns everything that has been written so far — like a socket.
type memPipe struct {
	rd, wr *memBuf
}

type memBuf struct {
	mu     sync.Mutex
	cond   *sync.Cond
	data   []byte
	closed bool
}

func newMemPipe() (*memPipe, *memPipe) {
	x, y := &memBuf{}, &memBuf{}
	x.cond, y.cond = sync.NewCond(&x.mu), sync.NewCond(&y.mu)
	return &memPipe{rd: x, wr: y}, &memPipe{rd: y, wr: x}
}

func (p *memPipe) Read(b []byte) (int, error) {
	m := p.rd
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(m.data) == 0 {
		if m.closed {
			return 0, io.EOF
		}
		m.cond.Wait()
	}
	n := copy(b, m.data)
	m.data = m.data[n:]
	return n, nil
}

func (p *memPipe) Write(b []byte) (int, error) {
	m := p.wr
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	m.data = append(m.data, b...)
	m.cond.Broadcast()
	return len(b), nil
}

// CloseWrite makes the peer's reads end once the buffered data has been read.
func (p *memPipe) CloseWrite() error {
	m := p.wr
	m.mu.Lock()
	m.closed = true
	m.cond.Broadcast()
	m.mu.Unlock()
	return nil
}

func (p *memPipe) Close() error {
	for _, m := range []*memBuf{p.rd, p.wr} {
		m.mu.Lock()
		m.closed = true
		m.cond.Broadcast()
		m.mu.Unlock()
	}
	return nil
}

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

func (p *memPipe) LocalAddr() net.Addr              { return memAddr{} }
func (p *memPipe) RemoteAddr() net.Addr             { return memAddr{} }
func (p *memPipe) SetDeadline(time.Time) error      { return nil }
func (p *memPipe) SetReadDeadline(time.Time) error  { return nil }
func (p *memPipe) SetWriteDeadline(time.Time) error { return nil }
