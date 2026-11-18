package miu

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	authHead = 32 + 2 // token · padlen

	defaultIdleTimeout      = 180 * time.Second
	defaultStreamTimeout    = 300 * time.Second
	defaultHandshakeTimeout = 4 * time.Second
	defaultDialTimeout      = 10 * time.Second

	// pskMinLen is the shortest PSK string accepted.
	pskMinLen = 16
	// upQueue is how many uplink chunks may wait for the target (it is also where uplink data sits while
	// the target is still being dialed).
	upQueue = 16
	// rawReadSize is the read size of the raw phase when the bytes have to pass through user space.
	rawReadSize = 128 << 10
)

var rawPool = sync.Pool{New: func() any { b := make([]byte, rawReadSize); return &b }}

// peekPool holds the buffers the segmented downlink looks at the target's receive buffer with, to find
// the inner record boundaries in it. A buffer is only held for the length of one look.
var peekPool = sync.Pool{New: func() any { b := make([]byte, maxSeg); return &b }}

// ErrAuth is returned by Server.Serve when a connection presents an unknown token.
var ErrAuth = errors.New("miu: auth failed: unknown token")

// User is one account of a server.
type User struct {
	Name string
	PSK  string
}

// Access describes one stream a server is about to open.
type Access struct {
	User    string   // name of the authenticated user
	Network string   // "tcp" or "udp"
	Target  string   // host:port; for UDP the destination named in the request
	Remote  net.Addr // the client's address
}

// Traffic is what a stream has carried by the time it ends: payload bytes in each direction, and how
// many of them travelled as raw segments (outside the outer TLS). Raw bytes in a direction mean that
// the sender of that direction found inner TLS 1.3 traffic and that the receiver can take raw segments.
type Traffic struct {
	Up, Down       int64 // client to target, target to client
	RawUp, RawDown int64 // the part of Up and Down sent as raw segments
}

type trafficCounter struct {
	up, down, rawUp, rawDown atomic.Int64
}

func (t *trafficCounter) addUp(n int, raw bool) {
	t.up.Add(int64(n))
	if raw {
		t.rawUp.Add(int64(n))
	}
}

func (t *trafficCounter) addDown(n int, raw bool) {
	t.down.Add(int64(n))
	if raw {
		t.rawDown.Add(int64(n))
	}
}

func (t *trafficCounter) snapshot() Traffic {
	return Traffic{Up: t.up.Load(), Down: t.down.Load(), RawUp: t.rawUp.Load(), RawDown: t.rawDown.Load()}
}

// ServerConfig configures a Server. Only Users is required.
type ServerConfig struct {
	Users []User
	// PaddingScheme overrides the built-in scheme; clients with a different one are sent this one.
	PaddingScheme string
	// IdleTimeout is how long a lane without a stream is kept (default 180s). Clients are told.
	IdleTimeout time.Duration
	// StreamTimeout closes a lane whose stream has been silent in both directions for this long (default 300s).
	StreamTimeout time.Duration
	// HandshakeTimeout bounds the wait for the authentication header (default 4s).
	HandshakeTimeout time.Duration
	// DisableRaw turns raw segments off: the server declares raw=0 and never sends any.
	DisableRaw bool
	// Dial connects to a TCP target. The default is a net.Dialer with a 10s timeout.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// ListenPacket opens the UDP socket of one UoT stream. The default listens on an ephemeral port.
	ListenPacket func(ctx context.Context) (net.PacketConn, error)
	// OnAccess, when set, is called for every stream before its target is contacted.
	OnAccess func(Access)
	// OnClose, when set, is called when a stream has ended, with what it carried.
	OnClose func(Access, Traffic)
	// Logf, when set, receives diagnostics (failed dials and the like).
	Logf func(format string, args ...any)
}

// Server serves lanes: connections on which the outer TLS handshake has already been done.
type Server struct {
	cfg    ServerConfig
	users  map[[32]byte]string
	scheme *paddingScheme
}

// pskToken is the authentication token of a PSK: the SHA-256 of the string with surrounding whitespace
// removed. The string is not base64-decoded.
func pskToken(psk string) ([32]byte, error) {
	psk = strings.TrimSpace(psk)
	if len(psk) < pskMinLen {
		return [32]byte{}, fmt.Errorf("miu: psk too short (need at least %d characters)", pskMinLen)
	}
	return sha256.Sum256([]byte(psk)), nil
}

func NewServer(cfg ServerConfig) (*Server, error) {
	s := &Server{cfg: cfg, users: make(map[[32]byte]string), scheme: defaultScheme}
	if len(cfg.Users) == 0 {
		return nil, errors.New("miu: no users")
	}
	for _, u := range cfg.Users {
		token, err := pskToken(u.PSK)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		if other, dup := s.users[token]; dup {
			return nil, fmt.Errorf("miu: users %q and %q share a psk", other, u.Name)
		}
		s.users[token] = u.Name
	}
	if cfg.PaddingScheme != "" {
		if s.scheme = parsePaddingScheme(cfg.PaddingScheme); s.scheme == nil {
			return nil, errors.New("miu: bad padding scheme")
		}
	}
	if s.cfg.IdleTimeout <= 0 {
		s.cfg.IdleTimeout = defaultIdleTimeout
	}
	if s.cfg.StreamTimeout <= 0 {
		s.cfg.StreamTimeout = defaultStreamTimeout
	}
	if s.cfg.HandshakeTimeout <= 0 {
		s.cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if s.cfg.Dial == nil {
		d := &net.Dialer{Timeout: defaultDialTimeout}
		s.cfg.Dial = d.DialContext
	}
	if s.cfg.ListenPacket == nil {
		s.cfg.ListenPacket = func(ctx context.Context) (net.PacketConn, error) {
			return (&net.ListenConfig{}).ListenPacket(ctx, "udp", "")
		}
	}
	return s, nil
}

func (s *Server) schemeForToken(token [32]byte) (*paddingScheme, error) {
	if s.cfg.PaddingScheme != "" {
		return s.scheme, nil
	}
	return derivePaddingScheme(token)
}

func (s *Server) logf(format string, args ...any) {
	if s.cfg.Logf != nil {
		s.cfg.Logf(format, args...)
	}
}

// Serve serves one lane until the client closes it, it has been idle for too long, or ctx is done.
// conn is the connection after the outer TLS handshake; raw segments are available when it is a
// *crypto/tls.Conn sitting directly on the TCP connection. Serve closes conn before returning.
//
// A nil error means the lane ended normally. ErrAuth and protocol violations are reported as errors.
func (s *Server) Serve(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))

	// The authentication header: token(32) · padlen(u16) · padding. Read piece by piece and never ahead.
	var h [authHead]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return fmt.Errorf("miu: auth failed: %w", err)
	}
	user, ok := s.users[[32]byte(h[:32])]
	if !ok {
		return ErrAuth
	}
	if padlen := int64(binary.BigEndian.Uint16(h[32:])); padlen > 0 {
		if _, err := io.CopyN(io.Discard, conn, padlen); err != nil {
			return fmt.Errorf("miu: auth failed: %w", err)
		}
	}

	l := newLane(conn, true, !s.cfg.DisableRaw)
	token := [32]byte(h[:32])
	base, err := s.schemeForToken(token)
	if err != nil {
		return err
	}
	l.base = base
	if s.cfg.PaddingScheme == "" {
		l.scheme.Store(newLaneScheme(token, base)) // this lane's own draw, for the downlink
	} else {
		l.scheme.Store(base)
	}
	// Close the lane when ctx is done.
	go func() {
		select {
		case <-ctx.Done():
			l.close()
		case <-l.done:
		}
	}()

	// There is a single frame reading loop. The uplink of a TCP stream (DATA / RAW / END) is handled
	// right here while its downlink runs in another goroutine, so the loop keeps reading after the
	// uplink's END — which is how a RESET sent after a half-close still gets through.
	var cur *tcpStream // the TCP stream on the lane; nil when there is none
	defer func() {
		l.close()
		if cur != nil {
			cur.abort()
			cur.endUplink()
			<-cur.down
			cur.release()
		}
	}()
	// settle waits for the downlink of cur to wrap up and lets go of it: the next stream is about to
	// start (the client sends the next OPEN only after it has seen the downlink's END).
	settle := func() error {
		if cur == nil {
			return nil
		}
		st := cur
		cur = nil
		if !st.upEnded() {
			st.abort()
			st.endUplink()
			<-st.down
			st.release()
			return errors.New("miu: OPEN before the previous stream ended")
		}
		err := <-st.down
		st.release()
		return err
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
	for {
		typ, payload, err := l.next()
		if err != nil {
			return nil // the client left, the lane idled out, or a failed downlink write closed it
		}
		switch typ {
		case frData, frRaw:
			if cur == nil || cur.upEnded() {
				return errors.New("miu: data outside of a stream")
			}
			for l.pending() {
				b := getBuf()
				n, err := l.readPayload(*b)
				if err != nil {
					putBuf(b)
					return nil
				}
				cur.traffic.addUp(n, typ == frRaw)
				if !cur.push(chunk{b, n}) {
					return nil
				}
			}
		case frEnd, frReset:
			if len(payload) != 0 {
				return errors.New("miu: bad END / RESET frame")
			}
			if cur == nil {
				continue // a RESET that arrives after its stream has ended: nothing left to abort
			}
			if typ == frReset {
				// Abort: stop the stream (the target connection goes away); the downlink finishes its
				// current segment and ends with END. The lane lives on.
				cur.abort()
			}
			cur.endUplink()
		case frSettings:
			if err := s.handleSettings(l, string(payload)); err != nil {
				return nil
			}
		case frOpen:
			if err := settle(); err != nil {
				return err
			}
			_ = conn.SetReadDeadline(time.Time{})
			host, port, n, err := socksAddr.parse(payload)
			if err != nil || n != len(payload) {
				return errors.New("miu: bad destination in OPEN")
			}
			if strings.HasSuffix(host, uotMagicSuffix) {
				if err := s.serveUDP(ctx, l, user); err != nil {
					return err
				}
				_ = conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
				continue
			}
			dest := joinHostPort(host, port)
			access := Access{User: user, Network: "tcp", Target: dest, Remote: conn.RemoteAddr()}
			if s.cfg.OnAccess != nil {
				s.cfg.OnAccess(access)
			}
			cur = s.openTCP(ctx, l, access)
		default:
			return fmt.Errorf("miu: unexpected frame type %d", typ)
		}
	}
}

// settingsWait is how long ServerSettings waits for the lane's next write to go out with. The client
// needs it only once its stream is past the inner handshake, which starts with the server's first
// downlink write; until then it would be a short record of its own.
const settingsWait = time.Second

// handleSettings notes whether the client can receive raw segments and answers with ServerSettings,
// followed by the server's padding scheme when the client's md5 differs. The answer goes out at the start
// of the next write on the lane, or alone after settingsWait.
func (s *Server) handleSettings(l *lane, text string) error {
	kv := parseKV(text)
	l.peerRaw.Store(kv["raw"] == "1")
	reply := appendFrame(nil, frServerSettings, l.settingsText(fmt.Sprintf("\nidle=%d", int(s.cfg.IdleTimeout/time.Second))))
	// The client is told the scheme its lanes should come from when its md5 is not that of the lane's
	// base (the PSK-derived scheme, or the configured one).
	base := l.base
	if base == nil {
		base = l.scheme.Load()
	}
	if md5 := strings.ToLower(strings.TrimSpace(kv["padding-md5"])); md5 != "" && md5 != base.md5 {
		reply = appendFrame(reply, frUpdatePadding, base.raw)
	}
	l.deferPrefix(reply, settingsWait)
	return nil
}

// activityTimer calls f once nothing has called update for d.
type activityTimer struct {
	d       time.Duration
	f       func()
	last    atomic.Int64
	stopped atomic.Bool
	t       *time.Timer
}

func newActivityTimer(d time.Duration, f func()) *activityTimer {
	a := &activityTimer{d: d, f: f}
	a.update()
	a.t = time.AfterFunc(d, a.check)
	return a
}

func (a *activityTimer) update() { a.last.Store(time.Now().UnixNano()) }

func (a *activityTimer) check() {
	if a.stopped.Load() {
		return
	}
	if idle := time.Duration(time.Now().UnixNano() - a.last.Load()); idle < a.d {
		a.t.Reset(a.d - idle)
		return
	}
	a.f()
}

func (a *activityTimer) stop() {
	a.stopped.Store(true)
	a.t.Stop()
}

// chunk is a piece of uplink payload in a pooled buffer.
type chunk struct {
	buf *[]byte
	n   int
}

// tcpStream is the TCP stream running on a lane (server side). The lane's read loop feeds the uplink
// into a queue that one goroutine writes to the target; the downlink has a goroutine of its own.
type tcpStream struct {
	s       *Server
	l       *lane
	ctx     context.Context
	cancel  context.CancelFunc
	timer   *activityTimer // closes the lane when both directions have been silent for too long
	up      chan chunk     // closed at the uplink's END
	down    chan error     // result of the downlink goroutine
	state   streamState
	access  Access
	traffic trafficCounter

	mu       sync.Mutex
	target   net.Conn
	upDone   bool
	downDone bool
	released bool
	// Abort: once stopping is set no new segment starts. busy means a segment is being moved straight
	// from the target to the client — the target must not be closed now (the declared bytes could no
	// longer be delivered), so the close waits in onIdle until the segment is through.
	stopping bool
	busy     bool
	onIdle   func()
}

// openTCP starts a TCP stream: the target is dialed in the background, so the read loop stays free to
// take the uplink (and a RESET) in the meantime.
func (s *Server) openTCP(ctx context.Context, l *lane, access Access) *tcpStream {
	dest := access.Target
	st := &tcpStream{s: s, l: l, access: access, up: make(chan chunk, upQueue), down: make(chan error, 1)}
	st.ctx, st.cancel = context.WithCancel(ctx)
	st.timer = newActivityTimer(s.cfg.StreamTimeout, l.close)
	go st.run(dest)
	return st
}

func (st *tcpStream) run(dest string) {
	target, err := st.s.cfg.Dial(st.ctx, "tcp", dest)
	if err == nil {
		st.mu.Lock()
		if st.stopping {
			target.Close()
			err = context.Canceled
		} else {
			st.target = target
		}
		st.mu.Unlock()
	} else {
		st.s.logf("miu: dial %s: %v", dest, err)
	}
	if err != nil {
		// No target: the downlink ends at once; the uplink is dropped up to the client's END.
		werr := st.l.writeFrame(frEnd, nil)
		if werr != nil {
			st.l.close()
		}
		st.mark(false, true)
		st.down <- werr
		for c := range st.up {
			putBuf(c.buf)
		}
		return
	}
	upDone := make(chan struct{})
	go st.pumpUp(target, upDone)
	err = st.pumpDown(target)
	if err != nil {
		st.l.close() // the lane cannot be written to any more; the read loop ends with it
	}
	// Record the end of the downlink (which arms the lane's idle deadline) before handing over the
	// result: the read loop may open the next stream and clear that deadline as soon as it has the
	// result, and a deadline set afterwards would land on the next stream.
	st.mark(false, true)
	st.down <- err
	<-upDone
	target.Close()
}

// pumpUp writes the queued uplink to the target. When the target stops taking data the rest is dropped:
// the lane's uplink still has to be read up to its END for the lane to stay usable.
func (st *tcpStream) pumpUp(target net.Conn, done chan struct{}) {
	defer close(done)
	dead := false
	for c := range st.up {
		if !dead {
			_, err := target.Write((*c.buf)[:c.n])
			dead = err != nil
		}
		putBuf(c.buf)
	}
	if cw, ok := target.(interface{ CloseWrite() error }); ok && !dead {
		_ = cw.CloseWrite() // pass the half-close on
	}
}

// push hands a chunk of uplink payload to the target writer. It reports false when the lane has closed.
func (st *tcpStream) push(c chunk) bool {
	st.timer.update()
	select {
	case st.up <- c:
		return true
	case <-st.l.done:
		putBuf(c.buf)
		return false
	}
}

func (st *tcpStream) upEnded() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.upDone
}

func (st *tcpStream) endUplink() {
	st.mu.Lock()
	ended := st.upDone
	st.mu.Unlock()
	if ended {
		return // a RESET after the END
	}
	close(st.up)
	st.mark(true, false)
}

// abort stops the stream: the target connection is closed, the downlink goroutine notices and sends END.
// If a segment is being moved right now the close happens once that segment is through.
func (st *tcpStream) abort() {
	st.mu.Lock()
	st.stopping = true
	if st.busy {
		st.onIdle = st.halt
		st.mu.Unlock()
		return
	}
	st.mu.Unlock()
	st.halt()
}

func (st *tcpStream) halt() {
	st.cancel()
	st.mu.Lock()
	target := st.target
	st.mu.Unlock()
	if target != nil {
		target.Close()
	}
}

func (st *tcpStream) beginSegment() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.stopping {
		return false
	}
	st.busy = true
	return true
}

func (st *tcpStream) endSegment() {
	st.mu.Lock()
	st.busy = false
	f := st.onIdle
	st.onIdle = nil
	st.mu.Unlock()
	if f != nil {
		f()
	}
}

// mark records the end of a direction. Once both have ended the stream is released and the lane starts
// counting idle time.
func (st *tcpStream) mark(up, down bool) {
	st.mu.Lock()
	st.upDone = st.upDone || up
	st.downDone = st.downDone || down
	done := st.upDone && st.downDone
	st.mu.Unlock()
	if done {
		st.release()
		_ = st.l.conn.SetReadDeadline(time.Now().Add(st.s.cfg.IdleTimeout))
	}
}

func (st *tcpStream) release() {
	st.mu.Lock()
	released := st.released
	st.released = true
	st.mu.Unlock()
	if !released {
		st.cancel()
		st.timer.stop()
		if st.s.cfg.OnClose != nil {
			st.s.cfg.OnClose(st.access, st.traffic.snapshot())
		}
	}
}

// pumpDown moves the target's data to the lane and ends the direction with END. It starts with DATA
// frames, following the inner TLS records on the way; once the inner TLS 1.3 handshake is past, it
// switches to raw segments. Packets are numbered from 1 for the shaping.
//
// However the target ends, the direction is closed in the regular way: the lane stays usable, and a
// truncated transfer is for the inner protocol to notice. An error means the lane is broken.
func (st *tcpStream) pumpDown(target net.Conn) error {
	l := st.l
	scan := recScan{st: &st.state, dead: !l.canRaw, follow: true}
	buf, fb := getBuf(), getBuf()
	defer putBuf(buf)
	defer putBuf(fb)
	for {
		n, err := target.Read((*buf)[:maxBatch])
		if n > 0 {
			st.timer.update()
			sw := scan.feed((*buf)[:n])
			if werr := l.writeLanePacket(appendData((*fb)[:0], (*buf)[:n])); werr != nil {
				return werr
			}
			st.traffic.addDown(n, false)
			if sw && l.peerRaw.Load() && err == nil {
				return st.pumpRaw(target, &scan, fb)
			}
		}
		if err != nil {
			break
		}
	}
	// END is not shaped: it has to be the last byte of the direction. A PAD after it would reach the
	// client once the lane is back in its pool, where data on an idle lane means "the server is closing".
	return l.writeFrame(frEnd, nil)
}

// pumpRaw is the raw phase of the downlink. Raw segments carry whole inner records only (see recScan):
// the start of a record whose rest has not been read yet waits at the front of the buffer for up to
// holdWait, then goes out as DATA, and so does the rest of that record. A record begun in DATA (the one
// the switch to the raw phase happened in) also ends in DATA.
func (st *tcpStream) pumpRaw(target net.Conn, scan *recScan, fb *[]byte) error {
	l := st.l
	src, ok := target.(*net.TCPConn)
	if _, tcp := l.sock.(*net.TCPConn); segmentedCopy && ok && tcp {
		return st.pumpSegments(src, scan, fb)
	}
	bp := rawPool.Get().(*[]byte)
	defer rawPool.Put(bp)
	big := *bp
	held := 0 // bytes at the front of big: the start of an inner record
	// heldSince is when the record at the front started to be held. The read deadline is set once and
	// moved on only when it passes: setting it on every read wakes the network poller every time.
	var heldSince time.Time
	armed := false
	sendData := func(p []byte) error {
		if len(p) == 0 {
			return nil
		}
		st.traffic.addDown(len(p), false)
		return l.writeUnshaped(appendData((*fb)[:0], p))
	}
	for {
		n, err := target.Read(big[held:])
		if n > 0 {
			st.timer.update()
			cont := held == 0 && !scan.atBoundary()
			fresh := held == 0
			first, last := scan.walk(big[held : held+n])
			fresh = fresh || first >= 0
			p := big[:held+n]
			held = 0
			var werr error
			switch {
			case scan.lost:
				werr = sendData(p)
			case cont && first < 0:
				werr = sendData(p)
			default:
				start, cut := 0, -1
				if cont {
					start, cut = first, last
					werr = sendData(p[:first])
				} else if last >= 0 {
					cut = len(p) - n + last
				}
				if werr == nil && cut > start {
					if whole := p[start:cut]; len(whole) >= rawMin {
						werr = l.writeRawRecords(whole, nil)
						st.traffic.addDown(len(whole), true)
					} else {
						werr = sendData(whole)
					}
				}
				if cut < start {
					cut = start
				}
				held = copy(big, p[cut:])
			}
			if werr != nil {
				return werr
			}
			if held > 0 && fresh {
				heldSince = time.Now()
			}
		}
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded):
			// Only the hold sets a deadline. Clear it: an expired one fails every read that follows.
			_ = target.SetReadDeadline(time.Time{})
			armed = false
			if held > 0 && time.Since(heldSince) >= holdWait {
				// The rest of the record is late: what has arrived of it goes as DATA, and the rest
				// will follow as DATA.
				l.event("holdflush")
				if werr := sendData(big[:held]); werr != nil {
					return werr
				}
				held = 0
			}
		default:
			if werr := sendData(big[:held]); werr != nil {
				return werr
			}
			return l.writeFrame(frEnd, nil)
		}
		switch {
		case held > 0 && !armed:
			_ = target.SetReadDeadline(heldSince.Add(holdWait))
			armed = true
		case held == 0 && armed:
			_ = target.SetReadDeadline(time.Time{})
			armed = false
		}
	}
}

// pumpSegments is the raw phase between two TCP connections: it looks at what is waiting in the
// target's receive buffer without taking it, declares the whole inner records among it in a RAW frame
// and moves exactly those. They are already in the kernel, so a declared segment can always be
// completed. On Linux the move is a splice: the bytes do not pass through user space on the way out.
//
// An inner record that is not complete yet stays in the kernel until it is, for up to holdWait; then
// what has arrived of it goes as DATA, and so does its rest.
func (st *tcpStream) pumpSegments(src *net.TCPConn, scan *recScan, fb *[]byte) error {
	l := st.l
	bp := rawPool.Get().(*[]byte)
	defer rawPool.Put(bp)
	data := *bp
	// readData moves up to n bytes into user space and sends them as DATA.
	readData := func(n int) error {
		k, err := src.Read(data[:minInt(n, len(data))])
		if k > 0 {
			scan.walk(data[:k])
			st.traffic.addDown(k, false)
			if werr := l.writeUnshaped(appendData((*fb)[:0], data[:k])); werr != nil {
				return werr
			}
		}
		return err
	}
	// look peeks at up to n waiting bytes and returns how many there are, the end of the last whole
	// record among them (-1 if none) and how many more bytes complete the first record that is not whole.
	look := func(n int) (m, last, more int, lost bool, err error) {
		pp := peekPool.Get().(*[]byte)
		defer peekPool.Put(pp)
		peek := *pp
		if m, err = peekAt(src, peek[:minInt(n, len(peek))]); err != nil {
			return
		}
		probe := scan.clone()
		_, last = probe.walk(peek[:m])
		return m, last, probe.remaining(), probe.lost, nil
	}
loop:
	for {
		if scan.lost {
			if err := readData(len(data)); err != nil {
				break
			}
			continue
		}
		n, err := readable(src, 1, time.Time{})
		if err != nil {
			break // end of stream, a reset, or the abort closed the target
		}
		st.timer.update()
		if !scan.atBoundary() {
			// Finish a record begun in DATA, as DATA.
			if err := readData(minInt(n, scan.remaining())); err != nil {
				break
			}
			continue
		}
		m, last, more, lost, err := look(n)
		if err != nil {
			break
		}
		switch {
		case lost:
			scan.lost = true
			continue
		case last <= 0:
			// Not one whole record yet: wait for the rest of it.
			need := m + more
			if _, err := readable(src, need, time.Now().Add(holdWait)); err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					break loop
				}
				l.event("holdflush")
				if err := readData(m); err != nil {
					break loop
				}
			}
			continue
		case last < rawMin:
			if err := readData(last); err != nil {
				break loop
			}
			continue
		}
		if !st.beginSegment() {
			break
		}
		err = l.spliceRaw(src, last)
		st.endSegment()
		if err != nil {
			return err // a segment was cut short: the byte count on the lane is off
		}
		// Whole records went out, so the scan is still on a boundary: nothing to walk.
		st.traffic.addDown(last, true)
	}
	return l.writeFrame(frEnd, nil)
}
