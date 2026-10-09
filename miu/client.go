package miu

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	// How long an idle lane stays in the pool. The warmLanes most recently returned ones are kept for
	// warmLaneIdle (two clicks are often more than half a minute apart, and an empty pool means another
	// handshake; idle lanes send no heartbeats, so keeping a few costs next to nothing), the others are
	// closed after defaultLaneIdle. Neither exceeds what the server announced minus 5s.
	defaultLaneIdle = 30 * time.Second
	warmLaneIdle    = 120 * time.Second
	warmLanes       = 4
	// abortDrain is how long an aborted stream waits for the server's END before giving the lane up.
	abortDrain = 3 * time.Second
	// Only when two streams are opened within laneBurstWindow is the pool topped up to minIdle lanes in
	// the background: an occasional background connection is not worth extra handshakes.
	laneBurstWindow = 10 * time.Second
	defaultMinIdle  = 2
	maxIdleLanes    = 32
	// firstPayloadWait is how long a new stream waits for the application's first bytes, so that they
	// leave in the same packet as OPEN.
	firstPayloadWait = 10 * time.Millisecond
	// replayLimit: a stream that hit a dead pooled lane is replayed on a fresh one only while it has
	// sent no more than this much and has not received anything.
	replayLimit = 64 << 10
)

// ErrClientClosed is returned by a Client that has been closed.
var ErrClientClosed = errors.New("miu: client closed")

// ClientConfig configures a Client. PSK and Dial are required.
type ClientConfig struct {
	// PSK is the pre-shared key, used as a string exactly as the server has it.
	PSK string
	// Dial opens a connection to the server and completes the outer TLS handshake on it. Raw segments
	// are available when the result is a *crypto/tls.Conn (or a uTLS connection) sitting directly on
	// the TCP connection. See TLSDialer.
	Dial func(ctx context.Context) (net.Conn, error)
	// LaneIdle is how long an idle lane beyond the newest four is kept (default 30s).
	LaneIdle time.Duration
	// MinIdle is how many idle lanes are kept warm while streams are being opened in a row (default 2).
	MinIdle int
	// DisableRaw turns raw segments off: the client declares raw=0 and never sends any.
	DisableRaw bool
}

// Client opens streams to one server over a pool of lanes.
type Client struct {
	cfg   ClientConfig
	token [32]byte

	mu       sync.Mutex
	idle     []idleLane
	pending  int
	lastOpen time.Time
	closed   bool
}

type idleLane struct {
	l     *lane
	since time.Time
	// used: the lane has carried a stream, so ServerSettings has been consumed and nothing should
	// arrive on it while it is idle.
	used bool
}

func NewClient(cfg ClientConfig) (*Client, error) {
	token, err := pskToken(cfg.PSK)
	if err != nil {
		return nil, err
	}
	if cfg.Dial == nil {
		return nil, errors.New("miu: no dialer")
	}
	if cfg.LaneIdle <= 0 {
		cfg.LaneIdle = defaultLaneIdle
	}
	if cfg.MinIdle <= 0 {
		cfg.MinIdle = defaultMinIdle
	}
	return &Client{cfg: cfg, token: token}, nil
}

// TLSDialer returns a ClientConfig.Dial that connects to address over TCP and performs a TLS handshake
// with cfg. A config without ServerName gets the host of address.
//
// The handshake is restricted to TLS 1.3, and Go's dynamic record sizing is switched off so that records
// leave with the lengths the padding scheme asks for.
func TLSDialer(address string, cfg *tls.Config) func(ctx context.Context) (net.Conn, error) {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg = cfg.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.DynamicRecordSizingDisabled = true
	// No TCP keep-alive probes: an idle lane is meant to be silent.
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: defaultDialTimeout, KeepAlive: -1}, Config: cfg}
	return func(ctx context.Context) (net.Conn, error) {
		return d.DialContext(ctx, "tcp", address)
	}
}

// ---- the lane pool ----

// dial opens a new lane: the outer handshake, then the authentication header, its padding and Settings
// in a single write. Nothing is waited for.
func (c *Client) dial(ctx context.Context) (*lane, error) {
	conn, err := c.cfg.Dial(ctx)
	if err != nil {
		return nil, err
	}
	l := newLane(conn, false, !c.cfg.DisableRaw)
	scheme := l.scheme.Load()
	padlen := scheme.padding0()
	hello := append(make([]byte, 0, authHead+int(padlen)+64), c.token[:]...)
	hello = append(hello, byte(padlen>>8), byte(padlen))
	hello = append(hello, make([]byte, padlen)...)
	hello = appendFrame(hello, frSettings, l.settingsText("\npadding-md5="+scheme.md5))
	if err := l.write(hello); err != nil {
		l.close()
		return nil, err
	}
	l.event("dial")
	return l, nil
}

// ttl is how long the lane ranked rank from the newest (0 = newest) may stay in the pool.
func (c *Client) ttl(l *lane, rank int) time.Duration {
	d := c.cfg.LaneIdle
	if rank < warmLanes && d < warmLaneIdle {
		d = warmLaneIdle
	}
	if peer := time.Duration(l.peerIdle.Load()) * time.Second; peer > 10*time.Second && peer-5*time.Second < d {
		d = peer - 5*time.Second
	}
	return d
}

// takeIdle returns the most recently returned idle lane that is still alive.
func (c *Client) takeIdle(now time.Time) (*lane, bool) {
	for {
		c.mu.Lock()
		n := len(c.idle)
		if n == 0 {
			c.mu.Unlock()
			return nil, false
		}
		it := c.idle[n-1]
		c.idle = c.idle[:n-1]
		c.mu.Unlock()

		alive, pending := connAlive(it.l.sock)
		// Nothing should arrive on an idle lane that has carried a stream: if something has, the server
		// is closing it (close_notify).
		if now.Sub(it.since) < c.ttl(it.l, 0) && alive && !(pending && it.used) {
			return it.l, it.used
		}
		it.l.close()
	}
}

// get returns a lane: one from the pool if there is any, a freshly dialed one otherwise. When streams
// are being opened in a row it also warms the pool up in the background.
func (c *Client) get(ctx context.Context) (l *lane, pooled, used bool, err error) {
	now := time.Now()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, false, ErrClientClosed
	}
	c.mu.Unlock()
	l, used = c.takeIdle(now)

	c.mu.Lock()
	burst := !c.lastOpen.IsZero() && now.Sub(c.lastOpen) <= laneBurstWindow
	c.lastOpen = now
	warm := 0
	if burst {
		if warm = c.cfg.MinIdle - len(c.idle) - c.pending; warm < 0 {
			warm = 0
		}
		c.pending += warm
	}
	c.mu.Unlock()
	for i := 0; i < warm; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
			nl, err := c.dial(ctx)
			cancel()
			c.mu.Lock()
			c.pending--
			c.mu.Unlock()
			if err == nil {
				c.put(nl, false)
			}
		}()
	}

	if l != nil {
		l.event("reuse")
		return l, true, used, nil
	}
	l, err = c.dial(ctx)
	return l, false, false, err
}

// put returns a lane to the pool.
func (c *Client) put(l *lane, used bool) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		l.close()
		return
	}
	if len(c.idle) >= maxIdleLanes {
		c.idle[0].l.close()
		c.idle = c.idle[1:]
	}
	c.idle = append(c.idle, idleLane{l: l, since: time.Now(), used: used})
	c.mu.Unlock()
	time.AfterFunc(c.cfg.LaneIdle+time.Second, c.sweep)
	time.AfterFunc(warmLaneIdle+time.Second, c.sweep)
}

// sweep closes the idle lanes that have been in the pool for too long.
func (c *Client) sweep() {
	now := time.Now()
	c.mu.Lock()
	keep := c.idle[:0]
	var stale []*lane
	for i, it := range c.idle {
		if now.Sub(it.since) < c.ttl(it.l, len(c.idle)-1-i) {
			keep = append(keep, it)
		} else {
			stale = append(stale, it.l)
		}
	}
	c.idle = keep
	c.mu.Unlock()
	for _, l := range stale {
		l.close()
	}
}

// CloseIdle closes every idle lane. Call it after the network has changed (Wi-Fi to cellular and the
// like): the pooled connections are dead by then. Streams in progress are not touched.
func (c *Client) CloseIdle() {
	c.mu.Lock()
	idle := c.idle
	c.idle = nil
	c.mu.Unlock()
	for _, it := range idle {
		it.l.close()
	}
}

// Close closes the idle lanes and makes the client refuse new streams. A stream in progress keeps
// working; its lane is closed when the stream ends.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.CloseIdle()
	return nil
}

// DialContext opens a stream to address ("host:port"; a domain name is resolved by the server).
// network must be "tcp", "tcp4" or "tcp6".
//
// The call returns as soon as a lane is at hand: the server does not acknowledge the destination, so a
// target that cannot be reached shows up as an immediate end of stream on the first Read. The returned
// connection also has a CloseWrite method. Closing it before both directions have ended aborts the
// stream (the lane still goes back to the pool).
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, net.UnknownNetworkError(network)
	}
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	open, err := socksAddr.append(nil, host, port)
	if err != nil {
		return nil, err
	}
	return c.open(ctx, appendFrame(nil, frOpen, open), HostPort(address), false)
}
