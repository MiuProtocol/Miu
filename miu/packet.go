package miu

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// packetConn carries UDP over one stream (UoT v2, not connected: every packet names its destination,
// and packets come back with their source). The stream is opened by the first WriteTo, whose
// destination goes into the request header, so that the first datagram leaves in the same packet as OPEN.
type packetConn struct {
	c *Client

	wmu sync.Mutex // serializes WriteTo
	rmu sync.Mutex // serializes ReadFrom
	acc []byte     // downlink bytes not yet parsed into packets
	tmp []byte

	mu     sync.Mutex
	s      *stream
	ready  chan struct{} // closed once s is set
	done   chan struct{} // closed by Close
	wake   chan struct{} // closed (and replaced) whenever the read deadline changes
	closed bool
	rd, wd time.Time
}

// ListenPacket returns a packet connection relayed by the server. WriteTo takes a *net.UDPAddr, or any
// net.Addr whose String is "host:port" (HostPort for a name the server should resolve). ReadFrom
// reports the source of each packet. Each connection occupies a lane of its own while it is open;
// closing it aborts the stream and returns the lane to the pool.
//
// No connection to the server is made until the first WriteTo.
func (c *Client) ListenPacket() (net.PacketConn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, ErrClientClosed
	}
	return &packetConn{
		c:     c,
		ready: make(chan struct{}),
		done:  make(chan struct{}),
		wake:  make(chan struct{}),
		tmp:   make([]byte, 16<<10),
	}, nil
}

// stream returns the UoT stream, opening it on first use. Caller holds wmu.
func (p *packetConn) stream(host string, port uint16) (*stream, error) {
	p.mu.Lock()
	s, closed := p.s, p.closed
	p.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if s != nil {
		return s, nil
	}
	open, err := socksAddr.append(nil, uotMagicDomain, 0)
	if err != nil {
		return nil, err
	}
	// The request: isConnect = 0, then the destination of the first packet.
	req, err := socksAddr.append([]byte{0}, host, port)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDialTimeout)
	defer cancel()
	s, err = p.c.open(ctx, appendFrame(appendFrame(nil, frOpen, open), frData, req), HostPort(joinHostPort(uotMagicDomain, 0)), true)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		s.Close()
		return nil, net.ErrClosed
	}
	_ = s.setDeadline(&p.rd, &p.wd)
	p.s = s
	close(p.ready)
	return s, nil
}

func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, port, err := splitHostPort(addr.String())
	if err != nil {
		return 0, err
	}
	pkt, err := appendUoTPacket(nil, host, port, b)
	if err != nil {
		return 0, err
	}
	p.wmu.Lock()
	defer p.wmu.Unlock()
	s, err := p.stream(host, port)
	if err != nil {
		return 0, err
	}
	if _, err := s.Write(pkt); err != nil {
		return 0, err
	}
	return len(b), nil
}

// waitStream blocks until the stream exists, the connection is closed or the read deadline passes.
func (p *packetConn) waitStream() (*stream, error) {
	for {
		p.mu.Lock()
		s, rd, wake := p.s, p.rd, p.wake
		p.mu.Unlock()
		if s != nil {
			return s, nil
		}
		var expire <-chan time.Time
		var timer *time.Timer
		if !rd.IsZero() {
			timer = time.NewTimer(time.Until(rd))
			expire = timer.C
		}
		var err error
		select {
		case <-p.ready:
		case <-wake:
		case <-p.done:
			err = net.ErrClosed
		case <-expire:
			err = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return nil, err
		}
	}
}

func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	s, err := p.waitStream()
	if err != nil {
		return 0, nil, err
	}
	for {
		host, port, payload, n, err := parseUoTPacket(p.acc, true)
		if err == nil {
			k := copy(b, payload)
			p.acc = p.acc[:copy(p.acc, p.acc[n:])]
			return k, packetAddr(host, port), nil
		}
		if err != errShort {
			return 0, nil, err
		}
		// A packet may span frames: gather more of the stream. What has been gathered survives a timeout.
		k, err := s.Read(p.tmp)
		p.acc = append(p.acc, p.tmp[:k]...)
		if err != nil {
			return 0, nil, err
		}
	}
}

func packetAddr(host string, port uint16) net.Addr {
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port))
	}
	return HostPort(joinHostPort(host, port))
}

// Close ends the session: the stream is aborted and its lane goes back to the pool.
func (p *packetConn) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.done)
	s := p.s
	p.mu.Unlock()
	if s != nil {
		return s.Close()
	}
	return nil
}

func (p *packetConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (p *packetConn) SetDeadline(t time.Time) error      { return p.setDeadline(&t, &t) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.setDeadline(&t, nil) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.setDeadline(nil, &t) }

func (p *packetConn) setDeadline(rd, wd *time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return net.ErrClosed
	}
	if rd != nil {
		p.rd = *rd
		close(p.wake)
		p.wake = make(chan struct{})
	}
	if wd != nil {
		p.wd = *wd
	}
	if p.s == nil {
		return nil
	}
	return p.s.setDeadline(rd, wd)
}

var _ interface {
	net.Conn
	CloseWrite() error
} = (*stream)(nil)
