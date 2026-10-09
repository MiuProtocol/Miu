package miu

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

// laneDataReader presents the payload of one direction of a lane as an io.Reader that reports io.EOF
// after END (or RESET). It is used for UDP streams, whose bytes are parsed rather than relayed.
type laneDataReader struct {
	l      *lane
	eof    bool
	update func()
	count  *trafficCounter // may be nil
}

func (r *laneDataReader) Read(p []byte) (int, error) {
	for !r.eof {
		if r.l.pending() {
			r.update()
			n, err := r.l.readPayload(p)
			if r.count != nil {
				r.count.addUp(n, false)
			}
			return n, err
		}
		typ, _, err := r.l.next()
		if err != nil {
			return 0, err
		}
		switch typ {
		case frData, frRaw:
		case frEnd, frReset:
			r.eof = true
		default:
			return 0, fmt.Errorf("miu: unexpected frame type %d in a UDP stream", typ)
		}
	}
	return 0, io.EOF
}

// serveUDP runs one UoT stream on the lane's read loop. The stream has a UDP socket of its own; whatever
// arrives on it, from any source, is sent back with its source address (full cone).
// An error means the lane cannot be used any more.
func (s *Server) serveUDP(ctx context.Context, l *lane, user string) error {
	timer := newActivityTimer(s.cfg.StreamTimeout, l.close)
	defer timer.stop()

	var traffic trafficCounter
	up := &laneDataReader{l: l, update: timer.update, count: &traffic}
	r := bufio.NewReader(up)
	// finish ends the stream here: END on the downlink, and the uplink dropped up to the client's END.
	finish := func() error {
		if err := l.writeFrame(frEnd, nil); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, r)
		return err
	}

	var isConnect [1]byte
	_, err := io.ReadFull(r, isConnect[:])
	var host string
	var port uint16
	if err == nil {
		host, port, err = socksAddr.read(r)
	}
	if err != nil {
		if up.eof {
			return finish()
		}
		return err
	}
	access := Access{User: user, Network: "udp", Target: joinHostPort(host, port), Remote: l.conn.RemoteAddr()}
	if s.cfg.OnAccess != nil {
		s.cfg.OnAccess(access)
	}
	if s.cfg.OnClose != nil {
		defer func() { s.cfg.OnClose(access, traffic.snapshot()) }()
	}
	pc, err := s.cfg.ListenPacket(ctx)
	if err != nil {
		s.logf("miu: UDP socket: %v", err)
		return finish()
	}
	defer pc.Close()

	// A connected stream talks to one peer only: its packets carry no address, and packets from anyone
	// else are dropped as a connected socket would.
	var peer *net.UDPAddr
	resolved := make(map[string]*net.UDPAddr)
	resolve := func(host string, port uint16) *net.UDPAddr {
		key := joinHostPort(host, port)
		if a, ok := resolved[key]; ok {
			return a
		}
		a, err := net.ResolveUDPAddr("udp", key)
		if err != nil {
			s.logf("miu: resolve %s: %v", key, err)
			a = nil
		}
		resolved[key] = a
		return a
	}
	if isConnect[0] != 0 {
		if peer = resolve(host, port); peer == nil {
			return finish()
		}
	}

	down := make(chan error, 1)
	go func() {
		err := udpDownlink(l, pc, peer, timer.update, &traffic)
		if err != nil {
			l.close()
		}
		down <- err
	}()

	var uerr error
	payload := make([]byte, 0xffff)
	for {
		to := peer
		if peer == nil {
			host, port, err := uotAddr.read(r)
			if err != nil {
				uerr = err
				break
			}
			to = resolve(host, port)
		}
		var size [2]byte
		if _, uerr = io.ReadFull(r, size[:]); uerr != nil {
			break
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if _, uerr = io.ReadFull(r, payload[:n]); uerr != nil {
			break
		}
		if to != nil {
			_, _ = pc.WriteTo(payload[:n], to)
		}
	}
	// The uplink ended (the client's END or RESET) or the lane broke: the session is over. Closing the
	// socket stops the downlink, which then sends END.
	pc.Close()
	if !up.eof {
		l.close()
		<-down
		return uerr
	}
	return <-down
}

// udpDownlink sends every packet that arrives on pc down the lane as UoT, and END when pc is closed.
func udpDownlink(l *lane, pc net.PacketConn, peer *net.UDPAddr, update func(), traffic *trafficCounter) error {
	buf := make([]byte, 0xffff)
	var pkt, frames []byte
	for failures := 0; ; {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			// A transient error (an ICMP error surfacing on the socket) is not the end of the session.
			if failures++; errors.Is(err, net.ErrClosed) || failures > 16 {
				return l.writeFrame(frEnd, nil)
			}
			continue
		}
		failures = 0
		src, ok := udpAddrPort(from)
		if !ok {
			continue
		}
		if peer != nil {
			if want, _ := udpAddrPort(peer); src != want {
				continue
			}
			pkt = append(binary.BigEndian.AppendUint16(pkt[:0], uint16(n)), buf[:n]...)
		} else if pkt, err = appendUoTPacket(pkt[:0], src.Addr().String(), src.Port(), buf[:n]); err != nil {
			continue
		}
		update()
		frames = appendData(frames[:0], pkt)
		if err := l.writeUnshaped(frames); err != nil {
			return err
		}
		traffic.addDown(len(pkt), false)
	}
}

// udpAddrPort normalizes a UDP address (IPv4-mapped addresses become IPv4).
func udpAddrPort(a net.Addr) (netip.AddrPort, bool) {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		ap, err := netip.ParseAddrPort(a.String())
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), err == nil
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port()), ap.IsValid()
}
