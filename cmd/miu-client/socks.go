package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MiuProtocol/Miu/miu"
)

// A minimal SOCKS5 server (RFC 1928): no authentication, CONNECT and UDP ASSOCIATE.

const (
	socksConnect      = 1
	socksUDPAssociate = 3

	socksOK              = 0
	socksFailure         = 1
	socksCmdUnsupported  = 7
	socksAddrUnsupported = 8

	// relayBuffer is the copy buffer of a CONNECT relay. A large one lets the uplink leave in large raw
	// segments once the inner TLS handshake is over.
	relayBuffer = 128 << 10
)

type socksServer struct {
	client  *miu.Client
	verbose bool
}

func (s *socksServer) serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *socksServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	cmd, target, err := socksHandshake(conn)
	if err != nil {
		if s.verbose {
			log.Printf("socks: %v: %v", conn.RemoteAddr(), err)
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})
	switch cmd {
	case socksConnect:
		s.connect(conn, target)
	case socksUDPAssociate:
		s.associate(conn)
	}
}

// socksHandshake reads the greeting and the request. It has replied already when it returns an error.
func socksHandshake(conn net.Conn) (cmd byte, target string, err error) {
	var b [2 + 255]byte
	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		return
	}
	if b[0] != 5 {
		return 0, "", fmt.Errorf("not SOCKS5 (version %d)", b[0])
	}
	methods := b[2 : 2+int(b[1])]
	if _, err = io.ReadFull(conn, methods); err != nil {
		return
	}
	noAuth := false
	for _, m := range methods {
		noAuth = noAuth || m == 0
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 0xff})
		return 0, "", errors.New("client offers no acceptable authentication method")
	}
	if _, err = conn.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err = io.ReadFull(conn, b[:3]); err != nil {
		return
	}
	cmd = b[1]
	host, port, err := readSocksAddr(conn)
	if err != nil {
		socksReply(conn, socksAddrUnsupported, nil)
		return 0, "", err
	}
	if cmd != socksConnect && cmd != socksUDPAssociate {
		socksReply(conn, socksCmdUnsupported, nil)
		return 0, "", fmt.Errorf("unsupported command %d", cmd)
	}
	return cmd, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readSocksAddr(r io.Reader) (host string, port uint16, err error) {
	var b [1 + 255 + 2]byte
	if _, err = io.ReadFull(r, b[:1]); err != nil {
		return
	}
	n := 0
	switch b[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if _, err = io.ReadFull(r, b[:1]); err != nil {
			return
		}
		n = int(b[0])
		if _, err = io.ReadFull(r, b[:n+2]); err != nil {
			return
		}
		return string(b[:n]), binary.BigEndian.Uint16(b[n:]), nil
	default:
		return "", 0, fmt.Errorf("unknown address type %d", b[0])
	}
	if _, err = io.ReadFull(r, b[:n+2]); err != nil {
		return
	}
	ip, _ := netip.AddrFromSlice(b[:n])
	return ip.String(), binary.BigEndian.Uint16(b[n:]), nil
}

// appendSocksAddr encodes an address as ATYP · address · port.
func appendSocksAddr(b []byte, host string, port uint16) []byte {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip = ip.Unmap(); ip.Is4() {
			b = append(append(b, 1), ip.AsSlice()...)
		} else {
			b = append(append(b, 4), ip.AsSlice()...)
		}
	} else {
		b = append(append(b, 3, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

// socksReply sends a reply with the given bound address (0.0.0.0:0 when nil).
func socksReply(conn net.Conn, code byte, bound *net.UDPAddr) {
	b := []byte{5, code, 0}
	if bound != nil {
		b = appendSocksAddr(b, bound.IP.String(), uint16(bound.Port))
	} else {
		b = appendSocksAddr(b, "0.0.0.0", 0)
	}
	_, _ = conn.Write(b)
}

// connect relays a CONNECT. The stream is ready as soon as a lane is at hand — the server does not
// acknowledge a destination — so success is reported right away, and the application's first bytes
// (which usually follow at once) leave together with OPEN.
func (s *socksServer) connect(conn net.Conn, target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	stream, err := s.client.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		log.Printf("connect %s: %v", target, err)
		socksReply(conn, socksFailure, nil)
		return
	}
	defer stream.Close()
	socksReply(conn, socksOK, nil)
	if s.verbose {
		log.Printf("connect %s", target)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Uplink. The application closing its side is a half-close; anything else ends the stream.
		if _, err := io.CopyBuffer(writerOnly{stream}, readerOnly{conn}, make([]byte, relayBuffer)); err == nil {
			_ = stream.(interface{ CloseWrite() error }).CloseWrite()
		} else {
			stream.Close()
		}
	}()
	// Downlink. When the application is gone the stream is aborted (Close), so that the server stops
	// sending; the lane is kept either way.
	if _, err := io.CopyBuffer(writerOnly{conn}, readerOnly{stream}, make([]byte, relayBuffer)); err == nil {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	} else {
		stream.Close()
		conn.Close()
	}
	wg.Wait()
}

// readerOnly and writerOnly hide ReadFrom / WriteTo, so that io.CopyBuffer really uses the buffer it is given.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

// associate serves a UDP ASSOCIATE: datagrams the application sends to the relay socket go out through
// one UoT stream, and what comes back is returned to the application. The association lasts as long as
// the TCP connection it was requested on.
func (s *socksServer) associate(conn net.Conn) {
	local, _ := conn.LocalAddr().(*net.TCPAddr)
	peer, _ := conn.RemoteAddr().(*net.TCPAddr)
	if local == nil || peer == nil {
		socksReply(conn, socksFailure, nil)
		return
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		socksReply(conn, socksFailure, nil)
		return
	}
	defer relay.Close()
	pc, err := s.client.ListenPacket()
	if err != nil {
		socksReply(conn, socksFailure, nil)
		return
	}
	defer pc.Close()
	socksReply(conn, socksOK, relay.LocalAddr().(*net.UDPAddr))
	if s.verbose {
		log.Printf("udp associate for %v on %v", peer, relay.LocalAddr())
	}

	var app atomic.Pointer[net.UDPAddr] // where the application sends from
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := relay.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.Equal(peer.IP) {
				continue // only the host that asked for the association may use it
			}
			// RSV(2) · FRAG(1) · ATYP · address · port · data. Fragments are not supported.
			if n < 4 || buf[2] != 0 {
				continue
			}
			r := &sliceReader{b: buf[3:n]}
			host, port, err := readSocksAddr(r)
			if err != nil {
				continue
			}
			app.Store(from)
			if _, err := pc.WriteTo(r.b, miu.HostPort(net.JoinHostPort(host, strconv.Itoa(int(port))))); err != nil {
				if s.verbose {
					log.Printf("udp: %v", err)
				}
				conn.Close() // the session is broken: end the association
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				conn.Close()
				return
			}
			to := app.Load()
			if to == nil {
				continue
			}
			host, p, err := net.SplitHostPort(from.String())
			if err != nil {
				continue
			}
			port, _ := strconv.Atoi(p)
			_, _ = relay.WriteToUDP(append(appendSocksAddr([]byte{0, 0, 0}, host, uint16(port)), buf[:n]...), to)
		}
	}()
	_, _ = io.Copy(io.Discard, conn) // until the application closes the control connection
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
