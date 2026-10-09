package miu

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// Two address encodings share one layout, "family(1) · address · port(u16 BE)", and differ only in the
// family byte:
//   - socksAddr: the OPEN destination and the UoT request header (SOCKS5 values);
//   - uotAddr: the per-packet address of UoT.
//
// A domain name is a 1-byte length followed by the bytes.
type addrCodec struct{ ipv4, ipv6, fqdn byte }

var (
	socksAddr = addrCodec{ipv4: 0x01, ipv6: 0x04, fqdn: 0x03}
	uotAddr   = addrCodec{ipv4: 0x00, ipv6: 0x01, fqdn: 0x02}
)

// errShort reports that a buffer ends before the address does.
var errShort = errors.New("miu: short address")

// append encodes host:port. host is an IP literal or a domain name.
func (c addrCodec) append(b []byte, host string, port uint16) ([]byte, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip = ip.Unmap().WithZone(""); ip.Is4() {
			b = append(append(b, c.ipv4), ip.AsSlice()...)
		} else {
			b = append(append(b, c.ipv6), ip.AsSlice()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("miu: bad domain length")
		}
		b = append(append(b, c.fqdn, byte(len(host))), host...)
	}
	return binary.BigEndian.AppendUint16(b, port), nil
}

// parse decodes an address from the start of b and returns how many bytes it took.
// It returns errShort when b is a valid prefix of an address.
func (c addrCodec) parse(b []byte) (host string, port uint16, n int, err error) {
	if len(b) < 1 {
		return "", 0, 0, errShort
	}
	switch b[0] {
	case c.ipv4:
		n = 1 + 4
	case c.ipv6:
		n = 1 + 16
	case c.fqdn:
		if len(b) < 2 {
			return "", 0, 0, errShort
		}
		if b[1] == 0 {
			return "", 0, 0, errors.New("miu: empty domain")
		}
		n = 2 + int(b[1])
	default:
		return "", 0, 0, errors.New("miu: unknown address family " + strconv.Itoa(int(b[0])))
	}
	if len(b) < n+2 {
		return "", 0, 0, errShort
	}
	switch b[0] {
	case c.fqdn:
		host = string(b[2:n])
	default:
		ip, _ := netip.AddrFromSlice(b[1:n])
		host = ip.String()
	}
	return host, binary.BigEndian.Uint16(b[n:]), n + 2, nil
}

// read decodes an address from a stream, reading exactly as many bytes as it takes.
func (c addrCodec) read(r io.Reader) (host string, port uint16, err error) {
	var b [1 + 1 + 255 + 2]byte
	if _, err = io.ReadFull(r, b[:1]); err != nil {
		return
	}
	n := 0
	switch b[0] {
	case c.ipv4:
		n = 1 + 4 + 2
	case c.ipv6:
		n = 1 + 16 + 2
	case c.fqdn:
		if _, err = io.ReadFull(r, b[1:2]); err != nil {
			return
		}
		n = 2 + int(b[1]) + 2
	default:
		return "", 0, errors.New("miu: unknown address family " + strconv.Itoa(int(b[0])))
	}
	k := 1
	if b[0] == c.fqdn {
		k = 2
	}
	if _, err = io.ReadFull(r, b[k:n]); err != nil {
		return
	}
	host, port, _, err = c.parse(b[:n])
	return
}

// HostPort is a net.Addr holding a "host:port" string whose host may be a domain name. It is what
// streams report as their remote address, and what a UoT packet connection accepts as a destination
// when the name should be resolved by the server.
type HostPort string

func (HostPort) Network() string  { return "miu" }
func (a HostPort) String() string { return string(a) }

// splitHostPort splits "host:port" as net.SplitHostPort does and parses the port.
func splitHostPort(address string) (string, uint16, error) {
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return "", 0, errors.New("miu: bad port in " + strconv.Quote(address))
	}
	if host == "" {
		return "", 0, errors.New("miu: missing host in " + strconv.Quote(address))
	}
	return host, uint16(port), nil
}

func joinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// UDP over TCP v2:
//
//	request  isConnect(1) · socksAddr
//	packet   [uotAddr (when not connected)] · len u16 BE · payload
const (
	uotMagicDomain = "sp.v2.udp-over-tcp.arpa"
	uotMagicSuffix = "udp-over-tcp.arpa"
)

// appendUoTPacket encodes one packet of an unconnected UoT stream.
func appendUoTPacket(b []byte, host string, port uint16, payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, errors.New("miu: UDP payload too large")
	}
	b, err := uotAddr.append(b, host, port)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...), nil
}

// parseUoTPacket decodes one packet from the start of b. It returns errShort when b ends early.
// withAddr is false on a connected stream, whose packets carry no address.
func parseUoTPacket(b []byte, withAddr bool) (host string, port uint16, payload []byte, n int, err error) {
	if withAddr {
		if host, port, n, err = uotAddr.parse(b); err != nil {
			return
		}
	}
	if len(b) < n+2 {
		return "", 0, nil, 0, errShort
	}
	size := int(binary.BigEndian.Uint16(b[n:]))
	if len(b) < n+2+size {
		return "", 0, nil, 0, errShort
	}
	return host, port, b[n+2 : n+2+size], n + 2 + size, nil
}
