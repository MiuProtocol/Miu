// Package fingerprint dials the outer TLS connection of a miu client with uTLS, so that the ClientHello
// looks like a browser's instead of Go's. It is the only part of the module that needs a third-party
// dependency; a client that is content with crypto/tls uses miu.TLSDialer and does not import it.
package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/MiuProtocol/Miu/miu"
)

// helloID maps a fingerprint name to the ClientHello it stands for.
func helloID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "chrome":
		return utls.HelloChrome_Auto, nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("fingerprint: unknown fingerprint %q (supported: chrome)", name)
}

func uconfig(cfg *tls.Config) *utls.Config {
	if cfg == nil {
		cfg = &tls.Config{}
	}
	return &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		MinVersion:         tls.VersionTLS13,
		// Records leave with the lengths the padding scheme asks for.
		DynamicRecordSizingDisabled: true,
	}
}

// Dialer returns a miu.ClientConfig.Dial that connects to address over TCP and performs the TLS
// handshake with the ClientHello of the named fingerprint. Only "chrome" is known. Of cfg, ServerName,
// InsecureSkipVerify and RootCAs are honored; a config without ServerName gets the host of address.
func Dialer(address, name string, cfg *tls.Config) (func(ctx context.Context) (net.Conn, error), error) {
	id, err := helloID(name)
	if err != nil {
		return nil, err
	}
	ucfg := uconfig(cfg)
	if ucfg.ServerName == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ucfg.ServerName = host
	}
	// No TCP keep-alive probes: an idle lane is meant to be silent.
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		uc := utls.UClient(conn, ucfg.Clone(), id)
		if err := uc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		if v := uc.ConnectionState().Version; v != tls.VersionTLS13 {
			conn.Close()
			return nil, fmt.Errorf("fingerprint: server negotiated TLS %#x, need TLS 1.3", v)
		}
		return uc, nil
	}, nil
}

// SelfTest is miu.SelfTest for uTLS connections with the named fingerprint.
func SelfTest(name string) error {
	id, err := helloID(name)
	if err != nil {
		return err
	}
	return miu.SelfTest(func(conn net.Conn, cfg *tls.Config) net.Conn {
		return utls.UClient(conn, uconfig(cfg), id)
	})
}
