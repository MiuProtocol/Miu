// Package realityserver is the server side of REALITY as an outer layer for miu. The handshake itself
// is done by github.com/xtls/reality; this package configures it and hands the resulting connection —
// a fork of crypto/tls's, on which miu's raw segments work the same way — to a miu.Server.
//
// A client that authenticates gets a TLS 1.3 connection to the miu server. Anyone else is connected,
// byte for byte, to the site the server borrows its appearance from.
package realityserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"

	xreality "github.com/xtls/reality"

	"github.com/MiuProtocol/Miu/miu"
	"github.com/MiuProtocol/Miu/miu/reality"
)

// Config configures the REALITY layer of a server.
type Config struct {
	// Dest is the site to look like, host:port. It must speak TLS 1.3. Connections that do not
	// authenticate are forwarded to it.
	Dest string
	// ServerNames are the SNI values clients may use; they should be names Dest's certificate covers.
	ServerNames []string
	// PrivateKey is the server's X25519 private key, base64url without padding (see reality.GenerateKeyPair).
	PrivateKey string
	// ShortIDs are the short ids clients may present, each up to 16 hex digits; "" is a valid one.
	ShortIDs []string
}

// Server performs REALITY handshakes.
type Server struct {
	cfg *xreality.Config
}

func buildConfig(cfg Config) (*xreality.Config, error) {
	if _, _, err := net.SplitHostPort(cfg.Dest); err != nil {
		return nil, fmt.Errorf("reality: dest: %w", err)
	}
	if len(cfg.ServerNames) == 0 {
		return nil, errors.New("reality: serverNames is required")
	}
	if len(cfg.ShortIDs) == 0 {
		return nil, errors.New(`reality: shortIds is required (it may be [""])`)
	}
	key, err := reality.DecodeKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("reality: privateKey: %w", err)
	}
	var dialer net.Dialer
	x := &xreality.Config{
		DialContext:            dialer.DialContext,
		Type:                   "tcp",
		Dest:                   cfg.Dest,
		PrivateKey:             key,
		ServerNames:            make(map[string]bool),
		ShortIds:               make(map[[8]byte]bool),
		SessionTicketsDisabled: true,
	}
	for _, name := range cfg.ServerNames {
		x.ServerNames[name] = true
	}
	for _, s := range cfg.ShortIDs {
		id, err := reality.ParseShortID(s)
		if err != nil {
			return nil, err
		}
		x.ShortIds[id] = true
	}
	return x, nil
}

// New prepares a REALITY server. It starts probing Dest in the background (the library needs to know
// what Dest sends after a handshake in order to send the same); handshakes that arrive before the
// probe is done, a few seconds, wait for it.
func New(cfg Config) (*Server, error) {
	x, err := buildConfig(cfg)
	if err != nil {
		return nil, err
	}
	xreality.DetectPostHandshakeRecordsLens(x)
	return &Server{cfg: x}, nil
}

// Ready reports whether the probe of Dest has finished. Until then handshakes are held back.
func (s *Server) Ready() bool {
	for name := range s.cfg.ServerNames {
		for _, alpn := range []string{"0", "1", "2"} {
			if v, _ := xreality.GlobalPostHandshakeRecordsLens.Load(s.cfg.Dest + " " + name + " " + alpn); v == nil || v == false {
				return false
			}
		}
	}
	return true
}

// Handshake performs the server side of the handshake on conn, which has to be a TCP connection (or
// anything else with a CloseWrite method). It returns the outer connection for miu.Server.Serve when
// the client has authenticated. Otherwise the client has been forwarded to Dest for as long as that
// lasted, conn is closed, and an error is returned.
func (s *Server) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if _, ok := conn.(interface{ CloseWrite() error }); !ok {
		conn.Close()
		return nil, fmt.Errorf("reality: %T cannot be half-closed", conn)
	}
	outer, err := xreality.Server(ctx, conn, s.cfg)
	if err != nil {
		return nil, err
	}
	return outer, nil
}

// SelfTest is miu.SelfTest for REALITY: it checks that raw segments work on this library's server
// connection, against the uTLS connection of the client. Everything stays in memory, the site to look
// like included.
func SelfTest() error {
	const name, dest = "miu.test", "selftest.invalid:443"
	private, public, err := reality.GenerateKeyPair()
	if err != nil {
		return err
	}
	x, err := buildConfig(Config{Dest: dest, ServerNames: []string{name}, PrivateKey: private, ShortIDs: []string{"5e1f"}})
	if err != nil {
		return err
	}
	// What the library would learn by probing the site: nothing follows its handshake.
	for _, alpn := range []string{"0", "1", "2"} {
		xreality.GlobalPostHandshakeRecordsLens.Store(dest+" "+name+" "+alpn, []int{})
	}
	cert, err := miu.SelfSignedCert(name)
	if err != nil {
		return err
	}
	return miu.SelfTestPair(func(pipe func() (net.Conn, net.Conn)) (net.Conn, net.Conn, error) {
		// The site: a TLS 1.3 server at the other end of a pipe.
		x.DialContext = func(context.Context, string, string) (net.Conn, error) {
			near, far := pipe()
			go func() {
				site := tls.Server(far, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
				_, _ = io.Copy(io.Discard, site)
				far.Close()
			}()
			return near, nil
		}
		a, b := pipe()
		type result struct {
			conn net.Conn
			err  error
		}
		done := make(chan result, 1)
		go func() {
			conn, err := xreality.Server(context.Background(), b, x)
			done <- result{conn, err}
		}()
		cc, err := reality.Handshake(context.Background(), a, reality.ClientConfig{ServerName: name, PublicKey: public, ShortID: "5e1f"})
		if err != nil {
			a.Close()
			<-done
			return nil, nil, err
		}
		r := <-done
		if r.err != nil {
			return nil, nil, r.err
		}
		return cc, r.conn, nil
	})
}
