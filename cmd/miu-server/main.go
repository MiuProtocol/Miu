// miu-server accepts miu clients over TLS 1.3 or REALITY and connects them to their destinations.
//
//	miu-server -c server.json
//	miu-server keygen          print a new REALITY key pair
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/MiuProtocol/Miu/miu"
	"github.com/MiuProtocol/Miu/miu/reality"
	"github.com/MiuProtocol/Miu/miu/realityserver"
)

type config struct {
	// Listen is the TCP address to accept clients on.
	Listen string `json:"listen"`
	// Cert and Key are the PEM files of the outer TLS certificate and its private key.
	Cert string `json:"cert"`
	Key  string `json:"key"`
	// Reality, in place of Cert and Key, makes the outer layer REALITY.
	Reality *struct {
		// Dest is the site to look like, host:port.
		Dest string `json:"dest"`
		// ServerNames are the SNI values clients may use.
		ServerNames []string `json:"serverNames"`
		// PrivateKey is the X25519 private key, base64url (see "miu-server keygen").
		PrivateKey string `json:"privateKey"`
		// ShortIDs are the short ids clients may present: up to 16 hex digits each, "" allowed.
		ShortIDs []string `json:"shortIds"`
	} `json:"reality"`
	Users []struct {
		Name string `json:"name"`
		PSK  string `json:"psk"`
	} `json:"users"`
	// IdleTimeout is how many seconds a lane without a stream is kept (default 180).
	IdleTimeout int `json:"idleTimeout"`
	// PaddingScheme overrides the built-in padding scheme, one line per element.
	PaddingScheme []string `json:"paddingScheme"`
}

func loadConfig(path string) (config, error) {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func keygen() {
	private, public, err := reality.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("privateKey: %s\npublicKey:  %s\n", private, public)
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) == 2 && os.Args[1] == "keygen" {
		keygen()
		return
	}
	var (
		path    = flag.String("c", "server.json", "path of the JSON configuration `file`")
		listen  = flag.String("listen", "", "listen `address`, overrides the file")
		verbose = flag.Bool("v", false, "log diagnostics (failed dials, rejected connections)")
	)
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected argument %q", flag.Arg(0))
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if err := run(cfg, *verbose); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config, verbose bool) error {
	scfg := miu.ServerConfig{
		IdleTimeout:   time.Duration(cfg.IdleTimeout) * time.Second,
		PaddingScheme: strings.Join(cfg.PaddingScheme, "\n"),
		OnAccess: func(a miu.Access) {
			log.Printf("%s %v -> %s %s", a.User, a.Remote, a.Network, a.Target)
		},
	}
	if verbose {
		scfg.Logf = log.Printf
		// Per stream: bytes each way, and how many of them left the outer TLS as raw segments.
		scfg.OnClose = func(a miu.Access, t miu.Traffic) {
			log.Printf("%s %v -> %s %s closed: up %d (raw %d), down %d (raw %d)", a.User, a.Remote, a.Network, a.Target, t.Up, t.RawUp, t.Down, t.RawDown)
		}
	}
	for _, u := range cfg.Users {
		scfg.Users = append(scfg.Users, miu.User{Name: u.Name, PSK: u.PSK})
	}

	// The outer layer, and a check that raw segments — which reach into the TLS connection — work with
	// the TLS stack it uses. If they do not, the server runs without them.
	var handshake func(ctx context.Context, conn net.Conn) (net.Conn, error)
	var selfTest error
	outer := "TLS 1.3"
	switch {
	case cfg.Reality != nil && (cfg.Cert != "" || cfg.Key != ""):
		return errors.New("cert / key and reality exclude each other")
	case cfg.Reality != nil:
		rs, err := realityserver.New(realityserver.Config{
			Dest:        cfg.Reality.Dest,
			ServerNames: cfg.Reality.ServerNames,
			PrivateKey:  cfg.Reality.PrivateKey,
			ShortIDs:    cfg.Reality.ShortIDs,
		})
		if err != nil {
			return err
		}
		// No deadline here: a visitor that is not a client is relayed to the site for as long as it stays.
		handshake = func(ctx context.Context, conn net.Conn) (net.Conn, error) { return rs.Handshake(ctx, conn) }
		selfTest = realityserver.SelfTest()
		outer = "REALITY, looking like " + cfg.Reality.Dest
	case cfg.Cert == "" || cfg.Key == "":
		return errors.New("either cert and key, or reality, is required")
	default:
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return err
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			// Records leave with the lengths the padding scheme asks for.
			DynamicRecordSizingDisabled: true,
		}
		handshake = func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			tc := tls.Server(conn, tlsCfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, err
			}
			return tc, nil
		}
		selfTest = miu.SelfTest(nil)
	}
	if selfTest != nil {
		log.Printf("ERROR: raw segments are not usable with this build, continuing without them: %v", selfTest)
		scfg.DisableRaw = true
	}

	srv, err := miu.NewServer(scfg)
	if err != nil {
		return err
	}
	// No TCP keep-alive probes: an idle lane is meant to be silent, and the idle timeout bounds its life.
	ln, err := (&net.ListenConfig{KeepAlive: -1}).Listen(context.Background(), "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("listening on %v (%s), %d user(s)", ln.Addr(), outer, len(scfg.Users))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			outer, err := handshake(ctx, conn)
			if err != nil {
				if verbose {
					log.Printf("%v: handshake: %v", conn.RemoteAddr(), err)
				}
				return
			}
			if err := srv.Serve(ctx, outer); err != nil && verbose {
				log.Printf("%v: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}
