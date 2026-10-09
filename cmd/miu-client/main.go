// miu-client is a local SOCKS5 proxy that forwards through a miu server.
//
//	miu-client -c client.json
//	miu-client keygen          print a new REALITY key pair
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/MiuProtocol/Miu/miu"
	"github.com/MiuProtocol/Miu/miu/fingerprint"
	"github.com/MiuProtocol/Miu/miu/reality"
)

type config struct {
	// Listen is the address of the local SOCKS5 proxy.
	Listen string `json:"listen"`
	// Server is the miu server, host:port.
	Server string `json:"server"`
	PSK    string `json:"psk"`
	// SNI is the server name of the outer TLS handshake; the host of Server when empty.
	SNI string `json:"sni"`
	// Insecure skips the verification of the server's certificate.
	Insecure bool `json:"insecure"`
	// Fingerprint, when "chrome", sends a browser's ClientHello (uTLS) instead of Go's.
	Fingerprint string `json:"fingerprint"`
	// Reality makes the outer layer REALITY (always with Chrome's ClientHello). Insecure and
	// Fingerprint do not apply then.
	Reality *struct {
		// ServerName is the SNI, one of the names the server accepts. Defaults to SNI above.
		ServerName string `json:"serverName"`
		// PublicKey is the server's X25519 public key, base64url.
		PublicKey string `json:"publicKey"`
		// ShortID is one of the server's short ids: up to 16 hex digits, possibly none.
		ShortID string `json:"shortId"`
	} `json:"reality"`
}

func loadConfig(path string) (config, error) {
	var cfg config
	if path == "" {
		return cfg, nil
	}
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

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) == 2 && os.Args[1] == "keygen" {
		private, public, err := reality.GenerateKeyPair()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("privateKey: %s\npublicKey:  %s\n", private, public)
		return
	}
	var (
		path            = flag.String("c", "", "path of the JSON configuration `file`")
		listen          = flag.String("listen", "", "local SOCKS5 `address` (default 127.0.0.1:1080)")
		server          = flag.String("server", "", "miu server, `host:port`")
		psk             = flag.String("psk", "", "pre-shared key")
		sni             = flag.String("sni", "", "TLS server `name` (default: the host of -server)")
		insecure        = flag.Bool("insecure", false, "do not verify the server's certificate")
		fingerprintName = flag.String("fingerprint", "", "ClientHello fingerprint: chrome (default: Go's own)")
		verbose         = flag.Bool("v", false, "log every connection")
	)
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected argument %q", flag.Arg(0))
	}
	cfg, err := loadConfig(*path)
	if err != nil {
		log.Fatal(err)
	}
	// Flags override the file.
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			cfg.Listen = *listen
		case "server":
			cfg.Server = *server
		case "psk":
			cfg.PSK = *psk
		case "sni":
			cfg.SNI = *sni
		case "insecure":
			cfg.Insecure = *insecure
		case "fingerprint":
			cfg.Fingerprint = *fingerprintName
		}
	})
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	if err := run(cfg, *verbose); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config, verbose bool) error {
	if cfg.Server == "" || cfg.PSK == "" {
		return errors.New("server and psk are required (see -h)")
	}
	if _, _, err := net.SplitHostPort(cfg.Server); err != nil {
		return fmt.Errorf("server: %w", err)
	}
	ccfg := miu.ClientConfig{PSK: cfg.PSK}
	tlsCfg := &tls.Config{ServerName: cfg.SNI, InsecureSkipVerify: cfg.Insecure}

	// Raw segments reach into the TLS connection. Make sure that works with the TLS stack in use, and
	// run without them if it does not.
	var selfTest error
	outer := "TLS 1.3"
	switch {
	case cfg.Reality != nil:
		rc := reality.ClientConfig{ServerName: cfg.Reality.ServerName, PublicKey: cfg.Reality.PublicKey, ShortID: cfg.Reality.ShortID}
		if rc.ServerName == "" {
			rc.ServerName = cfg.SNI
		}
		if cfg.Insecure || (cfg.Fingerprint != "" && cfg.Fingerprint != "chrome") {
			return errors.New("with reality, insecure does not apply and the fingerprint is always chrome")
		}
		dial, err := reality.Dialer(cfg.Server, rc)
		if err != nil {
			return err
		}
		ccfg.Dial = dial
		selfTest = fingerprint.SelfTest("chrome") // the client's REALITY connection is a uTLS connection
		outer = "REALITY, server name " + rc.ServerName
	case cfg.Fingerprint == "":
		ccfg.Dial = miu.TLSDialer(cfg.Server, tlsCfg)
		selfTest = miu.SelfTest(nil)
	default:
		dial, err := fingerprint.Dialer(cfg.Server, cfg.Fingerprint, tlsCfg)
		if err != nil {
			return err
		}
		ccfg.Dial = dial
		selfTest = fingerprint.SelfTest(cfg.Fingerprint)
		outer += ", " + cfg.Fingerprint + " fingerprint"
	}
	if selfTest != nil {
		log.Printf("ERROR: raw segments are not usable with this build, continuing without them: %v", selfTest)
		ccfg.DisableRaw = true
	}

	client, err := miu.NewClient(ccfg)
	if err != nil {
		return err
	}
	defer client.Close()
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 on %v, server %s (%s)", ln.Addr(), cfg.Server, outer)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		ln.Close()
	}()
	err = (&socksServer{client: client, verbose: verbose}).serve(ln)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
