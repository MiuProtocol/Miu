// Package reality is the client side of REALITY as an outer layer for miu: a TLS 1.3 handshake with a
// browser's ClientHello (uTLS) in which the client proves, inside the session id, that it knows the
// server's public key, and then recognizes the server by a certificate only that server can produce.
// To anyone else the server answers as the site it borrows its appearance from.
//
// The server side is in package realityserver.
package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ErrNotReality is returned when the server did not authenticate itself: the public key or short id is
// wrong, the server name is not one it serves, or something else answered in its place.
var ErrNotReality = errors.New("reality: the server did not prove its identity (check publicKey, shortId and serverName)")

// clientVersion is what the server reads as the client's version (three bytes, major.minor.patch).
// A server may be configured to refuse versions below a minimum.
var clientVersion = [3]byte{26, 3, 27}

const (
	// The session id sits at a fixed place in a ClientHello handshake message:
	// type(1) · length(3) · version(2) · random(32) · session id length(1) · session id(32).
	sessionIDOffset = 39
	sessionIDSize   = 32
)

// ClientConfig is what a client has to know about a REALITY server.
type ClientConfig struct {
	// ServerName is sent as SNI. It must be one of the names the server accepts.
	ServerName string
	// PublicKey is the server's X25519 public key, base64url without padding.
	PublicKey string
	// ShortID is one of the server's short ids: up to 16 hex digits, possibly none.
	ShortID string
}

type client struct {
	serverName string
	publicKey  *ecdh.PublicKey
	shortID    [8]byte
}

func newClient(cfg ClientConfig) (*client, error) {
	if cfg.ServerName == "" {
		return nil, errors.New("reality: serverName is required")
	}
	key, err := DecodeKey(cfg.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("reality: publicKey: %w", err)
	}
	pub, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("reality: publicKey: %w", err)
	}
	sid, err := ParseShortID(cfg.ShortID)
	if err != nil {
		return nil, err
	}
	return &client{serverName: cfg.ServerName, publicKey: pub, shortID: sid}, nil
}

// DecodeKey decodes a 32-byte key written in base64url (padding optional).
func DecodeKey(s string) ([]byte, error) {
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(strings.TrimSpace(s), "="))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("a key is 32 bytes, this one is %d", len(key))
	}
	return key, nil
}

// ParseShortID parses a short id: up to 16 hex digits, padded with zeros on the right.
func ParseShortID(s string) (id [8]byte, err error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) > len(id) {
		return id, fmt.Errorf("reality: bad short id %q (up to 16 hex digits)", s)
	}
	copy(id[:], b)
	return id, nil
}

// GenerateKeyPair returns a new X25519 key pair, both halves in base64url without padding: the private
// key belongs in the server's configuration, the public key in the clients'.
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(key.Bytes()), enc.EncodeToString(key.PublicKey().Bytes()), nil
}

// Dialer returns a miu.ClientConfig.Dial that connects to address over TCP and performs the REALITY
// handshake described by cfg, with Chrome's ClientHello.
func Dialer(address string, cfg ClientConfig) (func(ctx context.Context) (net.Conn, error), error) {
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	// No TCP keep-alive probes: an idle lane is meant to be silent.
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		outer, err := c.handshake(ctx, conn)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return outer, nil
	}, nil
}

// Handshake performs the REALITY handshake on an existing connection.
func Handshake(ctx context.Context, conn net.Conn, cfg ClientConfig) (net.Conn, error) {
	c, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	return c.handshake(ctx, conn)
}

func (c *client) handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	var authKey []byte
	verified := false
	uc := utls.UClient(conn, &utls.Config{
		ServerName: c.serverName,
		// The certificate does not come from a CA. It is checked against the authentication key
		// instead, and the handshake fails if that check does.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 || !verifyCertificate(rawCerts[0], authKey) {
				return ErrNotReality
			}
			verified = true
			return nil
		},
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS13,
		// Records leave with the lengths miu's padding scheme asks for.
		DynamicRecordSizingDisabled: true,
	}, utls.HelloChrome_Auto)
	if err := uc.BuildHandshakeState(); err != nil {
		return nil, err
	}
	hello := uc.HandshakeState.Hello
	if len(hello.Raw) < sessionIDOffset+sessionIDSize || hello.Raw[sessionIDOffset-1] != sessionIDSize || len(hello.Random) != 32 {
		return nil, errors.New("reality: unexpected ClientHello layout")
	}
	// The key that authenticates is the one behind the plain X25519 share of the ClientHello; only when
	// there is none, the X25519 half of the hybrid share. (Chrome sends both, with independent keys.)
	keys := uc.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return nil, errors.New("reality: the ClientHello has no X25519 key share")
	}
	private := keys.Ecdhe
	if private == nil || private.Curve() != ecdh.X25519() {
		private = keys.MlkemEcdhe
	}
	if private == nil || private.Curve() != ecdh.X25519() {
		return nil, errors.New("reality: the ClientHello has no X25519 key share")
	}

	var err error
	sealed := hello.Raw[sessionIDOffset : sessionIDOffset+sessionIDSize]
	if authKey, err = sealSessionID(sealed, private, c.publicKey, c.shortID, hello.Raw, hello.Random, time.Now()); err != nil {
		return nil, err
	}
	hello.SessionId = append([]byte(nil), sealed...)

	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !verified || uc.ConnectionState().Version != tls.VersionTLS13 {
		return nil, ErrNotReality
	}
	return uc, nil
}

// sealSessionID writes the authenticating session id into dst, which is the session id field inside
// raw, the ClientHello handshake message.
//
//	plaintext (16 bytes)  version(3) · 0 · unix time(u32 BE) · short id(8)
//	auth key              HKDF-SHA256(ikm = X25519(private, server key), salt = random[0:20], info = "REALITY")
//	session id (32 bytes) AES-GCM(auth key, nonce = random[20:32], plaintext, aad = raw with a zero session id)
//
// It returns the auth key, which the server's certificate is checked against later.
func sealSessionID(dst []byte, private *ecdh.PrivateKey, server *ecdh.PublicKey, shortID [8]byte, raw, random []byte, now time.Time) ([]byte, error) {
	shared, err := private.ECDH(server)
	if err != nil {
		return nil, err
	}
	authKey, err := hkdf.Key(sha256.New, shared, random[:20], "REALITY", 32)
	if err != nil {
		return nil, err
	}
	var plaintext [16]byte
	copy(plaintext[:], clientVersion[:])
	binary.BigEndian.PutUint32(plaintext[4:], uint32(now.Unix()))
	copy(plaintext[8:], shortID[:])

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	clear(dst)
	copy(dst, aead.Seal(nil, random[20:32], plaintext[:], raw))
	return authKey, nil
}

// verifyCertificate tells whether der is the certificate of the REALITY server the auth key was agreed
// with: an Ed25519 certificate whose signature field is HMAC-SHA512(auth key, the certificate's public key).
func verifyCertificate(der, authKey []byte) bool {
	cert, err := x509.ParseCertificate(der)
	if err != nil || len(authKey) == 0 {
		return false
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	return hmac.Equal(mac.Sum(nil), cert.Signature)
}
