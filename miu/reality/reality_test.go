package reality

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

// The session id as the server opens it: same shared secret from its side, same key derivation, and the
// ClientHello with a zeroed session id as additional data.
func TestSealSessionID(t *testing.T) {
	private, public, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privBytes, _ := DecodeKey(private)
	pubBytes, _ := DecodeKey(public)
	serverKey, _ := ecdh.X25519().NewPrivateKey(privBytes)
	if !bytes.Equal(serverKey.PublicKey().Bytes(), pubBytes) {
		t.Fatal("the generated public key does not belong to the private key")
	}
	clientKey, _ := ecdh.X25519().GenerateKey(rand.Reader)

	raw := make([]byte, 300) // a stand-in for a ClientHello: only the offsets matter
	_, _ = rand.Read(raw)
	raw[sessionIDOffset-1] = sessionIDSize
	random := raw[6:38]
	shortID, _ := ParseShortID("0123abcd")
	now := time.Unix(1_800_000_000, 0)
	authKey, err := sealSessionID(raw[sessionIDOffset:sessionIDOffset+sessionIDSize], clientKey, serverKey.PublicKey(), shortID, raw, random, now)
	if err != nil {
		t.Fatal(err)
	}

	shared, _ := serverKey.ECDH(clientKey.PublicKey())
	key, _ := hkdf.Key(sha256.New, shared, random[:20], "REALITY", 32)
	if !bytes.Equal(key, authKey) {
		t.Fatal("the two sides derive different auth keys")
	}
	sealed := append([]byte(nil), raw[sessionIDOffset:sessionIDOffset+sessionIDSize]...)
	aad := append([]byte(nil), raw...)
	clear(aad[sessionIDOffset : sessionIDOffset+sessionIDSize])
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	plain, err := aead.Open(nil, random[20:], sealed, aad)
	if err != nil {
		t.Fatalf("the server cannot open the session id: %v", err)
	}
	if !bytes.Equal(plain[:3], clientVersion[:]) || plain[3] != 0 ||
		binary.BigEndian.Uint32(plain[4:]) != uint32(now.Unix()) || !bytes.Equal(plain[8:], []byte{0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0}) {
		t.Fatalf("session id plaintext %x", plain)
	}
}

// The server's certificate is recognized by its signature field: HMAC-SHA512(auth key, public key).
func TestVerifyCertificate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	authKey := make([]byte, 32)
	_, _ = rand.Read(authKey)
	if verifyCertificate(der, authKey) {
		t.Fatal("an ordinary self-signed certificate was accepted")
	}
	// Put the HMAC where the signature is (the last 64 bytes of an Ed25519 certificate).
	mac := hmac.New(sha512.New, authKey)
	mac.Write(pub)
	forged := append([]byte(nil), der...)
	copy(forged[len(forged)-64:], mac.Sum(nil))
	if !verifyCertificate(forged, authKey) {
		t.Fatal("the server's certificate was not recognized")
	}
	other := append([]byte(nil), authKey...)
	other[0] ^= 1
	if verifyCertificate(forged, other) || verifyCertificate(forged, nil) || verifyCertificate(forged[:50], authKey) {
		t.Fatal("a certificate was accepted that should not have been")
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string][8]byte{
		"":                 {},
		"ab":               {0xab},
		"0123456789abcdef": {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	} {
		if got, err := ParseShortID(in); err != nil || got != want {
			t.Fatalf("short id %q: %x %v", in, got, err)
		}
	}
	for _, bad := range []string{"abc", "zz", "0123456789abcdef00"} {
		if _, err := ParseShortID(bad); err == nil {
			t.Fatalf("short id %q accepted", bad)
		}
	}
	if _, err := DecodeKey("AAAA"); err == nil {
		t.Fatal("a 3-byte key was accepted")
	}
	_, public, _ := GenerateKeyPair()
	if _, err := DecodeKey(public + "="); err != nil { // padding is tolerated
		t.Fatal(err)
	}
	if _, err := Dialer("example.com:443", ClientConfig{PublicKey: public}); err == nil {
		t.Fatal("a config without serverName was accepted")
	}
}
