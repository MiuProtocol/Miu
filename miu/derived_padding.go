package miu

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	derivedProfileSalt   = "miu/v2/padding-profile/salt"
	derivedProfileInfo   = "miu/v2/padding-profile/v1/psk-only"
	derivedProfileBlock  = 128
	derivedProfileBudget = 1984
)

type derivedPaddingReader struct {
	prk     []byte
	block   []byte
	pos     int
	counter uint32
	info    string
}

func newDerivedPaddingReader(authToken [32]byte) (*derivedPaddingReader, error) {
	return newDerivedPaddingReaderInfo(authToken, derivedProfileInfo)
}

func newDerivedPaddingReaderInfo(authToken [32]byte, info string) (*derivedPaddingReader, error) {
	prk := hmac.New(sha256.New, []byte(derivedProfileSalt))
	_, _ = prk.Write(authToken[:])
	block, err := hkdfExpand(prk.Sum(nil), info, derivedProfileBlock)
	if err != nil {
		return nil, err
	}
	return &derivedPaddingReader{prk: prk.Sum(nil), block: block, info: info}, nil
}

func (r *derivedPaddingReader) refill() error {
	r.counter++
	info := r.info + "/counter/" + strconv.FormatUint(uint64(r.counter), 10)
	block, err := hkdfExpand(r.prk, info, derivedProfileBlock)
	if err != nil {
		return err
	}
	r.block, r.pos = block, 0
	return nil
}

func hkdfExpand(prk []byte, info string, length int) ([]byte, error) {
	if length <= 0 || length > 255*sha256.Size {
		return nil, fmt.Errorf("miu: invalid HKDF output length %d", length)
	}
	out := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(previous)
		_, _ = mac.Write([]byte(info))
		_, _ = mac.Write([]byte{counter})
		previous = mac.Sum(nil)
		out = append(out, previous...)
	}
	return out[:length], nil
}

func (r *derivedPaddingReader) uint16() (uint16, error) {
	if r.pos+2 > len(r.block) {
		if err := r.refill(); err != nil {
			return 0, err
		}
	}
	x := binary.BigEndian.Uint16(r.block[r.pos : r.pos+2])
	r.pos += 2
	return x, nil
}

func (r *derivedPaddingReader) sample(lo, hi int) (int, error) {
	if lo >= hi {
		return 0, fmt.Errorf("miu: invalid derived range %d-%d", lo, hi)
	}
	span := hi - lo
	limit := 1<<16 - (1<<16)%span
	for {
		x, err := r.uint16()
		if err != nil {
			return 0, err
		}
		if int(x) < limit {
			return lo + int(x)%span, nil
		}
	}
}

func (r *derivedPaddingReader) bit() (bool, error) {
	x, err := r.sample(0, 2)
	return x == 1, err
}

// derivePaddingScheme creates the deterministic v1 profile from the existing
// authentication token. It is a shaping policy, not an authentication secret.
func derivePaddingScheme(authToken [32]byte) (*paddingScheme, error) {
	r, err := newDerivedPaddingReader(authToken)
	if err != nil {
		return nil, err
	}
	return generatePaddingScheme(r)
}

// laneProfileInfo is the HKDF info prefix of a lane's own scheme; the lane's nonce follows it.
const laneProfileInfo = derivedProfileInfo + "/lane/"

// deriveLanePaddingScheme draws one lane's scheme from the same family as the PSK-derived one: the same
// generator and bounds, fed by HKDF over the authentication token with a random per-lane nonce. Each
// side does this on its own, for what it sends, and tells nobody: shaping is the sender's business and
// the receiver does not check it, so no wire change is needed. Settings still carries the md5 of the
// PSK-derived scheme. Lanes of one user therefore do not share one fixed set of lengths.
func deriveLanePaddingScheme(authToken [32]byte, nonce []byte) (*paddingScheme, error) {
	r, err := newDerivedPaddingReaderInfo(authToken, laneProfileInfo+hex.EncodeToString(nonce))
	if err != nil {
		return nil, err
	}
	return generatePaddingScheme(r)
}

// newLaneScheme returns a fresh lane scheme from base's family, or base when no nonce can be had.
func newLaneScheme(authToken [32]byte, base *paddingScheme) *paddingScheme {
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return base
	}
	if p, err := deriveLanePaddingScheme(authToken, nonce[:]); err == nil {
		return p
	}
	return base
}

// generatePaddingScheme is the generator of the derived schemes, reading its choices from r.
func generatePaddingScheme(r *derivedPaddingReader) (*paddingScheme, error) {
	count, err := r.sample(4, 10)
	if err != nil {
		return nil, err
	}
	authLo, err := r.sample(24, 41)
	if err != nil {
		return nil, err
	}
	authHi, err := r.sample(authLo+16, 65)
	if err != nil {
		return nil, err
	}
	capPerPacket := (derivedProfileBudget - authHi) / count
	lines := []string{fmt.Sprintf("stop=%d", count+1), fmt.Sprintf("0=%d-%d", authLo, authHi)}
	upperBound := authHi
	for pkt := 1; pkt <= count; pkt++ {
		double := false
		if capPerPacket >= 384 {
			double, err = r.bit()
			if err != nil {
				return nil, err
			}
		}
		if double {
			partCap := capPerPacket / 2
			lo1, hi1, err := derivedRange(r, partCap, 8)
			if err != nil {
				return nil, err
			}
			lo2, hi2, err := derivedRange(r, partCap, 8)
			if err != nil {
				return nil, err
			}
			lines = append(lines, fmt.Sprintf("%d=%d-%d,c,%d-%d", pkt, lo1, hi1, lo2, hi2))
			upperBound += hi1 + hi2
		} else {
			lo, hi, err := derivedRange(r, capPerPacket, 16)
			if err != nil {
				return nil, err
			}
			lines = append(lines, fmt.Sprintf("%d=%d-%d", pkt, lo, hi))
			upperBound += hi
		}
	}
	if upperBound > derivedProfileBudget {
		return nil, fmt.Errorf("miu: derived profile budget exceeded: %d", upperBound)
	}
	p := parsePaddingScheme(strings.Join(lines, "\n"))
	if p == nil {
		return nil, fmt.Errorf("miu: generated invalid padding scheme")
	}
	return p, nil
}

func derivedRange(r *derivedPaddingReader, capPerPacket, minWidth int) (int, int, error) {
	lo, err := r.sample(128, capPerPacket-(2*minWidth-1))
	if err != nil {
		return 0, 0, err
	}
	hi, err := r.sample(lo+minWidth, capPerPacket+1)
	if err != nil {
		return 0, 0, err
	}
	return lo, hi, nil
}
