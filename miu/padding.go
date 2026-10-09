package miu

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"strconv"
	"strings"
)

// The padding scheme uses the AnyTLS text format: newline separated key=value pairs.
//
//	stop=N                         the first N packets are shaped, later ones are not
//	<idx>=<a>-<b>[,c,<a>-<b>...]   packet idx is cut into TLS records with a random length in each range;
//	                               "c" means: stop here if the payload has run out
//
// The client starts from the built-in scheme; the server pushes its own when the md5 differs.

const checkMark = -1

// DefaultPaddingScheme is the scheme both sides start from.
const DefaultPaddingScheme = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`

type paddingScheme struct {
	raw    []byte
	scheme map[string]string
	stop   uint32
	md5    string
}

// parsePaddingScheme returns nil when text is not a usable scheme.
func parsePaddingScheme(text string) *paddingScheme {
	scheme := parseKV(text)
	if len(scheme) == 0 {
		return nil
	}
	stop, err := strconv.ParseUint(strings.TrimSpace(scheme["stop"]), 10, 32)
	if err != nil {
		return nil
	}
	sum := md5.Sum([]byte(text))
	return &paddingScheme{raw: []byte(text), scheme: scheme, stop: uint32(stop), md5: hex.EncodeToString(sum[:])}
}

var defaultScheme = parsePaddingScheme(DefaultPaddingScheme)

// sizesFor returns the record lengths for packet pkt, with checkMark standing for "c".
func (p *paddingScheme) sizesFor(pkt uint32) []int {
	if p == nil {
		return nil
	}
	s, ok := p.scheme[strconv.FormatUint(uint64(pkt), 10)]
	if !ok {
		return nil
	}
	var sizes []int
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r == "c" {
			sizes = append(sizes, checkMark)
			continue
		}
		a, b, ok := strings.Cut(r, "-")
		if !ok {
			continue
		}
		lo, err1 := strconv.Atoi(a)
		hi, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil {
			continue
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		if lo <= 0 {
			continue
		}
		if lo == hi {
			sizes = append(sizes, lo)
			continue
		}
		sizes = append(sizes, lo+rand.Intn(hi-lo))
	}
	return sizes
}

// padding0 is the length of the padding that follows the authentication token (item 0 of the scheme).
func (p *paddingScheme) padding0() uint16 {
	if s := p.sizesFor(0); len(s) > 0 && s[0] != checkMark && s[0] <= 0xffff {
		return uint16(s[0])
	}
	return 30
}
