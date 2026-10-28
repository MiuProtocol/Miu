package miu

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type derivedVectorFile struct {
	Vectors []struct {
		ID     string `json:"id"`
		PSK    string `json:"psk"`
		Scheme struct {
			Text   string `json:"text"`
			MD5    string `json:"md5"`
			Stop   uint32 `json:"stop"`
			Count  int    `json:"shaped_packet_count"`
			Budget int    `json:"conservative_padding_budget_upper_bound"`
		} `json:"scheme"`
	} `json:"vectors"`
}

func readDerivedVectors(t *testing.T) derivedVectorFile {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "testdata", "miu-padding-profile-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors derivedVectorFile
	if err := json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestDerivedPaddingVectors(t *testing.T) {
	vectors := readDerivedVectors(t)
	for _, vector := range vectors.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			token, err := pskToken(vector.PSK)
			if err != nil {
				t.Fatal(err)
			}
			got, err := derivePaddingScheme(token)
			if err != nil {
				t.Fatal(err)
			}
			if string(got.raw) != vector.Scheme.Text {
				t.Fatalf("scheme mismatch\n got: %q\nwant: %q", got.raw, vector.Scheme.Text)
			}
			if got.md5 != vector.Scheme.MD5 || got.stop != vector.Scheme.Stop {
				t.Fatalf("scheme metadata mismatch: md5=%s stop=%d", got.md5, got.stop)
			}
			if int(got.stop)-1 != vector.Scheme.Count || derivedSchemeBudget(got) != vector.Scheme.Budget {
				t.Fatalf("scheme bounds mismatch: count=%d budget=%d", got.stop-1, derivedSchemeBudget(got))
			}
		})
	}
}

func derivedSchemeBudget(p *paddingScheme) int {
	budget := 0
	for index, spec := range p.scheme {
		if index == "stop" {
			continue
		}
		for _, part := range strings.Split(spec, ",") {
			if part == "c" {
				continue
			}
			bounds := strings.Split(part, "-")
			if len(bounds) == 2 {
				n, _ := strconv.Atoi(bounds[1])
				budget += n
			}
		}
	}
	return budget
}

func TestDerivedPaddingIsPerToken(t *testing.T) {
	first := sha256.Sum256([]byte("first-derived-profile"))
	second := sha256.Sum256([]byte("second-derived-profile"))
	a, err := derivePaddingScheme(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := derivePaddingScheme(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.raw, b.raw) {
		t.Fatal("different auth tokens produced the same profile")
	}
	again, err := derivePaddingScheme(first)
	if err != nil || !bytes.Equal(again.raw, a.raw) {
		t.Fatalf("same auth token was not deterministic: %v", err)
	}
}

func TestClientRemembersUpdatedPadding(t *testing.T) {
	initial := defaultScheme
	updated := parsePaddingScheme("stop=2\n0=31-31\n1=128-160")
	c := &Client{padding: initial}
	if c.currentPadding() != initial {
		t.Fatal("initial client scheme")
	}
	c.updatePadding(updated)
	if c.currentPadding() != updated {
		t.Fatal("client did not remember updated scheme")
	}
}

func TestExplicitServerPaddingTakesPrecedence(t *testing.T) {
	explicit := "stop=2\n0=30-30\n1=128-160"
	s, err := NewServer(ServerConfig{Users: []User{{Name: "user", PSK: "server-user-psk-2026"}}, PaddingScheme: explicit})
	if err != nil {
		t.Fatal(err)
	}
	if s.scheme.md5 != parsePaddingScheme(explicit).md5 {
		t.Fatal("explicit server scheme was not selected")
	}
}
