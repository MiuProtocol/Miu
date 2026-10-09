package fingerprint

import "testing"

func TestSelfTest(t *testing.T) {
	if err := SelfTest("chrome"); err != nil {
		t.Fatal(err)
	}
	if SelfTest("netscape") == nil {
		t.Fatal("an unknown fingerprint was accepted")
	}
	if _, err := Dialer("example.com:443", "netscape", nil); err == nil {
		t.Fatal("an unknown fingerprint was accepted")
	}
}
