package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		w    bool
	}{{"v0.7.3", "0.7.2", true}, {"0.7.10", "0.7.9", true}, {"v0.7.2", "0.7.2", false}, {"0.7", "0.7.1", false}, {"1.0.0", "0.9.9", true}} {
		if newerVersion(c.a, c.b) != c.w {
			t.Errorf("%s > %s: want %v", c.a, c.b, c.w)
		}
	}
}

func TestSumFor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "SHA256SUMS")
	_ = os.WriteFile(p, []byte("ABC  Gust-0.7.3-windows-x64.zip\ndef  gust-engine-0.7.3-windows-x64.zip\n"), 0o644)
	if sumFor(p, "Gust-0.7.3-windows-x64.zip") != "abc" || sumFor(p, "x.zip") != "" {
		t.Fatal("sumFor")
	}
}
