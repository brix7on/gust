package app

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExeAllowed(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		exe  string
		want bool
	}{
		{filepath.Join(root, "bin", "winws.exe"), true},
		{filepath.Join(root, "bin", "WinWS.EXE"), true}, // регистр не важен
		{filepath.Join(root, "bin", "evil.exe"), false}, // чужое имя
		{"/bin/sh", false}, // вне папки
		{filepath.Join(root, "..", "winws.exe"), false}, // выход наверх
	}
	for _, c := range cases {
		if got := exeAllowed(root, c.exe); got != c.want {
			t.Errorf("exeAllowed(%q)=%v, want %v", c.exe, got, c.want)
		}
	}
	if exeAllowed("", filepath.Join(root, "winws.exe")) {
		t.Error("без root ничего запускать нельзя")
	}
}

func TestEngineRefusesForeignExe(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	data := fakeZapret(t, state, map[string]string{"general": "good"})
	a := newApp(data, 0)
	defer a.shutdown()
	// стратегия, ссылающаяся на посторонний exe, не должна запуститься
	err := a.eng.Start(Strategy{Name: "evil", Exe: "/bin/sh", Args: []string{"-c", "echo"}}, false)
	if err == nil || !strings.Contains(err.Error(), "небезопасный") {
		t.Fatalf("ожидали отказ, получили %v", err)
	}
	if a.eng.Alive() {
		t.Fatal("посторонний процесс не должен быть запущен")
	}
}

func TestHostAllowed(t *testing.T) {
	ok := []string{"github.com", "api.github.com", "codeload.github.com",
		"objects.githubusercontent.com", "release-assets.githubusercontent.com", "github.com:443"}
	bad := []string{"evil.com", "github.com.evil.com", "githubusercontent.com.evil.com", "raw.evil.io"}
	for _, h := range ok {
		if !hostAllowed(h) {
			t.Errorf("%q должен быть разрешён", h)
		}
	}
	for _, h := range bad {
		if hostAllowed(h) {
			t.Errorf("%q должен быть запрещён", h)
		}
	}
}

func TestDownloadRejectsForeignHost(t *testing.T) {
	// хост проверяется до сетевого запроса, так что без доступа к сети
	err := downloadFile("http://evil.com/x.zip", filepath.Join(t.TempDir(), "x"), nil)
	if err == nil || !strings.Contains(err.Error(), "недоверенный") {
		t.Fatalf("ожидали отказ по хосту, получили %v", err)
	}
}

func writeZip(t *testing.T, path string, files map[string]int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, size := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(make([]byte, size))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestUnzipRejectsTooManyFiles(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "many.zip")
	writeZip(t, zp, map[string]int{"a": 1, "b": 1, "c": 1})
	old := maxZipFiles
	maxZipFiles = 2
	defer func() { maxZipFiles = old }()
	if err := unzipSafe(zp, filepath.Join(dir, "out")); err == nil || !strings.Contains(err.Error(), "много файлов") {
		t.Fatalf("ожидали отказ по числу файлов, получили %v", err)
	}
}

func TestUnzipRejectsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "big.zip")
	writeZip(t, zp, map[string]int{"big.bin": 5000})
	old := maxZipFile
	maxZipFile = 1000
	defer func() { maxZipFile = old }()
	if err := unzipSafe(zp, filepath.Join(dir, "out")); err == nil || !strings.Contains(err.Error(), "слишком большой") {
		t.Fatalf("ожидали отказ по размеру файла, получили %v", err)
	}
}
