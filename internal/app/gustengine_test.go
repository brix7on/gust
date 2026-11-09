package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTree — сборка zapret с файлами, на которые ссылаются general.bat и GU-стратегии.
func fakeTree(t *testing.T) (data, root string) {
	t.Helper()
	data = t.TempDir()
	root = filepath.Join(data, "zapret")
	for _, d := range []string{"bin", "lists"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	for _, f := range []string{"winws.exe", "WinDivert.dll", "tls_clienthello_www_google_com.bin", "tls_clienthello_4pda_to.bin",
		"quic_initial_www_google_com.bin", "stun.bin", "ACTIVE_DISCORD_UDP.bin", "ACTIVE_GAME_UDP.bin"} {
		_ = os.WriteFile(filepath.Join(root, "bin", f), []byte("\x16\x03\x01\x00\x02\x01\x00"), 0o755)
	}
	for f, body := range map[string]string{"list-general.txt": "discord.com\nyoutube.com\n", "list-google.txt": "googlevideo.com\n",
		"list-exclude.txt": "ya.ru\n", "ipset-all.txt": "162.159.128.0/19\n", "ipset-exclude.txt": "10.0.0.0/8\n"} {
		_ = os.WriteFile(filepath.Join(root, "lists", f), []byte(body), 0o644)
	}
	b, _ := os.ReadFile("testdata/general.bat")
	_ = os.WriteFile(filepath.Join(root, "general.bat"), []byte(strings.ReplaceAll(string(b), `\`, "/")), 0o644)
	_ = os.WriteFile(filepath.Join(root, "service.bat"), []byte("@echo off\r\n"), 0o644)
	return data, root
}

func allStrategies(t *testing.T, root string, game bool) []Strategy {
	t.Helper()
	st := parseBat(filepath.Join(root, "general.bat"), root, game)
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	out := append([]Strategy{st}, builtinStrategies(root, st.Exe)...)
	for _, s := range out {
		ensureLists(root, s.Args)
	}
	return out
}

func TestEngineCompatibleWithAllStrategies(t *testing.T) {
	_, root := fakeTree(t)
	all := allStrategies(t, root, true)
	if len(all) < 20 {
		t.Fatalf("стратегий: %d", len(all))
	}
	for _, s := range all {
		if !engineCompatible(s.Args) {
			for _, a := range s.Args {
				k, _, _ := strings.Cut(a, "=")
				if !engineFlags[k] {
					t.Errorf("%s: движок не знает %s", s.Name, k)
				}
			}
		}
	}
	if engineCompatible([]string{"--dpi-desync=fake", "--hostlist-auto=x"}) {
		t.Fatal("неизвестная опция должна отсекаться")
	}
}

func TestEngineModes(t *testing.T) {
	data, root := fakeTree(t)
	engineOverride = filepath.Join(data, "engine", engineName)
	defer func() { engineOverride = "" }()
	a := newApp(data, 0)
	defer a.shutdown()
	names := func(mode string) []string {
		a.updateSettings(func(s *Settings) { s.Engine = mode })
		var n []string
		for _, s := range a.loadStrategies() {
			n = append(n, s.Name)
		}
		return n
	}
	z, g, b := names("zapret"), names("gust"), names("both")
	if len(z) < 20 || len(g) != len(z) || len(b) != 2*len(z) {
		t.Fatalf("zapret %d, gust %d, both %d", len(z), len(g), len(b))
	}
	if !strings.HasPrefix(g[0], TwinPrefix) || g[0] != TwinPrefix+z[0] || b[len(z)] != g[0] {
		t.Fatalf("имена: %q %q %q", z[0], g[0], b[len(z)])
	}
	tw, _ := a.findStrategy(g[0])
	if tw.Exe != engineOverride || !strings.HasPrefix(tw.Args[0], "--windivert=") || !strings.HasSuffix(tw.Args[0], "WinDivert.dll") {
		t.Fatalf("двойник: %q %q", tw.Exe, tw.Args[0])
	}
	_ = os.Remove(filepath.Join(root, "bin", "WinDivert.dll"))
	if n := names("gust"); len(n) != len(z) || strings.HasPrefix(n[0], TwinPrefix) {
		t.Fatal("без WinDivert.dll двойников быть не должно")
	}
}

func TestEngineExeMayStart(t *testing.T) {
	data, root := fakeTree(t)
	eng := filepath.Join(data, "engine", engineName)
	_ = os.MkdirAll(filepath.Dir(eng), 0o755)
	_ = os.WriteFile(eng, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755)
	engineOverride = eng
	defer func() { engineOverride = "" }()
	a := newApp(data, 0)
	defer a.shutdown()
	if err := a.eng.Start(Strategy{Name: TwinPrefix + "x", Exe: eng, Args: []string{"--wf-tcp=80"}}, false); err != nil {
		t.Fatalf("движок не запустился: %v", err)
	}
	a.eng.Stop()
	evil := filepath.Join(data, "evil.exe")
	_ = os.WriteFile(evil, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755)
	if err := a.eng.Start(Strategy{Name: "evil", Exe: evil}, false); err == nil {
		a.eng.Stop()
		t.Fatal("посторонний exe не должен запускаться")
	}
	_ = root
}

func TestEngineExtract(t *testing.T) {
	data := t.TempDir()
	a := newApp(data, 0)
	defer a.shutdown()
	emb, err := engineFS.ReadFile("enginebin/" + engineName)
	p := a.engineExe()
	if err != nil || len(emb) == 0 {
		if p != "" {
			t.Fatalf("движок не встроен, а получили %q", p)
		}
		return
	}
	got, _ := os.ReadFile(p)
	if p != filepath.Join(data, "engine", engineName) || string(got) != string(emb) {
		t.Fatalf("распаковка: %q", p)
	}
	_ = os.WriteFile(p, []byte("old"), 0o755)
	b := newApp(data, 0)
	defer b.shutdown()
	if got, _ := os.ReadFile(b.engineExe()); string(got) != string(emb) {
		t.Fatal("устаревший файл движка не обновился")
	}
}

// Контракт с движком: каждая стратегия Gust принимается настоящим gust-engine (--check).
// Нужен собранный движок для текущей ОС: GUST_ENGINE_CHECK=engine/target/debug/gust-engine.
func TestStrategiesAcceptedByEngine(t *testing.T) {
	bin := os.Getenv("GUST_ENGINE_CHECK")
	if bin == "" {
		t.Skip("GUST_ENGINE_CHECK не задан")
	}
	for _, game := range []bool{false, true} {
		_, root := fakeTree(t)
		all := allStrategies(t, root, game)
		tw := engineTwins(all, bin, root)
		if len(tw) != len(all) {
			t.Fatalf("двойников %d из %d", len(tw), len(all))
		}
		for _, s := range tw {
			out, err := exec.Command(s.Exe, append(s.Args, "--check")...).CombinedOutput()
			if err != nil || !strings.HasPrefix(string(out), "ok:") {
				t.Errorf("%s (game=%v): %v\n%s", s.Name, game, err, out)
			}
		}
	}
}
