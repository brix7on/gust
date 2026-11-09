package app

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Допустимые значения взяты из документации zapret (nfqws/winws).
var (
	desyncPhase = map[string]int{"synack": 0, "syndata": 0, "fake": 1, "fakeknown": 1, "rst": 1, "rstack": 1,
		"multisplit": 2, "multidisorder": 2, "fakedsplit": 2, "hostfakesplit": 2, "fakeddisorder": 2}
	foolingOK   = map[string]bool{"none": true, "md5sig": true, "badseq": true, "badsum": true, "datanoack": true, "ts": true}
	posRe       = regexp.MustCompile(`^(-?\d+|(method|host|endhost|sld|endsld|midsld|sniext)([+-]\d+)?)$`)
	autottlRe   = regexp.MustCompile(`^[+-]?\d+(:\d+(-\d+)?)?$`)
	wssizeRe    = regexp.MustCompile(`^\d+(:\d+)?$`)
	cutoffRe    = regexp.MustCompile(`^[nds]?\d+$`)
	fakeLike    = map[string]bool{"fake": true, "fakedsplit": true, "hostfakesplit": true, "fakeddisorder": true}
	tlsModKnown = map[string]bool{"none": true, "rnd": true, "rndsni": true, "dupsid": true, "padencap": true}
)

func opt(block []string, name string) (string, bool) {
	for _, a := range block {
		if strings.HasPrefix(a, name+"=") {
			return a[len(name)+1:], true
		}
	}
	return "", false
}

func splitBlocks(t *testing.T, args []string) (wf []string, blocks [][]string) {
	t.Helper()
	if len(args) < 3 || !strings.HasPrefix(args[0], "--wf-tcp=") || !strings.HasPrefix(args[1], "--wf-udp=") {
		t.Fatalf("начало команды: %q", args)
	}
	wf = args[:2]
	cur := []string{}
	for _, a := range args[2:] {
		if a == "--new" {
			blocks = append(blocks, cur)
			cur = []string{}
			continue
		}
		cur = append(cur, a)
	}
	return wf, append(blocks, cur)
}

func validateStrategy(t *testing.T, st Strategy) {
	t.Helper()
	_, blocks := splitBlocks(t, st.Args)
	for bi, b := range blocks {
		if len(b) == 0 {
			t.Fatalf("%s: пустой блок %d (лишний --new?)", st.Name, bi)
		}
		if !strings.HasPrefix(b[0], "--filter-") {
			t.Fatalf("%s: блок %d начинается не с filter: %q", st.Name, bi, b[0])
		}
		isTCP := strings.HasPrefix(b[0], "--filter-tcp=")
		for _, a := range b {
			if !strings.HasPrefix(a, "--") || strings.ContainsAny(a, "%{}\"") {
				t.Fatalf("%s: некорректный аргумент %q", st.Name, a)
			}
			// все файлы, на которые есть ссылки, должны существовать (user-списки создаст ensureLists)
			if i := strings.Index(a, "="); i > 0 {
				v := a[i+1:]
				if (strings.HasSuffix(v, ".bin") || strings.HasSuffix(v, ".txt")) && !strings.Contains(v, "-user.txt") {
					if _, err := os.Stat(v); err != nil {
						t.Fatalf("%s: файл %q не существует", st.Name, v)
					}
				}
			}
		}
		var modes []string
		if v, ok := opt(b, "--dpi-desync"); ok {
			modes = strings.Split(v, ",")
			if len(modes) > 3 {
				t.Fatalf("%s: больше трёх режимов: %q", st.Name, v)
			}
			last := -1
			for _, m := range modes {
				p, ok := desyncPhase[m]
				if !ok {
					t.Fatalf("%s: неизвестный режим %q", st.Name, m)
				}
				if p <= last {
					t.Fatalf("%s: режимы %q не в порядке фаз", st.Name, v)
				}
				last = p
			}
		}
		if v, ok := opt(b, "--dpi-desync-split-pos"); ok {
			ps := strings.Split(v, ",")
			for _, p := range ps {
				if !posRe.MatchString(p) {
					t.Fatalf("%s: позиция %q", st.Name, p)
				}
			}
			for _, m := range modes {
				if (m == "fakedsplit" || m == "fakeddisorder") && len(ps) != 1 {
					t.Fatalf("%s: для %s допустима одна позиция, а тут %q", st.Name, m, v)
				}
			}
		}
		hasFool := false
		if v, ok := opt(b, "--dpi-desync-fooling"); ok {
			for _, f := range strings.Split(v, ",") {
				if !foolingOK[f] {
					t.Fatalf("%s: fooling %q", st.Name, f)
				}
				if f != "none" {
					hasFool = true
				}
			}
		}
		if v, ok := opt(b, "--dpi-desync-autottl"); ok {
			if !autottlRe.MatchString(v) {
				t.Fatalf("%s: autottl %q", st.Name, v)
			}
			hasFool = true
		}
		if v, ok := opt(b, "--dpi-desync-ttl"); ok {
			if _, err := strconv.Atoi(v); err != nil {
				t.Fatalf("%s: ttl %q", st.Name, v)
			}
			hasFool = true
		}
		if v, ok := opt(b, "--dpi-desync-repeats"); ok {
			if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 50 {
				t.Fatalf("%s: repeats %q", st.Name, v)
			}
		}
		if v, ok := opt(b, "--dpi-desync-fake-tls-mod"); ok {
			for _, m := range strings.Split(v, ",") {
				if !tlsModKnown[m] && !(strings.HasPrefix(m, "sni=") && len(m) > 4 && len(m) <= 4+63) {
					t.Fatalf("%s: fake-tls-mod %q", st.Name, m)
				}
			}
		}
		if v, ok := opt(b, "--dpi-desync-hostfakesplit-mod"); ok && !strings.HasPrefix(v, "host=") {
			t.Fatalf("%s: hostfakesplit-mod %q", st.Name, v)
		}
		if v, ok := opt(b, "--wssize"); ok && !wssizeRe.MatchString(v) {
			t.Fatalf("%s: wssize %q", st.Name, v)
		}
		if v, ok := opt(b, "--wssize-cutoff"); ok && !cutoffRe.MatchString(v) {
			t.Fatalf("%s: wssize-cutoff %q", st.Name, v)
		}
		// в TCP «фейк» без fooling/ttl дойдёт до сервера и сломает соединение
		if isTCP {
			for _, m := range modes {
				if fakeLike[m] && !hasFool {
					t.Fatalf("%s: режим %s без fooling/ttl в блоке %q", st.Name, m, b[0])
				}
			}
		}
	}
}

func mkRoot(t *testing.T, binFiles []string, withGeneral bool) (root, exe string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "zap ret") // с пробелом в пути
	_ = os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "lists"), 0o755)
	exe = filepath.Join(root, "bin", "winws.exe")
	_ = os.WriteFile(exe, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755)
	for _, f := range binFiles {
		_ = os.WriteFile(filepath.Join(root, "bin", f), []byte{0}, 0o644)
	}
	if withGeneral {
		for _, l := range []string{"list-general.txt", "list-google.txt", "list-exclude.txt"} {
			_ = os.WriteFile(filepath.Join(root, "lists", l), []byte("example.com\n"), 0o644)
		}
	}
	return
}

var allBins = []string{"quic_initial_www_google_com.bin", "tls_clienthello_www_google_com.bin", "tls_clienthello_4pda_to.bin", "stun.bin"}

func TestBuiltinStrategiesValid(t *testing.T) {
	root, exe := mkRoot(t, allBins, true)
	ss := builtinStrategies(root, exe)
	if len(ss) < 20 {
		t.Fatalf("мало стратегий: %d", len(ss))
	}
	names, seen := map[string]bool{}, map[string]bool{}
	voice := map[string]bool{}
	for _, st := range ss {
		validateStrategy(t, st)
		if names[st.Name] {
			t.Fatalf("повтор имени %q", st.Name)
		}
		names[st.Name] = true
		key := strings.Join(st.Args, "\x00")
		if seen[key] {
			t.Fatalf("%s: полностью повторяет другую стратегию", st.Name)
		}
		seen[key] = true
		if st.Exe != exe {
			t.Fatalf("exe: %q", st.Exe)
		}
		if !strings.HasPrefix(st.Name, "GU-") {
			t.Fatalf("имя: %q", st.Name)
		}
		_, blocks := splitBlocks(t, st.Args)
		if len(blocks) != 5 {
			t.Fatalf("%s: блоков %d, ожидали 5 (QUIC, голос, discord.media, HTTPS, HTTP)", st.Name, len(blocks))
		}
		v, _ := opt(blocks[1], "--dpi-desync-fake-discord")
		voice[v] = true
	}
	if len(voice) != 3 { // без файла, quic-файл, stun-файл
		t.Fatalf("варианты голоса не чередуются: %v", voice)
	}
	// user-списки должны подключиться и создаться при запуске
	ensureLists(root, ss[0].Args)
	if _, err := os.Stat(filepath.Join(root, "lists", "list-general-user.txt")); err != nil {
		t.Fatalf("пользовательский список не создан: %v", err)
	}
}

func TestBuiltinStrategiesWithoutOptionalFiles(t *testing.T) {
	root, exe := mkRoot(t, nil, true) // ни одного .bin
	ss := builtinStrategies(root, exe)
	want := 0
	for _, v := range tcpVariants {
		if v.needs == "" {
			want++
		}
	}
	if len(ss) != want {
		t.Fatalf("стратегий %d, ожидали %d (без вариантов, требующих файлы)", len(ss), want)
	}
	for _, st := range ss {
		validateStrategy(t, st)
		_, blocks := splitBlocks(t, st.Args)
		if len(blocks) != 4 { // без QUIC-блока
			t.Fatalf("%s: блоков %d, ожидали 4", st.Name, len(blocks))
		}
	}
}

func TestBuiltinStrategiesNeedGeneralList(t *testing.T) {
	root, exe := mkRoot(t, allBins, false)
	if ss := builtinStrategies(root, exe); ss != nil {
		t.Fatalf("без list-general.txt собирать нечего, а получили %d", len(ss))
	}
	root2, _ := mkRoot(t, allBins, true)
	if ss := builtinStrategies(root2, filepath.Join(root2, "nope.exe")); ss != nil {
		t.Fatal("без winws.exe собирать нечего")
	}
}

func TestExtraStrategiesAreAppendedAndRunnable(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	data := fakeZapret(t, state, map[string]string{"general": "good", "general (ALT)": "good"})
	root := filepath.Join(data, "zapret")
	_ = os.WriteFile(filepath.Join(root, "lists", "list-general.txt"), []byte("example.com\n"), 0o644)
	defer setupTestTiming("http://127.0.0.1:1")()

	a := newApp(data, 0)
	defer a.shutdown()
	all := a.loadStrategies()
	if len(all) < 2+20 {
		t.Fatalf("всего %d", len(all))
	}
	if all[0].Name != "general" || all[1].Name != "general (ALT)" {
		t.Fatalf("готовые стратегии должны идти первыми: %q, %q", all[0].Name, all[1].Name)
	}
	for _, s := range all[2:] {
		if !strings.HasPrefix(s.Name, "GU-") {
			t.Fatalf("после готовых ожидали GU-, а тут %q", s.Name)
		}
	}
	// переключение настройки
	a.updateSettings(func(s *Settings) { s.ExtraStrategies = false })
	if n := len(a.loadStrategies()); n != 2 {
		t.Fatalf("с выключенным набором должно быть 2, а %d", n)
	}
	a.updateSettings(func(s *Settings) { s.ExtraStrategies = true })

	// своя стратегия реально запускается и создаёт пользовательские списки
	st, ok := a.findStrategy("GU-01 fake+fakedsplit ts")
	if !ok {
		t.Fatal("GU-01 не найдена")
	}
	if err := a.eng.Start(st, false); err != nil {
		t.Fatalf("запуск: %v", err)
	}
	if !a.eng.Alive() {
		t.Fatal("процесс не работает")
	}
	if _, err := os.Stat(filepath.Join(root, "lists", "list-general-user.txt")); err != nil {
		t.Fatalf("user-список не создан при запуске: %v", err)
	}
}

func TestSkippedBatLoggedOnce(t *testing.T) {
	data := t.TempDir()
	root := filepath.Join(data, "zapret")
	_ = os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "bin", "winws.exe"), []byte("#!/bin/sh\nexec sleep 60\n"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "general.bat"),
		[]byte("@echo off\r\nstart \"x\" /min \"%~dp0bin/winws.exe\" --wf-tcp=80\r\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "broken.bat"),
		[]byte("@echo off\r\nstart \"x\" /min \"%~dp0bin/winws.exe\" --wf-tcp=%NOPE%\r\n"), 0o644)
	a := newApp(data, 0)
	defer a.shutdown()
	for i := 0; i < 5; i++ { // интерфейс опрашивает раз в секунду
		a.loadStrategies()
	}
	n := 0
	for _, l := range a.logTail(100) {
		if strings.Contains(l, "пропускаю broken.bat") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("в журнале %d записей про broken.bat, ожидали 1", n)
	}
}
