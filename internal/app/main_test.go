package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenize(t *testing.T) {
	got := tokenize(`start "zapret: x" /min "C:\my dir\winws.exe" --a=1 --b="C:\p q\r.txt" --c=""`)
	want := []string{"start", "zapret: x", "/min", `C:\my dir\winws.exe`, "--a=1", `--b=C:\p q\r.txt`, "--c="}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestParseRealGeneralBat(t *testing.T) {
	root := filepath.Join(t.TempDir(), "my zapret") // пробел в пути — частая причина поломок
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile("testdata/general.bat")
	// на Linux обратные слэши Windows-путей не разделители, поэтому для теста заменяем их
	fixed := strings.ReplaceAll(string(b), `\`, "/")
	p := filepath.Join(root, "general.bat")
	_ = os.WriteFile(p, []byte(fixed), 0o644)

	st := parseBat(p, root, false)
	if st.Err != "" {
		t.Fatal(st.Err)
	}
	if !strings.HasSuffix(st.Exe, "winws.exe") || !strings.HasPrefix(st.Exe, root) {
		t.Fatalf("exe: %q", st.Exe)
	}
	n := 0
	for _, a := range st.Args {
		if a == "--new" {
			n++
		}
		if strings.Contains(a, "%") || strings.Contains(a, `"`) || strings.Contains(a, "^") {
			t.Fatalf("осталась неразобранная часть: %q", a)
		}
	}
	if n != 8 {
		t.Fatalf("--new: %d, ожидали 8", n)
	}
	if st.Args[0] != "--wf-tcp=80,443,2053,2083,2087,2096,8443,12" {
		t.Fatalf("wf-tcp: %q", st.Args[0])
	}
	if st.Args[1] != "--wf-udp=443,19294-19344,50000-50100,12" {
		t.Fatalf("wf-udp: %q", st.Args[1])
	}
	found := false
	for _, a := range st.Args {
		if strings.HasPrefix(a, "--hostlist=") && strings.Contains(a, "list-general.txt") {
			found = strings.Contains(a, "my zapret")
		}
	}
	if !found {
		t.Fatal("путь к списку не подставлен")
	}
	// игровой фильтр
	st2 := parseBat(p, root, true)
	if st2.Args[0] != "--wf-tcp=80,443,2053,2083,2087,2096,8443,1024-10807,10810-18764,18766-65535" {
		t.Fatalf("game filter: %q", st2.Args[0])
	}
	// недостающие списки создаются
	ensureLists(root, st.Args)
	if _, err := os.Stat(filepath.Join(root, "lists", "list-general-user.txt")); err != nil {
		t.Fatalf("список не создан: %v", err)
	}
	b2, _ := os.ReadFile(filepath.Join(root, "lists", "ipset-exclude-user.txt"))
	if !strings.Contains(string(b2), "203.0.113.113") {
		t.Fatalf("заглушка ipset: %q", b2)
	}
}

// fixture: фальшивый winws, который «чинит» сеть, только если получил --mode=good.
func fakeZapret(t *testing.T, state string, modes map[string]string) string {
	t.Helper()
	data := t.TempDir()
	root := filepath.Join(data, "zapret")
	_ = os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	_ = os.MkdirAll(filepath.Join(root, "lists"), 0o755)
	script := "#!/bin/sh\nfor a in \"$@\"; do\n [ \"$a\" = \"--mode=good\" ] && echo good > \"" + state + "\"\n [ \"$a\" = \"--mode=bad\" ] && echo bad > \"" + state + "\"\ndone\nexec sleep 60\n"
	_ = os.WriteFile(filepath.Join(root, "bin", "winws.exe"), []byte(script), 0o755)
	_ = os.WriteFile(filepath.Join(root, "service.bat"), []byte("@echo off\r\n"), 0o644)
	for name, mode := range modes {
		bat := "@echo off\r\nset \"BIN=%~dp0bin/\"\r\nstart \"zapret: %~n0\" /min \"%BIN%winws.exe\" --mode=" + mode + " --wf-tcp=80,%GameFilterTCP%\r\n"
		_ = os.WriteFile(filepath.Join(root, name+".bat"), []byte(bat), 0o644)
	}
	return data
}

func fakeNet(t *testing.T, state string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := os.ReadFile(state)
		if strings.TrimSpace(string(b)) == "good" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		<-r.Context().Done() // как DPI: соединение зависает
	}))
	t.Cleanup(srv.Close)
	return srv
}

func waitTune(t *testing.T, a *App) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		r := a.tune.Running
		a.mu.Unlock()
		if !r {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("подбор завис")
}

func setupTestTiming(srvURL string) func() {
	oc, os_, ot, oi, ow := checkTimeout, settleAfterBoot, targetsOverride, internetProbe, startupWait
	ofmin, ofmax := fastMin, fastMax
	checkTimeout, settleAfterBoot, startupWait = 700*time.Millisecond, 100*time.Millisecond, 300*time.Millisecond
	fastMin, fastMax = 300*time.Millisecond, 300*time.Millisecond
	internetProbe = srvURL + "/probe-always"
	targetsOverride = []Target{
		{"discord", "a", srvURL + "/a"},
		{"discord", "b", srvURL + "/b"},
	}
	return func() {
		checkTimeout, settleAfterBoot, targetsOverride, internetProbe, startupWait = oc, os_, ot, oi, ow
		fastMin, fastMax = ofmin, ofmax
	}
}

func TestAutoTunePicksWorkingStrategy(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	_ = os.WriteFile(state, []byte("bad"), 0o644)
	data := fakeZapret(t, state, map[string]string{
		"general": "bad", "general (ALT)": "bad", "general (ALT2)": "good", "general (ALT3)": "good",
	})
	srv := fakeNet(t, state)
	// «интернет жив» — отдельный путь, который отвечает всегда
	mux := http.NewServeMux()
	mux.Handle("/probe-always", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("up")) }))
	mux.Handle("/", srv.Config.Handler)
	srv.Config.Handler = mux
	defer setupTestTiming(srv.URL)()

	a := newApp(data, 0)
	defer a.shutdown()
	if len(a.loadStrategies()) != 4 {
		t.Fatalf("стратегий: %d", len(a.loadStrategies()))
	}
	if a.loadStrategies()[0].Name != "general" {
		t.Fatal("general должен идти первым")
	}
	if err := a.startTune(); err != nil {
		t.Fatal(err)
	}
	waitTune(t, a)

	if got := a.settings().Selected; got != "general (ALT2)" {
		t.Fatalf("выбрана %q; лог:\n%s", got, strings.Join(a.logTail(40), "\n"))
	}
	if !a.eng.Alive() {
		t.Fatal("после подбора обход должен быть запущен")
	}
	a.mu.Lock()
	res := a.tune.Results
	a.mu.Unlock()
	if len(res) != 3 { // general, ALT, ALT2 — на ALT2 все цели открылись, дальше не идём
		t.Fatalf("проверено %d стратегий: %+v", len(res), res)
	}
	if res[0].Passed != 0 || res[2].Passed != 2 {
		t.Fatalf("результаты: %+v", res)
	}
}

func TestTuneNoBypassNeeded(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	_ = os.WriteFile(state, []byte("good"), 0o644) // сеть и так работает
	data := fakeZapret(t, state, map[string]string{"general": "bad"})
	srv := fakeNet(t, state)
	defer setupTestTiming(srv.URL)()
	internetProbe = srv.URL + "/p"

	a := newApp(data, 0)
	defer a.shutdown()
	_ = a.startTune()
	waitTune(t, a)
	a.mu.Lock()
	msg := a.tune.Msg
	a.mu.Unlock()
	if !strings.Contains(msg, "и так доступно") {
		t.Fatalf("msg=%q", msg)
	}
	if !a.eng.Alive() {
		t.Fatal("стратегия по умолчанию должна быть запущена")
	}
}

func TestTuneNothingWorks(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	_ = os.WriteFile(state, []byte("bad"), 0o644)
	data := fakeZapret(t, state, map[string]string{"general": "bad", "general (ALT)": "bad"})
	srv := fakeNet(t, state)
	mux := http.NewServeMux()
	mux.Handle("/probe-always", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("up")) }))
	mux.Handle("/", srv.Config.Handler)
	srv.Config.Handler = mux
	defer setupTestTiming(srv.URL)()

	a := newApp(data, 0)
	defer a.shutdown()
	_ = a.startTune()
	waitTune(t, a)
	a.mu.Lock()
	msg := a.tune.Msg
	a.mu.Unlock()
	if !strings.Contains(msg, "ни одна стратегия не помогла") {
		t.Fatalf("msg=%q", msg)
	}
	if a.eng.Alive() {
		t.Fatal("при неудаче обход не должен висеть включённым")
	}
}

func TestWatchdogRestartsCrashedWinws(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	data := fakeZapret(t, state, map[string]string{"general": "good"})
	defer setupTestTiming("http://127.0.0.1:1")()
	a := newApp(data, 0)
	defer a.shutdown()
	if err := a.startSelected(); err != nil {
		t.Fatal(err)
	}
	a.eng.mu.Lock()
	first := a.eng.cmd.Process.Pid
	_ = a.eng.cmd.Process.Kill() // имитируем падение
	a.eng.mu.Unlock()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		a.eng.mu.Lock()
		var pid int
		if a.eng.cmd != nil && a.eng.running {
			pid = a.eng.cmd.Process.Pid
		}
		a.eng.mu.Unlock()
		if pid != 0 && pid != first {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("watchdog не перезапустил процесс; лог:\n%s", strings.Join(a.logTail(20), "\n"))
}

func TestStartFailsWhenWinwsExitsImmediately(t *testing.T) {
	data := t.TempDir()
	root := filepath.Join(data, "zapret")
	_ = os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "bin", "winws.exe"),
		[]byte("#!/bin/sh\necho 'windivert: error 1275 driver blocked' >&2\nexit 1\n"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "general.bat"),
		[]byte("@echo off\r\nset \"BIN=%~dp0bin/\"\r\nstart \"x\" /min \"%BIN%winws.exe\" --wf-tcp=80\r\n"), 0o644)
	defer setupTestTiming("http://127.0.0.1:1")()
	a := newApp(data, 0)
	defer a.shutdown()
	err := a.startSelected()
	if err == nil || !strings.Contains(err.Error(), "заблокирован") {
		t.Fatalf("ожидали понятную ошибку про блокировку драйвера, получили %v", err)
	}
	if a.eng.Alive() {
		t.Fatal("не должен считаться запущенным")
	}
}

func TestAPIGuard(t *testing.T) {
	a := newApp(t.TempDir(), 18765)
	defer a.shutdown()
	h := a.routes()
	do := func(method, path, host, token string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Host = host
		if token != "" {
			r.Header.Set("X-GU-Token", token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := do("GET", "/api/state", "127.0.0.1:18765", ""); c != 403 {
		t.Fatalf("без токена: %d", c)
	}
	if c := do("GET", "/api/state", "evil.com:18765", a.token); c != 403 {
		t.Fatalf("чужой Host: %d", c)
	}
	if c := do("GET", "/api/state", "127.0.0.1:18765", a.token); c != 200 {
		t.Fatalf("штатный запрос: %d", c)
	}
	if c := do("GET", "/api/start", "127.0.0.1:18765", a.token); c != 405 {
		t.Fatalf("GET на POST-метод: %d", c)
	}
	if c := do("GET", "/", "127.0.0.1:18765", ""); c != 200 {
		t.Fatalf("индекс: %d", c)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "localhost:18765"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), a.token) || strings.Contains(w.Body.String(), "{{TOKEN}}") {
		t.Fatal("токен не подставлен в страницу")
	}
}

func TestUnzipRejectsPathTraversal(t *testing.T) {
	// zip с ../ в имени файла не должен выходить за пределы папки
	dir := t.TempDir()
	zp := filepath.Join(dir, "evil.zip")
	f, _ := os.Create(zp)
	zw := newZipWriter(f)
	zw("../escape.txt", "x")
	_ = f.Close()
	if err := unzipSafe(zp, filepath.Join(dir, "out")); err == nil {
		t.Fatal("ожидали ошибку")
	}
	if _, err := os.Stat(filepath.Join(dir, "escape.txt")); err == nil {
		t.Fatal("файл вышел за пределы папки")
	}
}

func TestTuneChecksRejectsHopelessFast(t *testing.T) {
	// сервер «как DPI»: соединение зависает; безнадёжная стратегия должна отсеяться за fast, а не за checkTimeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	oc := checkTimeout
	checkTimeout = 5 * time.Second
	defer func() { checkTimeout = oc }()
	ts := []Target{{"d", "a", srv.URL + "/a"}, {"d", "b", srv.URL + "/b"}}
	t0 := time.Now()
	res := tuneChecks(context.Background(), ts, 300*time.Millisecond)
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("отсев занял %v, ожидали около 300мс", el)
	}
	if countOK(res) != 0 {
		t.Fatalf("неожиданный успех: %+v", res)
	}
}

func TestTuneChecksKeepsSlowButWorking(t *testing.T) {
	// /a отвечает сразу, /b — через 600мс (дольше fast=300мс, но короче полного таймаута): должен засчитаться
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/b") {
			select {
			case <-time.After(600 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	oc := checkTimeout
	checkTimeout = 3 * time.Second
	defer func() { checkTimeout = oc }()
	ts := []Target{{"d", "a", srv.URL + "/a"}, {"d", "b", srv.URL + "/b"}}
	res := tuneChecks(context.Background(), ts, 300*time.Millisecond)
	if countOK(res) != 2 {
		t.Fatalf("медленная рабочая цель потеряна: %+v", res)
	}
	if !res[0].OK || res[0].Ms > 300 {
		t.Fatalf("быстрая цель: %+v", res[0])
	}
}

func TestTuneOfHopelessStrategiesIsFast(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	_ = os.WriteFile(state, []byte("bad"), 0o644)
	data := fakeZapret(t, state, map[string]string{"general": "bad", "general (ALT)": "bad", "general (ALT2)": "bad", "general (ALT3)": "bad"})
	srv := fakeNet(t, state)
	mux := http.NewServeMux()
	mux.Handle("/probe-always", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("up")) }))
	mux.Handle("/", srv.Config.Handler)
	srv.Config.Handler = mux
	defer setupTestTiming(srv.URL)()
	checkTimeout = 2 * time.Second // раньше каждая безнадёжная стратегия ждала бы весь этот таймаут

	a := newApp(data, 0)
	defer a.shutdown()
	t0 := time.Now()
	_ = a.startTune()
	waitTune(t, a)
	el := time.Since(t0)
	// база (один полный таймаут 2с) + 4 x (старт 0.3 + пауза 0.1 + отсев 0.3) ≈ 5с; по-старому было бы ≈ 12с
	if el > 8*time.Second {
		t.Fatalf("подбор занял %v — быстрый отсев не работает", el)
	}
}
