package app

import (
	"gust/internal/platform"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVoiceOrder(t *testing.T) {
	names := []string{"general", "ALT", "ALT2", "ALT3", "GU-01"}
	res := []TuneResult{
		{Strategy: "general", Passed: 1, Total: 4},
		{Strategy: "ALT2", Passed: 4, Total: 4},
		{Strategy: "gone", Passed: 4, Total: 4}, // стратегии уже нет в сборке
		{Strategy: "GU-01", Passed: 4, Total: 4},
	}
	got := voiceOrder(names, res)
	want := []string{"ALT2", "GU-01", "general", "ALT", "ALT3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

// Подбор «только под Discord» не должен смотреть на YouTube, который тут не открывается никогда.
func TestTuneScopeDiscordIgnoresOtherServices(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	_ = os.WriteFile(state, []byte("bad"), 0o644)
	data := fakeZapret(t, state, map[string]string{"general": "bad", "general (ALT)": "good"})
	srv := fakeNet(t, state)
	mux := http.NewServeMux()
	mux.Handle("/probe-always", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("up")) }))
	mux.Handle("/never", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	mux.Handle("/", srv.Config.Handler)
	srv.Config.Handler = mux
	defer setupTestTiming(srv.URL)()
	targetsOverride = append(targetsOverride, Target{"youtube", "yt", srv.URL + "/never"})

	a := newApp(data, 0)
	defer a.shutdown()
	if err := a.startTuneScope("discord"); err != nil {
		t.Fatal(err)
	}
	waitTune(t, a)
	a.mu.Lock()
	res, scope := a.tune.Results, a.tune.Scope
	a.mu.Unlock()
	if scope != "discord" || a.settings().Selected != "general (ALT)" {
		t.Fatalf("scope=%q selected=%q", scope, a.settings().Selected)
	}
	last := res[len(res)-1]
	if last.Total != 2 || last.Passed != 2 {
		t.Fatalf("в подбор под Discord попал чужой сервис: %+v", res)
	}
}

func TestVoiceNextCycles(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	data := fakeZapret(t, state, map[string]string{"general": "good", "general (ALT)": "good", "general (ALT2)": "good"})
	defer setupTestTiming("http://127.0.0.1:1")()
	a := newApp(data, 0)
	defer a.shutdown()
	a.updateSettings(func(s *Settings) { s.Selected = "general" })
	var seen []string
	for i := 0; i < 4; i++ {
		n, err := a.voiceNext()
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, n)
		if !a.eng.Alive() || a.settings().Selected != n {
			t.Fatalf("после переключения на %q обход не работает", n)
		}
	}
	if strings.Join(seen, "|") != "general (ALT)|general (ALT2)|general|general (ALT)" {
		t.Fatalf("порядок: %v", seen)
	}
}

func TestPlanDiscord(t *testing.T) {
	files := map[string]bool{
		"/L/Discord/Update.exe": true,
		"/R/Microsoft/Windows/Start Menu/Programs/Discord Inc/Discord.lnk": true,
		"/L/DiscordPTB/Update.exe": true,
	}
	has := func(p string) bool { return files[filepath.ToSlash(p)] }

	// запущен обычный Discord: путь берём у процесса
	l, ok := planDiscord([]platform.Proc{{PID: 1, Name: "Discord.exe", Exe: "/L/Discord/app-1.0.9200/Discord.exe"}}, "/R", "/L", has)
	if !ok || filepath.ToSlash(l.updater) != "/L/Discord/Update.exe" || l.exeName != "Discord.exe" || l.lnk == "" {
		t.Fatalf("%+v", l)
	}
	// запущен PTB, путь к процессу прочитать не дали — ищем по папкам, ярлык обычного Discord не берём
	l, ok = planDiscord([]platform.Proc{{PID: 2, Name: "DiscordPTB.exe"}}, "/R", "/L", has)
	if !ok || filepath.ToSlash(l.updater) != "/L/DiscordPTB/Update.exe" || l.lnk != "" || l.exeName != "DiscordPTB.exe" {
		t.Fatalf("PTB: %+v", l)
	}
	// не запущен — стандартные папки
	l, ok = planDiscord(nil, "/R", "/L", has)
	if !ok || l.exeName != "Discord.exe" || l.lnk == "" {
		t.Fatalf("не запущен: %+v", l)
	}
	// ничего нет
	if _, ok := planDiscord(nil, "", "", func(string) bool { return false }); ok {
		t.Fatal("нашёл несуществующий Discord")
	}
}

func TestDirectScript(t *testing.T) {
	env := map[string]string{"LOCALAPPDATA": `C:\Users\Пользователь\AppData\Local`, "APPDATA": `C:\Users\Пользователь\AppData\Roaming`}
	s := directScript(discordLaunch{exeName: "Discord.exe", updater: `C:\Users\Пользователь\AppData\Local\Discord\Update.exe`}, env)
	want := "@echo off\r\nstart \"\" \"%LOCALAPPDATA%\\Discord\\Update.exe\" --processStart \"Discord.exe\" --process-start-args \"--no-proxy-server\"\r\n"
	if s != want {
		t.Fatalf("%q", s)
	}
	// путь вне профиля с кириллицей — переключаем консоль на UTF-8
	s = directScript(discordLaunch{exePath: `D:\Программы\Discord.exe`}, env)
	if !strings.Contains(s, "chcp 65001") || !strings.Contains(s, `"D:\Программы\Discord.exe" --no-proxy-server`) {
		t.Fatalf("%q", s)
	}
	// похожий, но другой префикс не подменяем
	if p := envPath(`C:\Users\Пользователь\AppData\LocalX\a.exe`, env); strings.Contains(p, "%") {
		t.Fatal(p)
	}
}
