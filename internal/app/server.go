package app

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"gust/internal/platform"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

//go:embed ui.html
var uiHTML string

type apiResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.guard(false, a.handleIndex))
	mux.HandleFunc("/api/state", a.guard(true, a.handleState))
	mux.HandleFunc("/api/events", a.guard(false, a.handleEvents)) // токен проверяет сам обработчик (в адресе)
	mux.HandleFunc("/api/show", a.guard(false, a.handleShow))
	post := func(path string, f func(r *http.Request) error) {
		mux.HandleFunc(path, a.guard(true, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST only", http.StatusMethodNotAllowed)
				return
			}
			resp := apiResp{OK: true}
			if err := f(r); err != nil {
				resp = apiResp{Error: err.Error()}
			}
			writeJSON(w, resp)
		}))
	}
	post("/api/start", func(*http.Request) error {
		if a.tuning() {
			return fmt.Errorf("идёт подбор — дождитесь конца или остановите его")
		}
		return a.startSelected()
	})
	post("/api/stop", func(*http.Request) error {
		if a.tuning() {
			a.cancelTune() // подбор сам остановит winws и завершится
			return nil
		}
		a.eng.Stop()
		return nil
	})
	post("/api/tune", func(*http.Request) error { return a.startTune() })
	post("/api/tune/cancel", func(*http.Request) error { a.cancelTune(); return nil })
	post("/api/check", func(*http.Request) error { go a.CheckNow(); return nil })
	post("/api/setup/install", func(*http.Request) error {
		a.mu.Lock()
		busy := a.setup.Busy
		a.mu.Unlock()
		if busy {
			return fmt.Errorf("уже скачивается")
		}
		go a.installZapret()
		return nil
	})
	post("/api/select", func(r *http.Request) error {
		var in struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			return err
		}
		if a.tuning() {
			return fmt.Errorf("идёт подбор")
		}
		s, ok := a.findStrategy(in.Name)
		if !ok {
			return fmt.Errorf("нет такой стратегии")
		}
		if err := a.eng.Start(s, true); err != nil {
			return err
		}
		a.updateSettings(func(st *Settings) { st.Selected = s.Name })
		return nil
	})
	post("/api/settings", a.handleSettings)
	post("/api/autostart", func(r *http.Request) error {
		var in struct{ Enabled bool }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			return err
		}
		err := platform.SetAutostart(Name, in.Enabled)
		a.invalidateCache("autostart")
		return err
	})
	post("/api/discord/check", func(*http.Request) error { go a.CheckDiscord(); return nil })
	post("/api/discord/tune", func(*http.Request) error { return a.startTuneScope("discord") })
	post("/api/discord/next", func(*http.Request) error { _, err := a.voiceNext(); return err })
	post("/api/discord/restart", func(*http.Request) error { return a.restartDiscord() })
	post("/api/tg/start", func(*http.Request) error { return a.tgStart() })
	post("/api/tg/stop", func(*http.Request) error { a.tgStop(true); return nil })
	post("/api/tg/open", func(*http.Request) error { return a.tgOpen() })
	post("/api/openurl", func(r *http.Request) error {
		var in struct{ URL string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in); err != nil {
			return err
		}
		u, err := url.Parse(in.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(in.URL) > 2048 {
			return fmt.Errorf("только ссылки https")
		}
		platform.OpenBrowser(u.String())
		return nil
	})
	post("/api/quit", func(*http.Request) error {
		go func() { time.Sleep(200 * time.Millisecond); a.requestQuit() }()
		return nil
	})
	return mux
}

// guard защищает локальный API: только свой Host (против DNS-rebinding) и токен страницы
// (против запросов с чужих сайтов — токен им прочитать нельзя).
func (a *App) guard(needToken bool, h http.HandlerFunc) http.HandlerFunc {
	okHosts := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", a.port): true,
		fmt.Sprintf("localhost:%d", a.port): true,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !okHosts[r.Host] {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		if needToken {
			tok := r.Header.Get("X-GU-Token")
			if len(tok) != len(a.token) ||
				subtle.ConstantTimeCompare([]byte(tok), []byte(a.token)) != 1 {
				http.Error(w, "bad token", http.StatusForbidden)
				return
			}
		}
		h(w, r)
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(strings.NewReplacer("{{TOKEN}}", a.token, "{{LANG}}", a.lang()).Replace(uiHTML)))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

type settingsIn struct {
	GameFilter      *bool           `json:"game_filter"`
	AutoRetune      *bool           `json:"auto_retune"`
	ExtraStrategies *bool           `json:"extra_strategies"`
	AutoStartBypass *bool           `json:"auto_start_bypass"`
	DiscordDirect   *bool           `json:"discord_direct"`
	Groups          map[string]bool `json:"groups"`
	Lang            *string         `json:"lang"`
	Engine          *string         `json:"engine"`
}

func (a *App) handleSettings(r *http.Request) error {
	var in settingsIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return err
	}
	old := a.settings()
	a.updateSettings(func(s *Settings) {
		if in.GameFilter != nil {
			s.GameFilter = *in.GameFilter
		}
		if in.AutoRetune != nil {
			s.AutoRetune = *in.AutoRetune
		}
		if in.ExtraStrategies != nil {
			s.ExtraStrategies = *in.ExtraStrategies
		}
		if in.DiscordDirect != nil {
			s.DiscordDirect = *in.DiscordDirect
		}
		if in.AutoStartBypass != nil {
			s.AutoStartBypass = *in.AutoStartBypass
		}
		if in.Engine != nil && (*in.Engine == "zapret" || *in.Engine == "gust" || *in.Engine == "both") {
			s.Engine = *in.Engine
			s.EnginePicked = true
		}
		if in.Lang != nil && (*in.Lang == "auto" || *in.Lang == "ru" || *in.Lang == "en") {
			s.Lang = *in.Lang
		}
		for g, v := range in.Groups {
			if _, ok := serviceByID(g); ok {
				s.Groups[g] = v
			}
		}
	})
	if len(in.Groups) > 0 {
		go a.applyServiceHosts()
	}
	if in.Lang != nil {
		a.applyTrayLang()
	}
	// игровой фильтр меняет аргументы winws — перезапускаем, если он работает
	if in.GameFilter != nil && *in.GameFilter != old.GameFilter && a.eng.Alive() {
		return a.startSelected()
	}
	return nil
}

type stateOut struct {
	Version    string      `json:"version"`
	OS         string      `json:"os"`
	Admin      bool        `json:"admin"`
	SetupReady bool        `json:"setup_ready"`
	ZapDir     string      `json:"zap_dir"`
	Setup      SetupState  `json:"setup"`
	Engine     EngineState `json:"engine"`
	Strategies []string    `json:"strategies"`
	Settings   Settings    `json:"settings"`
	Tune       TuneState   `json:"tune"`
	Checks     CheckState  `json:"checks"`
	Targets    []Target    `json:"targets"`
	Autostart  bool        `json:"autostart"`
	TG         tgOut       `json:"tg"`
	Discord    discordOut  `json:"discord"`
	Log        []string    `json:"log"`
	Services   []Service   `json:"services"`
	EngineOK   bool        `json:"engine_available"`
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	var names []string
	for _, s := range a.loadStrategies() {
		names = append(names, s.Name)
	}
	set := a.settings()
	a.mu.Lock()
	out := stateOut{
		Version:    Version,
		OS:         runtime.GOOS,
		Admin:      platform.IsAdmin(),
		SetupReady: len(names) > 0,
		ZapDir:     a.zapDir,
		Setup:      a.setup,
		Strategies: names,
		Settings:   set,
		Tune:       a.tune,
		Checks:     a.checks,
	}
	out.Tune.Results = append([]TuneResult(nil), a.tune.Results...)
	out.Checks.Results = append([]CheckResult(nil), a.checks.Results...)
	a.mu.Unlock()
	out.Engine = a.eng.State()
	out.Targets = a.activeTargets()
	// schtasks/tasklist запускают процессы: кешируем, а во время подбора не обновляем вовсе,
	// чтобы не плодить запуск процессов на каждый опрос и не мешать winws
	tuning := a.tuning()
	out.Autostart = a.cachedBool("autostart", 8*time.Second, tuning,
		func() bool { return platform.AutostartEnabled(Name) })
	out.TG = a.tgState(tuning)
	out.Discord = a.discordState(tuning)
	out.Log = a.logTail(80)
	out.Services = services
	out.EngineOK = a.engineExe() != ""
	writeJSON(w, out)
}
