package app

import (
	"encoding/json"
	"fmt"
	"gust/internal/platform"
	"gust/internal/tgproxy"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Settings struct {
	Selected        string          `json:"selected"`
	GameFilter      bool            `json:"game_filter"`
	AutoRetune      bool            `json:"auto_retune"`
	ExtraStrategies bool            `json:"extra_strategies"`
	AutoStartBypass bool            `json:"auto_start_bypass"`
	Groups          map[string]bool `json:"groups"`
	ZapretVersion   string          `json:"zapret_version"`
	TGSecret        string          `json:"tg_secret"`
	DiscordDirect   bool            `json:"discord_direct"` // запускать Discord мимо системного прокси (VPN)
	TGEnabled       bool            `json:"tg_enabled"`     // прокси Telegram включён — поднимаем при запуске
	LastTune        int64           `json:"last_tune"`
	Lang            string          `json:"lang"`        // auto, ru, en
	AddedHosts      []string        `json:"added_hosts"` // домены, которые программа сама дописала в list-general-user.txt
}

func defaultSettings() Settings {
	return Settings{
		AutoRetune:      true,
		ExtraStrategies: true,
		AutoStartBypass: true,
		Lang:            "auto",
		Groups:          fillGroups(nil),
	}
}

type SetupState struct {
	Busy bool   `json:"busy"`
	Msg  string `json:"msg"`
	Err  string `json:"err"`
}

type TuneResult struct {
	Strategy string `json:"strategy"`
	Passed   int    `json:"passed"`
	Total    int    `json:"total"`
	Note     string `json:"note,omitempty"`
}

type TuneState struct {
	Running bool         `json:"running"`
	Scope   string       `json:"scope"` // "" — все сервисы из настроек, "discord" — только Discord
	Idx     int          `json:"idx"`
	Total   int          `json:"total"`
	Current string       `json:"current"`
	Msg     string       `json:"msg"`
	Results []TuneResult `json:"results"`
}

type CheckState struct {
	Running  bool          `json:"running"`
	At       int64         `json:"at"`
	Internet bool          `json:"internet"`
	Results  []CheckResult `json:"results"`
}

type App struct {
	dataDir string
	zapDir  string
	port    int
	token   string
	quit    chan struct{}
	quitO   sync.Once

	skipLogged sync.Map // имена .bat, про которые уже написали в журнал

	mu         sync.Mutex
	set        Settings
	setup      SetupState
	tune       TuneState
	tuneCancel chan struct{}
	checks     CheckState
	dchecks    CheckState // проверки вкладки Discord (все его адреса, независимо от настроек)
	failStreak int

	logMu   sync.Mutex
	logs    []string
	logFile *os.File

	eng   *Engine
	pages *pageHub // открытые вкладки интерфейса

	uiMu          sync.Mutex
	uiChild       *platform.Child // окно интерфейса (отдельный процесс)
	uiBrowserOnly bool            // окно на этом ПК не запускается — дальше только браузер

	tgMu  sync.Mutex
	tgs   *tgproxy.Server
	tgErr string
}

func newApp(dataDir string, port int) *App {
	a := &App{
		dataDir: dataDir,
		zapDir:  filepath.Join(dataDir, "zapret"),
		port:    port,
		token:   randHex(16),
		quit:    make(chan struct{}),
		set:     defaultSettings(),
	}
	a.openLog()
	a.loadSettings()
	a.pages = newPageHub()
	a.eng = newEngine(a)
	return a
}

type boolCacheEntry struct {
	v  bool
	at time.Time
}

var (
	boolCacheMu sync.Mutex
	boolCache   = map[string]boolCacheEntry{}
)

// cachedBool кеширует результат дорогой проверки (schtasks/tasklist запускают процессы).
// allowStale=true возвращает последнее известное значение без обновления — во время подбора,
// чтобы не плодить запуск процессов на каждый опрос страницы и не мешать winws.
func (a *App) cachedBool(key string, ttl time.Duration, allowStale bool, f func() bool) bool {
	boolCacheMu.Lock()
	e, ok := boolCache[key]
	boolCacheMu.Unlock()
	if ok && (allowStale || time.Since(e.at) < ttl) {
		return e.v
	}
	v := f()
	boolCacheMu.Lock()
	boolCache[key] = boolCacheEntry{v, time.Now()}
	boolCacheMu.Unlock()
	return v
}

func (a *App) invalidateCache(key string) {
	boolCacheMu.Lock()
	delete(boolCache, key)
	boolCacheMu.Unlock()
}

func (a *App) openLog() {
	p := filepath.Join(a.dataDir, "log.txt")
	if st, err := os.Stat(p); err == nil && st.Size() > 1<<20 {
		_ = os.Remove(p)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		a.logFile = f
	}
}

func (a *App) logf(format string, args ...any) {
	line := time.Now().Format("15:04:05") + " " + fmt.Sprintf(format, args...)
	a.logMu.Lock()
	defer a.logMu.Unlock()
	a.logs = append(a.logs, line)
	if len(a.logs) > 300 {
		a.logs = a.logs[len(a.logs)-300:]
	}
	if a.logFile != nil {
		fmt.Fprintln(a.logFile, time.Now().Format("2006-01-02 ")+line)
	}
}

func (a *App) logTail(n int) []string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	if len(a.logs) <= n {
		return append([]string(nil), a.logs...)
	}
	return append([]string(nil), a.logs[len(a.logs)-n:]...)
}

func (a *App) cfgPath() string { return filepath.Join(a.dataDir, "config.json") }

func (a *App) loadSettings() {
	b, err := os.ReadFile(a.cfgPath())
	if err != nil {
		return
	}
	s := defaultSettings()
	if json.Unmarshal(b, &s) != nil {
		return
	}
	s.Groups = fillGroups(s.Groups)
	a.set = s
}

// saveSettings вызывается при удержании a.mu.
func (a *App) saveSettingsLocked() {
	b, _ := json.MarshalIndent(a.set, "", "  ")
	tmp := a.cfgPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, a.cfgPath())
	}
}

func (a *App) settings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.set
	s.Groups = map[string]bool{}
	for k, v := range a.set.Groups {
		s.Groups[k] = v
	}
	return s
}

func (a *App) updateSettings(f func(s *Settings)) {
	a.mu.Lock()
	f(&a.set)
	a.saveSettingsLocked()
	a.mu.Unlock()
}

// boot вызывается один раз после запуска HTTP-сервера.
func (a *App) boot() {
	platform.KillWinws() // остатки прошлого запуска, если приложение падало
	go a.healthLoop()
	s := a.settings()
	if platform.AutostartEnabled(Name) {
		// обновляем задачу: после переезда exe или со старыми настройками она иначе не сработает
		go func() { _ = platform.SetAutostart(Name, true) }()
	}
	if s.TGEnabled {
		go func() { _ = a.tgStart() }()
	}
	_, _ = a.syncServiceHosts()
	if s.AutoStartBypass && a.zapretRoot() != "" {
		go func() {
			if err := a.startSelected(); err != nil {
				a.logf("автозапуск обхода: %v", err)
				return
			}
			// быстрая проверка после старта: сменился провайдер/сеть — подбираем заново
			time.Sleep(15 * time.Second)
			if a.settings().AutoRetune && a.degraded() {
				a.logf("после запуска обход не работает — подбираю заново")
				_ = a.startTune()
			}
		}()
	}
}

func (a *App) requestQuit() { a.quitO.Do(func() { close(a.quit) }) }

func (a *App) shutdown() {
	a.eng.Stop()
	a.tgStop(false)
	platform.CleanupDivert(true)
	a.logf("выход")
}
