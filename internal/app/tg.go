package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"gust/internal/platform"
	"gust/internal/tgproxy"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// Telegram режут по IP дата-центров, поэтому winws ему не помогает.
// Встроенный прокси (internal/tgproxy) уводит трафик в WebSocket к kwsN.web.telegram.org.

const oldTGImage = "TgWsProxy_windows.exe" // отдельная программа, которую мы раньше скачивали

type tgOut struct {
	Running  bool                  `json:"running"`
	Link     string                `json:"link"`
	Port     int                   `json:"port"`
	Err      string                `json:"err"`
	Stats    tgproxy.StatsSnapshot `json:"stats"`
	OldProxy bool                  `json:"old_proxy"` // запущен старый TgWsProxy и мешает
}

// tgSecret — постоянный секрет: Telegram запоминает прокси вместе с ним.
// Если раньше стоял TG WS Proxy, берём его секрет — тогда Telegram перенастраивать не придётся.
func (a *App) tgSecret() string {
	s := a.settings()
	if tgproxy.ValidSecret(s.TGSecret) {
		return s.TGSecret
	}
	sec := oldTGSecret()
	if sec != "" {
		a.logf("Telegram: взят секрет от прежнего TG WS Proxy — переподключать Telegram не нужно")
	} else {
		sec = tgproxy.NewSecret()
	}
	a.updateSettings(func(st *Settings) { st.TGSecret = sec })
	return sec
}

func oldTGSecret() string {
	dir := os.Getenv("APPDATA")
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "TgWsProxy", "config.json"))
	if err != nil {
		return ""
	}
	var c struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal(b, &c) != nil || !tgproxy.ValidSecret(c.Secret) {
		return ""
	}
	return c.Secret
}

func (a *App) tgStart() error {
	a.tgMu.Lock()
	defer a.tgMu.Unlock()
	if a.tgs != nil {
		return nil
	}
	s, err := tgproxy.Start(tgproxy.Config{
		Port:     tgproxy.DefaultPort,
		Secret:   a.tgSecret(),
		PoolSize: 4,
		Logf:     a.logf,
	})
	if err != nil {
		err = friendlyListenErr(err)
		a.tgErr = err.Error()
		a.logf("Telegram-прокси: %v", err)
		return err
	}
	a.tgs, a.tgErr = s, ""
	a.updateSettings(func(st *Settings) { st.TGEnabled = true })
	a.logf("Telegram-прокси запущен на 127.0.0.1:%d", tgproxy.DefaultPort)
	return nil
}

func friendlyListenErr(err error) error {
	if errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, syscall.Errno(10048)) { // WSAEADDRINUSE
		if runtime.GOOS == "windows" && platform.ProcRunning(oldTGImage) {
			return fmt.Errorf("порт %d занят старым TG WS Proxy. Закройте его (значок у часов → «Выход»): он больше не нужен", tgproxy.DefaultPort)
		}
		return fmt.Errorf("порт %d занят другой программой", tgproxy.DefaultPort)
	}
	return err
}

// tgStop останавливает прокси; remember=false — при выходе из программы (состояние «включён» сохраняется).
func (a *App) tgStop(remember bool) {
	a.tgMu.Lock()
	s := a.tgs
	a.tgs = nil
	a.tgMu.Unlock()
	if s != nil {
		s.Stop()
		a.logf("Telegram-прокси остановлен")
	}
	if remember {
		a.updateSettings(func(st *Settings) { st.TGEnabled = false })
	}
}

// tgOpen передаёт Telegram ссылку на прокси (Telegram спросит «Подключить?»).
func (a *App) tgOpen() error {
	if err := a.tgStart(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return fmt.Errorf("работает только в Windows")
	}
	platform.OpenAsUser(tgproxy.Link(tgproxy.DefaultPort, a.tgSecret()))
	return nil
}

func (a *App) tgState(stale bool) tgOut {
	a.tgMu.Lock()
	s := a.tgs
	out := tgOut{Running: s != nil, Port: tgproxy.DefaultPort, Err: a.tgErr}
	a.tgMu.Unlock()
	out.Link = tgproxy.Link(tgproxy.DefaultPort, a.settings().TGSecret)
	if s != nil {
		out.Stats = s.Stats()
	} else if runtime.GOOS == "windows" {
		out.OldProxy = a.cachedBool("oldtg", 10*time.Second, stale, func() bool { return platform.ProcRunning(oldTGImage) })
	}
	return out
}
