package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"gust/internal/platform"
	"gust/internal/tgproxy"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Telegram режут по IP дата-центров, поэтому winws ему не помогает.
// Встроенный прокси (engine/src/tg, Rust) уводит трафик в WebSocket к kwsN.web.telegram.org.

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

// tgRun — запущенный процесс прокси (gust-tg.exe tgproxy): строки его вывода — «ready», «error: …», «log: …», «stats: {json}».
type tgRun struct {
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	done     chan struct{}
	stopping atomic.Bool

	mu    sync.Mutex
	stats tgproxy.StatsSnapshot
}

func (r *tgRun) snapshot() tgproxy.StatsSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stats
}

func (r *tgRun) stop() {
	r.stopping.Store(true)
	_ = r.stdin.Close()
	if r.cmd.Process != nil {
		_ = r.cmd.Process.Kill()
	}
	select {
	case <-r.done:
	case <-time.After(3 * time.Second):
	}
}

func (a *App) tgStart() error {
	a.tgMu.Lock()
	defer a.tgMu.Unlock()
	if a.tgs != nil {
		return nil
	}
	exe := a.tgExe()
	if exe == "" {
		err := errors.New("в этой сборке нет встроенного движка — прокси Telegram недоступен")
		a.tgErr = err.Error()
		a.logf("Telegram-прокси: %v", err)
		return err
	}
	cmd := exec.Command(exe, "tgproxy", "--port", strconv.Itoa(tgproxy.DefaultPort), "--secret", a.tgSecret(), "--pool", "4")
	cmd.Dir = filepath.Dir(exe)
	platform.HideWindow(cmd)
	stdin, err := cmd.StdinPipe() // закроется вместе с нами — прокси сам завершится
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		a.tgErr = err.Error()
		a.logf("Telegram-прокси: %v", err)
		return err
	}
	r := &tgRun{cmd: cmd, stdin: stdin, done: make(chan struct{})}
	first := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "ready":
				select {
				case first <- nil:
				default:
				}
			case strings.HasPrefix(line, "error: "):
				select {
				case first <- errors.New(strings.TrimPrefix(line, "error: ")):
				default:
				}
			case strings.HasPrefix(line, "log: "):
				a.logf("%s", strings.TrimPrefix(line, "log: "))
			case strings.HasPrefix(line, "stats: "):
				var st tgproxy.StatsSnapshot
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "stats: ")), &st) == nil {
					r.mu.Lock()
					r.stats = st
					r.mu.Unlock()
				}
			}
		}
		_ = cmd.Wait()
		close(r.done)
		if r.stopping.Load() {
			return
		}
		select {
		case first <- errors.New("процесс прокси завершился"):
		default:
		}
		a.tgMu.Lock()
		if a.tgs == r {
			a.tgs, a.tgErr = nil, "процесс прокси неожиданно завершился"
			a.logf("Telegram-прокси: процесс неожиданно завершился")
		}
		a.tgMu.Unlock()
	}()

	select {
	case err = <-first:
	case <-time.After(10 * time.Second):
		err = errors.New("прокси не запустился за 10 секунд")
	}
	if err != nil {
		r.stop()
		err = friendlyListenErr(err)
		a.tgErr = err.Error()
		a.logf("Telegram-прокси: %v", err)
		return err
	}
	a.tgs, a.tgErr = r, ""
	a.updateSettings(func(st *Settings) { st.TGEnabled = true })
	a.logf("Telegram-прокси запущен на 127.0.0.1:%d", tgproxy.DefaultPort)
	return nil
}

func friendlyListenErr(err error) error {
	if err.Error() == "addr_in_use" {
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
		s.stop()
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
		out.Stats = s.snapshot()
	} else if runtime.GOOS == "windows" {
		out.OldProxy = a.cachedBool("oldtg", 10*time.Second, stale, func() bool { return platform.ProcRunning(oldTGImage) })
	}
	return out
}
