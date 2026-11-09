package app

import (
	"bufio"
	"fmt"
	"gust/internal/platform"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var startupWait = 1 * time.Second

// Engine управляет процессом winws.
type Engine struct {
	app *App

	mu       sync.Mutex
	cmd      *exec.Cmd
	done     chan struct{}
	gen      int
	running  bool
	strategy string
	since    time.Time
	lastErr  string
	want     bool
	crashes  []time.Time
	tail     []string
}

func newEngine(a *App) *Engine { return &Engine{app: a} }

type EngineState struct {
	Running  bool   `json:"running"`
	Strategy string `json:"strategy"`
	Since    int64  `json:"since"`
	LastErr  string `json:"last_err"`
}

func (e *Engine) State() EngineState {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := EngineState{Running: e.running, Strategy: e.strategy, LastErr: e.lastErr}
	if e.running {
		st.Since = e.since.Unix()
	}
	return st
}

func (e *Engine) addTail(line string) {
	e.mu.Lock()
	e.tail = append(e.tail, line)
	if len(e.tail) > 12 {
		e.tail = e.tail[len(e.tail)-12:]
	}
	e.mu.Unlock()
	e.app.logf("winws: %s", line)
}

func friendlyWinwsError(tail []string) string {
	all := strings.ToLower(strings.Join(tail, "\n"))
	switch {
	case strings.Contains(all, "access is denied") || strings.Contains(all, "error 5"):
		return "Нет прав администратора для драйвера WinDivert."
	case strings.Contains(all, "1275") || strings.Contains(all, "blocked") || strings.Contains(all, "signature"):
		return "Драйвер WinDivert заблокирован (антивирус, Secure Boot или «Целостность памяти»). Добавьте папку Gust в исключения антивируса."
	case strings.Contains(all, "1058") || strings.Contains(all, "already") || strings.Contains(all, "1117"):
		return "WinDivert занят другой программой. Закройте другие обходчики (GoodbyeDPI, другой zapret, VPN) и повторите."
	case strings.Contains(all, "file") && strings.Contains(all, "not found"):
		return "Не найден файл из сборки zapret. Переустановите сборку."
	}
	if len(tail) > 0 {
		return tail[len(tail)-1]
	}
	return "winws завершился сразу после запуска"
}

// Start запускает стратегию. want=true — держать запущенным (перезапуск при падении).
func (e *Engine) Start(s Strategy, want bool) error {
	wait := startupWait
	e.Stop()
	root := e.app.zapretRoot()
	// Защита: запускаем только winws.exe из папки сборки. Если подменённый .bat ссылается
	// на другой exe, мы бы запустили его с правами администратора — не даём.
	if !exeAllowed(root, s.Exe) {
		e.mu.Lock()
		e.lastErr = "стратегия ссылается на посторонний исполняемый файл"
		e.mu.Unlock()
		return fmt.Errorf("небезопасный путь к winws: %s", s.Exe)
	}
	ensureLists(root, s.Args)
	e.app.logf("запускаю стратегию «%s»", s.Name)

	cmd := exec.Command(s.Exe, s.Args...)
	cmd.Dir = filepath.Dir(s.Exe)
	platform.HideWindow(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			if t := strings.TrimSpace(sc.Text()); t != "" {
				e.addTail(t)
			}
		}
	}()

	e.mu.Lock()
	e.tail = nil
	e.mu.Unlock()
	if err := cmd.Start(); err != nil {
		_ = pw.Close()
		e.mu.Lock()
		e.lastErr = err.Error()
		e.mu.Unlock()
		return fmt.Errorf("не удалось запустить winws: %w", err)
	}
	done := make(chan struct{})
	e.mu.Lock()
	e.gen++
	gen := e.gen
	e.cmd, e.done = cmd, done
	e.running, e.strategy, e.since, e.lastErr, e.want = true, s.Name, time.Now(), "", want
	e.mu.Unlock()

	go func() {
		_ = cmd.Wait()
		_ = pw.Close()
		close(done)
		e.onExit(gen, s)
	}()

	select {
	case <-done:
		e.mu.Lock()
		if e.gen != gen { // пока стартовали, нас остановили или заменили другой стратегией
			e.mu.Unlock()
			return fmt.Errorf("запуск прерван")
		}
		tail := append([]string(nil), e.tail...)
		e.running, e.want = false, false
		msg := friendlyWinwsError(tail)
		e.lastErr = msg
		e.mu.Unlock()
		return fmt.Errorf("%s", msg)
	case <-time.After(wait):
	}
	return nil
}

func (e *Engine) onExit(gen int, s Strategy) {
	e.mu.Lock()
	if gen != e.gen { // остановили мы сами или уже запущена другая копия
		e.mu.Unlock()
		return
	}
	now := time.Now()
	if now.Sub(e.since) < startupWait { // ранний выход разбирает сам Start
		e.mu.Unlock()
		return
	}
	e.running = false
	want := e.want
	e.crashes = append(e.crashes, now)
	var recent []time.Time
	for _, t := range e.crashes {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	e.crashes = recent
	tooMany := len(recent) > 3
	if want && tooMany {
		e.want = false
		e.lastErr = "winws постоянно падает: " + friendlyWinwsError(e.tail)
	}
	e.mu.Unlock()
	if !want {
		return
	}
	if tooMany {
		e.app.logf("winws падает слишком часто, перезапуск отключён")
		return
	}
	e.app.logf("winws завершился сам, перезапускаю")
	time.Sleep(2 * time.Second)
	e.mu.Lock()
	stillWant := e.want && e.gen == gen
	e.mu.Unlock()
	if stillWant {
		if err := e.Start(s, true); err != nil {
			e.app.logf("перезапуск не удался: %v", err)
		}
	}
}

func (e *Engine) Stop() {
	e.mu.Lock()
	cmd, done := e.cmd, e.done
	e.want = false
	e.gen++
	e.running = false
	e.cmd, e.done = nil, nil
	e.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	platform.KillWinws()
	platform.CleanupDivert(false)
}

// Alive сообщает, что процесс ещё работает (для проверок во время подбора).
func (e *Engine) Alive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}
