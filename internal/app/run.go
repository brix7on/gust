package app

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"gust/internal/platform"
)

// Options — параметры запуска из командной строки.
type Options struct {
	DataDir    string
	Port       int
	Background bool
	NoAdmin    bool
}

// DefaultDataDir — папка данных по умолчанию. На Windows это ASCII-путь без пробелов и
// кириллицы (winws и драйвер к этому чувствительны), на остальных ОС — под домашней папкой.
func DefaultDataDir() string {
	if v := os.Getenv("GU_DATA"); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, Name)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "."+Name)
}

// Run поднимает приложение: права, папка данных, локальный веб-интерфейс, автозапуск обхода.
func Run(opt Options) {
	addr := fmt.Sprintf("127.0.0.1:%d", opt.Port)
	// Уже запущена другая копия — не просим права и не плодим окна: работающая копия сама выводит
	// окно вперёд (или открывает его). Проверка до UAC, чтобы Windows не спрашивал зря.
	if !opt.Background {
		platform.AllowForeground() // право выводить окно вперёд есть у нас, а не у работающей копии
		if running, pageOpen := showRunning(addr); running {
			if !pageOpen {
				platform.OpenBrowser("http://" + addr + "/")
			}
			return
		}
	}
	if !opt.NoAdmin && !platform.IsAdmin() {
		// WinDivert без админа не работает: перезапускаемся с запросом UAC.
		if platform.RelaunchAsAdmin(os.Args[1:]) {
			return
		}
	}

	if err := os.MkdirAll(opt.DataDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "не могу создать папку данных:", err)
		os.Exit(1)
	}
	platform.SecureDir(opt.DataDir)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Порт занят (копия только что стартовала или это не наша программа).
		if !opt.Background {
			if running, pageOpen := showRunning(addr); !running || !pageOpen {
				platform.OpenBrowser("http://" + addr + "/")
			}
		}
		return
	}

	a := newApp(opt.DataDir, opt.Port)
	a.logf("%s %s запущен (admin=%v, background=%v, data=%s)", Name, Version, platform.IsAdmin(), opt.Background, opt.DataDir)

	defer func() {
		if r := recover(); r != nil {
			a.logf("КРАШ: %v", r)
			a.shutdown()
			os.Exit(2)
		}
	}()

	srv := &http.Server{Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			a.logf("http: %v", err)
		}
	}()

	a.boot()

	// Значок в трее: щелчок — окно, меню — «Открыть» / «Выход». Закрыли окно — обход работает дальше.
	a.applyTrayLang()
	stopTray := platform.RunTray(Name, a.openUI, a.requestQuit)
	if opt.Background {
		// автозапуск: окна нет, поэтому говорим, что программа поднялась и где её искать
		platform.TrayNotice(Name, "Запущена в фоне. Значок — в трее (в Windows 11 он может быть под стрелкой ^).")
	}

	if !opt.Background {
		go a.openUI() // при автозапуске (--background) окна нет: только значок в трее
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
	case <-a.quit:
	}
	a.closeUI()
	stopTray()
	a.shutdown()
	_ = srv.Close()
}
