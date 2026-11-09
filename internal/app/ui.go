package app

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gust/internal/platform"
)

// Интерфейс открывается во встроенном окне (WebView2), а не во вкладке браузера: браузер на ПК
// может быть любой или не запущен вовсе. Окно — отдельный процесс (эта же программа с ключом
// --window): его падение не трогает обход. Закрыли окно — программа остаётся в трее.
// Если встроенного окна нет (нет WebView2, не запустилось) — запасной путь: браузер по умолчанию.

// windowFailWindow — если окно закрылось с ошибкой быстрее этого срока, считаем, что оно не запустилось.
const windowFailWindow = 15 * time.Second

// webviewDataDir — профиль встроенного браузера. Не в папке данных: та закрыта ACL только для
// админов, и процессы WebView2 в ней писать не могут («не удалось создать каталог данных»).
func webviewDataDir() string {
	if d, err := os.UserCacheDir(); err == nil && d != "" {
		return filepath.Join(d, Name, "webview")
	}
	return filepath.Join(os.TempDir(), Name+"-webview")
}

func (a *App) uiURL() string { return fmt.Sprintf("http://127.0.0.1:%d/", a.port) }

// openUI показывает интерфейс: окно уже есть — выводит его вперёд, нет — открывает.
func (a *App) openUI() {
	a.uiMu.Lock()
	defer a.uiMu.Unlock()
	if c := a.uiChild; c != nil && c.Alive() {
		platform.FocusWindow(c.PID)
		return
	}
	if a.uiBrowserOnly {
		platform.OpenBrowser(a.uiURL())
		return
	}
	select {
	case <-a.quit: // идёт выход — ничего не открываем
		return
	default:
	}
	c, err := platform.StartWindow(a.uiURL(), webviewDataDir(), filepath.Join(a.dataDir, "window.log"))
	if err != nil {
		a.logf("окно интерфейса недоступно (%v) — открываю в браузере", err)
		a.uiBrowserOnly = true
		platform.OpenBrowser(a.uiURL())
		return
	}
	a.uiChild = c
	started := time.Now()
	go func() {
		code := c.Wait()
		select {
		case <-a.quit: // выход: окно закрыли мы сами
			return
		default:
		}
		if code == 0 || time.Since(started) > windowFailWindow {
			return // пользователь закрыл окно — обход продолжает работать в трее
		}
		switch code {
		case platform.ExitNoRuntime:
			a.logf("на этом ПК нет WebView2 — интерфейс открывается в браузере")
			a.uiMu.Lock()
			a.uiBrowserOnly = true
			a.uiMu.Unlock()
		default:
			a.logf("окно интерфейса закрылось с ошибкой (код %d) — открываю в браузере", code)
		}
		platform.OpenBrowser(a.uiURL())
	}()
}

// uiWindowAlive сообщает, открыто ли встроенное окно.
func (a *App) uiWindowAlive() bool {
	a.uiMu.Lock()
	defer a.uiMu.Unlock()
	return a.uiChild != nil && a.uiChild.Alive()
}

// closeUI закрывает окно при выходе из программы.
func (a *App) closeUI() {
	a.uiMu.Lock()
	c := a.uiChild
	a.uiMu.Unlock()
	if c != nil {
		c.Kill()
	}
}
