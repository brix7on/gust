package app

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Открытые страницы интерфейса держат с программой постоянное соединение (SSE). Поэтому программа
// точно знает, открыта ли вкладка, и может её обновить, а не открывать вторую.

type pageHub struct {
	mu   chan struct{} // семафор на 1: простая блокировка без лишних импортов
	subs map[chan string]struct{}
}

func newPageHub() *pageHub {
	h := &pageHub{mu: make(chan struct{}, 1), subs: map[chan string]struct{}{}}
	return h
}

func (h *pageHub) lock()   { h.mu <- struct{}{} }
func (h *pageHub) unlock() { <-h.mu }

func (h *pageHub) add() chan string {
	ch := make(chan string, 4)
	h.lock()
	h.subs[ch] = struct{}{}
	h.unlock()
	return ch
}

func (h *pageHub) remove(ch chan string) {
	h.lock()
	delete(h.subs, ch)
	h.unlock()
}

func (h *pageHub) count() int {
	h.lock()
	defer h.unlock()
	return len(h.subs)
}

// broadcast шлёт событие всем открытым страницам; возвращает, сколько их было.
func (h *pageHub) broadcast(msg string) int {
	h.lock()
	defer h.unlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default: // страница не успевает читать — одно событие пропустит, не страшно
		}
	}
	return len(h.subs)
}

// handleEvents — поток событий для страницы. Токен в адресе: EventSource не умеет ставить заголовки.
func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	if len(t) != len(a.token) || subtle.ConstantTimeCompare([]byte(t), []byte(a.token)) != 1 {
		http.Error(w, "bad token", http.StatusForbidden)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no streaming", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := a.pages.add()
	defer a.pages.remove(ch)
	fmt.Fprint(w, "retry: 1000\n\n: hello\n\n")
	fl.Flush()
	ka := time.NewTicker(15 * time.Second)
	defer ka.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-a.quit:
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			fl.Flush()
		case <-ka.C:
			fmt.Fprint(w, ": ka\n\n")
			fl.Flush()
		}
	}
}

// handleShow вызывает вторая копия программы при запуске. Токена у неё нет, поэтому защита другая:
// только свой Host и нестандартный заголовок — чужой сайт не сможет прислать такой запрос без
// предварительного CORS-запроса, а мы его не разрешаем. Худшее, что можно сделать, — обновить вкладку.
func (a *App) handleShow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("X-GU-Show") != "1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if a.uiWindowAlive() {
		go a.openUI() // окно уже есть — выведет его вперёд, страницу не трогаем
		writeJSON(w, map[string]any{"ok": true, "page_open": true})
		return
	}
	n := a.pages.broadcast("show") // вкладки браузера (запасной путь) обновятся
	if n == 0 {
		go a.openUI() // ничего не открыто — открываем окно
	}
	writeJSON(w, map[string]any{"ok": true, "page_open": true})
}

// showRunning просит уже запущенную копию показать страницу. running=false — копии нет
// (или на порту не наша программа); pageOpen — вкладка была открыта и обновилась.
func showRunning(addr string) (running, pageOpen bool) {
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/api/show", nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("X-GU-Show", "1")
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	var out struct {
		OK       bool `json:"ok"`
		PageOpen bool `json:"page_open"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if resp.StatusCode != 200 || json.Unmarshal(b, &out) != nil || !out.OK {
		return false, false
	}
	return true, out.PageOpen
}
