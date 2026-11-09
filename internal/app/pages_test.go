package app

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func openEvents(t *testing.T, a *App, srv *httptest.Server) (*bufio.Reader, func()) {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+"/api/events?t="+url.QueryEscape(a.token), nil)
	req.Host = strings.TrimPrefix(srv.URL, "http://")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("events: %v %v", err, resp)
	}
	return bufio.NewReader(resp.Body), func() { resp.Body.Close() }
}

func TestShowReusesOpenPage(t *testing.T) {
	a := newApp(t.TempDir(), 0)
	defer a.shutdown()
	srv := newPageServer(a)
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	// страницы нет — работающая копия сама открывает интерфейс (на Linux окна нет → запасной путь),
	// а вторая копия ничего не открывает
	if running, open := showRunning(addr); !running || !open {
		t.Fatalf("без вкладки: running=%v pageOpen=%v", running, open)
	}
	waitUntil(t, func() bool {
		a.uiMu.Lock()
		defer a.uiMu.Unlock()
		return a.uiBrowserOnly
	})

	rd, closeEv := openEvents(t, a, srv)
	waitUntil(t, func() bool { return a.pages.count() == 1 })

	// вкладка открыта — браузер не открываем, вкладка получает «show»
	running, open := showRunning(addr)
	if !running || !open {
		t.Fatalf("с вкладкой: running=%v pageOpen=%v", running, open)
	}
	got := make(chan string, 1)
	go func() {
		for {
			l, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(l, "data: ") {
				got <- strings.TrimSpace(strings.TrimPrefix(l, "data: "))
				return
			}
		}
	}()
	select {
	case m := <-got:
		if m != "show" {
			t.Fatalf("событие %q", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("вкладка не получила «show»")
	}

	// вкладку закрыли — счётчик падает
	closeEv()
	waitUntil(t, func() bool { return a.pages.count() == 0 })
}

func TestOpenURLOnlyHTTPS(t *testing.T) {
	a := newApp(t.TempDir(), 0)
	defer a.shutdown()
	srv := newPageServer(a)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	post := func(body string, token string) (int, string) {
		req, _ := http.NewRequest("POST", srv.URL+"/api/openurl", strings.NewReader(body))
		req.Host = host
		if token != "" {
			req.Header.Set("X-GU-Token", token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if c, _ := post(`{"url":"https://example.com/"}`, ""); c != 403 {
		t.Fatalf("без токена: %d", c)
	}
	for _, bad := range []string{`{"url":"http://example.com"}`, `{"url":"file:///C:/Windows/System32/calc.exe"}`,
		`{"url":"javascript:alert(1)"}`, `{"url":"tg://resolve?domain=x"}`, `{"url":"https://"}`} {
		if _, b := post(bad, a.token); !strings.Contains(b, "только ссылки https") {
			t.Fatalf("%s принята: %s", bad, b)
		}
	}
	if _, b := post(`{"url":"https://example.com/"}`, a.token); !strings.Contains(b, `"ok":true`) {
		t.Fatalf("https отклонена: %s", b)
	}
}

func TestShowAndEventsAreGuarded(t *testing.T) {
	a := newApp(t.TempDir(), 0)
	defer a.shutdown()
	srv := newPageServer(a)
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	do := func(method, path string, hdr map[string]string, h string) int {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		req.Host = h
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := do("POST", "/api/show", nil, host); c != 403 {
		t.Fatalf("show без заголовка: %d", c)
	}
	if c := do("POST", "/api/show", map[string]string{"X-GU-Show": "1"}, "evil.example"); c != 403 {
		t.Fatalf("show с чужим Host: %d", c)
	}
	if c := do("GET", "/api/show", map[string]string{"X-GU-Show": "1"}, host); c != 403 {
		t.Fatalf("show методом GET: %d", c)
	}
	if c := do("GET", "/api/events", nil, host); c != 403 {
		t.Fatalf("events без токена: %d", c)
	}
	if c := do("GET", "/api/events?t=wrong", nil, host); c != 403 {
		t.Fatalf("events с неверным токеном: %d", c)
	}
	if a.pages.count() != 0 {
		t.Fatal("отклонённые запросы не должны регистрировать страницы")
	}
}

// newPageServer: порт нужен до routes() — защита сверяет Host с «127.0.0.1:порт».
func newPageServer(a *App) *httptest.Server {
	srv := httptest.NewUnstartedServer(nil)
	a.port = srv.Listener.Addr().(*net.TCPAddr).Port
	srv.Config.Handler = a.routes()
	srv.Start()
	return srv
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("условие не выполнилось")
}
