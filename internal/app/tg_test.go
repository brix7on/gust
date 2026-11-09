package app

import (
	"gust/internal/tgproxy"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Прокси Telegram — процесс движка: запуск, счётчики, остановка, занятый порт.
// Нужен собранный движок: GUST_ENGINE_CHECK=engine/target/debug/gust-engine.
func TestTGProxyProcess(t *testing.T) {
	bin := os.Getenv("GUST_ENGINE_CHECK")
	if bin == "" {
		t.Skip("GUST_ENGINE_CHECK не задан")
	}
	engineOverride = bin
	defer func() { engineOverride = "" }()
	addr := "127.0.0.1:" + strconv.Itoa(tgproxy.DefaultPort)

	busy, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("порт занят: %v", err)
	}
	a := newApp(t.TempDir(), 0)
	err = a.tgStart()
	if err == nil || !strings.Contains(err.Error(), "занят") {
		t.Fatalf("ждали ошибку про занятый порт, получили %v", err)
	}
	busy.Close()

	if err := a.tgStart(); err != nil {
		t.Fatal(err)
	}
	defer a.tgStop(false)
	if err := a.tgStart(); err != nil { // повторный запуск — без последствий
		t.Fatal(err)
	}
	st := a.tgState(false)
	if !st.Running || st.Port != tgproxy.DefaultPort || !strings.HasPrefix(st.Link, "tg://proxy?server=127.0.0.1") {
		t.Fatalf("состояние: %+v", st)
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write(make([]byte, 64)) // не тот секрет
	_ = c.Close()
	deadline := time.Now().Add(6 * time.Second)
	for a.tgState(false).Stats.Bad != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("счётчик чужих подключений не обновился: %+v", a.tgState(false).Stats)
		}
		time.Sleep(100 * time.Millisecond)
	}

	a.tgStop(true)
	if a.tgState(false).Running {
		t.Fatal("после остановки прокси всё ещё помечен запущенным")
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		l, err := net.Listen("tcp", addr)
		if err == nil {
			l.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("порт не освободился после остановки")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
