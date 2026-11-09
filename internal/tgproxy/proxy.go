package tgproxy

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Адреса по умолчанию — как в tg-ws-proxy.
var (
	DefaultRedirects = map[int]string{2: "149.154.167.220", 4: "149.154.167.220"}

	dcIPs = map[int]string{
		1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100",
		4: "149.154.167.91", 5: "149.154.171.5", 203: "91.105.192.100",
	}
	dcTestIPs = map[int]string{1: "149.154.175.10", 2: "149.154.167.40", 3: "149.154.175.117"}
)

const DefaultPort = 1443

type Config struct {
	Port        int
	Secret      string         // 32 hex-символа
	DCRedirects map[int]string // DC → IP, к которому идём по WebSocket
	PoolSize    int            // готовых WS на каждый DC (0 — без пула)
	Logf        func(format string, args ...any)

	// для тестов
	dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	roots  *x509.CertPool
	tcpIPs map[int]string
}

// Stats — счётчики для интерфейса.
type Stats struct {
	Total, Active, Bad             atomic.Int64
	ViaWS, ViaTCP, NoRoute         atomic.Int64
	Stalled                        atomic.Int64
	DeadWS                         atomic.Int64 // сессии, закрытые без единого байта от Telegram
	AnsweredWS                     atomic.Int64 // сессии, в которых Telegram хоть раз ответил
	BytesUp, BytesDown             atomic.Int64
	PoolHits, PoolMisses, WSErrors atomic.Int64
	lastBadUnix, lastOKUnix        atomic.Int64
}

// StatsSnapshot — копия счётчиков для JSON.
type StatsSnapshot struct {
	Total     int64  `json:"total"`
	Active    int64  `json:"active"`
	Bad       int64  `json:"bad"`
	ViaWS     int64  `json:"via_ws"`
	DeadWS    int64  `json:"dead_ws"`     // подключились по WebSocket, но Telegram не ответил ни байтом
	OKWS      int64  `json:"answered_ws"` // получили ответ
	ViaTCP    int64  `json:"via_tcp"`
	NoRoute   int64  `json:"no_route"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	LastBad   int64  `json:"last_bad"`
	LastOK    int64  `json:"last_ok"`
	WSLastOK  int64  `json:"ws_last_ok"` // когда прямой WebSocket подключался в последний раз
	WSErr     string `json:"ws_err"`     // почему он не подключается сейчас
}

type Server struct {
	cfg    Config
	secret []byte
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	pool   *wsPool
	st     Stats

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	tcpMu    sync.Mutex
	tcpRetry map[string]time.Time
	tcpFails map[string]int

	badLogAt time.Time
	badMu    sync.Mutex

	failMu    sync.Mutex
	failLogAt map[string]time.Time
}

// NewSecret генерирует случайный секрет.
func NewSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidSecret — 32 hex-символа.
func ValidSecret(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 16
}

// Start слушает 127.0.0.1:port и обслуживает Telegram, пока не вызван Stop.
func Start(cfg Config) (*Server, error) {
	if !ValidSecret(cfg.Secret) {
		return nil, errors.New("секрет прокси должен быть 32 hex-символа")
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.DCRedirects == nil {
		cfg.DCRedirects = DefaultRedirects
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.tcpIPs == nil {
		cfg.tcpIPs = dcIPs
	}
	sec, _ := hex.DecodeString(cfg.Secret)
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, secret: sec, ln: ln, conns: map[net.Conn]struct{}{},
		tcpRetry: map[string]time.Time{}, tcpFails: map[string]int{}}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.pool = newPool(s)

	s.wg.Add(3)
	go func() { defer s.wg.Done(); s.summaryLoop() }()
	go func() { defer s.wg.Done(); s.pool.maintain() }()
	go func() { defer s.wg.Done(); s.acceptLoop() }()
	s.pool.warmup()
	return s, nil
}

// summaryLoop раз в минуту пишет в журнал одну строку итогов — по ней видно, идёт ли трафик
// и где теряются соединения, не листая счётчики.
func (s *Server) summaryLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	prev := s.Stats()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		cur := s.Stats()
		if cur.Total == prev.Total && cur.BytesUp == prev.BytesUp && cur.BytesDown == prev.BytesDown {
			continue
		}
		s.logf("Telegram за минуту: новых %d (WS %d, прямых %d, без пути %d); с данными от Telegram %d, закрылись без данных %d, зависших %d; вниз %d КБ, вверх %d КБ; открыто %d",
			cur.Total-prev.Total, cur.ViaWS-prev.ViaWS, cur.ViaTCP-prev.ViaTCP, cur.NoRoute-prev.NoRoute,
			cur.OKWS-prev.OKWS, cur.DeadWS-prev.DeadWS, s.st.Stalled.Load(),
			(cur.BytesDown-prev.BytesDown)>>10, (cur.BytesUp-prev.BytesUp)>>10, cur.Active)
		prev = cur
	}
}

func (s *Server) logf(f string, a ...any) { s.cfg.Logf(f, a...) }

// Addr — реальный адрес (нужен тестам с портом 0).
func (s *Server) Addr() *net.TCPAddr { return s.ln.Addr().(*net.TCPAddr) }

// Link — ссылка tg://proxy, которую открывает Telegram Desktop.
func (s *Server) Link() string { return Link(s.Addr().Port, s.cfg.Secret) }

func Link(port int, secret string) string {
	return fmt.Sprintf("tg://proxy?server=127.0.0.1&port=%d&secret=dd%s", port, secret)
}

func (s *Server) Stats() StatsSnapshot {
	ok, werr := s.pool.directStatus()
	var wsOK int64
	if !ok.IsZero() {
		wsOK = ok.Unix()
	}
	return StatsSnapshot{
		WSLastOK: wsOK, WSErr: werr,
		Total: s.st.Total.Load(), Active: s.st.Active.Load(), Bad: s.st.Bad.Load(),
		ViaWS: s.st.ViaWS.Load(), DeadWS: s.st.DeadWS.Load(),
		OKWS: s.st.AnsweredWS.Load(), ViaTCP: s.st.ViaTCP.Load(), NoRoute: s.st.NoRoute.Load(),
		BytesUp: s.st.BytesUp.Load(), BytesDown: s.st.BytesDown.Load(),
		LastBad: s.st.lastBadUnix.Load(), LastOK: s.st.lastOKUnix.Load(),
	}
}

// Stop закрывает приёмник, все соединения и пул.
func (s *Server) Stop() {
	s.cancel()
	_ = s.ln.Close()
	s.connMu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.connMu.Unlock()
	s.pool.closeAll()
	s.wg.Wait()
	s.pool.closeAll() // то, что успело дозаполниться во время остановки
}

func (s *Server) track(c net.Conn, on bool) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if on {
		if s.ctx.Err() != nil {
			return false
		}
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	return true
}

func (s *Server) acceptLoop() {
	var delay time.Duration
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			// временная ошибка (нехватка дескрипторов и т.п.) — не роняем прокси
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			time.Sleep(delay)
			continue
		}
		delay = 0
		if !s.track(c, true) {
			c.Close()
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(c, false)
			defer c.Close()
			s.handle(c)
		}()
	}
}

// stallLimit — сколько ждём ответа Telegram на медиа-соединении, прежде чем считать путь зависшим.
// Только для медиа: там соединения одноразовые и Telegram открывает их заново без последствий.
// На основном соединении тишина нормальна (клиент шлёт подтверждения, на которые ответа нет).
const stallLimit = 20 * time.Second

func (s *Server) handle(c net.Conn) {
	s.st.Total.Add(1)
	s.st.Active.Add(1)
	defer s.st.Active.Add(-1)
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	init := make([]byte, handshakeLen)
	if _, err := io.ReadFull(c, init); err != nil {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	h := parseClientHello(init, s.secret)
	if h == nil {
		s.st.Bad.Add(1)
		s.st.lastBadUnix.Store(time.Now().Unix())
		s.badMu.Lock()
		if time.Since(s.badLogAt) > time.Minute {
			s.badLogAt = time.Now()
			s.logf("Telegram: подключение с чужим секретом — переподключите Telegram кнопкой «Подключить Telegram»")
		}
		s.badMu.Unlock()
		return
	}
	s.st.lastOKUnix.Store(time.Now().Unix())

	relay := makeRelayInit(h.protoTag, h.dcIdx)
	ctx := newCryptoCtx(h.prekeyIV, s.secret, relay)
	k := poolKey{dc: h.dc, media: h.media, test: h.test}

	// 1) WebSocket к Telegram (основной путь)
	if _, ok := s.cfg.DCRedirects[h.dc]; ok {
		ws := s.pool.get(k)
		if ws == nil && !s.pool.backedOff(k) {
			cctx, cancel := context.WithTimeout(s.ctx, 8*time.Second)
			ws = s.pool.connect(cctx, s.cfg.DCRedirects[h.dc], k)
			cancel()
		}
		if ws != nil {
			if err := ws.send(relay); err == nil {
				s.st.ViaWS.Add(1)
				s.bridgeWS(c, ws, ctx, newSplitter(h.protoTag), &s.st.AnsweredWS, &s.st.DeadWS, "напрямую", h.media)
				return
			}
			ws.close()
		}
	}

	// 2) прямой TCP к DC — сработает, только если провайдер его не режет
	ips := s.cfg.tcpIPs
	if h.test {
		ips = dcTestIPs
	}
	if ip := ips[h.dc]; ip != "" {
		if rc := s.dialTCP(ip); rc != nil {
			defer rc.Close()
			if _, err := rc.Write(relay); err == nil {
				s.st.ViaTCP.Add(1)
				s.bridgeTCP(c, rc, ctx)
				return
			}
		}
	}
	s.st.NoRoute.Add(1)
	s.routeFail(k, "ни один путь не сработал")
}

func (s *Server) dialTCP(ip string) net.Conn {
	addr := net.JoinHostPort(ip, "443")
	s.tcpMu.Lock()
	if time.Now().Before(s.tcpRetry[addr]) {
		s.tcpMu.Unlock()
		return nil
	}
	s.tcpMu.Unlock()

	dial := s.cfg.dialer
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	c, err := dial(ctx, "tcp", addr)
	s.tcpMu.Lock()
	defer s.tcpMu.Unlock()
	if err != nil {
		s.tcpFails[addr]++
		gap := 15 * time.Second << min(s.tcpFails[addr]-1, 2) // 15 → 30 → 60 с
		if gap > time.Minute {
			gap = time.Minute
		}
		s.tcpRetry[addr] = time.Now().Add(gap)
		return nil
	}
	delete(s.tcpFails, addr)
	delete(s.tcpRetry, addr)
	return c
}

// bridgeWS гонит данные клиент ⇄ Telegram с перешифровкой (ключ клиента ↔ ключ Telegram).
// answered/dead считают сессии, в которых Telegram ответил / закрылся, не ответив ни разу, —
// так видно, что путь только «подключается», но данные по нему не идут.
func (s *Server) bridgeWS(c net.Conn, ws *wsConn, ctx *cryptoCtx, sp *msgSplitter, answered, dead *atomic.Int64, route string, watch bool) {
	var gotDown atomic.Bool
	var pending atomic.Int64 // с какого момента Telegram не отвечает на отправленное (unix нс), 0 — всё в порядке
	started := time.Now()
	done := make(chan struct{}, 2)
	stop := make(chan struct{})
	defer close(stop)
	// Сторож: путь «завис» (соединение открыто, но ответа нет — так бывает, когда сеть молча режет сессию). Закрываем, и Telegram тут же переподключается по свежему пути,
	// а не ждёт свои долгие таймауты, из-за которых не грузятся картинки.
	if watch {
		go func() {
			t := time.NewTicker(3 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-stop:
					return
				case <-t.C:
				}
				if since := pending.Load(); since != 0 && time.Since(time.Unix(0, since)) > stallLimit {
					s.st.Stalled.Add(1)
					s.stallLog(route, int(time.Since(time.Unix(0, since)).Seconds()), int(time.Since(started).Seconds()), gotDown.Load())
					ws.close()
					_ = c.Close()
					return
				}
			}
		}()
	}
	go func() { // клиент → Telegram
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				pending.CompareAndSwap(0, time.Now().UnixNano())
				s.st.BytesUp.Add(int64(n))
				plain := make([]byte, n)
				ctx.cltDec.XORKeyStream(plain, buf[:n])
				enc := make([]byte, n)
				ctx.tgEnc.XORKeyStream(enc, plain)
				if parts := sp.split(enc, plain); len(parts) > 0 {
					if ws.send(parts...) != nil {
						return
					}
				}
			}
			if err != nil {
				if t := sp.flush(); t != nil {
					_ = ws.send(t)
				}
				return
			}
		}
	}()
	go func() { // Telegram → клиент
		defer func() { done <- struct{}{} }()
		for {
			data, err := ws.recv()
			if err != nil {
				return
			}
			gotDown.Store(true)
			pending.Store(0)
			s.st.BytesDown.Add(int64(len(data)))
			ctx.tgDec.XORKeyStream(data, data)
			ctx.cltEnc.XORKeyStream(data, data)
			if _, err := c.Write(data); err != nil {
				return
			}
		}
	}()
	<-done
	ws.close()
	_ = c.Close()
	<-done
	if gotDown.Load() {
		answered.Add(1)
		return
	}
	// Telegram сам открывает «запасные» соединения и тут же бросает их — это нормально,
	// в журнал не пишем, счётчик виден на вкладке Telegram.
	dead.Add(1)
	_, _ = started, route
}

// stallLog — не чаще раза в минуту: на медиа-соединениях такое случается и в норме.
func (s *Server) stallLog(route string, waited, session int, answered bool) {
	s.failMu.Lock()
	if s.failLogAt == nil {
		s.failLogAt = map[string]time.Time{}
	}
	quiet := time.Since(s.failLogAt["stall"]) < time.Minute
	if !quiet {
		s.failLogAt["stall"] = time.Now()
	}
	s.failMu.Unlock()
	if !quiet {
		s.logf("Telegram: медиа-соединение %s молчит %d с (живо %d с, ответы были: %v) — закрываю, Telegram откроет новое", route, waited, session, answered)
	}
}

// routeFail пишет в журнал, что для этого DC не нашлось пути (не чаще раза в минуту на DC),
// — по таким строкам видно, почему не грузятся аватарки и медиа.
func (s *Server) routeFail(k poolKey, msg string) {
	s.failMu.Lock()
	if s.failLogAt == nil {
		s.failLogAt = map[string]time.Time{}
	}
	key := k.String() + msg
	quiet := time.Since(s.failLogAt[key]) < time.Minute
	if !quiet {
		s.failLogAt[key] = time.Now()
	}
	s.failMu.Unlock()
	if !quiet {
		s.logf("Telegram: %s — %s", k, msg)
	}
}

func (s *Server) bridgeTCP(c, rc net.Conn, ctx *cryptoCtx) {
	done := make(chan struct{}, 2)
	pipe := func(src, dst net.Conn, a, b interface{ XORKeyStream(d, s []byte) }, cnt *atomic.Int64) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				cnt.Add(int64(n))
				a.XORKeyStream(buf[:n], buf[:n])
				b.XORKeyStream(buf[:n], buf[:n])
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(c, rc, ctx.cltDec, ctx.tgEnc, &s.st.BytesUp)
	go pipe(rc, c, ctx.tgDec, ctx.cltEnc, &s.st.BytesDown)
	<-done
	_ = c.Close()
	_ = rc.Close()
	<-done
}
