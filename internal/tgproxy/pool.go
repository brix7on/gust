package tgproxy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	wsPath       = "/apiws"
	wsPathTest   = "/apiws_test"
	poolMaxAge   = 120 * time.Second
	poolTick     = 5 * time.Second
	refillMinGap = time.Second
	refillMaxGap = 15 * time.Second // дольше нельзя: после короткого сбоя сети прямой путь должен вернуться быстро
	frontingSNI  = "sprinthost.ru"
)

// wsDomains — к каким именам Telegram идёт WebSocket для этого DC.
func wsDomains(dc int, media bool) []string {
	if dc == 203 {
		dc = 2
	}
	d := strconv.Itoa(dc)
	if !media {
		return []string{"kws" + d + ".web.telegram.org"}
	}
	return []string{"kws" + d + "-1.web.telegram.org", "kws" + d + ".web.telegram.org"}
}

type poolKey struct {
	dc    int
	media bool
	test  bool
}

func (k poolKey) String() string {
	s := fmt.Sprintf("DC%d", k.dc)
	if k.test {
		s += " (тест)"
	}
	if k.media {
		s += " медиа"
	}
	return s
}

type idleWS struct {
	ws      *wsConn
	created time.Time
}

type bucket struct {
	idle       []idleWS
	refilling  bool
	failures   int
	retryAfter time.Time
}

// wsPool держит наготове несколько WebSocket к каждому DC: новое соединение Telegram
// получает уже открытый канал без задержки на TLS.
type wsPool struct {
	s          *Server
	mu         sync.Mutex
	b          map[poolKey]*bucket
	frontFirst bool
	everWorked bool
	failLogged bool      // о закрытом прямом пути пишем в журнал один раз
	lastErr    string    // причина последней неудачи прямого WebSocket
	lastOK     time.Time // когда прямой WebSocket подключался в последний раз
}

// directStatus — для интерфейса: когда прямой путь работал и почему не работает сейчас.
func (p *wsPool) directStatus() (lastOK time.Time, lastErr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastOK, p.lastErr
}

func newPool(s *Server) *wsPool { return &wsPool{s: s, b: map[poolKey]*bucket{}} }

func (p *wsPool) bucket(k poolKey) *bucket {
	b := p.b[k]
	if b == nil {
		b = &bucket{}
		p.b[k] = b
	}
	return b
}

// get отдаёт готовое соединение или nil и запускает дозаполнение.
func (p *wsPool) get(k poolKey) *wsConn {
	p.mu.Lock()
	b := p.bucket(k)
	var stale []*wsConn
	var got *wsConn
	for len(b.idle) > 0 {
		e := b.idle[0]
		b.idle = b.idle[1:]
		if time.Since(e.created) >= poolMaxAge || !e.ws.alive() {
			stale = append(stale, e.ws)
			continue
		}
		got = e.ws
		break
	}
	p.mu.Unlock()
	for _, w := range stale {
		go w.close()
	}
	if got != nil {
		p.s.st.PoolHits.Add(1)
	} else {
		p.s.st.PoolMisses.Add(1)
	}
	p.refill(k)
	return got
}

// backedOff — WS к этому DC сейчас не работает, не стоит ждать подключения.
func (p *wsPool) backedOff(k poolKey) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return time.Now().Before(p.bucket(k).retryAfter)
}

func (p *wsPool) refill(k poolKey) {
	size := p.s.cfg.PoolSize
	if size <= 0 || p.s.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	b := p.bucket(k)
	need := size - len(b.idle)
	if need <= 0 || b.refilling || time.Now().Before(b.retryAfter) {
		p.mu.Unlock()
		return
	}
	b.refilling = true
	p.mu.Unlock()

	go func() {
		ip := p.s.cfg.DCRedirects[k.dc]
		res := make(chan *wsConn, need)
		for i := 0; i < need; i++ {
			go func() { res <- p.connect(p.s.ctx, ip, k) }()
		}
		ok := 0
		for i := 0; i < need; i++ {
			w := <-res
			if w == nil {
				continue
			}
			p.mu.Lock()
			if p.s.ctx.Err() != nil {
				p.mu.Unlock()
				w.close()
				continue
			}
			b.idle = append(b.idle, idleWS{w, time.Now()})
			p.mu.Unlock()
			ok++
		}
		p.mu.Lock()
		b.refilling = false
		if ok > 0 {
			b.failures, b.retryAfter = 0, time.Time{}
		} else {
			b.failures++
			gap := backoffGap(b.failures)
			b.retryAfter = time.Now().Add(gap)
			if !p.failLogged {
				p.failLogged = true
				p.s.logf("Telegram: прямой путь к %s закрыт (%s) — это нормально, использую прямой TCP, WebSocket проверяю в фоне", k, p.lastErr)
			}
		}
		p.mu.Unlock()
	}()
}

// connect открывает один WebSocket к DC: сначала по обычному имени, потом с подменой SNI
// (порядок запоминается — какой способ сработал, тот и первый).
func (p *wsPool) connect(ctx context.Context, ip string, k poolKey) *wsConn {
	if ip == "" {
		return nil
	}
	path := wsPath
	if k.test {
		path = wsPathTest
	}
	p.mu.Lock()
	modes := []bool{false, true}
	if p.frontFirst {
		modes = []bool{true, false}
	}
	p.mu.Unlock()
	for _, dom := range wsDomains(k.dc, k.media) {
		for _, fronted := range modes {
			o := wsDialOpts{addr: ip + ":443", host: dom, path: path, timeout: 8 * time.Second,
				roots: p.s.cfg.roots, dialer: p.s.cfg.dialer}
			if fronted {
				o.sni, o.noCheck, o.timeout = frontingSNI, true, 7*time.Second
			}
			w, err := dialWS(ctx, o)
			if err != nil {
				p.s.st.WSErrors.Add(1)
				p.mu.Lock()
				p.lastErr = shortDialErr(err)
				p.mu.Unlock()
				continue
			}
			p.mu.Lock()
			p.lastOK, p.lastErr = time.Now(), ""
			p.failLogged = false
			p.frontFirst = fronted
			first := !p.everWorked
			p.everWorked = true
			p.mu.Unlock()
			if first {
				how := "напрямую"
				if fronted {
					how = "с подменой SNI"
				}
				p.s.logf("Telegram: WebSocket к %s работает (%s)", dom, how)
			}
			return w
		}
	}
	return nil
}

// backoffGap — пауза перед новой попыткой после n неудач подряд: 1, 2, 4, 8, 15, 15… секунд.
func backoffGap(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	g := refillMinGap << min(failures-1, 12)
	if g > refillMaxGap {
		g = refillMaxGap
	}
	return g
}

// shortDialErr — причина по-русски, без технических подробностей.
func shortDialErr(err error) string {
	var se *stageErr
	if errors.As(err, &se) {
		return se.stage + ": " + shortDialErr(se.err)
	}
	var he *wsHandshakeError
	switch {
	case errors.As(err, &he):
		return "сервер ответил " + strconv.Itoa(he.code)
	case errors.Is(err, context.DeadlineExceeded):
		return "таймаут"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "i/o timeout"):
		return "таймаут"
	case strings.Contains(msg, "reset"):
		return "соединение сброшено"
	case strings.Contains(msg, "refused"):
		return "соединение отклонено"
	case strings.Contains(msg, "certificate"), strings.Contains(msg, "x509"):
		return "ошибка сертификата"
	}
	return "ошибка соединения"
}

// maintain выбрасывает старые соединения и держит пулы заполненными.
func (p *wsPool) maintain() {
	t := time.NewTicker(poolTick)
	defer t.Stop()
	for {
		select {
		case <-p.s.ctx.Done():
			return
		case <-t.C:
		}
		p.mu.Lock()
		var stale []*wsConn
		var keys []poolKey
		for k, b := range p.b {
			keep := b.idle[:0]
			for _, e := range b.idle {
				if time.Since(e.created) >= poolMaxAge || !e.ws.alive() {
					stale = append(stale, e.ws)
				} else {
					keep = append(keep, e)
				}
			}
			b.idle = keep
			keys = append(keys, k)
		}
		p.mu.Unlock()
		for _, w := range stale {
			go w.close()
		}
		for _, k := range keys {
			p.refill(k)
		}
	}
}

func (p *wsPool) warmup() {
	for dc := range p.s.cfg.DCRedirects {
		for _, m := range []bool{false, true} {
			p.refill(poolKey{dc: dc, media: m})
		}
	}
}

func (p *wsPool) closeAll() {
	p.mu.Lock()
	var all []*wsConn
	for _, b := range p.b {
		for _, e := range b.idle {
			all = append(all, e.ws)
		}
		b.idle = nil
	}
	p.mu.Unlock()
	for _, w := range all {
		w.close()
	}
}
