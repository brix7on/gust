package tgproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// ---------- фейковый Telegram Desktop ----------

type fakeClient struct {
	hello []byte
	enc   cipher.Stream // клиент → прокси
	dec   cipher.Stream // прокси → клиент
}

func newFakeClient(secret []byte, tag []byte, dcIdx int16) *fakeClient {
	r := make([]byte, 64)
	for {
		rand.Read(r)
		if validRelayStart(r) {
			break
		}
	}
	copy(r[56:], tag)
	binary.LittleEndian.PutUint16(r[60:], uint16(dcIdx))
	enc := newCTR(sha(r[8:40], secret), r[40:56])
	e := make([]byte, 64)
	enc.XORKeyStream(e, r)
	hello := append(append([]byte(nil), r[:56]...), e[56:]...)
	rev := reversed(r[8:56])
	return &fakeClient{hello: hello, enc: enc, dec: newCTR(sha(rev[:32], secret), rev[32:])}
}

// ---------- фейковый сервер Telegram (сторона DC) ----------

type tgSide struct {
	dec, enc cipher.Stream
	dcIdx    int16
	tag      []byte
}

func parseRelay(init []byte) *tgSide {
	dec := newCTR(init[8:40], init[40:56])
	p := make([]byte, 64)
	dec.XORKeyStream(p, init)
	rev := reversed(init[8:56])
	return &tgSide{dec: dec, enc: newCTR(rev[:32], rev[32:]),
		dcIdx: int16(binary.LittleEndian.Uint16(p[60:])), tag: append([]byte(nil), p[56:60]...)}
}

type tgServer struct {
	mu     sync.Mutex
	frames [][]byte // расшифрованные кадры после init
	inits  []*tgSide
	iHosts []string // Host того соединения, по которому пришёл init
	paths  []string
	hosts  []string
}

// reply на каждый целый пакет отвечает тем же пакетом с префиксом "OK".
func (t *tgServer) handleWS(rw *bufio.ReadWriter, conn net.Conn, host string) {
	ws := &wsConn{c: conn, r: rw.Reader, created: time.Now()}
	init, err := ws.recv()
	if err != nil || len(init) != 64 {
		return
	}
	side := parseRelay(init)
	t.mu.Lock()
	t.inits = append(t.inits, side)
	t.iHosts = append(t.iHosts, host)
	t.mu.Unlock()
	for {
		m, err := ws.recv()
		if err != nil {
			return
		}
		side.dec.XORKeyStream(m, m)
		t.mu.Lock()
		t.frames = append(t.frames, append([]byte(nil), m...))
		t.mu.Unlock()
		out := append([]byte("OK"), m...)
		side.enc.XORKeyStream(out, out)
		// сервер шлёт без маски
		hdr := []byte{0x82}
		if len(out) < 126 {
			hdr = append(hdr, byte(len(out)))
		} else {
			hdr = append(hdr, 126, byte(len(out)>>8), byte(len(out)))
		}
		conn.Write(append(hdr, out...))
	}
}

func (t *tgServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	t.paths = append(t.paths, r.URL.Path)
	t.hosts = append(t.hosts, r.Host)
	t.mu.Unlock()
	key := r.Header.Get("Sec-WebSocket-Key")
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	hj, _ := w.(http.Hijacker)
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(h[:]) + "\r\n\r\n")
	rw.Flush()
	t.handleWS(rw, conn, r.Host)
}

func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: names, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// startTG поднимает TLS-сервер с WebSocket; dialer направляет к нему любые адреса.
func startTG(t *testing.T, names ...string) (*tgServer, *x509.CertPool, func(context.Context, string, string) (net.Conn, error), *[]string) {
	cert, pool := testCert(t, names...)
	srv := &tgServer{}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	var mu sync.Mutex
	dialed := &[]string{}
	dial := func(ctx context.Context, nw, addr string) (net.Conn, error) {
		mu.Lock()
		*dialed = append(*dialed, addr)
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, nw, ln.Addr().String())
	}
	return srv, pool, dial, dialed
}

func startProxy(t *testing.T, cfg Config) *Server {
	cfg.Port = -1 // заменим ниже
	if cfg.Secret == "" {
		cfg.Secret = NewSecret()
	}
	cfg.Logf = t.Logf
	cfg.Port = 0
	s, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
	return s
}

func intermediatePkt(payload []byte) []byte {
	b := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint32(b, uint32(len(payload)))
	return append(b, payload...)
}

func connectClient(t *testing.T, s *Server, tag []byte, dcIdx int16) (net.Conn, *fakeClient) {
	sec, _ := hexDecode(s.cfg.Secret)
	fc := newFakeClient(sec, tag, dcIdx)
	c, err := net.Dial("tcp", s.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.Write(fc.hello)
	return c, fc
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, ch := range s[2*i : 2*i+2] {
			v <<= 4
			switch {
			case ch >= '0' && ch <= '9':
				v |= byte(ch - '0')
			default:
				v |= byte(ch-'a') + 10
			}
		}
		b[i] = v
	}
	return b, nil
}

func sendClient(c net.Conn, fc *fakeClient, data []byte) {
	e := make([]byte, len(data))
	fc.enc.XORKeyStream(e, data)
	c.Write(e)
}

func readClient(t *testing.T, c net.Conn, fc *fakeClient, n int) []byte {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatalf("ответ не пришёл: %v", err)
	}
	fc.dec.XORKeyStream(b, b)
	return b
}

func waitFor(t *testing.T, cond func() bool) {
	for i := 0; i < 300; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("условие не выполнилось")
}

// ---------- тесты ----------

func TestWSPathEndToEnd(t *testing.T) {
	tg, roots, dial, dialed := startTG(t, "*.web.telegram.org")
	s := startProxy(t, Config{PoolSize: 2, roots: roots, dialer: dial})
	c, fc := connectClient(t, s, tagSecure, 2)

	p1, p2, p3 := intermediatePkt([]byte("aaaa")), intermediatePkt(bytes.Repeat([]byte("b"), 300)), intermediatePkt([]byte("cccccccc"))
	// два пакета одной записью, третий — в два приёма
	sendClient(c, fc, append(append([]byte(nil), p1...), p2...))
	sendClient(c, fc, p3[:5])
	time.Sleep(50 * time.Millisecond)
	sendClient(c, fc, p3[5:])

	for _, want := range [][]byte{p1, p2, p3} {
		got := readClient(t, c, fc, len(want)+2)
		if !bytes.Equal(got, append([]byte("OK"), want...)) {
			t.Fatalf("неверный ответ: %q", got)
		}
	}
	tg.mu.Lock()
	defer tg.mu.Unlock()
	if len(tg.frames) != 3 {
		t.Fatalf("ждали 3 кадра (по пакету на кадр), пришло %d", len(tg.frames))
	}
	side := tg.inits[0]
	if !bytes.Equal(side.tag, tagSecure) || side.dcIdx != 2 {
		t.Fatalf("relay init: tag=%x dc=%d", side.tag, side.dcIdx)
	}
	if tg.paths[0] != "/apiws" || tg.iHosts[0] != "kws2.web.telegram.org" {
		t.Fatalf("путь/хост: %v %v", tg.paths, tg.iHosts)
	}
	for _, a := range *dialed {
		if a != "149.154.167.220:443" {
			t.Fatalf("WS должен идти на IP из DCRedirects, а не на %s", a)
		}
	}
	if s.Stats().ViaWS != 1 {
		t.Fatalf("stats: %+v", s.Stats())
	}
}

func TestMediaAndAbridged(t *testing.T) {
	tg, roots, dial, _ := startTG(t, "*.web.telegram.org")
	s := startProxy(t, Config{PoolSize: 0, roots: roots, dialer: dial})
	c, fc := connectClient(t, s, tagAbridged, -4)
	pkt := append([]byte{2}, []byte("12345678")...) // 2*4 байта
	long := append([]byte{0x7f, 64, 0, 0}, bytes.Repeat([]byte("x"), 256)...)
	sendClient(c, fc, append(append([]byte(nil), pkt...), long...))
	readClient(t, c, fc, len(pkt)+2)
	readClient(t, c, fc, len(long)+2)
	tg.mu.Lock()
	defer tg.mu.Unlock()
	if tg.iHosts[0] != "kws4-1.web.telegram.org" {
		t.Fatalf("медиа DC4 должен идти на kws4-1: %v", tg.iHosts)
	}
	if tg.inits[0].dcIdx != -4 || len(tg.frames) != 2 {
		t.Fatalf("dc=%d frames=%d", tg.inits[0].dcIdx, len(tg.frames))
	}
}

func TestFrontingWhenNameDoesNotMatch(t *testing.T) {
	// сертификат не на kws*.web.telegram.org — обычное подключение не пройдёт, фронтинг (без сверки имени) пройдёт
	_, roots, dial, _ := startTG(t, "other.example")
	s := startProxy(t, Config{PoolSize: 0, roots: roots, dialer: dial})
	c, fc := connectClient(t, s, tagSecure, 2)
	pkt := intermediatePkt([]byte("ping"))
	sendClient(c, fc, pkt)
	readClient(t, c, fc, len(pkt)+2)
}

func TestUntrustedCertRejected(t *testing.T) {
	_, _, dial, _ := startTG(t, "*.web.telegram.org")
	_, otherRoots := testCert(t, "x")
	s := startProxy(t, Config{PoolSize: 0, roots: otherRoots, dialer: dial})
	c, fc := connectClient(t, s, tagSecure, 2)
	sendClient(c, fc, intermediatePkt([]byte("ping")))
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("с чужим сертификатом соединение не должно было пройти")
	}
	if s.Stats().ViaWS != 0 {
		t.Fatal("WS засчитан при недоверенном сертификате")
	}
}

func TestTCPFallback(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		init := make([]byte, 64)
		io.ReadFull(c, init)
		side := parseRelay(init)
		buf := make([]byte, 9)
		io.ReadFull(c, buf)
		side.dec.XORKeyStream(buf, buf)
		out := append([]byte("OK"), buf...)
		side.enc.XORKeyStream(out, out)
		c.Write(out)
	}()
	dial := func(ctx context.Context, nw, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, nw, ln.Addr().String())
	}
	s := startProxy(t, Config{PoolSize: 0, DCRedirects: map[int]string{}, dialer: dial})
	c, fc := connectClient(t, s, tagSecure, 3)
	pkt := intermediatePkt([]byte("hello"))
	sendClient(c, fc, pkt)
	if got := readClient(t, c, fc, len(pkt)+2); !bytes.Equal(got, append([]byte("OK"), pkt...)) {
		t.Fatalf("%q", got)
	}
	if s.Stats().ViaTCP != 1 {
		t.Fatalf("%+v", s.Stats())
	}
}

func TestWrongSecret(t *testing.T) {
	s := startProxy(t, Config{PoolSize: 0, DCRedirects: map[int]string{}})
	fc := newFakeClient(bytes.Repeat([]byte{1}, 16), tagSecure, 2)
	c, _ := net.Dial("tcp", s.Addr().String())
	defer c.Close()
	c.Write(fc.hello)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("ждали закрытия соединения")
	}
	waitFor(t, func() bool { return s.Stats().Bad == 1 })
}

func TestPoolReuse(t *testing.T) {
	_, roots, dial, dialed := startTG(t, "*.web.telegram.org")
	s := startProxy(t, Config{PoolSize: 2, roots: roots, dialer: dial})
	// прогрев: DC2 и DC4, обычный и медиа, по 2 соединения
	waitFor(t, func() bool {
		s.pool.mu.Lock()
		defer s.pool.mu.Unlock()
		b := s.pool.b[poolKey{dc: 2}]
		return b != nil && len(b.idle) == 2
	})
	c, fc := connectClient(t, s, tagSecure, 2)
	pkt := intermediatePkt([]byte("x"))
	sendClient(c, fc, pkt)
	readClient(t, c, fc, len(pkt)+2)
	if s.Stats().ViaWS != 1 || s.st.PoolHits.Load() != 1 {
		t.Fatalf("ожидали соединение из пула: hits=%d", s.st.PoolHits.Load())
	}
	_ = dialed
}

func TestStopClosesEverything(t *testing.T) {
	_, roots, dial, _ := startTG(t, "*.web.telegram.org")
	cfg := Config{Secret: NewSecret(), PoolSize: 1, roots: roots, dialer: dial, Logf: t.Logf}
	s, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, fc := connectClient(t, s, tagSecure, 2)
	sendClient(c, fc, intermediatePkt([]byte("x")))
	readClient(t, c, fc, 4+1+2)
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop завис")
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("клиентское соединение должно закрыться")
	}
	// порт освобождён — можно снова запустить
	cfg.Port = s.Addr().Port
	s2, err := Start(cfg)
	if err != nil {
		t.Fatalf("повторный запуск: %v", err)
	}
	s2.Stop()
}

func TestSplitterGarbageLength(t *testing.T) {
	sp := newSplitter(tagSecure)
	huge := make([]byte, 8)
	binary.LittleEndian.PutUint32(huge, 0x7fffffff)
	parts := sp.split(huge, huge)
	if len(parts) != 1 || !sp.disabled {
		t.Fatal("мусорная длина должна отключить нарезку, а не копить буфер")
	}
}

func TestLink(t *testing.T) {
	if l := Link(1443, "00112233445566778899aabbccddeeff"); l != "tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff" {
		t.Fatal(l)
	}
}

func TestBackoffIsCapped(t *testing.T) {
	if backoffGap(1) != time.Second || backoffGap(4) != 8*time.Second {
		t.Fatal("начало прогрессии")
	}
	for _, n := range []int{5, 13, 100} {
		if g := backoffGap(n); g != 15*time.Second {
			t.Fatalf("после %d неудач пауза %s, а должна быть не больше 15 с", n, g)
		}
	}
}

// Сеть моргнула, потом вернулась: прямой WebSocket должен снова подключиться сам и быстро.
func TestDirectPathRecoversAfterOutage(t *testing.T) {
	_, roots, dial, _ := startTG(t, "*.web.telegram.org")
	var mu sync.Mutex
	down := true
	flaky := func(ctx context.Context, nw, addr string) (net.Conn, error) {
		mu.Lock()
		d := down
		mu.Unlock()
		if d {
			return nil, &net.OpError{Op: "dial", Err: context.DeadlineExceeded}
		}
		return dial(ctx, nw, addr)
	}
	s := startProxy(t, Config{PoolSize: 1, roots: roots, dialer: flaky})
	time.Sleep(2500 * time.Millisecond) // несколько неудач подряд, пауза растёт
	if _, e := s.pool.directStatus(); e == "" {
		t.Fatal("причина неудачи должна быть видна")
	}
	mu.Lock()
	down = false
	mu.Unlock()
	start := time.Now()
	waitFor3 := func() bool {
		s.pool.mu.Lock()
		defer s.pool.mu.Unlock()
		b := s.pool.b[poolKey{dc: 2}]
		return b != nil && len(b.idle) > 0
	}
	for !waitFor3() {
		if time.Since(start) > 25*time.Second {
			t.Fatal("прямой путь не вернулся после восстановления сети")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ok, e := s.pool.directStatus(); ok.IsZero() || e != "" {
		t.Fatalf("статус после восстановления: %v %q", ok, e)
	}
}

// Сессия, в которой Telegram не ответил ни байта, должна считаться «мёртвой», а с ответом — живой.
func TestDeadAndAnsweredSessionsAreCounted(t *testing.T) {
	_, roots, dial, _ := startTG(t, "*.web.telegram.org")
	s := startProxy(t, Config{PoolSize: 0, roots: roots, dialer: dial})

	c, fc := connectClient(t, s, tagSecure, 2)
	pkt := intermediatePkt([]byte("ping"))
	sendClient(c, fc, pkt)
	readClient(t, c, fc, len(pkt)+2)
	c.Close()
	waitFor(t, func() bool { return s.Stats().OKWS == 1 })

	// клиент подключился и сразу ушёл, ничего не получив
	c2, _ := connectClient(t, s, tagSecure, 2)
	time.Sleep(100 * time.Millisecond)
	c2.Close()
	waitFor(t, func() bool { return s.Stats().DeadWS == 1 })
	if st := s.Stats(); st.OKWS != 1 || st.DeadWS != 1 {
		t.Fatalf("%+v", st)
	}
}
