package tgproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA

	maxWSMessage = 16 << 20
)

var errWSClosed = errors.New("websocket закрыт")

// wsConn — минимальный клиент WebSocket (RFC 6455): только бинарные кадры, маскировка, ping/pong.
type wsConn struct {
	c       net.Conn
	r       *bufio.Reader
	wmu     sync.Mutex
	closeMu sync.Mutex
	closed  bool
	frag    []byte
	created time.Time
}

// wsDialOpts описывает, куда и как подключаться.
type wsDialOpts struct {
	addr    string // host:port для TCP (IP дата-центра или домен)
	host    string // заголовок Host
	path    string
	sni     string // имя в TLS ClientHello; "" — равно host
	noCheck bool   // фронтинг: цепочку сертификата проверяем, имя — нет
	timeout time.Duration
	roots   *x509.CertPool // для тестов; nil — системные
	dialer  func(ctx context.Context, network, addr string) (net.Conn, error)
}

type wsHandshakeError struct {
	code   int
	status string
}

func (e *wsHandshakeError) Error() string { return "HTTP " + strconv.Itoa(e.code) + ": " + e.status }

// stageErr помечает, на каком этапе подключение не удалось (DNS / TCP / TLS / WebSocket).
type stageErr struct {
	stage string
	err   error
}

func (e *stageErr) Error() string { return e.stage + ": " + e.err.Error() }
func (e *stageErr) Unwrap() error { return e.err }

func stage(st string, err error) error {
	if err == nil {
		return nil
	}
	return &stageErr{st, err}
}

var dnsCache = struct {
	sync.Mutex
	m map[string]dnsEntry
}{m: map[string]dnsEntry{}}

type dnsEntry struct {
	ips []string
	at  time.Time
}

const dnsTTL = 10 * time.Minute

// resolve — адреса домена с кэшем на 10 минут: при десятках соединений в секунду не нагружаем DNS
// (в режиме «Прокси» VPN-клиента DNS-запросы бывают медленными).
func resolve(ctx context.Context, host string) ([]string, error) {
	dnsCache.Lock()
	e, ok := dnsCache.m[host]
	dnsCache.Unlock()
	if ok && time.Since(e.at) < dnsTTL {
		return e.ips, nil
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	ips := append(v4, v6...)
	dnsCache.Lock()
	dnsCache.m[host] = dnsEntry{ips, time.Now()}
	dnsCache.Unlock()
	return ips, nil
}

func forgetDNS(host string) {
	dnsCache.Lock()
	delete(dnsCache.m, host)
	dnsCache.Unlock()
}

func dialWS(ctx context.Context, o wsDialOpts) (*wsConn, error) {
	if o.timeout == 0 {
		o.timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	dial := o.dialer
	var raw net.Conn
	var err error
	if dial == nil {
		d := &net.Dialer{KeepAlive: 30 * time.Second}
		host, port, _ := net.SplitHostPort(o.addr)
		if host != "" && net.ParseIP(host) == nil {
			ips, rerr := resolve(ctx, host)
			if rerr != nil {
				return nil, stage("DNS", rerr)
			}
			for _, ip := range ips {
				if raw, err = d.DialContext(ctx, "tcp", net.JoinHostPort(ip, port)); err == nil {
					break
				}
				if ctx.Err() != nil {
					break
				}
			}
			if err != nil {
				forgetDNS(host)
				return nil, stage("TCP", err)
			}
		} else {
			if raw, err = d.DialContext(ctx, "tcp", o.addr); err != nil {
				return nil, stage("TCP", err)
			}
		}
	} else if raw, err = dial(ctx, "tcp", o.addr); err != nil {
		return nil, stage("TCP", err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	sni := o.sni
	if sni == "" {
		sni = o.host
	}
	cfg := &tls.Config{ServerName: sni, RootCAs: o.roots, MinVersion: tls.VersionTLS12}
	if o.noCheck {
		roots := o.roots
		cfg.InsecureSkipVerify = true // имя не сверяем, но цепочку — да (см. ниже)
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("нет сертификата")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
			return err
		}
	}
	tc := tls.Client(raw, cfg)
	if dl, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(dl)
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, stage("TLS", err)
	}

	keyB := make([]byte, 16)
	_, _ = rand.Read(keyB)
	req := "GET " + o.path + " HTTP/1.1\r\n" +
		"Host: " + o.host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString(keyB) + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: binary\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		tc.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(tc, 64<<10)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		tc.Close()
		return nil, err
	}
	if _, err := tp.ReadMIMEHeader(); err != nil {
		tc.Close()
		return nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	code := 0
	if len(parts) >= 2 {
		code, _ = strconv.Atoi(parts[1])
	}
	if code != 101 {
		tc.Close()
		return nil, &wsHandshakeError{code: code, status: line}
	}
	_ = tc.SetDeadline(time.Time{})
	return &wsConn{c: tc, r: br, created: time.Now()}, nil
}

func buildFrame(op byte, data []byte) []byte {
	n := len(data)
	h := make([]byte, 0, 14+n)
	h = append(h, 0x80|op)
	switch {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n < 65536:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	default:
		h = append(h, 0x80|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	h = append(h, mask[:]...)
	start := len(h)
	h = append(h, data...)
	for i := 0; i < n; i++ {
		h[start+i] ^= mask[i&3]
	}
	return h
}

// send отправляет несколько бинарных кадров одной записью.
func (w *wsConn) send(parts ...[]byte) error {
	if w.isClosed() {
		return errWSClosed
	}
	var buf []byte
	for _, p := range parts {
		buf = append(buf, buildFrame(opBinary, p)...)
	}
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_, err := w.c.Write(buf)
	return err
}

func (w *wsConn) writeCtl(op byte, data []byte) {
	w.wmu.Lock()
	_ = w.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = w.c.Write(buildFrame(op, data))
	_ = w.c.SetWriteDeadline(time.Time{})
	w.wmu.Unlock()
}

// recv возвращает следующее сообщение; io.EOF — сервер закрыл соединение.
func (w *wsConn) recv() ([]byte, error) {
	for {
		op, payload, fin, err := w.readFrame()
		if err != nil {
			return nil, err
		}
		switch op {
		case opClose:
			code := payload
			if len(code) > 2 {
				code = code[:2]
			}
			w.writeCtl(opClose, code)
			w.markClosed()
			return nil, io.EOF
		case opPing:
			w.writeCtl(opPong, payload)
			continue
		case opPong:
			continue
		case opCont, opText, opBinary:
			if fin && len(w.frag) == 0 {
				return payload, nil
			}
			w.frag = append(w.frag, payload...)
			if len(w.frag) > maxWSMessage {
				return nil, fmt.Errorf("слишком большое сообщение WebSocket: %d байт", len(w.frag))
			}
			if !fin {
				continue
			}
			m := w.frag
			w.frag = nil
			return m, nil
		}
	}
}

func (w *wsConn) readFrame() (op byte, payload []byte, fin bool, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(w.r, hdr[:]); err != nil {
		return
	}
	fin = hdr[0]&0x80 != 0
	op = hdr[0] & 0x0f
	n := uint64(hdr[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(w.r, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(w.r, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > maxWSMessage {
		err = fmt.Errorf("слишком большой кадр WebSocket: %d байт", n)
		return
	}
	var mask [4]byte
	masked := hdr[1]&0x80 != 0
	if masked {
		if _, err = io.ReadFull(w.r, mask[:]); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(w.r, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return
}

func (w *wsConn) isClosed() bool {
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	return w.closed
}

func (w *wsConn) markClosed() {
	w.closeMu.Lock()
	w.closed = true
	w.closeMu.Unlock()
}

func (w *wsConn) close() {
	w.closeMu.Lock()
	was := w.closed
	w.closed = true
	w.closeMu.Unlock()
	if !was {
		w.writeCtl(opClose, nil)
	}
	_ = w.c.Close()
}

// alive — неблокирующая проверка простаивающего соединения из пула: не закрыл ли его сервер.
// Пришедшие данные (например, ping) остаются в буфере и будут прочитаны позже.
func (w *wsConn) alive() bool {
	if w.isClosed() {
		return false
	}
	if w.r.Buffered() > 0 {
		return true
	}
	_ = w.c.SetReadDeadline(time.Now().Add(time.Millisecond))
	_, err := w.r.Peek(1)
	_ = w.c.SetReadDeadline(time.Time{})
	if err == nil {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
