// Package tgproxy — локальный MTProto-прокси для Telegram Desktop, который отправляет трафик
// в дата-центры Telegram через WebSocket (kwsN.web.telegram.org), а не напрямую по IP,
// которые режут провайдеры.
//
// Логика перенесена с Python-проекта tg-ws-proxy (Flowseal), лицензия MIT —
// см. THIRD_PARTY_NOTICES.md в корне репозитория.
package tgproxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

const (
	handshakeLen = 64
	skipLen      = 8
	prekeyLen    = 32
	ivLen        = 16
	protoTagPos  = 56
	dcIdxPos     = 60
)

var (
	tagAbridged     = []byte{0xef, 0xef, 0xef, 0xef}
	tagIntermediate = []byte{0xee, 0xee, 0xee, 0xee}
	tagSecure       = []byte{0xdd, 0xdd, 0xdd, 0xdd}

	// начала init-пакета, которые сервер Telegram спутает с другими протоколами
	reservedStarts = [][]byte{
		[]byte("HEAD"), []byte("POST"), []byte("GET "), []byte("OPTI"),
		tagIntermediate, tagSecure, {0x16, 0x03, 0x01, 0x02},
	}
)

// clientHello — результат разбора первых 64 байт от Telegram Desktop.
type clientHello struct {
	dc       int  // номер дата-центра (для тестовых — уже без +10000)
	media    bool // соединение для медиа (отрицательный индекс DC)
	test     bool // тестовый DC (10001+)
	dcIdx    int16
	protoTag []byte
	prekeyIV []byte // 48 байт: prekey (32) + iv (16), как пришли от клиента
}

func newCTR(key, iv []byte) cipher.Stream {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // длина ключа всегда 32 — сюда не попадаем
	}
	return cipher.NewCTR(b, iv)
}

func sha(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

func reversed(b []byte) []byte {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return r
}

// parseClientHello расшифровывает init-пакет клиента ключом из секрета прокси.
// nil — секрет не тот или протокол неизвестен.
func parseClientHello(h, secret []byte) *clientHello {
	if len(h) != handshakeLen {
		return nil
	}
	prekeyIV := append([]byte(nil), h[skipLen:skipLen+prekeyLen+ivLen]...)
	key := sha(prekeyIV[:prekeyLen], secret)
	dec := make([]byte, handshakeLen)
	newCTR(key, prekeyIV[prekeyLen:]).XORKeyStream(dec, h)

	tag := dec[protoTagPos : protoTagPos+4]
	if !bytes.Equal(tag, tagAbridged) && !bytes.Equal(tag, tagIntermediate) && !bytes.Equal(tag, tagSecure) {
		return nil
	}
	idx := int16(binary.LittleEndian.Uint16(dec[dcIdxPos:]))
	ch := &clientHello{dcIdx: idx, protoTag: append([]byte(nil), tag...), prekeyIV: prekeyIV}
	dc := int(idx)
	if dc < 0 {
		dc, ch.media = -dc, true
	}
	if dc >= 10000 {
		dc, ch.test = dc-10000, true
	}
	ch.dc = dc
	return ch
}

func validRelayStart(r []byte) bool {
	if r[0] == 0xef {
		return false
	}
	for _, s := range reservedStarts {
		if bytes.Equal(r[:4], s) {
			return false
		}
	}
	return !bytes.Equal(r[4:8], []byte{0, 0, 0, 0})
}

// makeRelayInit строит init-пакет для соединения с Telegram (обычная обфускация без секрета).
func makeRelayInit(protoTag []byte, dcIdx int16) []byte {
	r := make([]byte, handshakeLen)
	for {
		if _, err := rand.Read(r); err != nil {
			panic(err)
		}
		if validRelayStart(r) {
			break
		}
	}
	enc := make([]byte, handshakeLen)
	newCTR(r[skipLen:skipLen+prekeyLen], r[skipLen+prekeyLen:skipLen+prekeyLen+ivLen]).XORKeyStream(enc, r)

	tail := make([]byte, 8)
	copy(tail, protoTag)
	binary.LittleEndian.PutUint16(tail[4:], uint16(dcIdx))
	_, _ = rand.Read(tail[6:])

	out := append([]byte(nil), r...)
	for i := 0; i < 8; i++ {
		ks := enc[protoTagPos+i] ^ r[protoTagPos+i]
		out[protoTagPos+i] = tail[i] ^ ks
	}
	return out
}

// cryptoCtx — четыре потока AES-CTR: клиентская сторона (с секретом) и сторона Telegram.
type cryptoCtx struct {
	cltDec cipher.Stream // расшифровать то, что прислал клиент
	cltEnc cipher.Stream // зашифровать то, что уходит клиенту
	tgEnc  cipher.Stream // зашифровать то, что уходит в Telegram
	tgDec  cipher.Stream // расшифровать то, что пришло из Telegram
}

func skip64(s cipher.Stream) {
	z := make([]byte, handshakeLen)
	s.XORKeyStream(z, z)
}

func newCryptoCtx(prekeyIV, secret, relayInit []byte) *cryptoCtx {
	c := &cryptoCtx{}
	c.cltDec = newCTR(sha(prekeyIV[:prekeyLen], secret), prekeyIV[prekeyLen:])
	skip64(c.cltDec) // init-пакет клиента уже прочитан

	rev := reversed(prekeyIV)
	c.cltEnc = newCTR(sha(rev[:prekeyLen], secret), rev[prekeyLen:])

	c.tgEnc = newCTR(relayInit[skipLen:skipLen+prekeyLen], relayInit[skipLen+prekeyLen:skipLen+prekeyLen+ivLen])
	skip64(c.tgEnc) // relay init уже «зашифрован» этим потоком

	rrev := reversed(relayInit[skipLen : skipLen+prekeyLen+ivLen])
	c.tgDec = newCTR(rrev[:prekeyLen], rrev[prekeyLen:])
	return c
}
