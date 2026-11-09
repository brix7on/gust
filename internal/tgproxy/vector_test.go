package tgproxy

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestDumpVector пишет тестовый вектор для сверки с оригинальной Python-реализацией
// (запуск: GU_VECTOR=файл go test -run DumpVector).
func TestDumpVector(t *testing.T) {
	path := os.Getenv("GU_VECTOR")
	if path == "" {
		t.Skip("GU_VECTOR не задан")
	}
	secret := []byte("0123456789abcdef")
	fc := newFakeClient(secret, tagSecure, -2)
	h := parseClientHello(fc.hello, secret)
	relay := makeRelayInit(h.protoTag, h.dcIdx)
	ctx := newCryptoCtx(h.prekeyIV, secret, relay)

	up := []byte("client says hello, this is a longer message to cross block boundaries.....")
	c := make([]byte, len(up))
	fc.enc.XORKeyStream(c, up)
	toTG := make([]byte, len(c))
	ctx.cltDec.XORKeyStream(toTG, c)
	ctx.tgEnc.XORKeyStream(toTG, toTG)

	side := parseRelay(relay)
	r := []byte("telegram answers with some bytes that also cross blocks.................")
	side.enc.XORKeyStream(r, r)
	toClient := make([]byte, len(r))
	ctx.tgDec.XORKeyStream(toClient, r)
	ctx.cltEnc.XORKeyStream(toClient, toClient)

	x := hex.EncodeToString
	b, _ := json.Marshal(map[string]any{
		"secret": x(secret), "hello": x(fc.hello), "relay": x(relay),
		"c": x(c), "to_tg": x(toTG), "r": x(r), "to_client": x(toClient), "dc": h.dc, "media": h.media,
	})
	os.WriteFile(path, b, 0o644)
}
