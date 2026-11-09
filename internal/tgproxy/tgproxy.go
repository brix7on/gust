// Package tgproxy — общие определения встроенного прокси Telegram. Сам прокси (MTProto поверх WebSocket,
// перенос tg-ws-proxy от Flowseal, MIT — см. THIRD_PARTY_NOTICES.md) работает в Rust-движке:
// engine/src/tg, запускается как «gust-engine tgproxy».
package tgproxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const DefaultPort = 1443

// StatsSnapshot — счётчики для интерфейса (их присылает движок строкой «stats: {json}»).
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

// Link — ссылка tg://proxy, которую открывает Telegram Desktop.
func Link(port int, secret string) string {
	return fmt.Sprintf("tg://proxy?server=127.0.0.1&port=%d&secret=dd%s", port, secret)
}
