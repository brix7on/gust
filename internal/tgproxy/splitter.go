package tgproxy

import (
	"bytes"
	"encoding/binary"
)

// msgSplitter режет поток на отдельные транспортные пакеты MTProto, чтобы каждый
// ушёл в Telegram отдельным WebSocket-кадром (так его ждёт сервер kwsN.web.telegram.org).
// Длины читаются из расшифрованного потока, а наружу отдаются зашифрованные куски той же длины.
type msgSplitter struct {
	abridged bool
	cipher   []byte
	plain    []byte
	disabled bool
}

func newSplitter(protoTag []byte) *msgSplitter {
	return &msgSplitter{abridged: bytes.Equal(protoTag, tagAbridged)}
}

// split добавляет кусок потока и возвращает целиком собранные пакеты (зашифрованные).
func (s *msgSplitter) split(enc, plain []byte) [][]byte {
	if len(enc) == 0 {
		return nil
	}
	if s.disabled {
		return [][]byte{append([]byte(nil), enc...)}
	}
	s.cipher = append(s.cipher, enc...)
	s.plain = append(s.plain, plain...)

	var parts [][]byte
	off := 0
	for off < len(s.cipher) {
		n, ok := s.nextLen(off, len(s.cipher)-off)
		if !ok {
			break // пакет ещё не пришёл целиком
		}
		if n <= 0 {
			// непонятная длина — дальше шлём как есть, без нарезки
			parts = append(parts, append([]byte(nil), s.cipher[off:]...))
			off = len(s.cipher)
			s.disabled = true
			break
		}
		parts = append(parts, append([]byte(nil), s.cipher[off:off+n]...))
		off += n
	}
	if off > 0 {
		s.cipher = append(s.cipher[:0], s.cipher[off:]...)
		s.plain = append(s.plain[:0], s.plain[off:]...)
	}
	return parts
}

// flush отдаёт недособранный хвост (при закрытии соединения клиентом).
func (s *msgSplitter) flush() []byte {
	if len(s.cipher) == 0 {
		return nil
	}
	t := append([]byte(nil), s.cipher...)
	s.cipher, s.plain = s.cipher[:0], s.plain[:0]
	return t
}

// nextLen: (длина пакета, true) или (_, false), если данных пока мало.
func (s *msgSplitter) nextLen(off, avail int) (int, bool) {
	p := s.plain[off:]
	if s.abridged {
		first := p[0]
		var payload, hdr int
		if first == 0x7f || first == 0xff {
			if avail < 4 {
				return 0, false
			}
			payload = int(uint32(p[1])|uint32(p[2])<<8|uint32(p[3])<<16) * 4
			hdr = 4
		} else {
			payload = int(first&0x7f) * 4
			hdr = 1
		}
		if payload <= 0 {
			return 0, true
		}
		if avail < hdr+payload {
			return 0, false
		}
		return hdr + payload, true
	}
	if avail < 4 {
		return 0, false
	}
	payload := int(binary.LittleEndian.Uint32(p) & 0x7fffffff)
	if payload <= 0 || payload > 16<<20 {
		return 0, true
	}
	if avail < 4+payload {
		return 0, false
	}
	return 4 + payload, true
}
