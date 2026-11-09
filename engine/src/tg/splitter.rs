// Cuts the stream into MTProto transport packets so each one goes out as its own WebSocket frame.

use super::obfs::TAG_ABRIDGED;

pub struct Splitter {
    abridged: bool,
    cipher: Vec<u8>,
    plain: Vec<u8>,
    disabled: bool,
}

impl Splitter {
    pub fn new(proto_tag: &[u8; 4]) -> Self {
        Splitter { abridged: *proto_tag == TAG_ABRIDGED, cipher: Vec::new(), plain: Vec::new(), disabled: false }
    }

    pub fn split(&mut self, enc: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if enc.is_empty() {
            return Vec::new();
        }
        if self.disabled {
            return vec![enc.to_vec()];
        }
        self.cipher.extend_from_slice(enc);
        self.plain.extend_from_slice(plain);

        let mut parts = Vec::new();
        let mut off = 0;
        while off < self.cipher.len() {
            match self.next_len(off, self.cipher.len() - off) {
                None => break,
                Some(0) => {
                    parts.push(self.cipher[off..].to_vec());
                    off = self.cipher.len();
                    self.disabled = true;
                    break;
                }
                Some(n) => {
                    parts.push(self.cipher[off..off + n].to_vec());
                    off += n;
                }
            }
        }
        if off > 0 {
            self.cipher.drain(..off);
            self.plain.drain(..off);
        }
        parts
    }

    pub fn flush(&mut self) -> Option<Vec<u8>> {
        if self.cipher.is_empty() {
            return None;
        }
        self.plain.clear();
        Some(std::mem::take(&mut self.cipher))
    }

    // Some(n) — packet length, Some(0) — unusable length, None — not enough data yet.
    fn next_len(&self, off: usize, avail: usize) -> Option<usize> {
        let p = &self.plain[off..];
        if self.abridged {
            let first = p[0];
            let (payload, hdr) = if first == 0x7f || first == 0xff {
                if avail < 4 {
                    return None;
                }
                ((p[1] as usize | (p[2] as usize) << 8 | (p[3] as usize) << 16) * 4, 4)
            } else {
                ((first & 0x7f) as usize * 4, 1)
            };
            if payload == 0 {
                return Some(0);
            }
            if avail < hdr + payload {
                return None;
            }
            return Some(hdr + payload);
        }
        if avail < 4 {
            return None;
        }
        let payload = (u32::from_le_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff) as usize;
        if payload == 0 || payload > 16 << 20 {
            return Some(0);
        }
        if avail < 4 + payload {
            return None;
        }
        Some(4 + payload)
    }
}
