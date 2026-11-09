// Разбор и сборка IPv4/IPv6 + TCP пакетов.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tcp {
    pub v6: bool,
    pub ip_hl: usize,
    pub tcp_hl: usize,
    pub payload_off: usize,
    pub total: usize,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
}

pub fn parse(b: &[u8]) -> Option<Tcp> {
    if b.is_empty() {
        return None;
    }
    let (v6, ip_hl, total) = match b[0] >> 4 {
        4 => {
            if b.len() < 20 || b[9] != 6 {
                return None;
            }
            let hl = ((b[0] & 0x0f) as usize) * 4;
            let tot = u16::from_be_bytes([b[2], b[3]]) as usize;
            if hl < 20
                || tot < hl
                || tot > b.len()
                || u16::from_be_bytes([b[6], b[7]]) & 0x3fff != 0
            {
                return None;
            }
            (false, hl, tot)
        }
        6 => {
            if b.len() < 40 || b[6] != 6 {
                return None;
            }
            let tot = 40 + u16::from_be_bytes([b[4], b[5]]) as usize;
            if tot > b.len() {
                return None;
            }
            (true, 40, tot)
        }
        _ => return None,
    };
    if total < ip_hl + 20 {
        return None;
    }
    let t = &b[ip_hl..];
    let tcp_hl = ((t[12] >> 4) as usize) * 4;
    if tcp_hl < 20 || ip_hl + tcp_hl > total {
        return None;
    }
    Some(Tcp {
        v6,
        ip_hl,
        tcp_hl,
        payload_off: ip_hl + tcp_hl,
        total,
        sport: u16::from_be_bytes([t[0], t[1]]),
        dport: u16::from_be_bytes([t[2], t[3]]),
        seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
    })
}

pub fn payload<'a>(b: &'a [u8], p: &Tcp) -> &'a [u8] {
    &b[p.payload_off..p.total]
}

// Ключ потока: адреса и порты.
pub fn flow_key(b: &[u8], p: &Tcp) -> Vec<u8> {
    let mut k = if p.v6 {
        b[8..40].to_vec()
    } else {
        b[12..20].to_vec()
    };
    k.extend_from_slice(&p.sport.to_be_bytes());
    k.extend_from_slice(&p.dport.to_be_bytes());
    k
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

pub fn fix_checksums(b: &mut [u8], p: &Tcp) {
    let tcp_len = p.total - p.ip_hl;
    if !p.v6 {
        b[10] = 0;
        b[11] = 0;
        let c = fold(sum16(&b[..p.ip_hl], 0));
        b[10..12].copy_from_slice(&c.to_be_bytes());
    }
    let mut acc = 0u32;
    if p.v6 {
        acc = sum16(&b[8..40], acc);
        acc += (tcp_len >> 16) as u32 + (tcp_len & 0xffff) as u32 + 6;
    } else {
        acc = sum16(&b[12..20], acc);
        acc += tcp_len as u32 + 6;
    }
    let t = p.ip_hl;
    b[t + 16] = 0;
    b[t + 17] = 0;
    acc = sum16(&b[t..p.total], acc);
    let c = fold(acc);
    b[t + 16..t + 18].copy_from_slice(&c.to_be_bytes());
}

// Новый сегмент: заголовки шаблона, свой seq и данные.
pub fn segment(tpl: &[u8], p: &Tcp, seq: u32, data: &[u8], idx: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(p.payload_off + data.len());
    b.extend_from_slice(&tpl[..p.payload_off]);
    b.extend_from_slice(data);
    let total = b.len();
    if p.v6 {
        b[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
    } else {
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        let id = u16::from_be_bytes([b[4], b[5]]).wrapping_add(idx);
        b[4..6].copy_from_slice(&id.to_be_bytes());
    }
    let t = p.ip_hl;
    b[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    let np = Tcp { total, ..*p };
    fix_checksums(&mut b, &np);
    b
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn ipv4_tcp(seq: u32, dport: u16, data: &[u8]) -> Vec<u8> {
        let total = 20 + 20 + data.len();
        let mut b = vec![0u8; total];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        b[8] = 64;
        b[9] = 6;
        b[12..16].copy_from_slice(&[192, 168, 1, 2]);
        b[16..20].copy_from_slice(&[1, 1, 1, 1]);
        b[20..22].copy_from_slice(&50000u16.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        b[24..28].copy_from_slice(&seq.to_be_bytes());
        b[32] = 0x50;
        b[33] = 0x18;
        b[40..].copy_from_slice(data);
        let p = parse(&b).unwrap();
        fix_checksums(&mut b, &p);
        b
    }

    pub fn checksums_ok(b: &[u8]) -> bool {
        let p = parse(b).unwrap();
        let mut c = b.to_vec();
        fix_checksums(&mut c, &p);
        c == b
    }

    #[test]
    fn parse_and_segment() {
        let pkt = ipv4_tcp(1000, 443, b"hello world");
        let p = parse(&pkt).unwrap();
        assert_eq!(
            (p.dport, p.seq, payload(&pkt, &p)),
            (443, 1000, &b"hello world"[..])
        );
        let s = segment(&pkt, &p, 1005, b" world", 1);
        let q = parse(&s).unwrap();
        assert_eq!((q.seq, payload(&s, &q)), (1005, &b" world"[..]));
        assert_eq!(u16::from_be_bytes([s[4], s[5]]), 0x1235);
        assert!(checksums_ok(&s));
    }

    #[test]
    fn known_checksum() {
        // эталонный IPv4-заголовок из RFC 1071-примеров (Wikipedia): контрольная сумма 0xb861
        let mut h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0x00,
            0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let c = fold(sum16(&h, 0));
        h[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(c, 0xb861);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45; 10]).is_none());
        let mut udp = ipv4_tcp(1, 443, b"x");
        udp[9] = 17;
        assert!(parse(&udp).is_none());
    }
}
