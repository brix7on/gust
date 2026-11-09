// Разбор и сборка IPv4/IPv6 + TCP/UDP пакетов, приёмы обмана DPI на уровне заголовков.

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const SYN: u8 = 0x02;
pub const ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pkt {
    pub v6: bool,
    pub proto: u8,
    pub ip_hl: usize,
    pub l4_hl: usize,
    pub payload_off: usize,
    pub total: usize,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub ttl: u8,
}

impl Pkt {
    pub fn is_tcp(&self) -> bool {
        self.proto == TCP
    }
    pub fn payload_len(&self) -> usize {
        self.total - self.payload_off
    }
    pub fn syn(&self) -> bool {
        self.flags & SYN != 0
    }
    pub fn has_ack(&self) -> bool {
        self.flags & ACK != 0
    }
}

pub fn parse(b: &[u8]) -> Option<Pkt> {
    let first = *b.first()?;
    let (v6, proto, ip_hl, total, ttl) = match first >> 4 {
        4 => {
            if b.len() < 20 {
                return None;
            }
            let hl = ((first & 0x0f) as usize) * 4;
            let tot = u16::from_be_bytes([b[2], b[3]]) as usize;
            if hl < 20
                || tot < hl
                || tot > b.len()
                || u16::from_be_bytes([b[6], b[7]]) & 0x3fff != 0
            {
                return None;
            }
            (false, b[9], hl, tot, b[8])
        }
        6 => {
            if b.len() < 40 {
                return None;
            }
            let tot = 40 + u16::from_be_bytes([b[4], b[5]]) as usize;
            if tot > b.len() {
                return None;
            }
            (true, b[6], 40, tot, b[7])
        }
        _ => return None,
    };
    let t = b.get(ip_hl..total)?;
    match proto {
        TCP => {
            if t.len() < 20 {
                return None;
            }
            let hl = ((t[12] >> 4) as usize) * 4;
            if hl < 20 || hl > t.len() {
                return None;
            }
            Some(Pkt {
                v6,
                proto,
                ip_hl,
                l4_hl: hl,
                payload_off: ip_hl + hl,
                total,
                sport: u16::from_be_bytes([t[0], t[1]]),
                dport: u16::from_be_bytes([t[2], t[3]]),
                seq: u32::from_be_bytes([t[4], t[5], t[6], t[7]]),
                ack: u32::from_be_bytes([t[8], t[9], t[10], t[11]]),
                flags: t[13],
                ttl,
            })
        }
        UDP => {
            if t.len() < 8 || (u16::from_be_bytes([t[4], t[5]]) as usize) != t.len() {
                return None;
            }
            Some(Pkt {
                v6,
                proto,
                ip_hl,
                l4_hl: 8,
                payload_off: ip_hl + 8,
                total,
                sport: u16::from_be_bytes([t[0], t[1]]),
                dport: u16::from_be_bytes([t[2], t[3]]),
                seq: 0,
                ack: 0,
                flags: 0,
                ttl,
            })
        }
        _ => None,
    }
}

pub fn payload<'a>(b: &'a [u8], p: &Pkt) -> &'a [u8] {
    &b[p.payload_off..p.total]
}

pub fn src_ip<'a>(b: &'a [u8], p: &Pkt) -> &'a [u8] {
    if p.v6 {
        &b[8..24]
    } else {
        &b[12..16]
    }
}

pub fn dst_ip<'a>(b: &'a [u8], p: &Pkt) -> &'a [u8] {
    if p.v6 {
        &b[24..40]
    } else {
        &b[16..20]
    }
}

// Ключ соединения со стороны клиента: протокол, локальный адрес/порт, удалённый адрес/порт.
pub fn flow_key(b: &[u8], p: &Pkt, outbound: bool) -> Vec<u8> {
    let (lip, lport, rip, rport) = if outbound {
        (src_ip(b, p), p.sport, dst_ip(b, p), p.dport)
    } else {
        (dst_ip(b, p), p.dport, src_ip(b, p), p.sport)
    };
    let mut k = Vec::with_capacity(37);
    k.push(p.proto);
    k.extend_from_slice(lip);
    k.extend_from_slice(&lport.to_be_bytes());
    k.extend_from_slice(rip);
    k.extend_from_slice(&rport.to_be_bytes());
    k
}

fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [x] = chunks.remainder() {
        acc += (*x as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

// Пересчёт контрольных сумм IP и TCP/UDP; badsum — заведомо неверная сумма L4.
pub fn fix_checksums(b: &mut [u8], p: &Pkt, badsum: bool) {
    let l4_len = p.total - p.ip_hl;
    if !p.v6 {
        b[10] = 0;
        b[11] = 0;
        let c = fold(sum16(&b[..p.ip_hl], 0));
        b[10..12].copy_from_slice(&c.to_be_bytes());
    }
    let mut acc = if p.v6 {
        sum16(&b[8..40], 0)
    } else {
        sum16(&b[12..20], 0)
    };
    acc += (l4_len >> 16) as u32 + (l4_len & 0xffff) as u32 + p.proto as u32;
    let off = p.ip_hl + if p.proto == TCP { 16 } else { 6 };
    b[off] = 0;
    b[off + 1] = 0;
    acc = sum16(&b[p.ip_hl..p.total], acc);
    let mut c = fold(acc);
    if p.proto == UDP && c == 0 {
        c = 0xffff;
    }
    if badsum {
        c = c.wrapping_add(1).max(1);
    }
    b[off..off + 2].copy_from_slice(&c.to_be_bytes());
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Mods {
    pub ttl: Option<u8>,
    pub ip_id_zero: bool,
    pub seq_delta: i32,
    pub ack_delta: i32,
    pub md5sig: bool,
    pub ts_delta: Option<i32>,
    pub datanoack: bool,
    pub badsum: bool,
}

fn tcp_options(h: &[u8]) -> Vec<(usize, u8, usize)> {
    let mut out = vec![];
    let mut i = 20;
    while i < h.len() {
        match h[i] {
            0 => break,
            1 => i += 1,
            k => {
                let Some(&l) = h.get(i + 1) else { break };
                let l = l as usize;
                if l < 2 || i + l > h.len() {
                    break;
                }
                out.push((i, k, l));
                i += l;
            }
        }
    }
    out
}

pub fn has_timestamp(b: &[u8], p: &Pkt) -> bool {
    p.is_tcp()
        && tcp_options(&b[p.ip_hl..p.payload_off])
            .iter()
            .any(|&(_, k, l)| k == 8 && l == 10)
}

fn set_ip(b: &mut [u8], v6: bool, total: usize, id: Option<u16>, ttl: Option<u8>) {
    if v6 {
        b[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
        if let Some(t) = ttl {
            b[7] = t;
        }
    } else {
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        if let Some(id) = id {
            b[4..6].copy_from_slice(&id.to_be_bytes());
        }
        if let Some(t) = ttl {
            b[8] = t;
        }
    }
}

fn next_id(tpl: &[u8], v6: bool, idx: u16, zero: bool) -> Option<u16> {
    if v6 {
        return None;
    }
    Some(if zero {
        0
    } else {
        u16::from_be_bytes([tpl[4], tpl[5]]).wrapping_add(idx)
    })
}

// Новый TCP-сегмент по шаблону: свой seq, данные и модификации.
pub fn tcp_segment(tpl: &[u8], p: &Pkt, seq: u32, data: &[u8], m: &Mods, idx: u16) -> Vec<u8> {
    let mut th = tpl[p.ip_hl..p.payload_off].to_vec();
    if m.md5sig && th.len() + 20 <= 60 {
        th.extend_from_slice(&[19, 18]);
        th.extend_from_slice(&[0; 16]);
        th.extend_from_slice(&[1, 1]);
    }
    if let Some(d) = m.ts_delta {
        if let Some(&(i, _, _)) = tcp_options(&th)
            .iter()
            .find(|&&(_, k, l)| k == 8 && l == 10)
        {
            let v = u32::from_be_bytes([th[i + 2], th[i + 3], th[i + 4], th[i + 5]])
                .wrapping_add(d as u32);
            th[i + 2..i + 6].copy_from_slice(&v.to_be_bytes());
        }
    }
    th[12] = ((th.len() / 4) as u8) << 4 | (th[12] & 0x0f);
    th[4..8].copy_from_slice(&seq.wrapping_add(m.seq_delta as u32).to_be_bytes());
    if m.datanoack {
        th[13] &= !ACK;
        th[8..12].copy_from_slice(&[0; 4]);
    } else if m.ack_delta != 0 {
        let a = u32::from_be_bytes([th[8], th[9], th[10], th[11]]).wrapping_add(m.ack_delta as u32);
        th[8..12].copy_from_slice(&a.to_be_bytes());
    }
    let mut b = Vec::with_capacity(p.ip_hl + th.len() + data.len());
    b.extend_from_slice(&tpl[..p.ip_hl]);
    b.extend_from_slice(&th);
    b.extend_from_slice(data);
    let total = b.len();
    set_ip(
        &mut b,
        p.v6,
        total,
        next_id(tpl, p.v6, idx, m.ip_id_zero),
        m.ttl,
    );
    let np = Pkt {
        l4_hl: th.len(),
        payload_off: p.ip_hl + th.len(),
        total,
        ..*p
    };
    fix_checksums(&mut b, &np, m.badsum);
    b
}

// Новая UDP-датаграмма по шаблону.
pub fn udp_datagram(tpl: &[u8], p: &Pkt, data: &[u8], m: &Mods, idx: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(p.payload_off + data.len());
    b.extend_from_slice(&tpl[..p.payload_off]);
    b.extend_from_slice(data);
    let total = b.len();
    let ul = (total - p.ip_hl) as u16;
    b[p.ip_hl + 4..p.ip_hl + 6].copy_from_slice(&ul.to_be_bytes());
    set_ip(
        &mut b,
        p.v6,
        total,
        next_id(tpl, p.v6, idx, m.ip_id_zero),
        m.ttl,
    );
    let np = Pkt { total, ..*p };
    fix_checksums(&mut b, &np, m.badsum);
    b
}

// Окно и множитель окна во входящем SYN-ACK (wssize).
pub fn set_window(b: &mut [u8], p: &Pkt, win: u16, scale: Option<u8>) {
    let t = p.ip_hl;
    b[t + 14..t + 16].copy_from_slice(&win.to_be_bytes());
    if let Some(s) = scale {
        let opts = tcp_options(&b[t..p.payload_off]);
        if let Some(&(i, _, _)) = opts.iter().find(|&&(_, k, l)| k == 3 && l == 3) {
            b[t + i + 2] = s.min(14);
        }
    }
    fix_checksums(b, p, false);
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn ipv4(
        proto: u8,
        sport: u16,
        dport: u16,
        seq: u32,
        flags: u8,
        opts: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let l4 = if proto == TCP { 20 + opts.len() } else { 8 };
        let total = 20 + l4 + data.len();
        let mut b = vec![0u8; total];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        b[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        b[8] = 64;
        b[9] = proto;
        b[12..16].copy_from_slice(&[192, 168, 1, 2]);
        b[16..20].copy_from_slice(&[1, 1, 1, 1]);
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        if proto == TCP {
            b[24..28].copy_from_slice(&seq.to_be_bytes());
            b[28..32].copy_from_slice(&777u32.to_be_bytes());
            b[32] = ((l4 / 4) as u8) << 4;
            b[33] = flags;
            b[34..36].copy_from_slice(&64240u16.to_be_bytes());
            b[40..40 + opts.len()].copy_from_slice(opts);
        } else {
            b[24..26].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
        }
        b[20 + l4..].copy_from_slice(data);
        let p = parse(&b).unwrap();
        fix_checksums(&mut b, &p, false);
        b
    }

    pub fn ipv4_tcp(seq: u32, dport: u16, data: &[u8]) -> Vec<u8> {
        ipv4(TCP, 50000, dport, seq, ACK | 0x08, &[], data)
    }

    pub fn ipv6_tcp(seq: u32, dport: u16, data: &[u8]) -> Vec<u8> {
        let total = 40 + 20 + data.len();
        let mut b = vec![0u8; total];
        b[0] = 0x60;
        b[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
        b[6] = TCP;
        b[7] = 64;
        b[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        b[24..40].copy_from_slice(&[
            0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ]);
        b[40..42].copy_from_slice(&50001u16.to_be_bytes());
        b[42..44].copy_from_slice(&dport.to_be_bytes());
        b[44..48].copy_from_slice(&seq.to_be_bytes());
        b[52] = 0x50;
        b[53] = ACK;
        b[60..].copy_from_slice(data);
        let p = parse(&b).unwrap();
        fix_checksums(&mut b, &p, false);
        b
    }

    pub fn checksums_ok(b: &[u8]) -> bool {
        let p = parse(b).unwrap();
        let mut c = b.to_vec();
        fix_checksums(&mut c, &p, false);
        c == b
    }

    #[test]
    fn parse_tcp_udp_v6() {
        let t = ipv4_tcp(1000, 443, b"hello");
        let p = parse(&t).unwrap();
        assert_eq!(
            (p.proto, p.dport, p.seq, p.ack, p.ttl, payload(&t, &p)),
            (TCP, 443, 1000, 777, 64, &b"hello"[..])
        );
        let u = ipv4(UDP, 5000, 443, 0, 0, &[], b"quic");
        let q = parse(&u).unwrap();
        assert_eq!(
            (q.proto, q.dport, payload(&u, &q)),
            (UDP, 443, &b"quic"[..])
        );
        assert!(checksums_ok(&u));
        let v = ipv6_tcp(5, 443, b"x");
        let r = parse(&v).unwrap();
        assert!(r.v6 && checksums_ok(&v));
        assert_eq!(dst_ip(&v, &r)[0], 0x26);
        assert_eq!(flow_key(&t, &p, true), {
            let mut tr = t.clone();
            tr.swap(12, 16);
            tr.swap(13, 17);
            tr.swap(14, 18);
            tr.swap(15, 19);
            tr.swap(20, 22);
            tr.swap(21, 23);
            let pr = parse(&tr).unwrap();
            flow_key(&tr, &pr, false)
        });
    }

    #[test]
    fn known_checksum() {
        let h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0x00,
            0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(fold(sum16(&h, 0)), 0xb861);
    }

    #[test]
    fn segment_mods() {
        let ts = [1, 1, 8, 10, 0, 0, 0, 100, 0, 0, 0, 0];
        let pkt = ipv4(TCP, 50000, 443, 1000, ACK | 0x08, &ts, b"hello world");
        let p = parse(&pkt).unwrap();
        let plain = tcp_segment(&pkt, &p, 1005, b" world", &Mods::default(), 1);
        let q = parse(&plain).unwrap();
        assert_eq!(
            (
                q.seq,
                payload(&plain, &q),
                u16::from_be_bytes([plain[4], plain[5]])
            ),
            (1005, &b" world"[..], 0x1235)
        );
        assert!(checksums_ok(&plain));

        let m = Mods {
            ttl: Some(5),
            ip_id_zero: true,
            seq_delta: -10000,
            ack_delta: -66000,
            md5sig: true,
            ts_delta: Some(-600000),
            ..Default::default()
        };
        let f = tcp_segment(&pkt, &p, 1000, b"fake", &m, 0);
        let q = parse(&f).unwrap();
        assert_eq!(q.ttl, 5);
        assert_eq!(&f[4..6], &[0, 0]);
        assert_eq!(q.seq, 1000u32.wrapping_sub(10000));
        assert_eq!(q.ack, 777u32.wrapping_sub(66000));
        assert_eq!(q.l4_hl, 20 + 12 + 20);
        assert_eq!(payload(&f, &q), b"fake");
        let opts = tcp_options(&f[q.ip_hl..q.payload_off]);
        assert!(opts.iter().any(|&(_, k, l)| k == 19 && l == 18));
        let (i, _, _) = *opts.iter().find(|o| o.1 == 8).unwrap();
        let o = q.ip_hl + i;
        assert_eq!(
            u32::from_be_bytes([f[o + 2], f[o + 3], f[o + 4], f[o + 5]]),
            100u32.wrapping_sub(600000)
        );
        assert!(checksums_ok(&f));

        let n = tcp_segment(
            &pkt,
            &p,
            1000,
            b"x",
            &Mods {
                datanoack: true,
                badsum: true,
                ..Default::default()
            },
            0,
        );
        let q = parse(&n).unwrap();
        assert_eq!((q.has_ack(), q.ack), (false, 0));
        assert!(!checksums_ok(&n));
    }

    #[test]
    fn md5_skipped_when_no_room() {
        let opts = [1u8; 40];
        let pkt = ipv4(TCP, 1, 443, 1, ACK, &opts, b"d");
        let p = parse(&pkt).unwrap();
        let s = tcp_segment(
            &pkt,
            &p,
            1,
            b"d",
            &Mods {
                md5sig: true,
                ..Default::default()
            },
            0,
        );
        assert_eq!(parse(&s).unwrap().l4_hl, 60);
    }

    #[test]
    fn udp_and_window() {
        let u = ipv4(UDP, 5000, 50010, 0, 0, &[], b"voice");
        let p = parse(&u).unwrap();
        let f = udp_datagram(
            &u,
            &p,
            &[0u8; 64],
            &Mods {
                ttl: Some(3),
                ..Default::default()
            },
            1,
        );
        let q = parse(&f).unwrap();
        assert_eq!((q.payload_len(), q.ttl), (64, 3));
        assert!(checksums_ok(&f));

        let ws = [1, 3, 3, 8];
        let mut sa = ipv4(TCP, 443, 50000, 9, SYN | ACK, &ws, b"");
        let p = parse(&sa).unwrap();
        set_window(&mut sa, &p, 1, Some(6));
        assert_eq!(u16::from_be_bytes([sa[34], sa[35]]), 1);
        assert_eq!(sa[43], 6);
        assert!(checksums_ok(&sa));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45; 10]).is_none());
        let mut icmp = ipv4_tcp(1, 443, b"x");
        icmp[9] = 1;
        assert!(parse(&icmp).is_none());
        let mut frag = ipv4_tcp(1, 443, b"x");
        frag[6] = 0x20;
        assert!(parse(&frag).is_none());
    }
}
