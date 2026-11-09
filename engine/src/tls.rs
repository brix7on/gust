// TLS ClientHello: распознавание, полная длина записи, положение SNI.

pub fn is_client_hello(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01
}

// Сколько байт занимает запись целиком (5 байт заголовка + длина).
pub fn record_len(p: &[u8]) -> usize {
    5 + u16::from_be_bytes([p[3], p[4]]) as usize
}

// Смещение начала и конца имени хоста в данных; None, если SNI в этих байтах нет.
pub fn sni(p: &[u8]) -> Option<(usize, usize)> {
    let rd = |i: usize, n: usize| -> Option<usize> {
        let s = p.get(i..i + n)?;
        Some(s.iter().fold(0usize, |a, &b| (a << 8) | b as usize))
    };
    let mut i = 5 + 4 + 2 + 32;
    i += 1 + rd(i, 1)?;
    i += 2 + rd(i, 2)?;
    i += 1 + rd(i, 1)?;
    let ext_end = (i + 2 + rd(i, 2)?).min(p.len());
    i += 2;
    while i + 4 <= ext_end {
        let typ = rd(i, 2)?;
        let len = rd(i + 2, 2)?;
        let body = i + 4;
        if typ == 0 {
            let name_len = rd(body + 3, 2)?;
            let s = body + 5;
            if p.get(body + 2) != Some(&0) || s + name_len > p.len() || name_len == 0 {
                return None;
            }
            return Some((s, s + name_len));
        }
        i = body + len;
    }
    None
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn client_hello(host: &str, pad_before: usize) -> Vec<u8> {
        let mut ext = Vec::new();
        if pad_before > 0 {
            ext.extend_from_slice(&[0x00, 0x15]);
            ext.extend_from_slice(&(pad_before as u16).to_be_bytes());
            ext.extend(std::iter::repeat_n(0u8, pad_before));
        }
        let h = host.as_bytes();
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&((h.len() + 5) as u16).to_be_bytes());
        ext.extend_from_slice(&((h.len() + 3) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(h.len() as u16).to_be_bytes());
        ext.extend_from_slice(h);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01, 0, 0, 0];
        hs[1..4].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn finds_sni() {
        let ch = client_hello("www.youtube.com", 0);
        assert!(is_client_hello(&ch));
        assert_eq!(record_len(&ch), ch.len());
        let (s, e) = sni(&ch).unwrap();
        assert_eq!(&ch[s..e], b"www.youtube.com");
    }

    #[test]
    fn sni_after_padding_and_truncated() {
        let ch = client_hello("discord.com", 1500);
        let (s, e) = sni(&ch).unwrap();
        assert_eq!(&ch[s..e], b"discord.com");
        assert!(sni(&ch[..1400]).is_none());
        assert!(!is_client_hello(b"GET / HTTP/1.1\r\n"));
    }
}
