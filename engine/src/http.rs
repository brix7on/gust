// HTTP-запрос: распознавание и положение Host.

const METHODS: [&[u8]; 8] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
];

pub fn is_request(p: &[u8]) -> bool {
    METHODS.iter().any(|m| p.starts_with(m))
}

// Смещения начала и конца значения заголовка Host (без пробелов и порта).
pub fn host(p: &[u8]) -> Option<(usize, usize)> {
    let mut i = p.windows(2).position(|w| w == b"\r\n")? + 2;
    while i + 5 <= p.len() {
        let end = p[i..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map_or(p.len(), |e| i + e);
        if end == i {
            return None;
        }
        if p[i..i + 5].eq_ignore_ascii_case(b"host:") {
            let mut s = i + 5;
            while s < end && (p[s] == b' ' || p[s] == b'\t') {
                s += 1;
            }
            let mut e = end;
            while e > s && (p[e - 1] == b' ' || p[e - 1] == b'\t') {
                e -= 1;
            }
            if p[s..e].first() != Some(&b'[') {
                if let Some(c) = p[s..e].iter().position(|&c| c == b':') {
                    e = s + c;
                }
            }
            return (e > s).then_some((s, e));
        }
        i = end + 2;
    }
    None
}

pub fn fake() -> Vec<u8> {
    b"GET / HTTP/1.1\r\nHost: www.iana.org\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n".to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header() {
        let r = b"GET /x HTTP/1.1\r\nUser-Agent: a\r\nhOsT:  example.com:8080 \r\n\r\n";
        assert!(is_request(r));
        let (s, e) = host(r).unwrap();
        assert_eq!(&r[s..e], b"example.com");
        assert!(host(b"GET / HTTP/1.1\r\n\r\nHost: x.com\r\n").is_none());
        assert!(!is_request(b"\x16\x03\x01"));
        let f = fake();
        let (s, e) = host(&f).unwrap();
        assert_eq!(&f[s..e], b"www.iana.org");
    }
}
