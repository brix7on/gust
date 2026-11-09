// Определение протокола по данным.

use crate::{http, quic, tls};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7 {
    Tls,
    Http,
    Quic,
    Discord,
    Stun,
    Unknown,
}

impl L7 {
    pub fn parse(s: &str) -> Result<L7, String> {
        Ok(match s {
            "tls" => L7::Tls,
            "http" => L7::Http,
            "quic" => L7::Quic,
            "discord" => L7::Discord,
            "stun" => L7::Stun,
            "unknown" => L7::Unknown,
            _ => return Err(format!("unsupported l7 protocol: {s}")),
        })
    }
}

pub fn tcp(p: &[u8]) -> L7 {
    if tls::is_client_hello(p) {
        L7::Tls
    } else if http::is_request(p) {
        L7::Http
    } else {
        L7::Unknown
    }
}

pub fn udp(p: &[u8]) -> L7 {
    if quic::is_initial(p) {
        L7::Quic
    } else if is_discord(p) {
        L7::Discord
    } else if is_stun(p) {
        L7::Stun
    } else {
        L7::Unknown
    }
}

// Discord IP Discovery: 74 байта, тип 1, длина 70.
pub fn is_discord(p: &[u8]) -> bool {
    p.len() == 74 && p[..4] == [0, 1, 0, 70]
}

pub fn is_stun(p: &[u8]) -> bool {
    p.len() >= 20
        && p[0] & 0xc0 == 0
        && p[4..8] == [0x21, 0x12, 0xa4, 0x42]
        && 20 + u16::from_be_bytes([p[2], p[3]]) as usize == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect() {
        let mut d = vec![0u8; 74];
        d[..4].copy_from_slice(&[0, 1, 0, 70]);
        assert_eq!(udp(&d), L7::Discord);
        let mut s = vec![0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42];
        s.extend_from_slice(&[9; 12]);
        assert_eq!(udp(&s), L7::Stun);
        s[3] = 4;
        assert_eq!(udp(&s), L7::Unknown);
        assert_eq!(tcp(b"POST / HTTP/1.1\r\n"), L7::Http);
        assert_eq!(tcp(&[0x17, 3, 3, 0, 1, 0]), L7::Unknown);
        assert!(L7::parse("wireguard").is_err());
    }
}
