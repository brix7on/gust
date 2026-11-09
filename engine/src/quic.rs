// QUIC Initial (v1 RFC 9001, v2 RFC 9369): снятие защиты, CRYPTO-фреймы, ClientHello и SNI.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

pub const V1: u32 = 1;
pub const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

fn version(p: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(p.get(1..5)?.try_into().ok()?))
}

pub fn is_initial(p: &[u8]) -> bool {
    if p.len() < 1200 || p[0] & 0xc0 != 0xc0 {
        return false;
    }
    let ty = (p[0] >> 4) & 3;
    match version(p) {
        Some(V1) => ty == 0,
        Some(V2) => ty == 1,
        _ => false,
    }
}

pub fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let f = *b.get(*i)?;
    let n = 1usize << (f >> 6);
    let s = b.get(*i..*i + n)?;
    *i += n;
    Some(
        s.iter()
            .skip(1)
            .fold((f & 0x3f) as u64, |a, &x| (a << 8) | x as u64),
    )
}

pub struct Keys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

fn expand_label(prk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    prk.expand(&info, out).expect("hkdf length");
}

pub fn client_secret(ver: u32, dcid: &[u8]) -> [u8; 32] {
    let salt = if ver == V2 { &SALT_V2 } else { &SALT_V1 };
    let (_, init) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let mut cs = [0u8; 32];
    expand_label(&init, "client in", &mut cs);
    cs
}

pub fn keys(ver: u32, dcid: &[u8]) -> Keys {
    let cs = client_secret(ver, dcid);
    let k = Hkdf::<Sha256>::from_prk(&cs).expect("prk");
    let p = if ver == V2 { "quicv2 " } else { "quic " };
    let mut out = Keys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    expand_label(&k, &format!("{p}key"), &mut out.key);
    expand_label(&k, &format!("{p}iv"), &mut out.iv);
    expand_label(&k, &format!("{p}hp"), &mut out.hp);
    out
}

pub fn hp_mask(hp: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let c = Aes128::new(hp.into());
    let mut b = aes::Block::clone_from_slice(&sample[..16]);
    c.encrypt_block(&mut b);
    b.into()
}

struct Header {
    ver: u32,
    dcid: Vec<u8>,
    pn_off: usize,
    end: usize,
}

fn header(p: &[u8]) -> Option<Header> {
    let ver = version(p)?;
    let mut i = 5;
    let dl = *p.get(i)? as usize;
    if dl > 20 {
        return None;
    }
    let dcid = p.get(i + 1..i + 1 + dl)?.to_vec();
    i += 1 + dl;
    let sl = *p.get(i)? as usize;
    i += 1 + sl;
    let tl = varint(p, &mut i)? as usize;
    i += tl;
    let len = varint(p, &mut i)? as usize;
    let end = i.checked_add(len)?;
    (end <= p.len() && len >= 20).then_some(Header {
        ver,
        dcid,
        pn_off: i,
        end,
    })
}

// Расшифрованная полезная нагрузка первого (Initial) QUIC-пакета в датаграмме.
pub fn decrypt(p: &[u8]) -> Option<Vec<u8>> {
    if !is_initial(p) {
        return None;
    }
    let h = header(p)?;
    let k = keys(h.ver, &h.dcid);
    let sample = p.get(h.pn_off + 4..h.pn_off + 20)?;
    let mask = hp_mask(&k.hp, sample);
    let first = p[0] ^ (mask[0] & 0x0f);
    let pn_len = (first & 3) as usize + 1;
    let mut aad = p[..h.pn_off + pn_len].to_vec();
    aad[0] = first;
    let mut pn = 0u64;
    for j in 0..pn_len {
        aad[h.pn_off + j] ^= mask[1 + j];
        pn = (pn << 8) | aad[h.pn_off + j] as u64;
    }
    let mut nonce = k.iv;
    for (j, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + j] ^= b;
    }
    let ct = &p[h.pn_off + pn_len..h.end];
    Aes128Gcm::new((&k.key).into())
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad: &aad })
        .ok()
}

// CRYPTO-фреймы (смещение, данные) из расшифрованных фреймов Initial.
pub fn crypto_frames(f: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = vec![];
    let mut i = 0;
    while i < f.len() {
        let Some(t) = varint(f, &mut i) else { break };
        match t {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                let ok = (|| {
                    varint(f, &mut i)?;
                    varint(f, &mut i)?;
                    let n = varint(f, &mut i)?;
                    varint(f, &mut i)?;
                    for _ in 0..n {
                        varint(f, &mut i)?;
                        varint(f, &mut i)?;
                    }
                    if t == 0x03 {
                        for _ in 0..3 {
                            varint(f, &mut i)?;
                        }
                    }
                    Some(())
                })();
                if ok.is_none() {
                    break;
                }
            }
            0x06 => {
                let (Some(off), Some(len)) = (varint(f, &mut i), varint(f, &mut i)) else {
                    break;
                };
                let Some(d) = f.get(i..i + len as usize) else {
                    break;
                };
                out.push((off, d.to_vec()));
                i += len as usize;
            }
            _ => break,
        }
    }
    out
}

#[derive(Default)]
pub struct Crypto {
    chunks: Vec<(u64, Vec<u8>)>,
}

impl Crypto {
    pub fn add_datagram(&mut self, p: &[u8]) -> bool {
        match decrypt(p) {
            Some(f) => {
                self.chunks.extend(crypto_frames(&f));
                true
            }
            None => false,
        }
    }

    // Непрерывные данные с нулевого смещения.
    pub fn contiguous(&self) -> Vec<u8> {
        let mut c = self.chunks.clone();
        c.sort_by_key(|x| x.0);
        let mut out: Vec<u8> = vec![];
        for (off, d) in c {
            let off = off as usize;
            if off > out.len() {
                break;
            }
            let end = off + d.len();
            if end > out.len() {
                out.extend_from_slice(&d[out.len() - off..]);
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HelloInfo {
    pub host: Option<String>,
    pub complete: bool,
}

pub fn hello_info(c: &Crypto) -> HelloInfo {
    let d = c.contiguous();
    let host = crate::tls::hs_sni(&d).map(|(s, e)| String::from_utf8_lossy(&d[s..e]).into_owned());
    let complete = d.len() >= 4
        && d[0] == 1
        && d.len() >= 4 + u32::from_be_bytes([0, d[1], d[2], d[3]]) as usize;
    HelloInfo { host, complete }
}

// Фейк по умолчанию: правдоподобный длинный заголовок Initial и случайные байты.
pub fn fake() -> Vec<u8> {
    let mut p = vec![0xc3, 0, 0, 0, 1, 8];
    p.extend(crate::rng::bytes(8));
    p.extend_from_slice(&[0, 0, 0x44, 0xd0]);
    p.extend(crate::rng::bytes(1200 - p.len()));
    p
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9001_keys() {
        let dcid = hex("8394c8f03e515708");
        assert_eq!(
            client_secret(V1, &dcid).to_vec(),
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        let k = keys(V1, &dcid);
        assert_eq!(k.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
        let mask = hp_mask(&k.hp, &hex("d1b1c98dd7689fb8ec11d242b123dc9b"));
        assert_eq!(mask[..5].to_vec(), hex("437b9aec36"));
    }

    #[test]
    fn rfc9369_keys() {
        let k = keys(V2, &hex("8394c8f03e515708"));
        assert_eq!(k.key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(k.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        assert_eq!(k.hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    fn put_varint(v: &mut Vec<u8>, x: u64) {
        if x < 64 {
            v.push(x as u8);
        } else if x < 16384 {
            v.extend_from_slice(&((x as u16) | 0x4000).to_be_bytes());
        } else {
            v.extend_from_slice(&((x as u32) | 0x8000_0000).to_be_bytes());
        }
    }

    // Клиентский Initial с заданными CRYPTO-фреймами (как у браузера), дополненный до 1250 байт.
    pub fn initial(ver: u32, dcid: &[u8], pn: u32, crypto: &[(u64, &[u8])]) -> Vec<u8> {
        let mut frames = vec![];
        for (off, d) in crypto {
            frames.push(0x06);
            put_varint(&mut frames, *off);
            put_varint(&mut frames, d.len() as u64);
            frames.extend_from_slice(d);
            frames.push(0x01);
        }
        let ty: u8 = if ver == V2 { 1 } else { 0 };
        let mut h = vec![0xc0 | (ty << 4) | 3];
        h.extend_from_slice(&ver.to_be_bytes());
        h.push(dcid.len() as u8);
        h.extend_from_slice(dcid);
        h.push(0);
        h.push(0);
        let target = 1250usize;
        let len = target - h.len() - 2;
        frames.resize(len - 4 - 16, 0);
        h.extend_from_slice(&((len as u16) | 0x4000).to_be_bytes());
        let pn_off = h.len();
        h.extend_from_slice(&pn.to_be_bytes());
        let k = keys(ver, dcid);
        let mut nonce = k.iv;
        for (j, b) in (pn as u64).to_be_bytes().iter().enumerate() {
            nonce[4 + j] ^= b;
        }
        let ct = Aes128Gcm::new((&k.key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &frames,
                    aad: &h,
                },
            )
            .unwrap();
        let mut p = h;
        p.extend_from_slice(&ct);
        let mask = hp_mask(&k.hp, &p[pn_off + 4..pn_off + 20]);
        p[0] ^= mask[0] & 0x0f;
        for j in 0..4 {
            p[pn_off + j] ^= mask[1 + j];
        }
        p
    }

    fn handshake(host: &str, pad_before: usize) -> Vec<u8> {
        crate::tls::tests::client_hello(host, pad_before)[5..].to_vec()
    }

    #[test]
    fn decrypt_shuffled_crypto() {
        let hs = handshake("www.youtube.com", 0);
        let (a, b) = hs.split_at(200);
        let d = initial(V1, &hex("0102030405060708"), 0, &[(200, b), (0, a)]);
        assert!(is_initial(&d));
        let mut c = Crypto::default();
        assert!(c.add_datagram(&d));
        assert_eq!(c.contiguous(), hs);
        assert_eq!(
            hello_info(&c),
            HelloInfo {
                host: Some("www.youtube.com".into()),
                complete: true
            }
        );
    }

    #[test]
    fn hello_across_two_datagrams_v2() {
        let hs = handshake("rr1---sn-abc.googlevideo.com", 1300);
        let (a, b) = hs.split_at(1000);
        let dcid = hex("aabbccddeeff0011");
        let d1 = initial(V2, &dcid, 0, &[(0, a)]);
        let d2 = initial(V2, &dcid, 1, &[(1000, b)]);
        let mut c = Crypto::default();
        c.add_datagram(&d1);
        assert_eq!(
            hello_info(&c),
            HelloInfo {
                host: None,
                complete: false
            }
        );
        c.add_datagram(&d2);
        let i = hello_info(&c);
        assert_eq!(
            (i.host.as_deref(), i.complete),
            (Some("rr1---sn-abc.googlevideo.com"), true)
        );
    }

    #[test]
    fn rejects_tampered_and_short() {
        let mut d = initial(
            V1,
            &hex("0102030405060708"),
            0,
            &[(0, &handshake("a.com", 0))],
        );
        let n = d.len();
        d[n - 1] ^= 1;
        assert!(decrypt(&d).is_none());
        assert!(!is_initial(&d[..1000]));
        assert!(!is_initial(&fake()[..10]));
        assert!(is_initial(&fake()));
        assert!(decrypt(&fake()).is_none());
    }
}
