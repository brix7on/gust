// TLS ClientHello: распознавание, SNI, разбор/сборка для фейков и их модификаций.

pub fn is_client_hello(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01
}

pub fn record_len(p: &[u8]) -> usize {
    5 + u16::from_be_bytes([p[3], p[4]]) as usize
}

struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn n(&mut self, k: usize) -> Option<usize> {
        let s = self.b.get(self.i..self.i + k)?;
        self.i += k;
        Some(s.iter().fold(0usize, |a, &x| (a << 8) | x as usize))
    }
    fn take(&mut self, k: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i + k)?;
        self.i += k;
        Some(s)
    }
}

// SNI внутри handshake-сообщения (тип 1 + длина 3 байта); допускает обрезанные данные.
pub fn hs_sni(h: &[u8]) -> Option<(usize, usize)> {
    if h.first() != Some(&1) {
        return None;
    }
    let mut r = Rd {
        b: h,
        i: 4 + 2 + 32,
    };
    let n = r.n(1)?;
    r.i += n;
    let n = r.n(2)?;
    r.i += n;
    let n = r.n(1)?;
    r.i += n;
    let ext_end = r.i + 2 + r.n(2)?;
    while r.i + 4 <= ext_end.min(h.len()) {
        let typ = r.n(2)?;
        let len = r.n(2)?;
        let body = r.i;
        if typ == 0 {
            let mut e = Rd { b: h, i: body + 2 };
            if e.n(1)? != 0 {
                return None;
            }
            let nl = e.n(2)?;
            let s = e.i;
            return (nl > 0 && s + nl <= h.len()).then_some((s, s + nl));
        }
        r.i = body + len;
    }
    None
}

pub fn sni(p: &[u8]) -> Option<(usize, usize)> {
    if !is_client_hello(p) {
        return None;
    }
    hs_sni(&p[5..]).map(|(s, e)| (s + 5, e + 5))
}

pub const EXT_SNI: u16 = 0;
pub const EXT_PADDING: u16 = 21;

#[derive(Debug, Clone, PartialEq)]
pub struct Hello {
    pub version: [u8; 2],
    pub random: [u8; 32],
    pub sid: Vec<u8>,
    pub ciphers: Vec<u8>,
    pub comp: Vec<u8>,
    pub exts: Vec<(u16, Vec<u8>)>,
}

impl Hello {
    // Полная TLS-запись с ClientHello.
    pub fn parse(rec: &[u8]) -> Option<Hello> {
        if !is_client_hello(rec) || rec.len() < record_len(rec) {
            return None;
        }
        let h = &rec[5..record_len(rec)];
        let mut r = Rd { b: h, i: 4 };
        let version = r.take(2)?.try_into().ok()?;
        let random = r.take(32)?.try_into().ok()?;
        let n = r.n(1)?;
        let sid = r.take(n)?.to_vec();
        let n = r.n(2)?;
        let ciphers = r.take(n)?.to_vec();
        let n = r.n(1)?;
        let comp = r.take(n)?.to_vec();
        let mut exts = vec![];
        if r.i < h.len() {
            let end = r.i + 2 + r.n(2)?;
            while r.i + 4 <= end {
                let t = r.n(2)? as u16;
                let l = r.n(2)?;
                exts.push((t, r.take(l)?.to_vec()));
            }
        }
        Some(Hello {
            version,
            random,
            sid,
            ciphers,
            comp,
            exts,
        })
    }

    pub fn host(&self) -> Option<String> {
        let (_, d) = self.exts.iter().find(|e| e.0 == EXT_SNI)?;
        let l = u16::from_be_bytes([*d.get(3)?, *d.get(4)?]) as usize;
        Some(String::from_utf8_lossy(d.get(5..5 + l)?).into_owned())
    }

    pub fn set_host(&mut self, host: &str) {
        let h = host.as_bytes();
        let mut d = Vec::with_capacity(h.len() + 5);
        d.extend_from_slice(&((h.len() + 3) as u16).to_be_bytes());
        d.push(0);
        d.extend_from_slice(&(h.len() as u16).to_be_bytes());
        d.extend_from_slice(h);
        match self.exts.iter_mut().find(|e| e.0 == EXT_SNI) {
            Some(e) => e.1 = d,
            None => self.exts.insert(0, (EXT_SNI, d)),
        }
    }

    // Сборка записи; extra — на сколько байт «растянуть» padding-расширение (padencap):
    // длины в заголовках увеличиваются, а сами байты не добавляются.
    pub fn to_record(&self, extra: usize) -> Vec<u8> {
        let mut exts = self.exts.clone();
        if extra > 0 {
            match exts.iter().position(|e| e.0 == EXT_PADDING) {
                Some(i) => {
                    let e = exts.remove(i);
                    exts.push(e);
                }
                None => exts.push((EXT_PADDING, vec![])),
            }
        }
        let mut eb = Vec::new();
        for (i, (t, d)) in exts.iter().enumerate() {
            eb.extend_from_slice(&t.to_be_bytes());
            let l = d.len()
                + if extra > 0 && i == exts.len() - 1 {
                    extra
                } else {
                    0
                };
            eb.extend_from_slice(&(l as u16).to_be_bytes());
            eb.extend_from_slice(d);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&self.version);
        body.extend_from_slice(&self.random);
        body.push(self.sid.len() as u8);
        body.extend_from_slice(&self.sid);
        body.extend_from_slice(&(self.ciphers.len() as u16).to_be_bytes());
        body.extend_from_slice(&self.ciphers);
        body.push(self.comp.len() as u8);
        body.extend_from_slice(&self.comp);
        body.extend_from_slice(&((eb.len() + extra) as u16).to_be_bytes());
        body.extend_from_slice(&eb);
        let hl = body.len() + extra;
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&((hl + 4) as u16).to_be_bytes());
        rec.extend_from_slice(&[0x01, (hl >> 16) as u8, (hl >> 8) as u8, hl as u8]);
        rec.extend_from_slice(&body);
        rec
    }

    // Правдоподобный ClientHello браузера, дополненный до 517 байт.
    pub fn browser(host: &str) -> Hello {
        let mut h = Hello {
            version: [3, 3],
            random: [0x5a; 32],
            sid: vec![0x3c; 32],
            ciphers: vec![],
            comp: vec![0],
            exts: vec![],
        };
        for c in [
            0x1301u16, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ] {
            h.ciphers.extend_from_slice(&c.to_be_bytes());
        }
        h.set_host(host);
        h.exts.push((0x0017, vec![]));
        h.exts.push((0xff01, vec![0]));
        h.exts
            .push((0x000a, vec![0, 8, 0, 0x1d, 0, 0x17, 0, 0x18, 0, 0x19]));
        h.exts.push((0x000b, vec![1, 0]));
        h.exts.push((0x0023, vec![]));
        h.exts
            .push((0x0010, b"\x00\x0c\x02h2\x08http/1.1".to_vec()));
        h.exts.push((0x0005, vec![1, 0, 0, 0, 0]));
        h.exts.push((
            0x000d,
            vec![0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1],
        ));
        let mut ks = vec![0, 36, 0, 0x1d, 0, 32];
        ks.extend_from_slice(&[0x77; 32]);
        h.exts.push((0x0033, ks));
        h.exts.push((0x002d, vec![1, 1]));
        h.exts.push((0x002b, vec![4, 3, 4, 3, 3]));
        let len = h.to_record(0).len();
        if len + 4 <= 517 {
            h.exts.push((EXT_PADDING, vec![0; 517 - len - 4]));
        }
        h
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Mods {
    pub rnd: bool,
    pub rndsni: bool,
    pub dupsid: bool,
    pub padencap: bool,
    pub sni: Option<String>,
}

impl Mods {
    pub fn parse(s: &str) -> Result<Mods, String> {
        let mut m = Mods::default();
        for x in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            match x {
                "none" => {}
                "rnd" => m.rnd = true,
                "rndsni" => m.rndsni = true,
                "dupsid" => m.dupsid = true,
                "padencap" => m.padencap = true,
                _ => match x.strip_prefix("sni=") {
                    Some(h) if !h.is_empty() => m.sni = Some(h.to_ascii_lowercase()),
                    _ => return Err(format!("unsupported tls mod: {x}")),
                },
            }
        }
        Ok(m)
    }

    pub fn is_empty(&self) -> bool {
        *self == Mods::default()
    }

    // Фейк с модификациями под конкретный настоящий ClientHello.
    pub fn apply(&self, fake: &[u8], real: &[u8]) -> Vec<u8> {
        if self.is_empty() {
            return fake.to_vec();
        }
        let Some(mut h) = Hello::parse(fake) else {
            return fake.to_vec();
        };
        if self.rnd {
            crate::rng::fill(&mut h.random);
            crate::rng::fill(&mut h.sid);
        }
        if self.dupsid {
            if let Some(r) = Hello::parse(real)
                .or_else(|| partial_sid(real).map(|sid| Hello { sid, ..h.clone() }))
            {
                h.sid = r.sid;
            }
        }
        if let Some(s) = &self.sni {
            h.set_host(s);
        } else if self.rndsni {
            let n = h.host().map_or(10, |x| x.len()).max(5);
            let tld = ["com", "net", "org", "ru"][(crate::rng::next() % 4) as usize];
            h.set_host(&format!(
                "{}.{tld}",
                crate::rng::letters(n.saturating_sub(tld.len() + 1).max(3))
            ));
        }
        h.to_record(if self.padencap { real.len() } else { 0 })
    }
}

// session id из начала (возможно, неполного) ClientHello.
fn partial_sid(rec: &[u8]) -> Option<Vec<u8>> {
    if !is_client_hello(rec) {
        return None;
    }
    let n = *rec.get(5 + 4 + 2 + 32)? as usize;
    rec.get(44..44 + n).map(<[u8]>::to_vec)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn client_hello(host: &str, pad_before: usize) -> Vec<u8> {
        let mut h = Hello::browser(host);
        h.exts.retain(|e| e.0 != EXT_PADDING);
        if pad_before > 0 {
            h.exts.insert(0, (EXT_PADDING, vec![0; pad_before]));
        }
        h.to_record(0)
    }

    #[test]
    fn finds_sni() {
        let ch = client_hello("www.youtube.com", 0);
        assert!(is_client_hello(&ch));
        assert_eq!(record_len(&ch), ch.len());
        let (s, e) = sni(&ch).unwrap();
        assert_eq!(&ch[s..e], b"www.youtube.com");
        let ch = client_hello("discord.com", 1500);
        let (s, e) = sni(&ch).unwrap();
        assert_eq!(&ch[s..e], b"discord.com");
        assert!(sni(&ch[..1400]).is_none());
        assert!(!is_client_hello(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn browser_fake_roundtrip() {
        let h = Hello::browser("www.iana.org");
        let rec = h.to_record(0);
        assert_eq!(rec.len(), 517);
        assert_eq!(Hello::parse(&rec).unwrap(), h);
        assert_eq!(h.host().as_deref(), Some("www.iana.org"));
    }

    #[test]
    fn mods() {
        let fake = Hello::browser("www.iana.org").to_record(0);
        let mut real_h = Hello::browser("discord.com");
        real_h.sid = vec![0xab; 32];
        let real = real_h.to_record(0);

        let m = Mods::parse("rnd,dupsid,sni=ya.ru").unwrap();
        let out = Hello::parse(&m.apply(&fake, &real)).unwrap();
        assert_eq!(out.host().as_deref(), Some("ya.ru"));
        assert_eq!(out.sid, vec![0xab; 32]);
        assert_ne!(out.random, [0x5a; 32]);
        let (s, e) = sni(&m.apply(&fake, &real)).unwrap();
        assert_eq!(e - s, 5);

        let r = Mods::parse("rndsni").unwrap().apply(&fake, &real);
        let host = Hello::parse(&r).unwrap().host().unwrap();
        assert_ne!(host, "www.iana.org");
        assert!(host.contains('.'));

        assert_eq!(Mods::parse("none").unwrap().apply(&fake, &real), fake);
        assert!(Mods::parse("bogus").is_err());
    }

    #[test]
    fn padencap_lengths() {
        let fake = Hello::browser("www.iana.org").to_record(0);
        let real = vec![0u8; 700];
        let p = Mods::parse("padencap").unwrap().apply(&fake, &real);
        assert_eq!(p.len(), fake.len());
        assert_eq!(record_len(&p), p.len() + 700);
        let hs = u32::from_be_bytes([0, p[6], p[7], p[8]]) as usize;
        assert_eq!(hs + 4, record_len(&p) - 5);
        let h = Hello::parse(&[&p[..], &real[..]].concat()).unwrap();
        assert_eq!(h.exts.last().unwrap().0, EXT_PADDING);
        let pad = Hello::browser("www.iana.org").exts.last().unwrap().1.len();
        assert_eq!(h.exts.last().unwrap().1.len(), pad + 700);
    }

    #[test]
    fn dupsid_from_partial() {
        let fake = Hello::browser("www.iana.org").to_record(0);
        let mut h = Hello::browser("x.com");
        h.sid = vec![7; 32];
        let real = h.to_record(0);
        let out = Mods::parse("dupsid").unwrap().apply(&fake, &real[..100]);
        assert_eq!(Hello::parse(&out).unwrap().sid, vec![7; 32]);
    }
}
