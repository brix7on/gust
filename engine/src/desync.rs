// Позиции разреза и план отправки: multisplit/multidisorder, fakedsplit/fakeddisorder, hostfakesplit, seqovl.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mark {
    Abs,
    Method,
    Host,
    EndHost,
    Sld,
    MidSld,
    EndSld,
    SniExt,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pos {
    pub mark: Mark,
    pub off: i32,
}

// Что известно о данных: длина, где имя хоста, тип протокола.
pub struct Ctx<'a> {
    pub len: usize,
    pub host: Option<(usize, usize)>,
    pub host_str: &'a str,
    pub tls: bool,
    pub http: bool,
}

impl Pos {
    pub fn parse(s: &str) -> Result<Pos, String> {
        let s = s.trim();
        let (name, off) = match s.find(['+', '-']).filter(|&i| i > 0) {
            Some(i) => (
                &s[..i],
                s[i..]
                    .parse::<i32>()
                    .map_err(|_| format!("bad offset in {s}"))?,
            ),
            None => (s, 0),
        };
        let mark = match name {
            "method" => Mark::Method,
            "host" => Mark::Host,
            "endhost" => Mark::EndHost,
            "sld" => Mark::Sld,
            "midsld" => Mark::MidSld,
            "endsld" => Mark::EndSld,
            "sniext" => Mark::SniExt,
            _ => {
                let v = s
                    .parse::<i32>()
                    .map_err(|_| format!("unknown split position: {s}"))?;
                return Ok(Pos {
                    mark: Mark::Abs,
                    off: v,
                });
            }
        };
        Ok(Pos { mark, off })
    }

    pub fn resolve(&self, c: &Ctx) -> Option<usize> {
        let base: i64 = match self.mark {
            Mark::Abs => {
                if self.off < 0 {
                    c.len as i64
                } else {
                    0
                }
            }
            Mark::Method => {
                if !c.http {
                    return None;
                }
                0
            }
            Mark::SniExt => {
                if !c.tls {
                    return None;
                }
                c.host?.0 as i64 - 5
            }
            Mark::Host => c.host?.0 as i64,
            Mark::EndHost => c.host?.1 as i64,
            Mark::Sld | Mark::MidSld | Mark::EndSld => {
                let (s, e) = sld(c.host_str)?;
                let start = c.host?.0 as i64;
                match self.mark {
                    Mark::Sld => start + s as i64,
                    Mark::EndSld => start + e as i64,
                    _ => start + (s + (e - s) / 2) as i64,
                }
            }
        };
        let v = base + self.off as i64;
        (v > 0 && (v as usize) < c.len).then_some(v as usize)
    }
}

pub fn sld(host: &str) -> Option<(usize, usize)> {
    let h = host.trim_end_matches('.');
    let last = h.rfind('.')?;
    let start = h[..last].rfind('.').map_or(0, |i| i + 1);
    (last > start).then_some((start, last))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Split {
    None,
    Multi { disorder: bool },
    Faked { disorder: bool },
    HostFake,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub split: Split,
    pub positions: Vec<Pos>,
    pub seqovl: usize,
    pub seqovl_pattern: Vec<u8>,
    pub faked_pattern: Vec<u8>,
    pub fake_host: Option<String>,
    pub midhost: Option<Pos>,
    pub altorder: bool,
}

impl Default for Plan {
    fn default() -> Self {
        Plan {
            split: Split::None,
            positions: vec![],
            seqovl: 0,
            seqovl_pattern: vec![],
            faked_pattern: vec![0],
            fake_host: None,
            midhost: None,
            altorder: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Piece {
    pub rel: i64,
    pub data: Vec<u8>,
    pub fake: bool,
}

fn fill(pattern: &[u8], n: usize) -> Vec<u8> {
    if pattern.is_empty() {
        return vec![0; n];
    }
    pattern.iter().copied().cycle().take(n).collect()
}

fn real(out: &mut Vec<Piece>, data: &[u8], a: usize, b: usize, mss: usize) {
    let mut x = a;
    while x < b {
        let y = (x + mss).min(b);
        out.push(Piece {
            rel: x as i64,
            data: data[x..y].to_vec(),
            fake: false,
        });
        x = y;
    }
}

// Поддельное имя той же длины: шаблон host= (дополненный слева) или случайные буквы с теми же точками.
pub fn fake_host(real: &[u8], tpl: Option<&str>) -> Vec<u8> {
    let n = real.len();
    let Some(t) = tpl else {
        return real
            .iter()
            .map(|&c| {
                if c == b'.' {
                    b'.'
                } else {
                    crate::rng::letters(1).as_bytes()[0]
                }
            })
            .collect();
    };
    let t = t.as_bytes();
    let mut v = if t.len() >= n {
        t[t.len() - n..].to_vec()
    } else if n - t.len() == 1 {
        [crate::rng::letters(1).as_bytes(), t].concat()
    } else {
        [crate::rng::letters(n - t.len() - 1).as_bytes(), b".", t].concat()
    };
    if v.first() == Some(&b'.') {
        v[0] = b'a';
    }
    v
}

impl Plan {
    pub fn pieces(&self, data: &[u8], c: &Ctx, mss: usize) -> Vec<Piece> {
        let mss = mss.max(64);
        let len = data.len();
        let mut out = vec![];
        match self.split {
            Split::None => real(&mut out, data, 0, len, mss),
            Split::Multi { disorder } => {
                let mut cuts: Vec<usize> =
                    self.positions.iter().filter_map(|p| p.resolve(c)).collect();
                cuts.sort_unstable();
                cuts.dedup();
                let mut bounds = vec![0];
                bounds.extend(cuts);
                bounds.push(len);
                for w in bounds.windows(2) {
                    real(&mut out, data, w[0], w[1], mss);
                }
                if self.seqovl > 0 && !out.is_empty() {
                    let room = mss.saturating_sub(self.seqovl).max(1);
                    if out[0].data.len() > room {
                        let rest = out[0].data.split_off(room);
                        out.insert(
                            1,
                            Piece {
                                rel: room as i64,
                                data: rest,
                                fake: false,
                            },
                        );
                    }
                    let mut first = fill(&self.seqovl_pattern, self.seqovl);
                    first.extend_from_slice(&out[0].data);
                    out[0] = Piece {
                        rel: -(self.seqovl as i64),
                        data: first,
                        fake: false,
                    };
                }
                if disorder {
                    out.reverse();
                }
            }
            Split::Faked { disorder } => {
                let cut = self.positions.iter().find_map(|p| p.resolve(c));
                let mut parts = match cut {
                    Some(x) => vec![(0, x), (x, len)],
                    None => vec![(0, len)],
                };
                if disorder {
                    parts.reverse();
                }
                for (a, b) in parts {
                    let mut chunks = vec![];
                    real(&mut chunks, data, a, b, mss);
                    for ch in chunks {
                        let f = Piece {
                            rel: ch.rel,
                            data: fill(&self.faked_pattern, ch.data.len()),
                            fake: true,
                        };
                        out.push(f.clone());
                        out.push(ch);
                        out.push(f);
                    }
                }
            }
            Split::HostFake => {
                let Some((hs, he)) = c.host.filter(|&(s, e)| s > 0 && e <= len && e > s) else {
                    real(&mut out, data, 0, len, mss);
                    return out;
                };
                let fh = Piece {
                    rel: hs as i64,
                    data: fake_host(&data[hs..he], self.fake_host.as_deref()),
                    fake: true,
                };
                real(&mut out, data, 0, hs, mss);
                if !self.altorder {
                    out.push(fh.clone());
                }
                let mid = self
                    .midhost
                    .and_then(|p| p.resolve(c))
                    .filter(|&m| m > hs && m < he);
                match mid {
                    Some(m) => {
                        real(&mut out, data, hs, m, mss);
                        real(&mut out, data, m, he, mss);
                    }
                    None => real(&mut out, data, hs, he, mss),
                }
                out.push(fh);
                real(&mut out, data, he, len, mss);
            }
        }
        out
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tls;

    // Что соберёт получатель из настоящих кусков (фейки до него не доходят).
    pub fn reassemble(pieces: &[Piece]) -> Vec<u8> {
        let mut s: Vec<&Piece> = pieces.iter().filter(|p| !p.fake).collect();
        s.sort_by_key(|x| x.rel);
        let mut out = Vec::new();
        for x in s {
            let skip = (-x.rel).max(0) as usize;
            let start = x.rel.max(0) as usize;
            assert!(start <= out.len(), "hole before {start}");
            let have = out.len() - start;
            if x.data.len() - skip > have {
                out.extend_from_slice(&x.data[skip + have..]);
            }
        }
        out
    }

    fn tls_ctx<'a>(d: &[u8], host: &'a str) -> Ctx<'a> {
        Ctx {
            len: d.len(),
            host: tls::sni(d),
            host_str: host,
            tls: true,
            http: false,
        }
    }

    fn plan(split: Split, pos: &str) -> Plan {
        Plan {
            split,
            positions: pos
                .split(',')
                .filter(|x| !x.is_empty())
                .map(|p| Pos::parse(p).unwrap())
                .collect(),
            ..Plan::default()
        }
    }

    #[test]
    fn positions() {
        assert_eq!(sld("www.youtube.com"), Some((4, 11)));
        assert_eq!(sld("discord.gg"), Some((0, 7)));
        assert_eq!(sld("localhost"), None);
        assert_eq!(
            Pos::parse("host+1").unwrap(),
            Pos {
                mark: Mark::Host,
                off: 1
            }
        );
        assert_eq!(
            Pos::parse("method+2").unwrap(),
            Pos {
                mark: Mark::Method,
                off: 2
            }
        );
        assert!(Pos::parse("bogus").is_err());
        let c = Ctx {
            len: 100,
            host: Some((50, 65)),
            host_str: "www.youtube.com",
            tls: true,
            http: false,
        };
        assert_eq!(Pos::parse("midsld").unwrap().resolve(&c), Some(57));
        assert_eq!(Pos::parse("sniext+1").unwrap().resolve(&c), Some(46));
        assert_eq!(Pos::parse("method+2").unwrap().resolve(&c), None);
        assert_eq!(Pos::parse("-10").unwrap().resolve(&c), Some(90));
        assert_eq!(Pos::parse("500").unwrap().resolve(&c), None);
        let h = Ctx {
            http: true,
            tls: false,
            ..c
        };
        assert_eq!(Pos::parse("method+2").unwrap().resolve(&h), Some(2));
        assert_eq!(Pos::parse("sniext").unwrap().resolve(&h), None);
    }

    #[test]
    fn multisplit_and_seqovl() {
        let ch = tls::tests::client_hello("www.youtube.com", 0);
        let c = tls_ctx(&ch, "www.youtube.com");
        let p = plan(Split::Multi { disorder: false }, "1,midsld");
        let s = p.pieces(&ch, &c, 1460);
        assert_eq!(s.len(), 3);
        assert_eq!(reassemble(&s), ch);
        let p = Plan {
            seqovl: 681,
            seqovl_pattern: b"PAT".to_vec(),
            ..plan(Split::Multi { disorder: true }, "1")
        };
        let s = p.pieces(&ch, &c, 1460);
        let first = s.last().unwrap();
        assert_eq!(
            (first.rel, &first.data[..6], first.data.len()),
            (-681, &b"PATPAT"[..], 682)
        );
        assert_eq!(reassemble(&s), ch);
    }

    #[test]
    fn mss_respected() {
        let ch = tls::tests::client_hello("x.com", 3000);
        let c = tls_ctx(&ch, "x.com");
        for p in [
            Plan {
                seqovl: 600,
                seqovl_pattern: vec![1],
                ..plan(Split::Multi { disorder: false }, "2")
            },
            plan(Split::Faked { disorder: false }, "2"),
            plan(Split::HostFake, ""),
            plan(Split::None, ""),
        ] {
            let s = p.pieces(&ch, &c, 1400);
            assert!(s.iter().all(|x| x.data.len() <= 1400));
            assert_eq!(reassemble(&s), ch);
        }
    }

    #[test]
    fn fakedsplit_order() {
        let d: Vec<u8> = (0..20).collect();
        let c = Ctx {
            len: 20,
            host: None,
            host_str: "",
            tls: false,
            http: false,
        };
        let s = Plan {
            faked_pattern: vec![0xee],
            ..plan(Split::Faked { disorder: false }, "5")
        }
        .pieces(&d, &c, 1460);
        let shape: Vec<(i64, usize, bool)> =
            s.iter().map(|p| (p.rel, p.data.len(), p.fake)).collect();
        assert_eq!(
            shape,
            vec![
                (0, 5, true),
                (0, 5, false),
                (0, 5, true),
                (5, 15, true),
                (5, 15, false),
                (5, 15, true)
            ]
        );
        assert!(s[0].data.iter().all(|&b| b == 0xee));
        let r = plan(Split::Faked { disorder: true }, "5").pieces(&d, &c, 1460);
        assert_eq!(r[1].rel, 5);
        assert_eq!(reassemble(&r), d);
    }

    #[test]
    fn hostfakesplit() {
        let ch = tls::tests::client_hello("www.youtube.com", 0);
        let c = tls_ctx(&ch, "www.youtube.com");
        let (hs, he) = c.host.unwrap();
        let p = Plan {
            fake_host: Some("ya.ru".into()),
            midhost: Some(Pos::parse("midsld").unwrap()),
            ..plan(Split::HostFake, "")
        };
        let s = p.pieces(&ch, &c, 1460);
        let fakes: Vec<&Piece> = s.iter().filter(|x| x.fake).collect();
        assert_eq!(fakes.len(), 2);
        assert_eq!(fakes[0].rel, hs as i64);
        assert_eq!(fakes[0].data.len(), he - hs);
        assert!(fakes[0].data.ends_with(b".ya.ru"));
        assert_eq!(s.iter().filter(|x| !x.fake).count(), 4);
        assert_eq!(reassemble(&s), ch);
    }

    #[test]
    fn fake_host_shapes() {
        assert_eq!(fake_host(b"ab.cd", Some("ya.ru")), b"ya.ru");
        assert_eq!(fake_host(b"a.b", Some("ya.ru")), b"aru");
        assert_eq!(fake_host(b"abcdef", Some("ya.ru"))[1..], *b"ya.ru");
        let r = fake_host(b"www.youtube.com", None);
        assert_eq!((r.len(), r[3], r[11]), (15, b'.', b'.'));
    }
}
