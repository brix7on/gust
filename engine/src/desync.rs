// Позиции разреза и план сегментов (multisplit / multidisorder / seqovl).

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mark {
    Abs,
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

    // Абсолютное смещение в данных; None — маркер неприменим.
    pub fn resolve(&self, len: usize, sni: Option<(usize, usize)>, host: &str) -> Option<usize> {
        let base: i64 = match self.mark {
            Mark::Abs => {
                if self.off < 0 {
                    len as i64
                } else {
                    0
                }
            }
            Mark::SniExt => sni?.0 as i64 - 9,
            Mark::Host => sni?.0 as i64,
            Mark::EndHost => sni?.1 as i64,
            Mark::Sld | Mark::MidSld | Mark::EndSld => {
                let (s, e) = sld(host)?;
                let start = sni?.0 as i64;
                match self.mark {
                    Mark::Sld => start + s as i64,
                    Mark::EndSld => start + e as i64,
                    _ => start + (s + (e - s) / 2) as i64,
                }
            }
        };
        let v = base + self.off as i64;
        (v > 0 && (v as usize) < len).then_some(v as usize)
    }
}

// Границы домена второго уровня внутри имени хоста.
pub fn sld(host: &str) -> Option<(usize, usize)> {
    let h = host.trim_end_matches('.');
    let last = h.rfind('.')?;
    let start = h[..last].rfind('.').map_or(0, |i| i + 1);
    (last > start).then_some((start, last))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Desync {
    pub disorder: bool,
    pub positions: Vec<Pos>,
    pub seqovl: usize,
    pub pattern: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Seg {
    pub rel_seq: i64,
    pub data: Vec<u8>,
}

impl Desync {
    // План отправки: сегменты со сдвигом seq относительно начала данных.
    pub fn plan(
        &self,
        data: &[u8],
        sni: Option<(usize, usize)>,
        host: &str,
        mss: usize,
    ) -> Vec<Seg> {
        let mss = mss.max(64);
        let mut cuts: Vec<usize> = self
            .positions
            .iter()
            .filter_map(|p| p.resolve(data.len(), sni, host))
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        let mut bounds = vec![0];
        bounds.extend(cuts);
        bounds.push(data.len());
        let mut segs = Vec::new();
        for w in bounds.windows(2) {
            let mut a = w[0];
            while a < w[1] {
                let b = (a + mss).min(w[1]);
                segs.push(Seg {
                    rel_seq: a as i64,
                    data: data[a..b].to_vec(),
                });
                a = b;
            }
        }
        if self.seqovl > 0 && !segs.is_empty() {
            let room = mss.saturating_sub(self.seqovl).max(1);
            if segs[0].data.len() > room {
                let rest = segs[0].data.split_off(room);
                segs.insert(
                    1,
                    Seg {
                        rel_seq: room as i64,
                        data: rest,
                    },
                );
            }
            let mut first = filler(&self.pattern, self.seqovl);
            first.extend_from_slice(&segs[0].data);
            segs[0] = Seg {
                rel_seq: -(self.seqovl as i64),
                data: first,
            };
        }
        if self.disorder {
            segs.reverse();
        }
        segs
    }
}

fn filler(pattern: &[u8], n: usize) -> Vec<u8> {
    if pattern.is_empty() {
        return vec![0; n];
    }
    pattern.iter().copied().cycle().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls;

    // Как соберёт получатель: байты до начала данных отбрасываются.
    fn reassemble(segs: &[Seg], seqovl: usize) -> Vec<u8> {
        let mut s = segs.to_vec();
        s.sort_by_key(|x| x.rel_seq);
        let mut out = Vec::new();
        for x in s {
            let skip = (-x.rel_seq).max(0) as usize;
            assert!(skip == 0 || skip == seqovl);
            assert_eq!(x.rel_seq.max(0) as usize, out.len());
            out.extend_from_slice(&x.data[skip..]);
        }
        out
    }

    #[test]
    fn positions() {
        assert_eq!(sld("www.youtube.com"), Some((4, 11)));
        assert_eq!(sld("discord.gg"), Some((0, 7)));
        assert_eq!(sld("localhost"), None);
        assert_eq!(
            Pos::parse("midsld").unwrap(),
            Pos {
                mark: Mark::MidSld,
                off: 0
            }
        );
        assert_eq!(
            Pos::parse("host+1").unwrap(),
            Pos {
                mark: Mark::Host,
                off: 1
            }
        );
        assert_eq!(
            Pos::parse("-10").unwrap(),
            Pos {
                mark: Mark::Abs,
                off: -10
            }
        );
        assert!(Pos::parse("bogus").is_err());
        let p = Pos::parse("midsld").unwrap();
        assert_eq!(p.resolve(100, Some((50, 65)), "www.youtube.com"), Some(57));
        assert_eq!(p.resolve(100, None, ""), None);
        assert_eq!(Pos::parse("-10").unwrap().resolve(100, None, ""), Some(90));
        assert_eq!(Pos::parse("500").unwrap().resolve(100, None, ""), None);
    }

    #[test]
    fn multisplit_reassembles() {
        let ch = tls::tests::client_hello("www.youtube.com", 0);
        let sni = tls::sni(&ch);
        let d = Desync {
            disorder: false,
            positions: vec![Pos::parse("1").unwrap(), Pos::parse("midsld").unwrap()],
            seqovl: 0,
            pattern: vec![],
        };
        let segs = d.plan(&ch, sni, "www.youtube.com", 1460);
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].data.len(), 1);
        assert_eq!(reassemble(&segs, 0), ch);
    }

    #[test]
    fn seqovl_prefix_and_disorder() {
        let ch = tls::tests::client_hello("discord.com", 0);
        let d = Desync {
            disorder: true,
            positions: vec![Pos::parse("1").unwrap()],
            seqovl: 681,
            pattern: b"PAT".to_vec(),
        };
        let segs = d.plan(&ch, tls::sni(&ch), "discord.com", 1460);
        let first = segs.iter().find(|s| s.rel_seq < 0).unwrap();
        assert_eq!(first.rel_seq, -681);
        assert_eq!(&first.data[..6], b"PATPAT");
        assert_eq!(first.data.len(), 682);
        assert_eq!(segs.last().unwrap().rel_seq, -681);
        assert_eq!(reassemble(&segs, 681), ch);
    }

    #[test]
    fn respects_mss() {
        let ch = tls::tests::client_hello("x.com", 3000);
        let d = Desync {
            disorder: false,
            positions: vec![Pos::parse("2").unwrap()],
            seqovl: 600,
            pattern: vec![1],
        };
        let segs = d.plan(&ch, tls::sni(&ch), "x.com", 1400);
        assert!(segs.iter().all(|s| s.data.len() <= 1400));
        assert_eq!(reassemble(&segs, 600), ch);
    }
}
