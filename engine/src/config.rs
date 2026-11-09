// Аргументы в стиле winws: --wf-tcp, профили через --new.

use crate::desync::{Desync, Pos};
use crate::hostlist::HostList;

#[derive(Debug, Clone)]
pub struct Profile {
    pub ports: Vec<(u16, u16)>,
    pub include: HostList,
    pub exclude: HostList,
    pub desync: Option<Desync>,
}

impl Profile {
    fn new() -> Self {
        Profile {
            ports: vec![],
            include: HostList::default(),
            exclude: HostList::default(),
            desync: None,
        }
    }

    pub fn port_ok(&self, port: u16) -> bool {
        self.ports.is_empty() || self.ports.iter().any(|&(a, b)| (a..=b).contains(&port))
    }

    // Подходит ли соединение: порт, имя хоста (None — SNI не найден).
    pub fn accepts(&self, port: u16, host: Option<&str>) -> bool {
        if !self.port_ok(port) {
            return false;
        }
        match host {
            Some(h) => {
                !self.exclude.matches(h) && (self.include.is_empty() || self.include.matches(h))
            }
            None => self.include.is_empty(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub wf_tcp: Vec<(u16, u16)>,
    pub windivert: Option<String>,
    pub profiles: Vec<Profile>,
}

fn ports(s: &str) -> Result<Vec<(u16, u16)>, String> {
    s.split(',')
        .filter(|x| !x.trim().is_empty())
        .map(|x| {
            let x = x.trim();
            let (a, b) = x.split_once('-').unwrap_or((x, x));
            let a = a.parse::<u16>().map_err(|_| format!("bad port: {x}"))?;
            let b = b.parse::<u16>().map_err(|_| format!("bad port: {x}"))?;
            if a > b || a == 0 {
                return Err(format!("bad port range: {x}"));
            }
            Ok((a, b))
        })
        .collect()
}

pub fn parse(args: &[String]) -> Result<Config, String> {
    let mut cfg = Config {
        wf_tcp: vec![],
        windivert: None,
        profiles: vec![],
    };
    let mut cur = Profile::new();
    let mut mode: Option<String> = None;
    let mut positions: Vec<Pos> = vec![];
    let mut seqovl = 0usize;
    let mut pattern: Vec<u8> = vec![];
    let finish = |cur: &mut Profile,
                  mode: &mut Option<String>,
                  positions: &mut Vec<Pos>,
                  seqovl: &mut usize,
                  pattern: &mut Vec<u8>|
     -> Result<(), String> {
        if let Some(m) = mode.take() {
            let disorder = match m.as_str() {
                "multisplit" | "split" => false,
                "multidisorder" | "disorder" => true,
                _ => return Err(format!("unsupported --dpi-desync={m}")),
            };
            if positions.is_empty() {
                positions.push(Pos::parse("2").unwrap());
            }
            cur.desync = Some(Desync {
                disorder,
                positions: std::mem::take(positions),
                seqovl: *seqovl,
                pattern: std::mem::take(pattern),
            });
        }
        *seqovl = 0;
        positions.clear();
        pattern.clear();
        Ok(())
    };
    for a in args {
        let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
        let v = v.trim_matches('"');
        match k {
            "--wf-tcp" => cfg.wf_tcp.extend(ports(v)?),
            "--windivert" => cfg.windivert = Some(v.to_string()),
            "--filter-tcp" => cur.ports.extend(ports(v)?),
            "--hostlist" => cur.include.load(v)?,
            "--hostlist-domains" => v.split(',').for_each(|d| cur.include.add(d)),
            "--hostlist-exclude" => cur.exclude.load(v)?,
            "--hostlist-exclude-domains" => v.split(',').for_each(|d| cur.exclude.add(d)),
            "--dpi-desync" => mode = Some(v.to_string()),
            "--dpi-desync-split-pos" => {
                for p in v.split(',') {
                    positions.push(Pos::parse(p)?);
                }
            }
            "--dpi-desync-split-seqovl" => {
                seqovl = v.parse().map_err(|_| format!("bad seqovl: {v}"))?
            }
            "--dpi-desync-split-seqovl-pattern" => {
                pattern = if let Some(hex) = v.strip_prefix("0x") {
                    (0..hex.len() / 2)
                        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
                        .collect::<Result<_, _>>()
                        .map_err(|_| format!("bad hex pattern: {v}"))?
                } else {
                    std::fs::read(v).map_err(|e| format!("{v}: {e}"))?
                }
            }
            "--new" => {
                finish(
                    &mut cur,
                    &mut mode,
                    &mut positions,
                    &mut seqovl,
                    &mut pattern,
                )?;
                cfg.profiles
                    .push(std::mem::replace(&mut cur, Profile::new()));
            }
            _ => return Err(format!("unsupported option: {a}")),
        }
    }
    finish(
        &mut cur,
        &mut mode,
        &mut positions,
        &mut seqovl,
        &mut pattern,
    )?;
    cfg.profiles.push(cur);
    if cfg.seqovl_too_big() {
        return Err("seqovl must be below 1400".into());
    }
    if cfg.wf_tcp.is_empty() {
        cfg.wf_tcp = cfg.profiles.iter().flat_map(|p| p.ports.clone()).collect();
    }
    if cfg.wf_tcp.is_empty() {
        cfg.wf_tcp = vec![(443, 443)];
    }
    Ok(cfg)
}

impl Config {
    fn seqovl_too_big(&self) -> bool {
        self.profiles
            .iter()
            .any(|p| p.desync.as_ref().is_some_and(|d| d.seqovl >= 1400))
    }

    pub fn pick(&self, port: u16, host: Option<&str>) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.accepts(port, host))
    }

    // Фильтр WinDivert: исходящий TCP с данными на выбранные порты.
    pub fn filter(&self) -> String {
        let ports: Vec<String> = self
            .wf_tcp
            .iter()
            .map(|&(a, b)| {
                if a == b {
                    format!("tcp.DstPort == {a}")
                } else {
                    format!("(tcp.DstPort >= {a} and tcp.DstPort <= {b})")
                }
            })
            .collect();
        format!(
            "outbound and !loopback and !impostor and tcp and tcp.PayloadLength > 0 and ({})",
            ports.join(" or ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn profiles() {
        let c = parse(&a("--wf-tcp=80,443,2053-2096 --filter-tcp=443 --hostlist-domains=discord.com,discord.gg --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-split-seqovl-pattern=0x1603 --new --filter-tcp=80,443 --hostlist-exclude-domains=ya.ru --dpi-desync=multidisorder --dpi-desync-split-pos=1,midsld")).unwrap();
        assert_eq!(c.profiles.len(), 2);
        let d0 = c.profiles[0].desync.as_ref().unwrap();
        assert_eq!(
            (d0.seqovl, d0.pattern.as_slice(), d0.disorder),
            (681, &[0x16u8, 0x03][..], false)
        );
        assert!(c.profiles[1].desync.as_ref().unwrap().disorder);
        assert_eq!(
            c.pick(443, Some("cdn.discord.com"))
                .map(|p| p.desync.as_ref().unwrap().seqovl),
            Some(681)
        );
        assert_eq!(
            c.pick(443, Some("youtube.com"))
                .map(|p| p.desync.as_ref().unwrap().seqovl),
            Some(0)
        );
        assert!(c.pick(443, Some("ya.ru")).is_none());
        assert!(c.pick(8443, Some("youtube.com")).is_none());
        assert!(c
            .filter()
            .contains("(tcp.DstPort >= 2053 and tcp.DstPort <= 2096)"));
    }

    #[test]
    fn rejects_unknown() {
        assert!(parse(&a("--dpi-desync=fake")).is_err());
        assert!(parse(&a("--ipset=x.txt")).is_err());
        assert!(parse(&a("--filter-tcp=0")).is_err());
        let c = parse(&a("--dpi-desync=multisplit")).unwrap();
        assert_eq!(c.wf_tcp, vec![(443, 443)]);
    }
}
