// Аргументы в стиле winws: глобальные --wf-*, профили через --new.

use crate::desync::{Plan, Pos, Split};
use crate::hostlist::HostList;
use crate::ipset::IpSet;
use crate::l7::L7;
use crate::{http, quic, tls};

pub type Ports = Vec<(u16, u16)>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CutKind {
    Packets,
    Data,
    Seq,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cutoff {
    pub kind: CutKind,
    pub n: u64,
}

impl Cutoff {
    fn parse(s: &str) -> Result<Cutoff, String> {
        let (kind, num) = match s.as_bytes().first() {
            Some(b'n') => (CutKind::Packets, &s[1..]),
            Some(b'd') => (CutKind::Data, &s[1..]),
            Some(b's') => (CutKind::Seq, &s[1..]),
            _ => (CutKind::Packets, s),
        };
        let n = num.parse().map_err(|_| format!("bad cutoff: {s}"))?;
        Ok(Cutoff { kind, n })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AutoTtl {
    pub delta: u8,
    pub min: u8,
    pub max: u8,
}

impl AutoTtl {
    fn parse(s: &str) -> Result<Option<AutoTtl>, String> {
        let bad = || format!("bad autottl: {s}");
        let (d, range) = s.split_once(':').unwrap_or((s, "3-20"));
        let delta = d
            .trim_start_matches(['-', '+'])
            .parse::<u8>()
            .map_err(|_| bad())?;
        let (a, b) = range.split_once('-').ok_or_else(bad)?;
        let (min, max) = (
            a.parse::<u8>().map_err(|_| bad())?,
            b.parse::<u8>().map_err(|_| bad())?,
        );
        if min == 0 || min > max {
            return Err(bad());
        }
        Ok((delta > 0).then_some(AutoTtl { delta, min, max }))
    }

    pub fn ttl(&self, hops: u8) -> u8 {
        hops.saturating_sub(self.delta).clamp(self.min, self.max)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fooling {
    pub md5sig: bool,
    pub badseq: bool,
    pub badsum: bool,
    pub ts: bool,
    pub datanoack: bool,
    pub ttl: Option<u8>,
    pub ttl6: Option<u8>,
    pub autottl: Option<AutoTtl>,
    pub autottl6: Option<AutoTtl>,
    pub badseq_inc: i32,
    pub badack_inc: i32,
    pub ts_inc: i32,
}

impl Default for Fooling {
    fn default() -> Self {
        Fooling {
            md5sig: false,
            badseq: false,
            badsum: false,
            ts: false,
            datanoack: false,
            ttl: None,
            ttl6: None,
            autottl: None,
            autottl6: None,
            badseq_inc: -10000,
            badack_inc: -66000,
            ts_inc: -600000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Desync {
    pub fake: bool,
    pub syndata: bool,
    pub plan: Plan,
    pub repeats: u32,
    pub fool: Fooling,
    pub fake_tls: Vec<u8>,
    pub tls_mods: tls::Mods,
    pub fake_http: Vec<u8>,
    pub fake_quic: Vec<u8>,
    pub fake_discord: Option<Vec<u8>>,
    pub fake_stun: Option<Vec<u8>>,
    pub fake_unknown: Vec<u8>,
    pub fake_unknown_udp: Vec<u8>,
    pub fake_syndata: Vec<u8>,
    pub any_protocol: bool,
    pub cutoff: Option<Cutoff>,
    pub ip_id_zero: bool,
}

impl Default for Desync {
    fn default() -> Self {
        Desync {
            fake: false,
            syndata: false,
            plan: Plan::default(),
            repeats: 1,
            fool: Fooling::default(),
            fake_tls: tls::Hello::browser("www.iana.org").to_record(0),
            tls_mods: tls::Mods::default(),
            fake_http: http::fake(),
            fake_quic: quic::fake(),
            fake_discord: None,
            fake_stun: None,
            fake_unknown: vec![0; 256],
            fake_unknown_udp: vec![0; 64],
            fake_syndata: vec![0; 16],
            any_protocol: false,
            cutoff: None,
            ip_id_zero: false,
        }
    }
}

impl Desync {
    pub fn active(&self) -> bool {
        self.fake || self.syndata || self.plan.split != Split::None
    }

    pub fn udp_fake(&self, l7: L7) -> &[u8] {
        match l7 {
            L7::Quic => &self.fake_quic,
            L7::Discord => self
                .fake_discord
                .as_deref()
                .unwrap_or(&self.fake_unknown_udp),
            L7::Stun => self.fake_stun.as_deref().unwrap_or(&self.fake_unknown_udp),
            _ => &self.fake_unknown_udp,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub tcp: Ports,
    pub udp: Ports,
    pub l7: Vec<L7>,
    pub include: HostList,
    pub exclude: HostList,
    pub ipset: Option<IpSet>,
    pub ipset_ex: Option<IpSet>,
    pub desync: Desync,
    pub wssize: Option<(u16, Option<u8>)>,
}

pub struct Match<'a> {
    pub udp: bool,
    pub port: u16,
    pub ip: &'a [u8],
    pub l7: L7,
    pub host: Option<&'a str>,
}

fn in_ports(ps: &Ports, p: u16) -> bool {
    ps.iter().any(|&(a, b)| (a..=b).contains(&p))
}

impl Profile {
    pub fn port_ok(&self, udp: bool, port: u16) -> bool {
        if self.tcp.is_empty() && self.udp.is_empty() {
            return true;
        }
        in_ports(if udp { &self.udp } else { &self.tcp }, port)
    }

    pub fn ip_ok(&self, ip: &[u8]) -> bool {
        self.ipset.as_ref().is_none_or(|s| s.contains(ip))
            && !self.ipset_ex.as_ref().is_some_and(|s| s.contains(ip))
    }

    pub fn matches(&self, m: &Match) -> bool {
        if !self.port_ok(m.udp, m.port) || !self.ip_ok(m.ip) {
            return false;
        }
        if self.l7.is_empty() {
            if m.l7 == L7::Unknown && !self.desync.any_protocol {
                return false;
            }
        } else if !self.l7.contains(&m.l7) {
            return false;
        }
        match m.host {
            Some(h) => {
                !self.exclude.matches(h) && (self.include.is_empty() || self.include.matches(h))
            }
            None => self.include.is_empty(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub wf_tcp: Ports,
    pub wf_udp: Ports,
    pub windivert: Option<String>,
    pub profiles: Vec<Profile>,
}

fn ports(s: &str) -> Result<Ports, String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|x| {
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

pub fn blob(v: &str) -> Result<Vec<u8>, String> {
    if let Some(hex) = v.strip_prefix("0x") {
        if hex.is_empty() || hex.len() % 2 != 0 {
            return Err(format!("bad hex: {v}"));
        }
        return (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
            .collect::<Result<_, _>>()
            .map_err(|_| format!("bad hex: {v}"));
    }
    let b = std::fs::read(v).map_err(|e| format!("{v}: {e}"))?;
    if b.is_empty() {
        return Err(format!("{v}: empty file"));
    }
    Ok(b)
}

fn num<T: std::str::FromStr>(k: &str, v: &str) -> Result<T, String> {
    v.parse().map_err(|_| format!("bad value {k}={v}"))
}

fn modes(d: &mut Desync, v: &str) -> Result<(), String> {
    for m in v.split(',').map(str::trim) {
        let split = |d: &mut Desync, s: Split| -> Result<(), String> {
            if d.plan.split != Split::None {
                return Err(format!("only one split mode allowed: {v}"));
            }
            d.plan.split = s;
            Ok(())
        };
        match m {
            "fake" => d.fake = true,
            "syndata" => d.syndata = true,
            "multisplit" | "split" | "split2" => split(d, Split::Multi { disorder: false })?,
            "multidisorder" | "disorder" | "disorder2" => {
                split(d, Split::Multi { disorder: true })?
            }
            "fakedsplit" => split(d, Split::Faked { disorder: false })?,
            "fakeddisorder" => split(d, Split::Faked { disorder: true })?,
            "hostfakesplit" => split(d, Split::HostFake)?,
            "none" => {}
            _ => return Err(format!("unsupported --dpi-desync mode: {m}")),
        }
    }
    Ok(())
}

fn fooling(f: &mut Fooling, v: &str) -> Result<(), String> {
    for x in v.split(',').map(str::trim) {
        match x {
            "md5sig" => f.md5sig = true,
            "badseq" => f.badseq = true,
            "badsum" => f.badsum = true,
            "ts" => f.ts = true,
            "datanoack" => f.datanoack = true,
            "none" => {}
            _ => return Err(format!("unsupported fooling: {x}")),
        }
    }
    Ok(())
}

fn hostfake_mod(p: &mut Plan, v: &str) -> Result<(), String> {
    for x in v.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        match x.split_once('=') {
            Some(("host", h)) if !h.is_empty() => p.fake_host = Some(h.to_ascii_lowercase()),
            Some(("altorder", "0")) => p.altorder = false,
            Some(("altorder", "1")) => p.altorder = true,
            _ => return Err(format!("unsupported hostfakesplit mod: {x}")),
        }
    }
    Ok(())
}

fn finish(cur: &mut Profile, positions: &mut Vec<Pos>) {
    if positions.is_empty() {
        let def = match cur.desync.plan.split {
            Split::HostFake | Split::None => vec![],
            _ => vec![Pos::parse("2").unwrap()],
        };
        cur.desync.plan.positions = def;
    } else {
        cur.desync.plan.positions = std::mem::take(positions);
    }
    for s in [&mut cur.ipset, &mut cur.ipset_ex].into_iter().flatten() {
        s.finish();
    }
}

pub fn parse(args: &[String]) -> Result<Config, String> {
    let mut cfg = Config::default();
    let mut cur = Profile::default();
    let mut positions: Vec<Pos> = vec![];
    for a in args {
        let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
        let v = v.trim().trim_matches('"');
        let d = &mut cur.desync;
        match k {
            "--wf-tcp" => cfg.wf_tcp.extend(ports(v)?),
            "--wf-udp" => cfg.wf_udp.extend(ports(v)?),
            "--windivert" => cfg.windivert = Some(v.to_string()),
            "--new" => {
                finish(&mut cur, &mut positions);
                cfg.profiles.push(std::mem::take(&mut cur));
            }
            "--filter-tcp" => cur.tcp.extend(ports(v)?),
            "--filter-udp" => cur.udp.extend(ports(v)?),
            "--filter-l7" => {
                for x in v.split(',') {
                    cur.l7.push(L7::parse(x.trim())?);
                }
            }
            "--hostlist" => cur.include.load(v)?,
            "--hostlist-domains" => v.split(',').for_each(|x| cur.include.add(x)),
            "--hostlist-exclude" => cur.exclude.load(v)?,
            "--hostlist-exclude-domains" => v.split(',').for_each(|x| cur.exclude.add(x)),
            "--ipset" => cur.ipset.get_or_insert_with(IpSet::default).load(v)?,
            "--ipset-ip" => {
                let s = cur.ipset.get_or_insert_with(IpSet::default);
                for x in v.split(',') {
                    s.add(x)?;
                }
            }
            "--ipset-exclude" => cur.ipset_ex.get_or_insert_with(IpSet::default).load(v)?,
            "--ipset-exclude-ip" => {
                let s = cur.ipset_ex.get_or_insert_with(IpSet::default);
                for x in v.split(',') {
                    s.add(x)?;
                }
            }
            "--ip-id" => match v {
                "zero" => d.ip_id_zero = true,
                "seq" => d.ip_id_zero = false,
                _ => return Err(format!("unsupported --ip-id={v}")),
            },
            "--dpi-desync" => modes(d, v)?,
            "--dpi-desync-repeats" => d.repeats = num::<u32>(k, v)?.clamp(1, 64),
            "--dpi-desync-split-pos" => {
                for p in v.split(',') {
                    positions.push(Pos::parse(p)?);
                }
            }
            "--dpi-desync-split-seqovl" => d.plan.seqovl = num(k, v)?,
            "--dpi-desync-split-seqovl-pattern" => d.plan.seqovl_pattern = blob(v)?,
            "--dpi-desync-fakedsplit-pattern" => d.plan.faked_pattern = blob(v)?,
            "--dpi-desync-hostfakesplit-mod" => hostfake_mod(&mut d.plan, v)?,
            "--dpi-desync-hostfakesplit-midhost" => d.plan.midhost = Some(Pos::parse(v)?),
            "--dpi-desync-fooling" => fooling(&mut d.fool, v)?,
            "--dpi-desync-ttl" => d.fool.ttl = Some(num::<u8>(k, v)?).filter(|&t| t > 0),
            "--dpi-desync-ttl6" => d.fool.ttl6 = Some(num::<u8>(k, v)?).filter(|&t| t > 0),
            "--dpi-desync-autottl" => {
                d.fool.autottl = AutoTtl::parse(if v.is_empty() { "1" } else { v })?
            }
            "--dpi-desync-autottl6" => {
                d.fool.autottl6 = AutoTtl::parse(if v.is_empty() { "1" } else { v })?
            }
            "--dpi-desync-badseq-increment" => d.fool.badseq_inc = num(k, v)?,
            "--dpi-desync-badack-increment" => d.fool.badack_inc = num(k, v)?,
            "--dpi-desync-ts-increment" => d.fool.ts_inc = num(k, v)?,
            "--dpi-desync-fake-tls" => d.fake_tls = blob(v)?,
            "--dpi-desync-fake-tls-mod" => d.tls_mods = tls::Mods::parse(v)?,
            "--dpi-desync-fake-http" => d.fake_http = blob(v)?,
            "--dpi-desync-fake-quic" => d.fake_quic = blob(v)?,
            "--dpi-desync-fake-discord" => d.fake_discord = Some(blob(v)?),
            "--dpi-desync-fake-stun" => d.fake_stun = Some(blob(v)?),
            "--dpi-desync-fake-unknown" => d.fake_unknown = blob(v)?,
            "--dpi-desync-fake-unknown-udp" => d.fake_unknown_udp = blob(v)?,
            "--dpi-desync-fake-syndata" => d.fake_syndata = blob(v)?,
            "--dpi-desync-any-protocol" => d.any_protocol = v.is_empty() || v == "1",
            "--dpi-desync-cutoff" => d.cutoff = Some(Cutoff::parse(v)?),
            "--wssize" => {
                let (w, s) = v.split_once(':').map_or((v, None), |(w, s)| (w, Some(s)));
                let w = num::<u16>(k, w)?;
                let s = s.map(|s| num::<u8>(k, s)).transpose()?;
                cur.wssize = (w > 0).then_some((w, s));
            }
            "--wssize-cutoff" => {
                Cutoff::parse(v)?;
            }
            _ => return Err(format!("unsupported option: {a}")),
        }
    }
    finish(&mut cur, &mut positions);
    cfg.profiles.push(cur);
    for p in &cfg.profiles {
        if p.desync.plan.seqovl >= 1400 {
            return Err("seqovl must be below 1400".into());
        }
    }
    if cfg.wf_tcp.is_empty() && cfg.wf_udp.is_empty() {
        for p in &cfg.profiles {
            cfg.wf_tcp.extend(p.tcp.iter().copied());
            cfg.wf_udp.extend(p.udp.iter().copied());
        }
        if cfg.wf_tcp.is_empty() && cfg.wf_udp.is_empty() {
            cfg.wf_tcp = vec![(80, 80), (443, 443)];
        }
    }
    Ok(cfg)
}

fn port_expr(field: &str, ps: &Ports) -> String {
    let v: Vec<String> = ps
        .iter()
        .map(|&(a, b)| {
            if a == b {
                format!("{field} == {a}")
            } else {
                format!("({field} >= {a} and {field} <= {b})")
            }
        })
        .collect();
    format!("({})", v.join(" or "))
}

impl Config {
    pub fn pick(&self, m: &Match) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.matches(m))
    }

    // Фильтр WinDivert: исходящие данные и SYN на нужные порты, входящие SYN-ACK (для autottl и wssize).
    pub fn filter(&self) -> String {
        let mut out = vec![];
        if !self.wf_tcp.is_empty() {
            out.push(format!(
                "(outbound and tcp and {} and (tcp.PayloadLength > 0 or (tcp.Syn and !tcp.Ack)))",
                port_expr("tcp.DstPort", &self.wf_tcp)
            ));
            out.push(format!(
                "(inbound and tcp and tcp.Syn and tcp.Ack and {})",
                port_expr("tcp.SrcPort", &self.wf_tcp)
            ));
        }
        if !self.wf_udp.is_empty() {
            out.push(format!(
                "(outbound and udp and udp.PayloadLength > 0 and {})",
                port_expr("udp.DstPort", &self.wf_udp)
            ));
        }
        format!("!loopback and !impostor and ({})", out.join(" or "))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn profiles_and_matching() {
        let c = parse(&args("--wf-tcp=80,443,2053-2096 --wf-udp=443,50000-50100 --filter-tcp=443 --hostlist-domains=discord.com --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1,midsld --dpi-desync-split-seqovl-pattern=0x1603 --dpi-desync-fooling=md5sig,badseq --dpi-desync-autottl=2 --dpi-desync-repeats=6 --new --filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord=0x0102 --new --filter-tcp=80,443 --ipset-ip=104.16.0.0/13 --hostlist-exclude-domains=ya.ru --dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=ya.ru --ip-id=zero")).unwrap();
        assert_eq!(c.profiles.len(), 3);
        let d0 = &c.profiles[0].desync;
        assert!(d0.fake && d0.fool.md5sig && d0.fool.badseq);
        assert_eq!(
            (
                d0.plan.seqovl,
                d0.plan.seqovl_pattern.as_slice(),
                d0.repeats,
                d0.plan.positions.len()
            ),
            (681, &[0x16u8, 0x03][..], 6, 2)
        );
        assert_eq!(
            d0.fool.autottl,
            Some(AutoTtl {
                delta: 2,
                min: 3,
                max: 20
            })
        );
        let ip = [104, 17, 1, 1];
        let m = |udp, port, l7, host| Match {
            udp,
            port,
            ip: &ip,
            l7,
            host,
        };
        assert!(
            c.pick(&m(false, 443, L7::Tls, Some("cdn.discord.com")))
                .unwrap()
                .desync
                .fake
        );
        assert_eq!(
            c.pick(&m(false, 443, L7::Tls, Some("youtube.com")))
                .unwrap()
                .desync
                .plan
                .split,
            Split::HostFake
        );
        assert!(c.pick(&m(false, 443, L7::Tls, Some("ya.ru"))).is_none());
        assert!(c.pick(&m(false, 443, L7::Unknown, None)).is_none());
        assert_eq!(
            c.pick(&m(true, 50010, L7::Discord, None))
                .unwrap()
                .desync
                .udp_fake(L7::Discord),
            &[1, 2]
        );
        assert!(c.pick(&m(true, 50010, L7::Unknown, None)).is_none());
        assert!(c.profiles[2].desync.ip_id_zero);
        let f = c.filter();
        assert!(
            f.contains("(tcp.DstPort >= 2053 and tcp.DstPort <= 2096)")
                && f.contains("udp.DstPort == 443")
                && f.contains("tcp.SrcPort == 443")
        );
    }

    #[test]
    fn values() {
        assert_eq!(
            AutoTtl::parse("-1:3-20").unwrap(),
            Some(AutoTtl {
                delta: 1,
                min: 3,
                max: 20
            })
        );
        assert_eq!(AutoTtl::parse("0").unwrap(), None);
        assert!(AutoTtl::parse("2:9-3").is_err());
        assert_eq!(
            AutoTtl {
                delta: 2,
                min: 3,
                max: 20
            }
            .ttl(10),
            8
        );
        assert_eq!(
            AutoTtl {
                delta: 2,
                min: 3,
                max: 20
            }
            .ttl(2),
            3
        );
        assert_eq!(
            Cutoff::parse("d3").unwrap(),
            Cutoff {
                kind: CutKind::Data,
                n: 3
            }
        );
        assert_eq!(
            Cutoff::parse("4").unwrap(),
            Cutoff {
                kind: CutKind::Packets,
                n: 4
            }
        );
        let c = parse(&args("--wssize=1:6 --dpi-desync=multisplit")).unwrap();
        assert_eq!(c.profiles[0].wssize, Some((1, Some(6))));
        assert_eq!(c.wf_tcp, vec![(80, 80), (443, 443)]);
    }

    #[test]
    fn rejects() {
        for bad in [
            "--dpi-desync=fakeknown",
            "--dpi-desync=multisplit,fakedsplit",
            "--dpi-desync-fooling=hopbyhop",
            "--filter-tcp=0",
            "--filter-l7=wireguard",
            "--dpi-desync-fake-tls-mod=bogus",
            "--ip-id=rnd",
            "--dpi-desync-split-seqovl=1500",
            "--foo",
            "--dpi-desync-fake-tls=0x1",
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad}");
        }
    }
}
