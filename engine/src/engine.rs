// Обработка пакетов: соединения, выбор профиля, фейки и разрез, склейка ClientHello (TCP и QUIC).

use crate::config::{Config, CutKind, Desync, Match, Profile};
use crate::desync::{Ctx, Split};
use crate::l7::{self, L7};
use crate::packet::{self, Mods, Pkt};
use crate::{http, quic, tls};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const HOLD_TTL: Duration = Duration::from_millis(250);
const FLOW_TTL: Duration = Duration::from_secs(120);
const HOPS_TTL: Duration = Duration::from_secs(600);
const SWEEP: Duration = Duration::from_secs(10);
const MAX_RECORD: usize = 16 * 1024;
const MAX_FLOWS: usize = 200_000;

pub struct Out<A> {
    pub pkt: Vec<u8>,
    pub addr: A,
    pub modified: bool,
}

impl<A> Out<A> {
    fn orig(pkt: Vec<u8>, addr: A) -> Self {
        Out {
            pkt,
            addr,
            modified: false,
        }
    }
}

#[derive(Default)]
struct Flow {
    last: Option<Instant>,
    syn: bool,
    isn: u32,
    packets: u64,
    data: u64,
    done: bool,
    hello_seq: Option<u32>,
}

struct Hold<A> {
    pkts: Vec<(Vec<u8>, A)>,
    at: Instant,
    crypto: Option<quic::Crypto>,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Stats {
    pub hellos: u64,
    pub desynced: u64,
    pub fakes: u64,
    pub reassembled: u64,
    pub udp: u64,
    pub retrans: u64,
}

pub struct Engine<A> {
    cfg: Config,
    flows: HashMap<Vec<u8>, Flow>,
    hops: HashMap<Vec<u8>, (u8, Instant)>,
    held: HashMap<Vec<u8>, Hold<A>>,
    swept: Option<Instant>,
    logged: HashMap<String, Instant>,
    warned: Vec<&'static str>,
    pub stats: Stats,
    pub log: Vec<String>,
}

fn guess_hops(ttl: u8) -> u8 {
    let init: u16 = if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    };
    (init - ttl as u16) as u8
}

impl<A: Clone> Engine<A> {
    pub fn new(cfg: Config) -> Self {
        Engine {
            cfg,
            flows: HashMap::new(),
            hops: HashMap::new(),
            held: HashMap::new(),
            swept: None,
            logged: HashMap::new(),
            warned: vec![],
            stats: Stats::default(),
            log: vec![],
        }
    }

    pub fn handle(
        &mut self,
        mut pkt: Vec<u8>,
        addr: A,
        outbound: bool,
        now: Instant,
    ) -> Vec<Out<A>> {
        let mut out = self.expire(now);
        self.sweep(now);
        let Some(p) = packet::parse(&pkt) else {
            out.push(Out::orig(pkt, addr));
            return out;
        };
        if !outbound {
            let modified =
                p.is_tcp() && p.syn() && p.has_ack() && self.on_synack(&mut pkt, &p, now);
            out.push(Out {
                pkt,
                addr,
                modified,
            });
            return out;
        }
        if p.is_tcp() {
            self.tcp_out(pkt, p, addr, now, &mut out);
        } else {
            self.udp_out(pkt, p, addr, now, &mut out);
        }
        out
    }

    fn sweep(&mut self, now: Instant) {
        if self.swept.is_some_and(|t| now.duration_since(t) < SWEEP) {
            return;
        }
        self.swept = Some(now);
        self.flows
            .retain(|_, f| f.last.is_some_and(|t| now.duration_since(t) < FLOW_TTL));
        self.hops.retain(|_, h| now.duration_since(h.1) < HOPS_TTL);
        self.logged
            .retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
        if self.flows.len() > MAX_FLOWS {
            self.flows.clear();
        }
    }

    fn warn_once(&mut self, key: &'static str, msg: &str) {
        if !self.warned.contains(&key) {
            self.warned.push(key);
            self.log.push(format!("warning: {msg}"));
        }
    }

    fn note(&mut self, msg: String, now: Instant) {
        if !self.logged.contains_key(&msg) {
            self.logged.insert(msg.clone(), now);
            self.log.push(msg);
        }
    }

    // Входящий SYN-ACK: запоминаем число хопов до сервера, при wssize подменяем окно.
    fn on_synack(&mut self, pkt: &mut [u8], p: &Pkt, now: Instant) -> bool {
        let ip = packet::src_ip(pkt, p).to_vec();
        self.hops.insert(ip.clone(), (guess_hops(p.ttl), now));
        let ws = self
            .cfg
            .profiles
            .iter()
            .find(|pr| pr.wssize.is_some() && pr.port_ok(false, p.sport) && pr.ip_ok(&ip))
            .and_then(|pr| pr.wssize);
        if let Some((w, s)) = ws {
            packet::set_window(pkt, p, w, s);
            return true;
        }
        false
    }

    fn tcp_out(&mut self, pkt: Vec<u8>, p: Pkt, addr: A, now: Instant, out: &mut Vec<Out<A>>) {
        let key = packet::flow_key(&pkt, &p, true);
        if p.syn() && !p.has_ack() {
            self.flows.insert(
                key,
                Flow {
                    last: Some(now),
                    syn: true,
                    isn: p.seq,
                    packets: 1,
                    ..Flow::default()
                },
            );
            out.push(self.syndata(pkt, &p, addr));
            return;
        }
        if let Some(h) = self.held.remove(&key) {
            let (hpkt, haddr) = h.pkts.into_iter().next().expect("held tcp packet");
            let hp = packet::parse(&hpkt).expect("held packet parses");
            if p.seq == hp.seq.wrapping_add(hp.payload_len() as u32) {
                let mut data = packet::payload(&hpkt, &hp).to_vec();
                data.extend_from_slice(packet::payload(&pkt, &p));
                self.stats.reassembled += 1;
                self.bump(&key, now, true);
                let orig = vec![(hpkt.clone(), haddr), (pkt, addr.clone())];
                out.extend(self.tcp_hello(&key, &hpkt, &hp, &data, addr, orig, now));
                return;
            }
            out.push(Out::orig(hpkt, haddr));
        }
        let flow = self.bump(&key, now, true);
        let retrans = flow.hello_seq == Some(p.seq);
        let first = !flow.done;
        if !first && !retrans && !http::is_request(packet::payload(&pkt, &p)) {
            let within = self.unknown_within(&key, &p);
            if !within {
                out.push(Out::orig(pkt, addr));
                return;
            }
        }
        if retrans {
            self.stats.retrans += 1;
        }
        let data = packet::payload(&pkt, &p);
        if tls::is_client_hello(data) && (first || retrans) {
            let need = tls::record_len(data);
            if need > data.len() && need <= MAX_RECORD && tls::sni(data).is_none() {
                self.held.insert(
                    key,
                    Hold {
                        pkts: vec![(pkt, addr)],
                        at: now,
                        crypto: None,
                    },
                );
                return;
            }
        }
        let data = data.to_vec();
        let orig = vec![(pkt.clone(), addr.clone())];
        out.extend(self.tcp_hello(&key, &pkt, &p, &data, addr, orig, now));
    }

    fn bump(&mut self, key: &[u8], now: Instant, data: bool) -> &mut Flow {
        let f = self.flows.entry(key.to_vec()).or_default();
        f.last = Some(now);
        f.packets += 1;
        if data {
            f.data += 1;
        }
        f
    }

    // Соединение уже обработано: продолжаем только для any-protocol в пределах cutoff.
    fn unknown_within(&self, key: &[u8], p: &Pkt) -> bool {
        let Some(f) = self.flows.get(key) else {
            return false;
        };
        let ip = &key[1 + if p.v6 { 18 } else { 6 }..key.len() - 2];
        let m = Match {
            udp: !p.is_tcp(),
            port: p.dport,
            ip,
            l7: L7::Unknown,
            host: None,
        };
        match self.cfg.pick(&m) {
            Some(pr) if pr.desync.any_protocol && pr.desync.cutoff.is_some() => within(
                f,
                pr.desync.cutoff.unwrap().kind,
                pr.desync.cutoff.unwrap().n,
                p,
            ),
            _ => false,
        }
    }

    fn syndata(&mut self, pkt: Vec<u8>, p: &Pkt, addr: A) -> Out<A> {
        let ip = packet::dst_ip(&pkt, p);
        let pr = self
            .cfg
            .profiles
            .iter()
            .find(|pr| pr.desync.syndata && pr.port_ok(false, p.dport) && pr.ip_ok(ip));
        match pr {
            Some(pr) => {
                let m = Mods {
                    ip_id_zero: pr.desync.ip_id_zero,
                    ..Mods::default()
                };
                let s = packet::tcp_segment(&pkt, p, p.seq, &pr.desync.fake_syndata, &m, 0);
                self.stats.fakes += 1;
                Out {
                    pkt: s,
                    addr,
                    modified: true,
                }
            }
            None => Out::orig(pkt, addr),
        }
    }

    fn fake_mods(&mut self, d: &Desync, tpl: &[u8], p: &Pkt) -> Option<Mods> {
        let f = &d.fool;
        let auto = if p.v6 {
            f.autottl6.or(f.autottl)
        } else {
            f.autottl
        };
        let hops = self.hops.get(packet::dst_ip(tpl, p)).map(|h| h.0);
        let ttl = match (auto, hops) {
            (Some(a), Some(h)) => Some(a.ttl(h)),
            _ => {
                if p.v6 {
                    f.ttl6.or(f.ttl)
                } else {
                    f.ttl
                }
            }
        };
        if auto.is_some() && hops.is_none() {
            self.warn_once(
                "autottl",
                "autottl: server hop count unknown (no SYN-ACK seen), using fixed ttl/fooling only",
            );
        }
        let ts = f.ts && packet::has_timestamp(tpl, p);
        if f.ts && !ts {
            self.warn_once("ts", "ts fooling: TCP timestamps are off on this system (netsh int tcp set global timestamps=enabled)");
        }
        let m = Mods {
            ttl,
            ip_id_zero: d.ip_id_zero,
            seq_delta: if f.badseq { f.badseq_inc } else { 0 },
            ack_delta: if f.badseq { f.badack_inc } else { 0 },
            md5sig: f.md5sig,
            ts_delta: ts.then_some(f.ts_inc),
            datanoack: f.datanoack,
            badsum: f.badsum,
        };
        if p.is_tcp()
            && m.ttl.is_none()
            && !f.badseq
            && !f.md5sig
            && !ts
            && !f.datanoack
            && !f.badsum
        {
            self.warn_once("nofool", "fakes skipped: no working fooling (ttl/autottl/md5sig/badseq/badsum/datanoack) — a fake would reach the server");
            return None;
        }
        Some(m)
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp_hello(
        &mut self,
        key: &[u8],
        tpl: &[u8],
        p: &Pkt,
        data: &[u8],
        addr: A,
        orig: Vec<(Vec<u8>, A)>,
        now: Instant,
    ) -> Vec<Out<A>> {
        let kind = l7::tcp(data);
        let (host_span, tls_, http_) = match kind {
            L7::Tls => (tls::sni(data), true, false),
            L7::Http => (http::host(data), false, true),
            _ => (None, false, false),
        };
        let host =
            host_span.map(|(s, e)| String::from_utf8_lossy(&data[s..e]).to_ascii_lowercase());
        let ip = packet::dst_ip(tpl, p).to_vec();
        let m = Match {
            udp: false,
            port: p.dport,
            ip: &ip,
            l7: kind,
            host: host.as_deref(),
        };
        let prof: Option<Profile> = self.cfg.pick(&m).cloned();
        let flow = self.flows.entry(key.to_vec()).or_default();
        if kind != L7::Unknown {
            self.stats.hellos += 1;
            flow.done = true;
            flow.hello_seq = Some(p.seq);
        } else if prof
            .as_ref()
            .is_none_or(|pr| !pr.desync.any_protocol || pr.desync.cutoff.is_none())
        {
            flow.done = true;
        }
        let passthrough =
            |orig: Vec<(Vec<u8>, A)>| orig.into_iter().map(|(k, a)| Out::orig(k, a)).collect();
        let Some(pr) = prof.filter(|pr| pr.desync.active()) else {
            return passthrough(orig);
        };
        if let Some(c) = pr.desync.cutoff {
            let f = self.flows.get(key).expect("flow exists");
            if !within(f, c.kind, c.n, p) {
                return passthrough(orig);
            }
        }
        let d = &pr.desync;
        let fake_m = if d.fake || matches!(d.plan.split, Split::Faked { .. } | Split::HostFake) {
            self.fake_mods(d, tpl, p)
        } else {
            None
        };
        let real_m = Mods {
            ip_id_zero: d.ip_id_zero,
            ..Mods::default()
        };
        let mss = p.payload_len().max(536) - if d.fool.md5sig { 20 } else { 0 };
        let mut res = vec![];
        let mut idx = 0u16;
        let mut emit = |res: &mut Vec<Out<A>>, seq: u32, body: &[u8], m: &Mods| {
            res.push(Out {
                pkt: packet::tcp_segment(tpl, p, seq, body, m, idx),
                addr: addr.clone(),
                modified: true,
            });
            idx = idx.wrapping_add(1);
        };
        if d.fake {
            if let Some(fm) = fake_m {
                let fake = match kind {
                    L7::Tls => d.tls_mods.apply(&d.fake_tls, data),
                    L7::Http => d.fake_http.clone(),
                    _ => d.fake_unknown.clone(),
                };
                let fake = &fake[..fake.len().min(mss)];
                for _ in 0..d.repeats {
                    emit(&mut res, p.seq, fake, &fm);
                }
                self.stats.fakes += d.repeats as u64;
            }
        }
        if d.plan.split == Split::None {
            res.extend(orig.into_iter().map(|(k, a)| Out {
                pkt: k,
                addr: a,
                modified: false,
            }));
        } else {
            let ctx = Ctx {
                len: data.len(),
                host: host_span,
                host_str: host.as_deref().unwrap_or(""),
                tls: tls_,
                http: http_,
            };
            for pc in d.plan.pieces(data, &ctx, mss) {
                let seq = p.seq.wrapping_add(pc.rel as i32 as u32);
                if pc.fake {
                    if let Some(fm) = fake_m {
                        for _ in 0..d.repeats {
                            emit(&mut res, seq, &pc.data, &fm);
                        }
                        self.stats.fakes += d.repeats as u64;
                    }
                } else {
                    emit(&mut res, seq, &pc.data, &real_m);
                }
            }
        }
        self.stats.desynced += 1;
        let what = match kind {
            L7::Tls => "tls",
            L7::Http => "http",
            _ => "tcp",
        };
        self.note(
            format!(
                "{what} {} :{} -> {} packets",
                host.as_deref().unwrap_or("?"),
                p.dport,
                res.len()
            ),
            now,
        );
        res
    }

    fn udp_out(&mut self, pkt: Vec<u8>, p: Pkt, addr: A, now: Instant, out: &mut Vec<Out<A>>) {
        let key = packet::flow_key(&pkt, &p, true);
        self.bump(&key, now, true);
        let data = packet::payload(&pkt, &p);
        let kind = l7::udp(data);
        if kind == L7::Quic {
            let mut hold = self.held.remove(&key).unwrap_or(Hold {
                pkts: vec![],
                at: now,
                crypto: Some(quic::Crypto::default()),
            });
            let crypto = hold.crypto.get_or_insert_with(quic::Crypto::default);
            crypto.add_datagram(data);
            let info = quic::hello_info(crypto);
            let started = crypto.contiguous().first() == Some(&1);
            hold.pkts.push((pkt, addr));
            if started
                && info.host.is_none()
                && !info.complete
                && hold.pkts.len() < 2
                && self
                    .cfg
                    .profiles
                    .iter()
                    .any(|pr| !pr.include.is_empty() || !pr.exclude.is_empty())
            {
                self.held.insert(key, hold);
                return;
            }
            if hold.pkts.len() > 1 {
                self.stats.reassembled += 1;
            }
            out.extend(self.udp_fakes(&p, kind, info.host, hold.pkts, now));
            return;
        }
        if let Some(h) = self.held.remove(&key) {
            out.extend(h.pkts.into_iter().map(|(k, a)| Out::orig(k, a)));
        }
        out.extend(self.udp_fakes(&p, kind, None, vec![(pkt, addr)], now));
    }

    fn udp_fakes(
        &mut self,
        p: &Pkt,
        kind: L7,
        host: Option<String>,
        orig: Vec<(Vec<u8>, A)>,
        now: Instant,
    ) -> Vec<Out<A>> {
        let (tpl, addr) = (orig[0].0.clone(), orig[0].1.clone());
        let key = packet::flow_key(&tpl, p, true);
        let ip = packet::dst_ip(&tpl, p).to_vec();
        let m = Match {
            udp: true,
            port: p.dport,
            ip: &ip,
            l7: kind,
            host: host.as_deref(),
        };
        let mut res: Vec<Out<A>> = vec![];
        let prof = self.cfg.pick(&m).filter(|pr| pr.desync.fake).cloned();
        if let Some(pr) = prof {
            let d = &pr.desync;
            let ok = d.cutoff.is_none_or(|c| {
                self.flows
                    .get(&key)
                    .is_some_and(|f| within(f, c.kind, c.n, p))
            });
            if ok {
                let ttl = if p.v6 {
                    d.fool.ttl6.or(d.fool.ttl)
                } else {
                    d.fool.ttl
                };
                let fm = Mods {
                    ttl,
                    ip_id_zero: d.ip_id_zero,
                    badsum: d.fool.badsum,
                    ..Mods::default()
                };
                let fake = d.udp_fake(kind).to_vec();
                for i in 0..d.repeats {
                    res.push(Out {
                        pkt: packet::udp_datagram(&tpl, p, &fake, &fm, i as u16),
                        addr: addr.clone(),
                        modified: true,
                    });
                }
                self.stats.fakes += d.repeats as u64;
                self.stats.udp += 1;
                let what = format!("{kind:?}").to_lowercase();
                self.note(
                    format!(
                        "udp {what} {} :{} -> {} fakes",
                        host.as_deref().unwrap_or("?"),
                        p.dport,
                        d.repeats
                    ),
                    now,
                );
            }
        }
        res.extend(orig.into_iter().map(|(k, a)| Out::orig(k, a)));
        res
    }

    // Придержанные пакеты, которые ждут слишком долго, обрабатываются с тем, что есть.
    pub fn expire(&mut self, now: Instant) -> Vec<Out<A>> {
        let old: Vec<Vec<u8>> = self
            .held
            .iter()
            .filter(|(_, h)| now.duration_since(h.at) >= HOLD_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = vec![];
        for k in old {
            let Some(h) = self.held.remove(&k) else {
                continue;
            };
            let Some(p) = packet::parse(&h.pkts[0].0) else {
                out.extend(h.pkts.into_iter().map(|(k, a)| Out::orig(k, a)));
                continue;
            };
            if p.is_tcp() {
                let (tpl, addr) = h.pkts[0].clone();
                let data = packet::payload(&tpl, &p).to_vec();
                out.extend(self.tcp_hello(&k, &tpl, &p, &data, addr, h.pkts, now));
            } else {
                let host = h.crypto.as_ref().and_then(|c| quic::hello_info(c).host);
                out.extend(self.udp_fakes(&p, L7::Quic, host, h.pkts, now));
            }
        }
        out
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held.len()
    }
}

fn within(f: &Flow, kind: CutKind, n: u64, p: &Pkt) -> bool {
    match kind {
        CutKind::Packets => f.packets + u64::from(f.syn && p.is_tcp()) <= n,
        CutKind::Data => f.data <= n,
        CutKind::Seq => !f.syn || (p.seq.wrapping_sub(f.isn.wrapping_add(1)) as u64) < n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, tests::args};
    use crate::desync::tests::reassemble;
    use crate::desync::Piece;
    use crate::packet::tests::{checksums_ok, ipv4, ipv4_tcp, ipv6_tcp};
    use crate::packet::{ACK, SYN, TCP, UDP};
    use crate::tls::tests::client_hello;

    fn eng(s: &str) -> Engine<u8> {
        Engine::new(config::parse(&args(s)).unwrap())
    }

    // Пакеты → куски относительно base; фейк — пакет с изменённым TTL/md5/badseq и т.п.
    fn pieces(outs: &[Out<u8>], base: u32) -> Vec<Piece> {
        outs.iter()
            .map(|o| {
                let p = packet::parse(&o.pkt).unwrap();
                let fake = p.ttl != 64
                    || p.l4_hl > 20
                    || p.seq.wrapping_sub(base) as i32 <= -5000
                    || !p.has_ack();
                Piece {
                    rel: p.seq.wrapping_sub(base) as i32 as i64,
                    data: packet::payload(&o.pkt, &p).to_vec(),
                    fake,
                }
            })
            .collect()
    }

    fn synack(e: &mut Engine<u8>, ttl: u8, ws: &[u8]) -> Vec<Out<u8>> {
        let mut sa = ipv4(TCP, 443, 50000, 9, SYN | ACK, ws, b"");
        sa.swap(12, 16);
        sa.swap(13, 17);
        sa.swap(14, 18);
        sa.swap(15, 19);
        sa[8] = ttl;
        let p = packet::parse(&sa).unwrap();
        packet::fix_checksums(&mut sa, &p, false);
        e.handle(sa, 0, false, Instant::now())
    }

    #[test]
    fn multisplit_seqovl() {
        let mut e = eng("--filter-tcp=443 --hostlist-domains=youtube.com --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-split-seqovl=100");
        let ch = client_hello("www.youtube.com", 0);
        let out = e.handle(ipv4_tcp(5000, 443, &ch), 1, true, Instant::now());
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|o| o.modified && checksums_ok(&o.pkt)));
        assert_eq!(reassemble(&pieces(&out, 5000)), ch);
    }

    #[test]
    fn fake_autottl_then_multidisorder() {
        let mut e = eng("--dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-autottl=2 --dpi-desync-repeats=3 --dpi-desync-fake-tls-mod=rnd,sni=ya.ru");
        synack(&mut e, 54, &[]);
        let ch = client_hello("discord.com", 0);
        let out = e.handle(ipv4_tcp(100, 443, &ch), 0, true, Instant::now());
        let ps = pieces(&out, 100);
        let fakes: Vec<_> = out
            .iter()
            .take(3)
            .map(|o| packet::parse(&o.pkt).unwrap())
            .collect();
        assert!(fakes.iter().all(|f| f.ttl == 8));
        let f0 = packet::payload(&out[0].pkt, &fakes[0]);
        assert_eq!(
            tls::Hello::parse(f0).unwrap().host().as_deref(),
            Some("ya.ru")
        );
        assert_eq!(ps.iter().filter(|x| x.fake).count(), 3);
        assert_eq!(reassemble(&ps), ch);
        assert!(ps[3].rel > ps[4].rel);
    }

    #[test]
    fn fake_without_fooling_is_skipped() {
        let mut e = eng("--dpi-desync=fake --dpi-desync-autottl=2");
        let ch = client_hello("discord.com", 0);
        let pkt = ipv4_tcp(1, 443, &ch);
        let out = e.handle(pkt.clone(), 0, true, Instant::now());
        assert_eq!((out.len(), out[0].pkt == pkt), (1, true));
        assert!(e.log.iter().any(|l| l.contains("fakes skipped")));
    }

    #[test]
    fn fakedsplit_md5_badseq() {
        let mut e = eng("--dpi-desync=fakedsplit --dpi-desync-split-pos=midsld --dpi-desync-fooling=md5sig,badseq");
        let ch = client_hello("www.youtube.com", 0);
        let out = e.handle(ipv4_tcp(1000, 443, &ch), 0, true, Instant::now());
        assert_eq!(out.len(), 6);
        let p0 = packet::parse(&out[0].pkt).unwrap();
        assert_eq!((p0.l4_hl, p0.seq), (40, 1000u32.wrapping_sub(10000)));
        assert_eq!(reassemble(&pieces(&out, 1000)), ch);
    }

    #[test]
    fn hostfakesplit_http_and_method_pos() {
        let mut e = eng("--filter-tcp=80 --dpi-desync=hostfakesplit --dpi-desync-ttl=4 --new --filter-tcp=8080 --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2 --dpi-desync-fooling=md5sig");
        let req = b"GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\n".to_vec();
        let out = e.handle(
            ipv4(TCP, 50000, 80, 7, ACK, &[], &req),
            0,
            true,
            Instant::now(),
        );
        let ps = pieces(&out, 7);
        assert_eq!(ps.iter().filter(|x| x.fake).count(), 2);
        assert_eq!(reassemble(&ps), req);
        let out = e.handle(
            ipv4(TCP, 50001, 8080, 7, ACK, &[], &req),
            0,
            true,
            Instant::now(),
        );
        let real: Vec<_> = pieces(&out, 7).into_iter().filter(|x| !x.fake).collect();
        assert_eq!(real[0].data, b"GE");
    }

    #[test]
    fn md5sig_keeps_packets_within_mtu() {
        let mut e =
            eng("--dpi-desync=fakedsplit --dpi-desync-split-pos=1 --dpi-desync-fooling=md5sig");
        let ch = client_hello("discord.com", 1300);
        let (a, _) = ch.split_at(1460);
        let out = e.handle(
            ipv4_tcp(1, 443, &ch[..ch.len().min(1460)]),
            0,
            true,
            Instant::now(),
        );
        let orig_total = 40 + a.len();
        assert!(
            out.iter().all(|o| o.pkt.len() <= orig_total),
            "{:?}",
            out.iter().map(|o| o.pkt.len()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_http_request_in_keepalive() {
        let mut e = eng("--filter-tcp=80 --dpi-desync=multisplit --dpi-desync-split-pos=method+2");
        let t = Instant::now();
        let r1 = e.handle(
            ipv4(
                TCP,
                50000,
                80,
                1,
                ACK,
                &[],
                b"GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n",
            ),
            0,
            true,
            t,
        );
        let body = e.handle(
            ipv4(TCP, 50000, 80, 40, ACK, &[], b"some body bytes"),
            0,
            true,
            t,
        );
        let r2 = e.handle(
            ipv4(
                TCP,
                50000,
                80,
                60,
                ACK,
                &[],
                b"GET /b HTTP/1.1\r\nHost: a.com\r\n\r\n",
            ),
            0,
            true,
            t,
        );
        assert_eq!((r1.len(), body.len(), r2.len()), (2, 1, 2));
    }

    #[test]
    fn two_segment_hello_and_retransmit() {
        let mut e = eng("--dpi-desync=multisplit --dpi-desync-split-pos=1,sniext+1");
        let ch = client_hello("discord.com", 1500);
        let (a, b) = ch.split_at(1200);
        let t = Instant::now();
        assert!(e.handle(ipv4_tcp(7000, 443, a), 0, true, t).is_empty());
        let out = e.handle(ipv4_tcp(8200, 443, b), 0, true, t);
        assert_eq!(e.held(), 0);
        assert!(out
            .iter()
            .all(|o| packet::parse(&o.pkt).unwrap().payload_len() <= 1200));
        assert_eq!(reassemble(&pieces(&out, 7000)), ch);
        assert!(e.handle(ipv4_tcp(7000, 443, a), 0, true, t).is_empty());
        let again = e.handle(ipv4_tcp(8200, 443, b), 0, true, t);
        assert!(again.len() > 2 && again.iter().all(|o| o.modified));
        assert_eq!(reassemble(&pieces(&again, 7000)), ch);
        assert_eq!(e.stats.retrans, 1);
        let later = e.handle(ipv4_tcp(9000, 443, b"app data"), 0, true, t);
        assert!(!later[0].modified);
    }

    #[test]
    fn syndata_and_wssize() {
        let mut e = eng("--wssize=1:6 --dpi-desync=syndata,multisplit --dpi-desync-split-pos=1");
        let syn = ipv4(TCP, 50000, 443, 41, SYN, &[], b"");
        let out = e.handle(syn, 0, true, Instant::now());
        let p = packet::parse(&out[0].pkt).unwrap();
        assert_eq!(
            (p.payload_len(), p.syn(), out[0].modified),
            (16, true, true)
        );
        let o = synack(&mut e, 120, &[1, 3, 3, 9]);
        assert!(o[0].modified);
        assert_eq!(u16::from_be_bytes([o[0].pkt[34], o[0].pkt[35]]), 1);
        assert_eq!(o[0].pkt[43], 6);
        assert!(checksums_ok(&o[0].pkt));
    }

    #[test]
    fn any_protocol_cutoff() {
        let mut e = eng("--filter-tcp=1024-65535 --dpi-desync=multisplit --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n3 --dpi-desync-split-pos=1");
        let t = Instant::now();
        e.handle(ipv4(TCP, 50000, 27015, 1, SYN, &[], b""), 0, true, t);
        let o1 = e.handle(ipv4(TCP, 50000, 27015, 2, ACK, &[], b"hello"), 0, true, t);
        assert_eq!(o1.len(), 2);
        let o2 = e.handle(ipv4(TCP, 50000, 27015, 7, ACK, &[], b"world"), 0, true, t);
        assert_eq!((o2.len(), o2[0].modified), (1, false));
        let tls_only = &mut eng("--dpi-desync=multisplit");
        let o = tls_only.handle(ipv4(TCP, 50000, 443, 2, ACK, &[], b"hello"), 0, true, t);
        assert!(!o[0].modified);
    }

    #[test]
    fn udp_discord_and_unknown() {
        let mut e = eng("--filter-udp=50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-discord=0x0102 --new --filter-udp=27000-27100 --dpi-desync=fake --dpi-desync-any-protocol=1 --dpi-desync-cutoff=n2 --dpi-desync-repeats=2");
        let mut d = vec![0u8; 74];
        d[..4].copy_from_slice(&[0, 1, 0, 70]);
        let t = Instant::now();
        let out = e.handle(ipv4(UDP, 6000, 50010, 0, 0, &[], &d), 0, true, t);
        assert_eq!(out.len(), 7);
        assert_eq!(
            packet::payload(&out[0].pkt, &packet::parse(&out[0].pkt).unwrap()),
            &[1, 2]
        );
        assert!(!out[6].modified);
        let rtp = e.handle(ipv4(UDP, 6000, 50010, 0, 0, &[], &[0x80; 100]), 0, true, t);
        assert_eq!(rtp.len(), 1);
        let g1 = e.handle(ipv4(UDP, 6001, 27005, 0, 0, &[], b"game"), 0, true, t);
        let g2 = e.handle(ipv4(UDP, 6001, 27005, 0, 0, &[], b"game"), 0, true, t);
        let g3 = e.handle(ipv4(UDP, 6001, 27005, 0, 0, &[], b"game"), 0, true, t);
        assert_eq!((g1.len(), g2.len(), g3.len()), (3, 3, 1));
    }

    #[test]
    fn quic_hostlist_across_datagrams() {
        let mut e = eng("--filter-udp=443 --hostlist-domains=googlevideo.com --dpi-desync=fake --dpi-desync-repeats=4");
        let hs = client_hello("rr3---sn-x.googlevideo.com", 1300)[5..].to_vec();
        let (a, b) = hs.split_at(1000);
        let dcid = [9u8; 8];
        let d1 = quic::tests::initial(quic::V1, &dcid, 0, &[(0, a)]);
        let d2 = quic::tests::initial(quic::V1, &dcid, 1, &[(1000, b)]);
        let t = Instant::now();
        assert!(e
            .handle(ipv4(UDP, 6000, 443, 0, 0, &[], &d1), 0, true, t)
            .is_empty());
        let out = e.handle(ipv4(UDP, 6000, 443, 0, 0, &[], &d2), 0, true, t);
        assert_eq!(out.len(), 6);
        assert!(out[..4].iter().all(|o| o.modified));
        assert_eq!(
            packet::payload(&out[4].pkt, &packet::parse(&out[4].pkt).unwrap()),
            &d1[..]
        );
        let other = quic::tests::initial(
            quic::V1,
            &[8; 8],
            0,
            &[(0, &client_hello("example.com", 0)[5..])],
        );
        assert_eq!(
            e.handle(ipv4(UDP, 6002, 443, 0, 0, &[], &other), 0, true, t)
                .len(),
            1
        );
        let ack_only = quic::tests::initial(quic::V1, &[7; 8], 2, &[]);
        assert_eq!(
            e.handle(ipv4(UDP, 6003, 443, 0, 0, &[], &ack_only), 0, true, t)
                .len(),
            1
        );
        assert_eq!(e.held(), 0);
    }

    #[test]
    fn held_packets_expire() {
        let mut e = eng("--dpi-desync=multisplit --dpi-desync-split-pos=1");
        let ch = client_hello("discord.com", 1500);
        let t = Instant::now();
        assert!(e
            .handle(ipv4_tcp(1, 443, &ch[..1000]), 0, true, t)
            .is_empty());
        let out = e.expire(t + Duration::from_millis(300));
        assert!(!out.is_empty() && e.held() == 0);
    }

    #[test]
    fn ipv6_and_ip_id_zero() {
        let mut e = eng("--dpi-desync=multisplit --dpi-desync-split-pos=2 --ip-id=zero");
        let ch = client_hello("youtube.com", 0);
        let out = e.handle(ipv6_tcp(5, 443, &ch), 0, true, Instant::now());
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|o| checksums_ok(&o.pkt)));
        let out4 = e.handle(ipv4_tcp(5, 443, &ch), 0, true, Instant::now());
        assert!(out4.iter().all(|o| o.pkt[4..6] == [0, 0]));
    }

    #[test]
    fn hops() {
        assert_eq!(
            (
                guess_hops(54),
                guess_hops(120),
                guess_hops(250),
                guess_hops(64)
            ),
            (10, 8, 5, 0)
        );
    }
}
