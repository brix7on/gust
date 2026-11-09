// Обработка пакетов: склейка ClientHello из двух сегментов, выбор профиля, разрез.

use crate::config::Config;
use crate::packet::{self, Tcp};
use crate::tls;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const HOLD_TTL: Duration = Duration::from_millis(250);
const MAX_RECORD: usize = 16 * 1024;

pub struct Out<A> {
    pub pkt: Vec<u8>,
    pub addr: A,
    pub modified: bool,
}

struct Held<A> {
    pkt: Vec<u8>,
    addr: A,
    at: Instant,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Stats {
    pub hellos: u64,
    pub desynced: u64,
    pub reassembled: u64,
    pub passed: u64,
}

pub struct Engine<A> {
    cfg: Config,
    held: HashMap<Vec<u8>, Held<A>>,
    pub stats: Stats,
    pub log: Vec<String>,
}

impl<A: Clone> Engine<A> {
    pub fn new(cfg: Config) -> Self {
        Engine {
            cfg,
            held: HashMap::new(),
            stats: Stats::default(),
            log: vec![],
        }
    }

    pub fn handle(&mut self, pkt: Vec<u8>, addr: A, now: Instant) -> Vec<Out<A>> {
        let mut out = self.expire(now);
        let Some(p) = packet::parse(&pkt) else {
            out.push(Out {
                pkt,
                addr,
                modified: false,
            });
            return out;
        };
        let key = packet::flow_key(&pkt, &p);
        if let Some(h) = self.held.remove(&key) {
            let hp = packet::parse(&h.pkt).expect("held packet parses");
            let hlen = (hp.total - hp.payload_off) as u32;
            if p.seq == hp.seq.wrapping_add(hlen) {
                let mut data = packet::payload(&h.pkt, &hp).to_vec();
                data.extend_from_slice(packet::payload(&pkt, &p));
                self.stats.reassembled += 1;
                let orig = vec![(h.pkt.clone(), h.addr), (pkt.clone(), addr.clone())];
                out.extend(self.hello(&h.pkt, &hp, &data, addr, orig));
                return out;
            }
            out.push(Out {
                pkt: h.pkt,
                addr: h.addr,
                modified: false,
            });
        }
        let data = packet::payload(&pkt, &p);
        if !tls::is_client_hello(data) {
            self.stats.passed += 1;
            out.push(Out {
                pkt,
                addr,
                modified: false,
            });
            return out;
        }
        let need = tls::record_len(data);
        if need > data.len() && need <= MAX_RECORD && tls::sni(data).is_none() {
            self.held.insert(key, Held { pkt, addr, at: now });
            return out;
        }
        let data = data.to_vec();
        let orig = vec![(pkt.clone(), addr.clone())];
        out.extend(self.hello(&pkt, &p, &data, addr, orig));
        out
    }

    // Отпустить придержанные пакеты, которые ждут слишком долго.
    pub fn expire(&mut self, now: Instant) -> Vec<Out<A>> {
        let old: Vec<Vec<u8>> = self
            .held
            .iter()
            .filter(|(_, h)| now.duration_since(h.at) >= HOLD_TTL)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::new();
        for k in old {
            let Some(h) = self.held.remove(&k) else {
                continue;
            };
            match packet::parse(&h.pkt) {
                Some(p) => {
                    let data = packet::payload(&h.pkt, &p).to_vec();
                    let orig = vec![(h.pkt.clone(), h.addr.clone())];
                    out.extend(self.hello(&h.pkt, &p, &data, h.addr, orig));
                }
                None => out.push(Out {
                    pkt: h.pkt,
                    addr: h.addr,
                    modified: false,
                }),
            }
        }
        out
    }

    fn hello(
        &mut self,
        tpl: &[u8],
        p: &Tcp,
        data: &[u8],
        addr: A,
        orig: Vec<(Vec<u8>, A)>,
    ) -> Vec<Out<A>> {
        self.stats.hellos += 1;
        let sni = tls::sni(data);
        let host = sni.map(|(s, e)| String::from_utf8_lossy(&data[s..e]).to_string());
        let desync = self
            .cfg
            .pick(p.dport, host.as_deref())
            .and_then(|pr| pr.desync.clone());
        let Some(d) = desync else {
            return orig
                .into_iter()
                .map(|(pkt, addr)| Out {
                    pkt,
                    addr,
                    modified: false,
                })
                .collect();
        };
        let mss = (p.total - p.payload_off).max(536);
        let segs = d.plan(data, sni, host.as_deref().unwrap_or(""), mss);
        self.stats.desynced += 1;
        self.log.push(format!(
            "{} :{} -> {} segments",
            host.as_deref().unwrap_or("?"),
            p.dport,
            segs.len()
        ));
        segs.iter()
            .enumerate()
            .map(|(i, s)| Out {
                pkt: packet::segment(
                    tpl,
                    p,
                    p.seq.wrapping_add(s.rel_seq as i32 as u32),
                    &s.data,
                    i as u16,
                ),
                addr: addr.clone(),
                modified: true,
            })
            .collect()
    }

    #[cfg(test)]
    pub fn held(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::packet::tests::{checksums_ok, ipv4_tcp};
    use crate::tls::tests::client_hello;

    fn cfg(s: &str) -> Config {
        config::parse(&s.split_whitespace().map(String::from).collect::<Vec<_>>()).unwrap()
    }

    fn rebuild(outs: &[Out<u8>], base: u32) -> Vec<u8> {
        let mut segs: Vec<(i64, Vec<u8>)> = outs
            .iter()
            .map(|o| {
                let p = packet::parse(&o.pkt).unwrap();
                assert!(checksums_ok(&o.pkt));
                (
                    p.seq.wrapping_sub(base) as i32 as i64,
                    packet::payload(&o.pkt, &p).to_vec(),
                )
            })
            .collect();
        segs.sort_by_key(|s| s.0);
        let mut v = Vec::new();
        for (rel, d) in segs {
            let skip = (-rel).max(0) as usize;
            assert_eq!(rel.max(0) as usize, v.len());
            v.extend_from_slice(&d[skip..]);
        }
        v
    }

    #[test]
    fn single_packet_hello() {
        let mut e = Engine::new(cfg("--filter-tcp=443 --hostlist-domains=youtube.com --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-split-seqovl=100"));
        let ch = client_hello("www.youtube.com", 0);
        let out = e.handle(ipv4_tcp(5000, 443, &ch), 1u8, Instant::now());
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|o| o.modified));
        assert_eq!(rebuild(&out, 5000), ch);
        assert_eq!(e.stats.desynced, 1);
    }

    #[test]
    fn two_segment_hello_is_reassembled() {
        let mut e = Engine::new(cfg(
            "--dpi-desync=multisplit --dpi-desync-split-pos=1,sniext+1",
        ));
        let ch = client_hello("discord.com", 1500);
        let (a, b) = ch.split_at(1200);
        let t = Instant::now();
        assert!(e.handle(ipv4_tcp(7000, 443, a), 0u8, t).is_empty());
        assert_eq!(e.held(), 1);
        let out = e.handle(ipv4_tcp(7000 + 1200, 443, b), 0u8, t);
        assert_eq!(e.held(), 0);
        assert!(out
            .iter()
            .all(|o| packet::parse(&o.pkt).unwrap().total <= 40 + 1200));
        assert_eq!(rebuild(&out, 7000), ch);
        assert_eq!(e.stats.reassembled, 1);
    }

    #[test]
    fn other_traffic_and_excluded_hosts_pass() {
        let mut e = Engine::new(cfg(
            "--hostlist-domains=discord.com --dpi-desync=multisplit",
        ));
        let t = Instant::now();
        let get = ipv4_tcp(1, 443, b"GET / HTTP/1.1\r\n\r\n");
        assert!(!e.handle(get.clone(), 0u8, t)[0].modified);
        let yt = ipv4_tcp(1, 443, &client_hello("youtube.com", 0));
        let out = e.handle(yt.clone(), 0u8, t);
        assert_eq!(
            (out.len(), out[0].pkt == yt, out[0].modified),
            (1, true, false)
        );
    }

    #[test]
    fn stale_hold_is_released() {
        let mut e = Engine::new(cfg("--dpi-desync=multisplit --dpi-desync-split-pos=1"));
        let ch = client_hello("discord.com", 1500);
        let t = Instant::now();
        assert!(e.handle(ipv4_tcp(1, 443, &ch[..1000]), 0u8, t).is_empty());
        let out = e.expire(t + Duration::from_millis(300));
        assert!(!out.is_empty());
        assert_eq!(e.held(), 0);
        let mut other = e.handle(ipv4_tcp(9, 443, &ch[..1000]), 0u8, t);
        other.extend(e.handle(ipv4_tcp(50, 443, b"zz"), 0u8, t));
        assert_eq!(e.held(), 0);
    }
}
