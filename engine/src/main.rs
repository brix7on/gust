#![cfg_attr(not(windows), allow(dead_code))]

mod config;
mod desync;
mod divert;
mod engine;
mod hostlist;
mod http;
mod ipset;
mod l7;
mod packet;
mod quic;
mod rng;
mod tg;
mod tls;

use std::process::exit;

const USAGE: &str = "gust-engine — packet-level DPI desync for Windows (WinDivert), winws-compatible options

global:   --wf-tcp=PORTS --wf-udp=PORTS --windivert=PATH\\WinDivert.dll --check --version
profile:  --filter-tcp=PORTS --filter-udp=PORTS --filter-l7=tls,http,quic,discord,stun,unknown
          --hostlist=FILE --hostlist-domains=a,b --hostlist-exclude=FILE --hostlist-exclude-domains=a,b
          --ipset=FILE --ipset-ip=CIDR,.. --ipset-exclude=FILE --ipset-exclude-ip=CIDR,.. --ip-id=seq|zero
desync:   --dpi-desync=[fake,][syndata,]multisplit|multidisorder|fakedsplit|fakeddisorder|hostfakesplit
          --dpi-desync-split-pos=N,method,host,endhost,sld,midsld,endsld,sniext[+-N]
          --dpi-desync-split-seqovl=N --dpi-desync-split-seqovl-pattern=FILE|0xHEX
          --dpi-desync-fakedsplit-pattern=FILE|0xHEX --dpi-desync-hostfakesplit-mod=host=NAME
          --dpi-desync-hostfakesplit-midhost=POS --dpi-desync-repeats=N
          --dpi-desync-fooling=md5sig,badseq,badsum,ts,datanoack --dpi-desync-ttl[6]=N
          --dpi-desync-autottl[6]=DELTA[:MIN-MAX] --dpi-desync-badseq-increment=N
          --dpi-desync-badack-increment=N --dpi-desync-ts-increment=N
          --dpi-desync-fake-tls=FILE|0xHEX --dpi-desync-fake-tls-mod=rnd,rndsni,dupsid,padencap,sni=NAME
          --dpi-desync-fake-{http,quic,discord,stun,unknown,unknown-udp,syndata}=FILE|0xHEX
          --dpi-desync-any-protocol=1 --dpi-desync-cutoff=nN|dN|sN --wssize=WIN[:SCALE]
          --new  start the next profile";

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("tgproxy") {
        exit(tg::run_cli(&args[1..]));
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }
    if args.iter().any(|a| a == "--version") {
        println!("gust-engine {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let check = args.iter().any(|a| a == "--check");
    args.retain(|a| a != "--check");
    let cfg = config::parse(&args).unwrap_or_else(|e| {
        eprintln!("gust-engine: {e}");
        exit(2)
    });
    if check {
        println!("ok: {} profile(s)", cfg.profiles.len());
        println!("filter: {}", cfg.filter());
        return;
    }
    run(cfg);
}

#[cfg(windows)]
fn run(cfg: config::Config) {
    use std::io::Write;
    use std::time::{Duration, Instant};

    let dll = cfg.windivert.clone().unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("WinDivert.dll")))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "WinDivert.dll".into())
    });
    let dv = divert::Divert::open(&dll, &cfg.filter()).unwrap_or_else(|e| {
        eprintln!("gust-engine: {e}");
        exit(3)
    });
    println!(
        "gust-engine {}: running, {} profile(s)",
        env!("CARGO_PKG_VERSION"),
        cfg.profiles.len()
    );
    let _ = std::io::stdout().flush();
    let mut eng: engine::Engine<divert::Addr> = engine::Engine::new(cfg);
    let mut buf = vec![0u8; 65535];
    let mut last = Instant::now();
    loop {
        let (n, addr) = match dv.recv(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("gust-engine: {e}");
                exit(4)
            }
        };
        for o in eng.handle(buf[..n].to_vec(), addr, addr.outbound(), Instant::now()) {
            let a = if o.modified {
                o.addr.mark_checksums()
            } else {
                o.addr
            };
            dv.send(&o.pkt, &a);
        }
        let mut wrote = false;
        for l in eng.log.drain(..) {
            println!("{l}");
            wrote = true;
        }
        if last.elapsed() >= Duration::from_secs(60) {
            let s = eng.stats;
            println!(
                "stats: hellos {} desynced {} fakes {} reassembled {} udp {} retrans {}",
                s.hellos, s.desynced, s.fakes, s.reassembled, s.udp, s.retrans
            );
            last = Instant::now();
            wrote = true;
        }
        if wrote {
            let _ = std::io::stdout().flush();
        }
    }
}

#[cfg(not(windows))]
fn run(_: config::Config) {
    eprintln!("gust-engine: Windows only");
    exit(1)
}
