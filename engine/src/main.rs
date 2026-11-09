#![cfg_attr(not(windows), allow(dead_code))]

mod config;
mod desync;
mod divert;
mod engine;
mod hostlist;
mod packet;
mod tls;

use std::process::exit;

const USAGE: &str = "gust-engine — packet-level DPI desync (WinDivert)

  --wf-tcp=PORTS                    ports to intercept (default: from --filter-tcp, or 443)
  --windivert=PATH                  WinDivert.dll (default: next to the exe)
  --filter-tcp=PORTS                profile: ports
  --hostlist=FILE --hostlist-domains=a,b
  --hostlist-exclude=FILE --hostlist-exclude-domains=a,b
  --dpi-desync=multisplit|multidisorder
  --dpi-desync-split-pos=N,host,endhost,sld,midsld,endsld,sniext[+-N]
  --dpi-desync-split-seqovl=N --dpi-desync-split-seqovl-pattern=FILE|0xHEX
  --new                             start next profile
  --check                           validate arguments and exit";

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
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
        println!(
            "ok: {} profile(s), filter: {}",
            cfg.profiles.len(),
            cfg.filter()
        );
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
        for o in eng.handle(buf[..n].to_vec(), addr, Instant::now()) {
            let a = if o.modified {
                o.addr.mark_checksums()
            } else {
                o.addr
            };
            dv.send(&o.pkt, &a);
        }
        for l in eng.log.drain(..) {
            println!("{l}");
        }
        if last.elapsed() >= Duration::from_secs(60) {
            let s = eng.stats;
            println!(
                "stats: hellos {} desynced {} reassembled {} passed {}",
                s.hellos, s.desynced, s.reassembled, s.passed
            );
            last = Instant::now();
        }
        let _ = std::io::stdout().flush();
    }
}

#[cfg(not(windows))]
fn run(_: config::Config) {
    eprintln!("gust-engine: Windows only");
    exit(1)
}
