// Local MTProto proxy for Telegram Desktop that sends traffic to Telegram data centres over
// WebSocket (kwsN.web.telegram.org) instead of raw IPs that providers block.
//
// Logic ported from the Python project tg-ws-proxy (Flowseal), MIT — see THIRD_PARTY_NOTICES.md.

pub mod obfs;
pub mod pool;
pub mod splitter;
pub mod ws;

use obfs::{DownCrypto, UpCrypto, HANDSHAKE_LEN};
use pool::PoolKey;
use splitter::Splitter;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::RootCertStore;
use ws::WsConn;

pub const DEFAULT_PORT: u16 = 1443;
const STALL_LIMIT: Duration = Duration::from_secs(20);

// Where to connect in tests: every address leads to one local server.
pub struct Dial {
    pub target: SocketAddr,
    pub dialed: std::sync::Mutex<Vec<String>>,
}

impl Dial {
    #[allow(dead_code)]
    pub fn new(target: SocketAddr) -> Self {
        Dial { target, dialed: Default::default() }
    }

    pub async fn connect(&self, addr: &str) -> io::Result<TcpStream> {
        self.dialed.lock().unwrap().push(addr.to_string());
        TcpStream::connect(self.target).await
    }
}

pub struct Config {
    pub port: u16,
    pub secret: String,
    pub dc_redirects: HashMap<i32, String>,
    pub tcp_ips: HashMap<i32, String>,
    pub pool_size: usize,
    pub log: Arc<dyn Fn(String) + Send + Sync>,
    pub roots: Option<Arc<RootCertStore>>,
    pub dial: Option<Arc<Dial>>,
}

impl Config {
    pub fn new(port: u16, secret: &str, pool_size: usize, log: Arc<dyn Fn(String) + Send + Sync>) -> Self {
        let r = |v: &[(i32, &str)]| v.iter().map(|(k, ip)| (*k, ip.to_string())).collect();
        Config {
            port,
            secret: secret.to_string(),
            dc_redirects: r(&[(2, "149.154.167.220"), (4, "149.154.167.220")]),
            tcp_ips: r(&[
                (1, "149.154.175.50"),
                (2, "149.154.167.51"),
                (3, "149.154.175.100"),
                (4, "149.154.167.91"),
                (5, "149.154.171.5"),
                (203, "91.105.192.100"),
            ]),
            pool_size,
            log,
            roots: None,
            dial: None,
        }
    }
}

fn test_ips() -> HashMap<i32, &'static str> {
    HashMap::from([(1, "149.154.175.10"), (2, "149.154.167.40"), (3, "149.154.175.117")])
}

#[derive(Default)]
pub struct Stats {
    pub total: AtomicI64,
    pub active: AtomicI64,
    pub bad: AtomicI64,
    pub via_ws: AtomicI64,
    pub via_tcp: AtomicI64,
    pub no_route: AtomicI64,
    pub stalled: AtomicI64,
    pub dead_ws: AtomicI64,
    pub answered_ws: AtomicI64,
    pub bytes_up: AtomicI64,
    pub bytes_down: AtomicI64,
    pub pool_hits: AtomicI64,
    pub pool_misses: AtomicI64,
    pub ws_errors: AtomicI64,
    pub last_bad: AtomicI64,
    pub last_ok: AtomicI64,
}

#[derive(Clone, Default, Debug)]
pub struct Snapshot {
    pub total: i64,
    pub active: i64,
    pub bad: i64,
    pub via_ws: i64,
    pub dead_ws: i64,
    pub answered_ws: i64,
    pub via_tcp: i64,
    pub no_route: i64,
    pub stalled: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub last_bad: i64,
    pub last_ok: i64,
    pub ws_last_ok: i64,
    pub ws_err: String,
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

impl Snapshot {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"total\":{},\"active\":{},\"bad\":{},\"via_ws\":{},\"dead_ws\":{},\"answered_ws\":{},\"via_tcp\":{},\"no_route\":{},\"bytes_up\":{},\"bytes_down\":{},\"last_bad\":{},\"last_ok\":{},\"ws_last_ok\":{},\"ws_err\":{}}}",
            self.total, self.active, self.bad, self.via_ws, self.dead_ws, self.answered_ws, self.via_tcp,
            self.no_route, self.bytes_up, self.bytes_down, self.last_bad, self.last_ok, self.ws_last_ok,
            json_str(&self.ws_err)
        )
    }
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub struct Shared {
    pub cfg: Config,
    pub secret: Vec<u8>,
    pub st: Stats,
    pub pool: pool::Pool,
    tcp_state: std::sync::Mutex<HashMap<String, (Instant, u32)>>,
    log_at: std::sync::Mutex<HashMap<String, Instant>>,
}

impl Shared {
    pub fn log(&self, m: String) {
        (self.cfg.log)(m)
    }

    // At most once a minute per key.
    fn log_throttled(&self, key: &str, m: impl FnOnce() -> String) {
        {
            let mut g = self.log_at.lock().unwrap();
            if g.get(key).is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                return;
            }
            g.insert(key.to_string(), Instant::now());
        }
        self.log(m());
    }

    pub fn snapshot(&self) -> Snapshot {
        let (ok, err) = self.pool.direct_status();
        let s = &self.st;
        Snapshot {
            total: s.total.load(Relaxed),
            active: s.active.load(Relaxed),
            bad: s.bad.load(Relaxed),
            via_ws: s.via_ws.load(Relaxed),
            dead_ws: s.dead_ws.load(Relaxed),
            answered_ws: s.answered_ws.load(Relaxed),
            via_tcp: s.via_tcp.load(Relaxed),
            no_route: s.no_route.load(Relaxed),
            stalled: s.stalled.load(Relaxed),
            bytes_up: s.bytes_up.load(Relaxed),
            bytes_down: s.bytes_down.load(Relaxed),
            last_bad: s.last_bad.load(Relaxed),
            last_ok: s.last_ok.load(Relaxed),
            ws_last_ok: ok.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs() as i64),
            ws_err: err,
        }
    }
}

pub struct Server {
    pub sh: Arc<Shared>,
    #[allow(dead_code)]
    pub addr: SocketAddr,
}

#[allow(dead_code)]
pub fn link(port: u16, secret: &str) -> String {
    format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{secret}")
}

// Listens on 127.0.0.1:port and serves Telegram until the runtime stops.
pub async fn start(cfg: Config) -> io::Result<Server> {
    let secret = obfs::decode_hex(&cfg.secret)
        .filter(|_| obfs::valid_secret(&cfg.secret))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "секрет прокси должен быть 32 hex-символа"))?;
    let ln = TcpListener::bind(("127.0.0.1", cfg.port)).await?;
    let addr = ln.local_addr()?;
    let sh = Arc::new(Shared {
        cfg,
        secret,
        st: Stats::default(),
        pool: Default::default(),
        tcp_state: Default::default(),
        log_at: Default::default(),
    });
    tokio::spawn(summary_loop(sh.clone()));
    tokio::spawn(pool::maintain(sh.clone()));
    tokio::spawn(accept_loop(sh.clone(), ln));
    pool::warmup(&sh);
    Ok(Server { sh, addr })
}

// One summary line a minute: shows whether traffic flows and where connections get lost.
async fn summary_loop(sh: Arc<Shared>) {
    let mut t = tokio::time::interval(Duration::from_secs(60));
    t.tick().await;
    let mut prev = sh.snapshot();
    loop {
        t.tick().await;
        let c = sh.snapshot();
        if c.total == prev.total && c.bytes_up == prev.bytes_up && c.bytes_down == prev.bytes_down {
            continue;
        }
        sh.log(format!(
            "Telegram за минуту: новых {} (WS {}, прямых {}, без пути {}); с данными от Telegram {}, закрылись без данных {}, зависших {}; вниз {} КБ, вверх {} КБ; открыто {}",
            c.total - prev.total, c.via_ws - prev.via_ws, c.via_tcp - prev.via_tcp, c.no_route - prev.no_route,
            c.answered_ws - prev.answered_ws, c.dead_ws - prev.dead_ws, c.stalled,
            (c.bytes_down - prev.bytes_down) >> 10, (c.bytes_up - prev.bytes_up) >> 10, c.active
        ));
        prev = c;
    }
}

async fn accept_loop(sh: Arc<Shared>, ln: TcpListener) {
    let mut delay = Duration::ZERO;
    loop {
        match ln.accept().await {
            Ok((c, _)) => {
                delay = Duration::ZERO;
                let sh = sh.clone();
                tokio::spawn(async move { handle(sh, c).await });
            }
            Err(_) => {
                delay = if delay.is_zero() { Duration::from_millis(5) } else { (delay * 2).min(Duration::from_secs(1)) };
                tokio::time::sleep(delay).await;
            }
        }
    }
}

struct ActiveGuard(Arc<Shared>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.st.active.fetch_sub(1, Relaxed);
    }
}

async fn handle(sh: Arc<Shared>, mut c: TcpStream) {
    sh.st.total.fetch_add(1, Relaxed);
    sh.st.active.fetch_add(1, Relaxed);
    let _g = ActiveGuard(sh.clone());
    let _ = c.set_nodelay(true);

    let mut init = [0u8; HANDSHAKE_LEN];
    match tokio::time::timeout(Duration::from_secs(10), c.read_exact(&mut init)).await {
        Ok(Ok(_)) => {}
        _ => return,
    }
    let Some(h) = obfs::parse_client_hello(&init, &sh.secret) else {
        sh.st.bad.fetch_add(1, Relaxed);
        sh.st.last_bad.store(now_unix(), Relaxed);
        sh.log_throttled("bad", || {
            "Telegram: подключение с чужим секретом — переподключите Telegram кнопкой «Подключить Telegram»".into()
        });
        return;
    };
    sh.st.last_ok.store(now_unix(), Relaxed);

    let relay = obfs::make_relay_init(&h.proto_tag, h.dc_idx);
    let (up, down) = obfs::new_crypto(&h.prekey_iv, &sh.secret, &relay);
    let k = PoolKey { dc: h.dc, media: h.media, test: h.test };

    // 1) WebSocket to Telegram (main path)
    if let Some(ip) = sh.cfg.dc_redirects.get(&h.dc).cloned() {
        let mut ws = pool::get(&sh, k).await;
        if ws.is_none() && !sh.pool.backed_off(k) {
            ws = tokio::time::timeout(Duration::from_secs(8), pool::connect(&sh, &ip, k)).await.ok().flatten();
        }
        if let Some(ws) = ws {
            if ws.send(&[relay.to_vec()]).await.is_ok() {
                sh.st.via_ws.fetch_add(1, Relaxed);
                bridge_ws(&sh, c, ws, up, down, Splitter::new(&h.proto_tag), "напрямую", h.media).await;
                return;
            }
            ws.close().await;
        }
    }

    // 2) direct TCP to the DC — works only if the provider does not cut it
    let ip = if h.test { test_ips().get(&h.dc).map(|s| s.to_string()) } else { sh.cfg.tcp_ips.get(&h.dc).cloned() };
    if let Some(ip) = ip.filter(|s| !s.is_empty()) {
        if let Some(mut rc) = dial_tcp(&sh, &ip).await {
            if rc.write_all(&relay).await.is_ok() {
                sh.st.via_tcp.fetch_add(1, Relaxed);
                bridge_tcp(&sh, c, rc, up, down).await;
                return;
            }
        }
    }
    sh.st.no_route.fetch_add(1, Relaxed);
    sh.log_throttled(&format!("{k}route"), || format!("Telegram: {k} — ни один путь не сработал"));
}

async fn dial_tcp(sh: &Arc<Shared>, ip: &str) -> Option<TcpStream> {
    let addr = format!("{ip}:443");
    if sh.tcp_state.lock().unwrap().get(&addr).is_some_and(|(retry, _)| Instant::now() < *retry) {
        return None;
    }
    let r = tokio::time::timeout(Duration::from_secs(10), async {
        match &sh.cfg.dial {
            Some(d) => d.connect(&addr).await,
            None => TcpStream::connect(&addr).await,
        }
    })
    .await;
    let mut g = sh.tcp_state.lock().unwrap();
    match r {
        Ok(Ok(c)) => {
            g.remove(&addr);
            Some(c)
        }
        _ => {
            let fails = g.get(&addr).map_or(0, |e| e.1) + 1;
            let gap = (Duration::from_secs(15) * (1u32 << (fails - 1).min(2))).min(Duration::from_secs(60));
            g.insert(addr, (Instant::now() + gap, fails));
            None
        }
    }
}

// Client ⇄ Telegram with re-encryption (client key ↔ Telegram key).
// answered/dead count sessions in which Telegram replied / closed without a single reply.
#[allow(clippy::too_many_arguments)]
async fn bridge_ws(
    sh: &Arc<Shared>,
    c: TcpStream,
    ws: Arc<WsConn>,
    mut up: UpCrypto,
    mut down: DownCrypto,
    mut sp: Splitter,
    route: &'static str,
    watch: bool,
) {
    use obfs::StreamCipher as _;
    let (mut cr, mut cw) = c.into_split();
    let got_down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // when Telegram stopped answering what was sent (ms since start + 1), 0 — all is fine
    let pending = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let ms = move || started.elapsed().as_millis() as u64 + 1;

    let t_up = {
        let (sh, ws, pending) = (sh.clone(), ws.clone(), pending.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 << 10];
            loop {
                let n = cr.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    if let Some(t) = sp.flush() {
                        let _ = ws.send(&[t]).await;
                    }
                    return;
                }
                let _ = pending.compare_exchange(0, ms(), Relaxed, Relaxed);
                sh.st.bytes_up.fetch_add(n as i64, Relaxed);
                let plain = &mut buf[..n];
                up.clt_dec.apply_keystream(plain);
                let mut enc = plain.to_vec();
                up.tg_enc.apply_keystream(&mut enc);
                let parts = sp.split(&enc, plain);
                if !parts.is_empty() && ws.send(&parts).await.is_err() {
                    return;
                }
            }
        })
    };
    let t_down = {
        let (sh, ws, pending, got_down) = (sh.clone(), ws.clone(), pending.clone(), got_down.clone());
        tokio::spawn(async move {
            loop {
                let Ok(mut data) = ws.recv().await else { return };
                got_down.store(true, Relaxed);
                pending.store(0, Relaxed);
                sh.st.bytes_down.fetch_add(data.len() as i64, Relaxed);
                down.tg_dec.apply_keystream(&mut data);
                down.clt_enc.apply_keystream(&mut data);
                if cw.write_all(&data).await.is_err() {
                    return;
                }
            }
        })
    };
    // Watchdog: the path "hung" (connection open, no reply — the network silently cut the session).
    // Closing makes Telegram reconnect over a fresh path instead of waiting for its long timeouts.
    let t_watch = tokio::spawn({
        let (sh, got_down, pending) = (sh.clone(), got_down.clone(), pending.clone());
        async move {
            if !watch {
                return std::future::pending::<()>().await;
            }
            let mut t = tokio::time::interval(Duration::from_secs(3));
            loop {
                t.tick().await;
                let since = pending.load(Relaxed);
                if since == 0 {
                    continue;
                }
                let waited = Duration::from_millis(ms().saturating_sub(since));
                if waited > STALL_LIMIT {
                    sh.st.stalled.fetch_add(1, Relaxed);
                    sh.log_throttled("stall", || {
                        format!(
                            "Telegram: медиа-соединение {route} молчит {} с (живо {} с, ответы были: {}) — закрываю, Telegram откроет новое",
                            waited.as_secs(),
                            started.elapsed().as_secs(),
                            got_down.load(Relaxed)
                        )
                    });
                    return;
                }
            }
        }
    });

    let (mut t_up, mut t_down) = (t_up, t_down);
    tokio::select! {
        _ = &mut t_up => {}
        _ = &mut t_down => {}
        _ = t_watch => {}
    }
    t_up.abort();
    t_down.abort();
    ws.close().await;
    // Telegram opens spare connections and drops them at once — normal, counted but not logged.
    if got_down.load(Relaxed) {
        sh.st.answered_ws.fetch_add(1, Relaxed);
    } else {
        sh.st.dead_ws.fetch_add(1, Relaxed);
    }
}

async fn bridge_tcp(sh: &Arc<Shared>, c: TcpStream, rc: TcpStream, mut up: UpCrypto, mut down: DownCrypto) {
    use obfs::StreamCipher as _;
    let (mut cr, mut cw) = c.into_split();
    let (mut rr, mut rw) = rc.into_split();
    async fn pipe(
        src: &mut OwnedReadHalf,
        dst: &mut OwnedWriteHalf,
        cnt: &std::sync::atomic::AtomicI64,
        mut f: impl FnMut(&mut [u8]),
    ) {
        let mut buf = vec![0u8; 64 << 10];
        loop {
            let n = src.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            cnt.fetch_add(n as i64, Relaxed);
            f(&mut buf[..n]);
            if dst.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
    }
    let s1 = sh.clone();
    let s2 = sh.clone();
    let a = tokio::spawn(async move {
        pipe(&mut cr, &mut rw, &s1.st.bytes_up, |b| {
            up.clt_dec.apply_keystream(b);
            up.tg_enc.apply_keystream(b);
        })
        .await
    });
    let b = tokio::spawn(async move {
        pipe(&mut rr, &mut cw, &s2.st.bytes_down, |b| {
            down.tg_dec.apply_keystream(b);
            down.clt_enc.apply_keystream(b);
        })
        .await
    });
    let (mut a, mut b) = (a, b);
    tokio::select! {
        _ = &mut a => {}
        _ = &mut b => {}
    }
    a.abort();
    b.abort();
}

fn emit(line: &str) {
    use std::io::Write;
    if writeln!(std::io::stdout().lock(), "{line}").is_err() {
        std::process::exit(0); // parent is gone
    }
}

// Runs the proxy as a standalone mode of gust-engine; the Go shell reads these stdout lines:
//   ready | error: <why> | log: <text> | stats: <json>
pub fn run_cli(args: &[String]) -> i32 {
    let (mut port, mut secret, mut pool) = (DEFAULT_PORT, String::new(), 4usize);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let v = it.next().cloned().unwrap_or_default();
        match a.as_str() {
            "--port" => port = v.parse().unwrap_or(DEFAULT_PORT),
            "--secret" => secret = v,
            "--pool" => pool = v.parse().unwrap_or(4),
            _ => {
                eprintln!("gust-engine tgproxy: unknown option {a}");
                return 2;
            }
        }
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            emit(&format!("error: {e}"));
            return 5;
        }
    };
    rt.block_on(async move {
        let cfg = Config::new(port, &secret, pool, Arc::new(|m| emit(&format!("log: {}", m.replace('\n', " ")))));
        let srv = match start(cfg).await {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                emit("error: addr_in_use");
                return 5;
            }
            Err(e) => {
                emit(&format!("error: {e}"));
                return 5;
            }
        };
        emit("ready");
        // parent gone (stdin closed) — exit
        tokio::spawn(async {
            let mut b = [0u8; 256];
            let mut si = tokio::io::stdin();
            while matches!(si.read(&mut b).await, Ok(n) if n > 0) {}
            std::process::exit(0);
        });
        let mut t = tokio::time::interval(Duration::from_secs(1));
        loop {
            t.tick().await;
            emit(&format!("stats: {}", srv.sh.snapshot().to_json()));
        }
    })
}

#[cfg(test)]
mod tests;
