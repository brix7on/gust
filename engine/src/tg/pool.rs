// Pool of ready WebSockets per DC: a new Telegram connection gets an open channel without a TLS delay.

use super::ws::{dial_ws, DialError, DialOpts, WsConn};
use super::Shared;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const WS_PATH: &str = "/apiws";
const WS_PATH_TEST: &str = "/apiws_test";
const POOL_MAX_AGE: Duration = Duration::from_secs(120);
const POOL_TICK: Duration = Duration::from_secs(5);
const REFILL_MIN_GAP: Duration = Duration::from_secs(1);
const REFILL_MAX_GAP: Duration = Duration::from_secs(15);
const OK_FRESH: Duration = Duration::from_secs(180);
const WARM_DCS: [i32; 2] = [2, 4];
const ALT_FRONT: &str = "149.154.167.99";
const FRONTING_SNI: &str = "sprinthost.ru";

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub dc: i32,
    pub media: bool,
    pub test: bool,
}

impl fmt::Display for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DC{}", self.dc)?;
        if self.test {
            write!(f, " (тест)")?;
        }
        if self.media {
            write!(f, " медиа")?;
        }
        Ok(())
    }
}

fn ws_domains(dc: i32, media: bool) -> Vec<String> {
    let dc = if dc == 203 { 2 } else { dc };
    if !media {
        return vec![format!("kws{dc}.web.telegram.org")];
    }
    vec![format!("kws{dc}-1.web.telegram.org"), format!("kws{dc}.web.telegram.org")]
}

pub fn backoff_gap(failures: u32) -> Duration {
    let f = failures.max(1);
    (REFILL_MIN_GAP * (1u32 << (f - 1).min(12))).min(REFILL_MAX_GAP)
}

struct Idle {
    ws: Arc<WsConn>,
    created: Instant,
}

#[derive(Default)]
struct Bucket {
    idle: VecDeque<Idle>,
    refilling: bool,
    failures: u32,
    retry_after: Option<Instant>,
}

#[derive(Default)]
struct Inner {
    b: HashMap<PoolKey, Bucket>,
    front_first: bool,
    ever_worked: bool,
    fail_logged: bool,
    last_err: String,
    last_ok: Option<SystemTime>,
}

#[derive(Default)]
pub struct Pool {
    inner: std::sync::Mutex<Inner>,
}

fn close_later(ws: Arc<WsConn>) {
    tokio::spawn(async move { ws.close().await });
}

impl Pool {
    pub fn direct_status(&self) -> (Option<SystemTime>, String) {
        let g = self.inner.lock().unwrap();
        let fresh = g.last_ok.is_some_and(|t| t.elapsed().is_ok_and(|d| d < OK_FRESH));
        (g.last_ok, if fresh { String::new() } else { g.last_err.clone() })
    }

    pub fn backed_off(&self, k: PoolKey) -> bool {
        let mut g = self.inner.lock().unwrap();
        g.b.entry(k).or_default().retry_after.is_some_and(|t| Instant::now() < t)
    }
}

pub async fn get(sh: &Arc<Shared>, k: PoolKey) -> Option<Arc<WsConn>> {
    let mut got = None;
    loop {
        let e = sh.pool.inner.lock().unwrap().b.entry(k).or_default().idle.pop_front();
        let Some(e) = e else { break };
        if e.created.elapsed() >= POOL_MAX_AGE || !e.ws.alive().await {
            close_later(e.ws);
            continue;
        }
        got = Some(e.ws);
        break;
    }
    if got.is_some() {
        sh.st.pool_hits.fetch_add(1, Relaxed);
    } else {
        sh.st.pool_misses.fetch_add(1, Relaxed);
    }
    refill(sh, k);
    got
}

pub fn refill(sh: &Arc<Shared>, k: PoolKey) {
    let size = sh.cfg.pool_size;
    if size == 0 {
        return;
    }
    let need = {
        let mut g = sh.pool.inner.lock().unwrap();
        let b = g.b.entry(k).or_default();
        let need = size.saturating_sub(b.idle.len());
        if need == 0 || b.refilling || b.retry_after.is_some_and(|t| Instant::now() < t) {
            return;
        }
        b.refilling = true;
        need
    };
    let sh = sh.clone();
    tokio::spawn(async move {
        let ip = sh.cfg.dc_redirects.get(&k.dc).cloned().unwrap_or_default();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..need {
            let (sh, ip) = (sh.clone(), ip.clone());
            set.spawn(async move { connect(&sh, &ip, k).await });
        }
        let mut ok = 0;
        while let Some(r) = set.join_next().await {
            if let Ok(Some(ws)) = r {
                sh.pool.inner.lock().unwrap().b.entry(k).or_default().idle.push_back(Idle { ws, created: Instant::now() });
                ok += 1;
            }
        }
        let mut note = None;
        {
            let mut g = sh.pool.inner.lock().unwrap();
            let g = &mut *g;
            let b = g.b.entry(k).or_default();
            b.refilling = false;
            if ok > 0 {
                b.failures = 0;
                b.retry_after = None;
            } else {
                b.failures += 1;
                b.retry_after = Some(Instant::now() + backoff_gap(b.failures));
                if !g.fail_logged {
                    g.fail_logged = true;
                    note = Some(format!(
                        "Telegram: прямой путь к {k} закрыт ({}) — это нормально, использую прямой TCP, WebSocket проверяю в фоне",
                        g.last_err
                    ));
                }
            }
        }
        if let Some(n) = note {
            sh.log(n);
        }
    });
}

// One WebSocket to the DC: first by the plain name, then with a substituted SNI
// (whichever worked is tried first next time).
pub async fn connect(sh: &Arc<Shared>, ip: &str, k: PoolKey) -> Option<Arc<WsConn>> {
    if ip.is_empty() {
        return None;
    }
    let mut ips = vec![ip.to_string()];
    if ip != ALT_FRONT {
        ips.push(ALT_FRONT.to_string());
    }
    for ip in ips {
        if let Some(w) = connect_ip(sh, &ip, k).await {
            return Some(w);
        }
    }
    None
}

async fn connect_ip(sh: &Arc<Shared>, ip: &str, k: PoolKey) -> Option<Arc<WsConn>> {
    let path = if k.test { WS_PATH_TEST } else { WS_PATH };
    let modes: [bool; 2] = if sh.pool.inner.lock().unwrap().front_first { [true, false] } else { [false, true] };
    for dom in ws_domains(k.dc, k.media) {
        for fronted in modes {
            let o = DialOpts {
                addr: format!("{ip}:443"),
                host: dom.clone(),
                path: path.into(),
                sni: fronted.then(|| FRONTING_SNI.to_string()),
                no_check: fronted,
                timeout: Duration::from_secs(if fronted { 7 } else { 8 }),
                roots: sh.cfg.roots.clone(),
                dial: sh.cfg.dial.clone(),
            };
            match dial_ws(o).await {
                Err(e) => {
                    sh.st.ws_errors.fetch_add(1, Relaxed);
                    sh.pool.inner.lock().unwrap().last_err = e.short();
                    if matches!(e, DialError::Stage("TCP", _)) {
                        return None;
                    }
                }
                Ok(w) => {
                    let first = {
                        let mut g = sh.pool.inner.lock().unwrap();
                        g.last_ok = Some(SystemTime::now());
                        g.last_err.clear();
                        g.fail_logged = false;
                        g.front_first = fronted;
                        !std::mem::replace(&mut g.ever_worked, true)
                    };
                    if first {
                        let how = if fronted { "с подменой SNI" } else { "напрямую" };
                        sh.log(format!("Telegram: WebSocket к {dom} работает ({how})"));
                    }
                    return Some(Arc::new(w));
                }
            }
        }
    }
    None
}

// Drops old connections and keeps the pools filled.
pub async fn maintain(sh: Arc<Shared>) {
    let mut t = tokio::time::interval(POOL_TICK);
    t.tick().await;
    loop {
        t.tick().await;
        let taken: Vec<(PoolKey, VecDeque<Idle>)> = {
            let mut g = sh.pool.inner.lock().unwrap();
            g.b.iter_mut().map(|(k, b)| (*k, std::mem::take(&mut b.idle))).collect()
        };
        for (k, list) in taken {
            let mut keep = VecDeque::new();
            for e in list {
                if e.created.elapsed() >= POOL_MAX_AGE || !e.ws.alive().await {
                    close_later(e.ws);
                } else {
                    keep.push_back(e);
                }
            }
            {
                let mut g = sh.pool.inner.lock().unwrap();
                let b = g.b.entry(k).or_default();
                keep.append(&mut b.idle);
                b.idle = keep;
            }
            refill(&sh, k);
        }
    }
}

pub fn warmup(sh: &Arc<Shared>) {
    for dc in sh.cfg.dc_redirects.keys().filter(|d| WARM_DCS.contains(d)) {
        for media in [false, true] {
            refill(sh, PoolKey { dc: *dc, media, test: false });
        }
    }
}

#[cfg(test)]
impl Pool {
    pub fn idle_len(&self, k: PoolKey) -> usize {
        self.inner.lock().unwrap().b.get(&k).map_or(0, |b| b.idle.len())
    }
}
