// Second WebSocket route for providers that cut Telegram IPs: the endpoint is read from
// %ProgramData%\Gust\relay.txt (host and key, whitespace separated); without the file it is off.

use super::pool::PoolKey;
use super::ws::{dial_ws, DialOpts, WsConn};
use super::Shared;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TRIES: usize = 3;
const STAGGER: Duration = Duration::from_millis(1200);
const ATTEMPT: Duration = Duration::from_secs(6);
const DNS_TTL: Duration = Duration::from_secs(300);

static SEEN_OK: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicUsize = AtomicUsize::new(0);
static BAD: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());
const BAD_TTL: Duration = Duration::from_secs(120);

// Edge address whose connection went silent: avoided for a while
pub fn mark_bad(addr: &str) {
    let mut b = BAD.lock().unwrap();
    b.retain(|(a, t)| a != addr && t.elapsed() < BAD_TTL);
    b.push((addr.to_string(), Instant::now()));
}

fn is_bad(addr: &str) -> bool {
    BAD.lock().unwrap().iter().any(|(a, t)| a == addr && t.elapsed() < BAD_TTL)
}

pub struct Relay {
    host: String,
    key: String,
    addrs: Mutex<Option<(Instant, Vec<String>)>>,
}

impl Relay {
    pub fn load() -> Option<Relay> {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        let text = std::fs::read_to_string(std::path::Path::new(&base).join("Gust").join("relay.txt")).ok()?;
        Relay::parse(&text)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    fn parse(text: &str) -> Option<Relay> {
        let mut it = text.split_whitespace();
        let host = it.next()?.trim_start_matches("wss://").trim_start_matches("https://").trim_end_matches('/');
        let key = it.next()?;
        if host.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        Some(Relay { host: host.to_string(), key: key.to_string(), addrs: Mutex::new(None) })
    }

    // Edge addresses of the host (IPv4 first), refreshed every few minutes.
    async fn resolve(&self) -> Vec<String> {
        if let Some((t, a)) = self.addrs.lock().unwrap().as_ref() {
            if t.elapsed() < DNS_TTL {
                return a.clone();
            }
        }
        let all: Vec<std::net::SocketAddr> = match tokio::net::lookup_host((self.host.as_str(), 443)).await {
            Ok(it) => it.collect(),
            Err(_) => Vec::new(),
        };
        let v4: Vec<String> = all.iter().filter(|a| a.is_ipv4()).map(|a| a.to_string()).collect();
        let mut list = if v4.is_empty() { all.iter().map(|a| a.to_string()).collect() } else { v4 };
        if list.is_empty() {
            list.push(format!("{}:443", self.host));
        }
        *self.addrs.lock().unwrap() = Some((Instant::now(), list.clone()));
        list
    }
}

// Up to TRIES handshakes, each through the next edge address; a new one starts when the previous
// failed or did not answer within STAGGER, the first success wins.
pub async fn connect(sh: &Arc<Shared>, r: &Relay, k: PoolKey) -> Option<(Arc<WsConn>, String)> {
    let all = r.resolve().await;
    let good: Vec<String> = all.iter().filter(|a| !is_bad(a)).cloned().collect();
    let addrs = if good.is_empty() { all } else { good };
    let base = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut set = tokio::task::JoinSet::new();
    let mut started = 0;
    loop {
        if started < TRIES {
            let o = DialOpts {
                addr: addrs[(base + started) % addrs.len()].clone(),
                host: r.host.clone(),
                path: format!("/tg?dc={}&key={}", k.dc, r.key),
                sni: None,
                no_check: false,
                timeout: ATTEMPT,
                roots: sh.cfg.roots.clone(),
                dial: sh.cfg.dial.clone(),
            };
            started += 1;
            let addr = o.addr.clone();
            set.spawn(async move { dial_ws(o).await.map(|w| (w, addr)) });
        }
        let wait = if started < TRIES { STAGGER } else { ATTEMPT };
        match tokio::time::timeout(wait, set.join_next()).await {
            Ok(Some(Ok(Ok((w, addr))))) => {
                set.abort_all();
                if !SEEN_OK.swap(true, Ordering::Relaxed) {
                    sh.log("Telegram: запасной WebSocket-путь работает".into());
                }
                return Some((Arc::new(w), addr));
            }
            Ok(Some(Ok(Err(e)))) => {
                sh.st.ws_errors.fetch_add(1, Ordering::Relaxed);
                let why = e.short();
                sh.log_throttled(&format!("alt {why}"), || format!("Telegram: запасной WebSocket-путь недоступен ({why})"));
            }
            Ok(Some(Err(_))) => {}
            Ok(None) => return None,
            Err(_) if started >= TRIES => {
                set.abort_all();
                return None;
            }
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Relay;

    #[test]
    fn parses_host_and_key() {
        let r = Relay::parse("https://gust.example.net/\nabc123\n").unwrap();
        assert_eq!((r.host.as_str(), r.key.as_str()), ("gust.example.net", "abc123"));
        assert!(Relay::parse("only-host").is_none());
        assert!(Relay::parse("host bad!").is_none());
    }

    #[tokio::test]
    async fn resolves_literal_ip() {
        let r = Relay::parse("127.0.0.1 k").unwrap();
        assert_eq!(r.resolve().await, vec!["127.0.0.1:443".to_string()]);
    }
}
