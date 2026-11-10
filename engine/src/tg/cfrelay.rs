// Second WebSocket route for providers that cut Telegram IPs: the endpoint is read from
// %ProgramData%\Gust\relay.txt (host and key, whitespace separated); without the file it is off.

use super::pool::PoolKey;
use super::ws::{dial_ws, DialOpts, WsConn};
use super::Shared;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

static SEEN_OK: AtomicBool = AtomicBool::new(false);

pub struct Relay {
    host: String,
    key: String,
}

impl Relay {
    pub fn load() -> Option<Relay> {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        let text = std::fs::read_to_string(std::path::Path::new(&base).join("Gust").join("relay.txt")).ok()?;
        Relay::parse(&text)
    }

    fn parse(text: &str) -> Option<Relay> {
        let mut it = text.split_whitespace();
        let host = it.next()?.trim_start_matches("wss://").trim_start_matches("https://").trim_end_matches('/');
        let key = it.next()?;
        if host.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
            return None;
        }
        Some(Relay { host: host.to_string(), key: key.to_string() })
    }
}

pub async fn connect(sh: &Arc<Shared>, r: &Relay, k: PoolKey) -> Option<Arc<WsConn>> {
    for _ in 0..2 {
        let o = DialOpts {
            addr: format!("{}:443", r.host),
            host: r.host.clone(),
            path: format!("/tg?dc={}&key={}", k.dc, r.key),
            sni: None,
            no_check: false,
            timeout: Duration::from_secs(6),
            roots: sh.cfg.roots.clone(),
            dial: sh.cfg.dial.clone(),
        };
        match dial_ws(o).await {
            Ok(w) => {
                if !SEEN_OK.swap(true, Ordering::Relaxed) {
                    sh.log("Telegram: запасной WebSocket-путь работает".into());
                }
                return Some(Arc::new(w));
            }
            Err(e) => {
                sh.st.ws_errors.fetch_add(1, Ordering::Relaxed);
                let why = e.short();
                sh.log_throttled(&format!("alt {why}"), || format!("Telegram: запасной WebSocket-путь недоступен ({why})"));
            }
        }
    }
    None
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
}
