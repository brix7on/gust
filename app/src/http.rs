use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub struct Req {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, k: &str) -> &str {
        self.headers.get(k).map(|s| s.as_str()).unwrap_or("")
    }

    pub fn query_param(&self, k: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (a, b) = kv.split_once('=').unwrap_or((kv, ""));
            (a == k).then(|| b.to_string())
        })
    }
}

pub struct Resp {
    pub status: u16,
    pub ctype: &'static str,
    pub body: Vec<u8>,
    pub headers: Vec<(&'static str, String)>,
}

impl Resp {
    pub fn text(status: u16, s: &str) -> Resp {
        Resp { status, ctype: "text/plain; charset=utf-8", body: format!("{s}\n").into_bytes(), headers: Vec::new() }
    }

    pub fn json(v: &impl serde::Serialize) -> Resp {
        let mut b = serde_json::to_vec(v).unwrap_or_default();
        b.push(b'\n');
        Resp {
            status: 200,
            ctype: "application/json; charset=utf-8",
            body: b,
            headers: vec![("Cache-Control", "no-store".into())],
        }
    }

    pub fn html(s: String) -> Resp {
        Resp {
            status: 200,
            ctype: "text/html; charset=utf-8",
            body: s.into_bytes(),
            headers: vec![("Cache-Control", "no-store".into())],
        }
    }
}

fn reason(s: u16) -> &'static str {
    match s {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

pub fn write_resp(s: &mut TcpStream, r: &Resp) {
    let mut h = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n",
        r.status,
        reason(r.status),
        r.ctype,
        r.body.len()
    );
    for (k, v) in &r.headers {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    let _ = s.write_all(h.as_bytes());
    let _ = s.write_all(&r.body);
    let _ = s.flush();
}

const MAX_HEAD: usize = 32 << 10;
const MAX_BODY: usize = 1 << 20;

fn read_req(s: &mut TcpStream) -> Result<Req, u16> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err(400);
        }
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return Err(400),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next().ok_or(400u16)?;
    let mut p = first.split(' ');
    let (method, target) = (p.next().ok_or(400u16)?.to_string(), p.next().ok_or(400u16)?.to_string());
    let (path, query) = match target.split_once('?') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (target, String::new()),
    };
    let mut headers = HashMap::new();
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    if len > MAX_BODY {
        return Err(413);
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < len {
        match s.read(&mut tmp) {
            Ok(0) | Err(_) => return Err(400),
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    body.truncate(len);
    Ok(Req { method, path, query, headers, body })
}

/// None — обработчик сам всё написал в сокет (поток событий).
pub type Handler = Arc<dyn Fn(&Req, &mut TcpStream) -> Option<Resp> + Send + Sync>;

pub fn serve(ln: TcpListener, h: Handler) {
    for conn in ln.incoming() {
        let Ok(mut s) = conn else { continue };
        let h = h.clone();
        std::thread::spawn(move || {
            let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
            let _ = s.set_write_timeout(Some(Duration::from_secs(30)));
            match read_req(&mut s) {
                Ok(req) => {
                    let _ = s.set_read_timeout(None);
                    if let Some(r) = h(&req, &mut s) {
                        write_resp(&mut s, &r);
                    }
                }
                Err(code) => write_resp(&mut s, &Resp::text(code, reason(code))),
            }
            let _ = s.shutdown(Shutdown::Both);
        });
    }
}

/// Клиент закрыл соединение? (читаем без блокировки)
pub fn peer_closed(s: &TcpStream) -> bool {
    let _ = s.set_read_timeout(Some(Duration::from_millis(1)));
    let mut b = [0u8; 1];
    match s.peek(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
    }
}
