use crate::http::{peer_closed, Req, Resp};
use crate::App;
use std::io::Write;
use std::net::TcpStream;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct PageHub {
    subs: Mutex<Vec<(u64, SyncSender<String>)>>,
    next: Mutex<u64>,
}

impl PageHub {
    fn add(&self) -> (u64, Receiver<String>) {
        let (tx, rx) = sync_channel(4);
        let id = {
            let mut n = self.next.lock().unwrap();
            *n += 1;
            *n
        };
        self.subs.lock().unwrap().push((id, tx));
        (id, rx)
    }

    fn remove(&self, id: u64) {
        self.subs.lock().unwrap().retain(|(i, _)| *i != id);
    }

    pub fn count(&self) -> usize {
        self.subs.lock().unwrap().len()
    }

    pub fn broadcast(&self, msg: &str) -> usize {
        let subs = self.subs.lock().unwrap();
        for (_, tx) in subs.iter() {
            let _ = tx.try_send(msg.to_string());
        }
        subs.len()
    }
}

impl App {
    pub fn handle_events(self: &Arc<Self>, req: &Req, s: &mut TcpStream) -> Option<Resp> {
        let t = req.query_param("t").unwrap_or_default();
        if !self.token_ok(&t) {
            return Some(Resp::text(403, "bad token"));
        }
        let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\nConnection: close\r\n\r\n";
        if s.write_all(head.as_bytes()).is_err() || s.write_all(b"retry: 1000\n\n: hello\n\n").is_err() {
            return None;
        }
        let (id, rx) = self.pages.add();
        let mut last_ka = Instant::now();
        loop {
            if self.quitting() || peer_closed(s) {
                break;
            }
            match rx.recv_timeout(Duration::from_millis(400)) {
                Ok(msg) => {
                    if s.write_all(format!("data: {msg}\n\n").as_bytes()).is_err() {
                        break;
                    }
                }
                Err(_) => {}
            }
            if last_ka.elapsed() >= Duration::from_secs(15) {
                last_ka = Instant::now();
                if s.write_all(b": ka\n\n").is_err() {
                    break;
                }
            }
        }
        self.pages.remove(id);
        None
    }

    pub fn handle_show(self: &Arc<Self>, req: &Req) -> Resp {
        if req.method != "POST" || req.header("x-gu-show") != "1" {
            return Resp::text(403, "forbidden");
        }
        let body = serde_json::json!({"ok": true, "page_open": true});
        if self.ui_window_alive() {
            let a = self.clone();
            std::thread::spawn(move || a.open_ui());
            return Resp::json(&body);
        }
        if self.pages.broadcast("show") == 0 {
            let a = self.clone();
            std::thread::spawn(move || a.open_ui());
        }
        Resp::json(&body)
    }
}

/// Просит уже запущенную копию показать страницу: (запущена ли, открыта ли вкладка).
pub fn show_running(addr: &str) -> (bool, bool) {
    let a = crate::net::agent(Duration::from_secs(2));
    let Ok(mut r) = a.post(format!("http://{addr}/api/show")).header("X-GU-Show", "1").send_empty() else {
        return (false, false);
    };
    if r.status().as_u16() != 200 {
        return (false, false);
    }
    let Ok(v) = r.body_mut().read_json::<serde_json::Value>() else { return (false, false) };
    if v["ok"].as_bool() != Some(true) {
        return (false, false);
    }
    (true, v["page_open"].as_bool().unwrap_or(false))
}
