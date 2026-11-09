use crate::platform;
use crate::util::rand_hex;
use crate::App;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_PORT: u16 = 1443;

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct StatsSnapshot {
    pub total: i64,
    pub active: i64,
    pub bad: i64,
    pub via_ws: i64,
    pub dead_ws: i64,
    pub answered_ws: i64,
    pub via_tcp: i64,
    pub no_route: i64,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub last_bad: i64,
    pub last_ok: i64,
    pub ws_last_ok: i64,
    pub ws_err: String,
}

#[derive(Serialize)]
pub struct TgOut {
    pub running: bool,
    pub link: String,
    pub port: u16,
    pub err: String,
    pub stats: StatsSnapshot,
    pub old_proxy: bool,
}

pub fn valid_secret(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn link(port: u16, secret: &str) -> String {
    format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{secret}")
}

pub struct TgRun {
    child: Mutex<Child>,
    stdin: Mutex<Option<ChildStdin>>,
    done: AtomicBool,
    stopping: AtomicBool,
    stats: Mutex<StatsSnapshot>,
}

impl TgRun {
    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        drop(self.stdin.lock().unwrap().take());
        let _ = self.child.lock().unwrap().kill();
        let t0 = std::time::Instant::now();
        while !self.done.load(Ordering::SeqCst) && t0.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[derive(Default)]
pub struct TgState {
    pub run: Option<Arc<TgRun>>,
    pub err: String,
}

fn old_tg_secret() -> String {
    let Ok(dir) = std::env::var("APPDATA") else { return String::new() };
    let Ok(b) = std::fs::read(std::path::Path::new(&dir).join("TgWsProxy").join("config.json")) else { return String::new() };
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
    let s = v["secret"].as_str().unwrap_or("");
    if valid_secret(s) {
        s.to_string()
    } else {
        String::new()
    }
}

fn friendly_listen_err(e: String) -> String {
    if e == "addr_in_use" {
        if cfg!(windows) && platform::proc_running(crate::consts::OLD_TG_IMAGE) {
            return format!("порт {DEFAULT_PORT} занят старым TG WS Proxy. Закройте его (значок у часов → «Выход»): он больше не нужен");
        }
        return format!("порт {DEFAULT_PORT} занят другой программой");
    }
    e
}

impl App {
    fn tg_secret(&self) -> String {
        let s = self.settings();
        if valid_secret(&s.tg_secret) {
            return s.tg_secret;
        }
        let mut sec = old_tg_secret();
        if !sec.is_empty() {
            self.logf("Telegram: взят секрет от прежнего TG WS Proxy — переподключать Telegram не нужно".into());
        } else {
            sec = rand_hex(16);
        }
        self.update_settings(|st| st.tg_secret = sec.clone());
        sec
    }

    pub fn tg_start(self: &Arc<Self>) -> Result<(), String> {
        let mut tg = self.tg.lock().unwrap();
        if tg.run.is_some() {
            return Ok(());
        }
        let Some(exe) = self.tg_exe() else {
            let e = "в этой сборке нет встроенного движка — прокси Telegram недоступен".to_string();
            tg.err = e.clone();
            self.logf(format!("Telegram-прокси: {e}"));
            return Err(e);
        };
        let mut cmd = Command::new(&exe);
        cmd.args(["tgproxy", "--port", &DEFAULT_PORT.to_string(), "--secret", &self.tg_secret(), "--pool", "4"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(d) = exe.parent() {
            cmd.current_dir(d);
        }
        platform::hide_window(&mut cmd);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                tg.err = e.to_string();
                self.logf(format!("Telegram-прокси: {e}"));
                return Err(e.to_string());
            }
        };
        let stdin = child.stdin.take();
        let out = child.stdout.take().unwrap();
        let r = Arc::new(TgRun {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            done: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            stats: Mutex::new(StatsSnapshot::default()),
        });
        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        {
            let app = self.clone();
            let r = r.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(out).lines() {
                    let Ok(line) = line else { break };
                    if line == "ready" {
                        let _ = tx.send(Ok(()));
                    } else if let Some(e) = line.strip_prefix("error: ") {
                        let _ = tx.send(Err(e.to_string()));
                    } else if let Some(l) = line.strip_prefix("log: ") {
                        app.logf(l.to_string());
                    } else if let Some(j) = line.strip_prefix("stats: ") {
                        if let Ok(st) = serde_json::from_str::<StatsSnapshot>(j) {
                            *r.stats.lock().unwrap() = st;
                        }
                    }
                }
                loop {
                    if matches!(r.child.lock().unwrap().try_wait(), Ok(Some(_)) | Err(_)) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                r.done.store(true, Ordering::SeqCst);
                if r.stopping.load(Ordering::SeqCst) {
                    return;
                }
                let _ = tx.send(Err("процесс прокси завершился".into()));
                let mut tg = app.tg.lock().unwrap();
                if tg.run.as_ref().map(|x| Arc::ptr_eq(x, &r)).unwrap_or(false) {
                    tg.run = None;
                    tg.err = "процесс прокси неожиданно завершился".into();
                    app.logf("Telegram-прокси: процесс неожиданно завершился".into());
                }
            });
        }
        let first = rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| Err("прокси не запустился за 10 секунд".into()));
        if let Err(e) = first {
            r.stop();
            let e = friendly_listen_err(e);
            tg.err = e.clone();
            self.logf(format!("Telegram-прокси: {e}"));
            return Err(e);
        }
        tg.run = Some(r);
        tg.err.clear();
        drop(tg);
        self.update_settings(|st| st.tg_enabled = true);
        self.logf(format!("Telegram-прокси запущен на 127.0.0.1:{DEFAULT_PORT}"));
        Ok(())
    }

    pub fn tg_stop(&self, remember: bool) {
        let s = self.tg.lock().unwrap().run.take();
        if let Some(s) = s {
            s.stop();
            self.logf("Telegram-прокси остановлен".into());
        }
        if remember {
            self.update_settings(|st| st.tg_enabled = false);
        }
    }

    pub fn tg_open(self: &Arc<Self>) -> Result<(), String> {
        self.tg_start()?;
        if !cfg!(windows) {
            return Err("работает только в Windows".into());
        }
        platform::open_as_user(&link(DEFAULT_PORT, &self.tg_secret()));
        Ok(())
    }

    pub fn tg_state(&self, stale: bool) -> TgOut {
        let (run, err) = {
            let tg = self.tg.lock().unwrap();
            (tg.run.clone(), tg.err.clone())
        };
        let mut out = TgOut {
            running: run.is_some(),
            link: link(DEFAULT_PORT, &self.settings().tg_secret),
            port: DEFAULT_PORT,
            err,
            stats: StatsSnapshot::default(),
            old_proxy: false,
        };
        if let Some(r) = run {
            out.stats = r.stats.lock().unwrap().clone();
        } else if cfg!(windows) {
            out.old_proxy = self.cached_bool("oldtg", Duration::from_secs(10), stale, || platform::proc_running(crate::consts::OLD_TG_IMAGE));
        }
        out
    }
}
