#![cfg_attr(windows, windows_subsystem = "windows")]

mod consts;
mod discord;
mod engine;
mod home;
mod http;
mod net;
mod pages;
mod platform;
mod server;
mod services;
mod settings;
mod state;
mod strategies;
mod tg;
mod tuner;
mod ui;
mod update;
mod util;
mod zapret;

use consts::*;
use settings::Settings;
use state::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub static ENGINE_BIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/engine.bin"));
pub static WINDOW_BIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/window.bin"));
pub static LOADER_BIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/loader.bin"));

pub struct St {
    pub set: Settings,
    pub setup: SetupState,
    pub tune: TuneState,
    pub tune_cancel: Option<Arc<AtomicBool>>,
    pub checks: CheckState,
    pub dchecks: CheckState,
    pub fail_streak: u32,
}

struct Log {
    lines: Vec<String>,
    file: Option<fs::File>,
}

pub struct App {
    pub data_dir: PathBuf,
    pub zap_dir: PathBuf,
    pub port: u16,
    pub token: String,
    quit: (Mutex<bool>, Condvar),
    pub skip_logged: Mutex<HashSet<String>>,
    pub eng: engine::Engine,
    pub engine_override: Mutex<Option<PathBuf>>,
    pub eng_path: OnceLock<Option<PathBuf>>,
    pub tg_path: OnceLock<Option<PathBuf>>,
    pub win_path: OnceLock<Option<PathBuf>>,
    pub st: Mutex<St>,
    log: Mutex<Log>,
    pub pages: pages::PageHub,
    pub ui: Mutex<ui::Ui>,
    pub tg: Mutex<tg::TgState>,
}

static BOOL_CACHE: Mutex<Option<HashMap<String, (bool, Instant)>>> = Mutex::new(None);

impl App {
    pub fn new(data_dir: PathBuf, port: u16) -> Arc<App> {
        let a = App {
            zap_dir: data_dir.join("zapret"),
            data_dir,
            port,
            token: util::rand_hex(16),
            quit: (Mutex::new(false), Condvar::new()),
            skip_logged: Mutex::new(HashSet::new()),
            eng: engine::Engine::default(),
            engine_override: Mutex::new(None),
            eng_path: OnceLock::new(),
            tg_path: OnceLock::new(),
            win_path: OnceLock::new(),
            st: Mutex::new(St {
                set: Settings::default(),
                setup: SetupState::default(),
                tune: TuneState::default(),
                tune_cancel: None,
                checks: CheckState::default(),
                dchecks: CheckState::default(),
                fail_streak: 0,
            }),
            log: Mutex::new(Log { lines: Vec::new(), file: None }),
            pages: pages::PageHub::default(),
            ui: Mutex::new(ui::Ui::default()),
            tg: Mutex::new(tg::TgState::default()),
        };
        a.open_log();
        a.load_settings();
        a.load_cached_strategies();
        Arc::new(a)
    }

    pub fn cached_bool(&self, key: &str, ttl: Duration, allow_stale: bool, f: impl FnOnce() -> bool) -> bool {
        if let Some((v, at)) = BOOL_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).get(key).copied() {
            if allow_stale || at.elapsed() < ttl {
                return v;
            }
        }
        let v = f();
        BOOL_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).insert(key.to_string(), (v, Instant::now()));
        v
    }

    pub fn invalidate_cache(&self, key: &str) {
        BOOL_CACHE.lock().unwrap().get_or_insert_with(HashMap::new).remove(key);
    }

    fn open_log(&self) {
        let p = self.data_dir.join("log.txt");
        if fs::metadata(&p).map(|m| m.len() > 1 << 20).unwrap_or(false) {
            let _ = fs::remove_file(&p);
        }
        self.log.lock().unwrap().file = fs::OpenOptions::new().create(true).append(true).open(p).ok();
    }

    pub fn logf(&self, msg: String) {
        let now = chrono::Local::now();
        let line = format!("{} {msg}", now.format("%H:%M:%S"));
        let mut l = self.log.lock().unwrap();
        l.lines.push(line.clone());
        if l.lines.len() > 300 {
            let n = l.lines.len() - 300;
            l.lines.drain(..n);
        }
        if let Some(f) = l.file.as_mut() {
            let _ = writeln!(f, "{} {line}", now.format("%Y-%m-%d"));
        }
    }

    pub fn log_tail(&self, n: usize) -> Vec<String> {
        let l = self.log.lock().unwrap();
        l.lines[l.lines.len().saturating_sub(n)..].to_vec()
    }

    fn cfg_path(&self) -> PathBuf {
        self.data_dir.join("config.json")
    }

    fn load_settings(&self) {
        let Ok(b) = fs::read(self.cfg_path()) else { return };
        let Ok(mut s) = serde_json::from_slice::<Settings>(&b) else { return };
        s.groups = services::fill_groups(std::mem::take(&mut s.groups));
        if !s.engine_picked || (s.engine != "zapret" && s.engine != "both") {
            s.engine = "gust".into();
        }
        self.st.lock().unwrap().set = s;
    }

    fn save_settings(&self, s: &Settings) {
        let Ok(b) = serde_json::to_vec_pretty(s) else { return };
        let tmp = self.cfg_path().with_extension("json.tmp");
        if fs::write(&tmp, b).is_ok() {
            let _ = fs::rename(&tmp, self.cfg_path());
        }
    }

    pub fn settings(&self) -> Settings {
        self.st.lock().unwrap().set.clone()
    }

    pub fn update_settings(&self, f: impl FnOnce(&mut Settings)) {
        let mut st = self.st.lock().unwrap();
        f(&mut st.set);
        self.save_settings(&st.set);
    }

    pub fn quitting(&self) -> bool {
        *self.quit.0.lock().unwrap()
    }

    pub fn request_quit(&self) {
        *self.quit.0.lock().unwrap() = true;
        self.quit.1.notify_all();
    }

    pub fn wait_quit(&self, d: Duration) -> bool {
        let g = self.quit.0.lock().unwrap();
        let (g, _) = self.quit.1.wait_timeout_while(g, d, |q| !*q).unwrap();
        *g
    }

    pub fn boot(self: &Arc<Self>) {
        platform::kill_winws();
        {
            let a = self.clone();
            std::thread::spawn(move || a.health_loop());
            let a = self.clone();
            std::thread::spawn(move || a.update_loop());
            let a = self.clone();
            std::thread::spawn(move || {
                util::sleep_ms(15000);
                let _ = a;
                update::cleanup_old_exe();
            });
        }
        let s = self.settings();
        if platform::autostart_enabled(NAME) {
            std::thread::spawn(|| {
                let _ = platform::set_autostart(NAME, true);
            });
        }
        if s.tg_enabled {
            let a = self.clone();
            std::thread::spawn(move || {
                let _ = a.tg_start();
            });
        }
        let _ = self.sync_service_hosts();
        if s.auto_start_bypass && self.zapret_root().is_some() {
            let a = self.clone();
            std::thread::spawn(move || {
                if let Err(e) = a.start_selected() {
                    a.logf(format!("автозапуск обхода: {e}"));
                    return;
                }
                util::sleep_ms(15000);
                if a.settings().auto_retune && a.degraded() {
                    a.logf("после запуска обход не работает — подбираю заново".into());
                    let _ = a.start_tune();
                }
            });
        }
    }

    pub fn shutdown(&self) {
        self.eng_stop();
        self.tg_stop(false);
        platform::cleanup_divert(true);
        self.logf("выход".into());
    }
}

pub struct Options {
    pub data_dir: PathBuf,
    pub port: u16,
    pub background: bool,
    pub no_admin: bool,
    pub after_update: bool,
    pub portable: bool,
}

pub fn default_data_dir() -> PathBuf {
    if let Ok(v) = std::env::var("GU_DATA") {
        if !v.is_empty() {
            return PathBuf::from(v);
        }
    }
    if cfg!(windows) {
        let pd = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        return PathBuf::from(pd).join(NAME);
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(format!(".{NAME}"))
}

fn run(opt: Options, raw_args: Vec<String>) {
    if !opt.portable && !opt.after_update && home::move_home() {
        return;
    }
    let addr = format!("127.0.0.1:{}", opt.port);
    if opt.after_update {
        update::wait_port_free(&addr, Duration::from_secs(20));
    }
    if !opt.background {
        platform::allow_foreground();
        let (running, page_open) = pages::show_running(&addr);
        if running {
            if !page_open {
                platform::open_browser(&format!("http://{addr}/"));
            }
            return;
        }
    }
    if !opt.no_admin && !platform::is_admin() && platform::relaunch_as_admin(&raw_args) {
        return;
    }
    if let Err(e) = fs::create_dir_all(&opt.data_dir) {
        eprintln!("не могу создать папку данных: {e}");
        std::process::exit(1);
    }
    platform::secure_dir(&opt.data_dir);

    let ln = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(_) => {
            if !opt.background {
                let (running, page_open) = pages::show_running(&addr);
                if !running || !page_open {
                    platform::open_browser(&format!("http://{addr}/"));
                }
            }
            return;
        }
    };

    let a = App::new(opt.data_dir.clone(), opt.port);
    a.logf(format!("{NAME} {VERSION} запущен (admin={}, background={}, data={})", platform::is_admin(), opt.background, opt.data_dir.display()));

    {
        let a = a.clone();
        std::thread::spawn(move || {
            let h: http::Handler = {
                let a = a.clone();
                Arc::new(move |req, s| a.route(req, s))
            };
            http::serve(ln, h);
        });
    }
    a.boot();

    a.apply_tray_lang();
    let (a1, a2) = (a.clone(), a.clone());
    let stop_tray = platform::run_tray(
        NAME,
        Arc::new(move || a1.open_ui()),
        Arc::new(move || a2.request_quit()),
    );
    if opt.background {
        platform::tray_notice(NAME, "Запущена в фоне. Значок — в трее (в Windows 11 он может быть под стрелкой ^).");
    }
    if !opt.background {
        let a = a.clone();
        std::thread::spawn(move || a.open_ui());
    }

    let hook = a.clone();
    let _ = ctrlc_hook(move || hook.request_quit());
    while !a.wait_quit(Duration::from_secs(3600)) {}
    a.close_ui();
    stop_tray();
    a.shutdown();
}

#[cfg(unix)]
fn ctrlc_hook(f: impl Fn() + Send + 'static) -> Result<(), ()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static HIT: AtomicBool = AtomicBool::new(false);
    extern "C" fn handler(_: i32) {
        HIT.store(true, Ordering::SeqCst);
    }
    extern "C" {
        fn signal(sig: i32, h: extern "C" fn(i32)) -> usize;
    }
    unsafe {
        signal(2, handler);
        signal(15, handler);
    }
    std::thread::spawn(move || loop {
        if HIT.load(Ordering::SeqCst) {
            f();
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    });
    Ok(())
}

#[cfg(not(unix))]
fn ctrlc_hook(_: impl Fn() + Send + 'static) -> Result<(), ()> {
    Ok(())
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut opt = Options {
        data_dir: default_data_dir(),
        port: DEFAULT_PORT,
        background: false,
        no_admin: false,
        after_update: false,
        portable: false,
    };
    let mut it = raw.iter();
    while let Some(a) = it.next() {
        let a = a.trim_start_matches('-');
        let (k, inline) = match a.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (a, None),
        };
        let mut val = || inline.clone().or_else(|| it.next().cloned()).unwrap_or_default();
        match k {
            "background" => opt.background = true,
            "no-admin" => opt.no_admin = true,
            "after-update" => opt.after_update = true,
            "portable" => opt.portable = true,
            "port" => opt.port = val().parse().unwrap_or(DEFAULT_PORT),
            "data" => opt.data_dir = PathBuf::from(val()),
            _ => {}
        }
    }
    run(opt, raw);
}

#[cfg(test)]
mod tests;
