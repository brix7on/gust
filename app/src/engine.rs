use crate::consts::*;
use crate::strategies::Strategy;
use crate::zapret::{ensure_lists, exe_allowed};
use crate::{platform, util, App};
use serde::Serialize;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub static STARTUP_WAIT_MS: AtomicU64 = AtomicU64::new(1000);

fn startup_wait() -> Duration {
    Duration::from_millis(STARTUP_WAIT_MS.load(Ordering::Relaxed))
}

#[derive(Default)]
pub struct Engine {
    pub(crate) m: Mutex<EngInner>,
}

#[derive(Default)]
pub(crate) struct EngInner {
    child: Option<Arc<Mutex<Child>>>,
    done: Option<Arc<AtomicBool>>,
    gen: u64,
    running: bool,
    strategy: String,
    since: Option<Instant>,
    since_unix: i64,
    last_err: String,
    want: bool,
    crashes: Vec<Instant>,
    tail: Vec<String>,
}

#[derive(Serialize)]
pub struct EngineState {
    pub running: bool,
    pub strategy: String,
    pub since: i64,
    pub last_err: String,
}

pub const ENGINE_FLAGS: &[&str] = &[
    "--wf-tcp", "--wf-udp", "--windivert", "--new", "--filter-tcp", "--filter-udp", "--filter-l7",
    "--hostlist", "--hostlist-domains", "--hostlist-exclude", "--hostlist-exclude-domains",
    "--ipset", "--ipset-ip", "--ipset-exclude", "--ipset-exclude-ip", "--ip-id",
    "--dpi-desync", "--dpi-desync-repeats", "--dpi-desync-split-pos",
    "--dpi-desync-split-seqovl", "--dpi-desync-split-seqovl-pattern",
    "--dpi-desync-fakedsplit-pattern", "--dpi-desync-hostfakesplit-mod", "--dpi-desync-hostfakesplit-midhost",
    "--dpi-desync-fooling", "--dpi-desync-ttl", "--dpi-desync-ttl6",
    "--dpi-desync-autottl", "--dpi-desync-autottl6",
    "--dpi-desync-badseq-increment", "--dpi-desync-badack-increment", "--dpi-desync-ts-increment",
    "--dpi-desync-fake-tls", "--dpi-desync-fake-tls-mod", "--dpi-desync-fake-http",
    "--dpi-desync-fake-quic", "--dpi-desync-fake-discord", "--dpi-desync-fake-stun",
    "--dpi-desync-fake-unknown", "--dpi-desync-fake-unknown-udp", "--dpi-desync-fake-syndata",
    "--dpi-desync-any-protocol", "--dpi-desync-cutoff", "--wssize", "--wssize-cutoff",
];

pub fn engine_compatible(args: &[String]) -> bool {
    args.iter().all(|a| ENGINE_FLAGS.contains(&a.split('=').next().unwrap_or("")))
}

pub fn engine_twins(input: &[Strategy], exe: &Path, root: &Path) -> Vec<Strategy> {
    let dll = root.join("bin").join("WinDivert.dll");
    if !util::exists(&dll) {
        return Vec::new();
    }
    input
        .iter()
        .filter(|s| engine_compatible(&s.args))
        .map(|s| {
            let mut args = vec![format!("--windivert={}", dll.display())];
            args.extend(s.args.iter().cloned());
            Strategy { name: format!("{TWIN_PREFIX}{}", s.name), exe: exe.to_path_buf(), args }
        })
        .collect()
}

pub fn friendly_winws_error(tail: &[String]) -> String {
    let all = tail.join("\n").to_lowercase();
    if all.contains("access is denied") || all.contains("error 5") {
        "Нет прав администратора для драйвера WinDivert.".into()
    } else if all.contains("1275") || all.contains("blocked") || all.contains("signature") {
        "Драйвер WinDivert заблокирован (антивирус, Secure Boot или «Целостность памяти»). Добавьте папку Gust в исключения антивируса.".into()
    } else if all.contains("1058") || all.contains("already") || all.contains("1117") {
        "WinDivert занят другой программой. Закройте другие обходчики (GoodbyeDPI, другой zapret, VPN) и повторите.".into()
    } else if all.contains("file") && all.contains("not found") {
        "Не найден файл из сборки zapret. Переустановите сборку.".into()
    } else if let Some(l) = tail.last() {
        l.clone()
    } else {
        "winws завершился сразу после запуска".into()
    }
}

fn pump(app: Arc<App>, name: String, r: impl std::io::Read + Send + 'static) {
    std::thread::spawn(move || {
        for line in BufReader::new(r).lines() {
            let Ok(l) = line else { break };
            let t = l.trim();
            if !t.is_empty() {
                app.eng_add_tail(&name, t);
            }
        }
    });
}

impl App {
    pub fn eng_state(&self) -> EngineState {
        let e = self.eng.m.lock().unwrap();
        EngineState {
            running: e.running,
            strategy: e.strategy.clone(),
            since: if e.running { e.since_unix } else { 0 },
            last_err: e.last_err.clone(),
        }
    }

    #[cfg(test)]
    pub fn eng_pid(&self) -> Option<u32> {
        let e = self.eng.m.lock().unwrap();
        if !e.running {
            return None;
        }
        e.child.as_ref().map(|c| c.lock().unwrap().id())
    }

    #[cfg(test)]
    pub fn eng_kill_current(&self) {
        if let Some(c) = self.eng.m.lock().unwrap().child.clone() {
            let _ = c.lock().unwrap().kill();
        }
    }

    pub fn eng_alive(&self) -> bool {
        self.eng.m.lock().unwrap().running
    }

    fn eng_add_tail(&self, name: &str, line: &str) {
        {
            let mut e = self.eng.m.lock().unwrap();
            e.tail.push(line.to_string());
            if e.tail.len() > 12 {
                let n = e.tail.len() - 12;
                e.tail.drain(..n);
            }
        }
        self.logf(format!("{name}: {line}"));
    }

    pub fn eng_start(self: &Arc<Self>, s: &Strategy, want: bool) -> Result<(), String> {
        let wait = startup_wait();
        self.eng_stop();
        let root = self.zapret_root();
        if !exe_allowed(root.as_deref(), &s.exe) && !self.is_engine_exe(&s.exe) {
            self.eng.m.lock().unwrap().last_err = "стратегия ссылается на посторонний исполняемый файл".into();
            return Err(format!("небезопасный путь к winws: {}", s.exe.display()));
        }
        ensure_lists(root.as_deref(), &s.args);
        self.logf(format!("запускаю стратегию «{}»", s.name));

        let name = s
            .exe
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default()
            .trim_end_matches(".exe")
            .to_string();
        let mut cmd = Command::new(&s.exe);
        cmd.args(&s.args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(d) = s.exe.parent() {
            cmd.current_dir(d);
        }
        platform::hide_window(&mut cmd);
        self.eng.m.lock().unwrap().tail.clear();
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.eng.m.lock().unwrap().last_err = e.to_string();
                return Err(format!("не удалось запустить winws: {e}"));
            }
        };
        if let Some(o) = child.stdout.take() {
            pump(self.clone(), name.clone(), o);
        }
        if let Some(o) = child.stderr.take() {
            pump(self.clone(), name.clone(), o);
        }
        let child = Arc::new(Mutex::new(child));
        let done = Arc::new(AtomicBool::new(false));
        let gen = {
            let mut e = self.eng.m.lock().unwrap();
            e.gen += 1;
            e.child = Some(child.clone());
            e.done = Some(done.clone());
            e.running = true;
            e.strategy = s.name.clone();
            e.since = Some(Instant::now());
            e.since_unix = util::now_unix();
            e.last_err.clear();
            e.want = want;
            e.gen
        };

        {
            let app = self.clone();
            let s = s.clone();
            let done = done.clone();
            std::thread::spawn(move || {
                loop {
                    let fin = matches!(child.lock().unwrap().try_wait(), Ok(Some(_)) | Err(_));
                    if fin {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                std::thread::sleep(Duration::from_millis(100));
                done.store(true, Ordering::SeqCst);
                app.eng_on_exit(gen, s);
            });
        }

        let t0 = Instant::now();
        while t0.elapsed() < wait {
            if done.load(Ordering::SeqCst) {
                let mut e = self.eng.m.lock().unwrap();
                if e.gen != gen {
                    return Err("запуск прерван".into());
                }
                let tail = e.tail.clone();
                e.running = false;
                e.want = false;
                let msg = friendly_winws_error(&tail);
                e.last_err = msg.clone();
                return Err(msg);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn eng_on_exit(self: &Arc<Self>, gen: u64, s: Strategy) {
        let (want, too_many) = {
            let mut e = self.eng.m.lock().unwrap();
            if gen != e.gen {
                return;
            }
            let now = Instant::now();
            if e.since.map(|t| now.duration_since(t) < startup_wait()).unwrap_or(false) {
                return;
            }
            e.running = false;
            let want = e.want;
            e.crashes.push(now);
            e.crashes.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
            let too_many = e.crashes.len() > 3;
            if want && too_many {
                e.want = false;
                e.last_err = format!("winws постоянно падает: {}", friendly_winws_error(&e.tail));
            }
            (want, too_many)
        };
        if !want {
            return;
        }
        if too_many {
            self.logf("winws падает слишком часто, перезапуск отключён".into());
            return;
        }
        self.logf("winws завершился сам, перезапускаю".into());
        std::thread::sleep(Duration::from_secs(2));
        let still = {
            let e = self.eng.m.lock().unwrap();
            e.want && e.gen == gen
        };
        if still {
            if let Err(e) = self.eng_start(&s, true) {
                self.logf(format!("перезапуск не удался: {e}"));
            }
        }
    }

    pub fn eng_stop(&self) {
        let (child, done) = {
            let mut e = self.eng.m.lock().unwrap();
            e.want = false;
            e.gen += 1;
            e.running = false;
            (e.child.take(), e.done.take())
        };
        let Some(child) = child else { return };
        let _ = child.lock().unwrap().kill();
        if let Some(d) = done {
            let t0 = Instant::now();
            while !d.load(Ordering::SeqCst) && t0.elapsed() < Duration::from_secs(3) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        platform::kill_winws();
        platform::cleanup_divert(false);
    }

    pub fn engine_exe(&self) -> Option<PathBuf> {
        if let Some(p) = self.engine_override.lock().unwrap().clone() {
            return Some(p);
        }
        self.eng_path.get_or_init(|| self.extract_as(ENGINE_NAME)).clone()
    }

    pub fn tg_exe(&self) -> Option<PathBuf> {
        if let Some(p) = self.engine_override.lock().unwrap().clone() {
            return Some(p);
        }
        self.tg_path.get_or_init(|| self.extract_as(TG_IMAGE)).clone()
    }

    fn extract_as(&self, name: &str) -> Option<PathBuf> {
        self.extract_bytes(name, crate::ENGINE_BIN)
    }

    pub fn window_exe(&self) -> Option<PathBuf> {
        self.win_path
            .get_or_init(|| {
                self.extract_bytes("WebView2Loader.dll", crate::LOADER_BIN)?;
                self.extract_bytes("gust-window.exe", crate::WINDOW_BIN)
            })
            .clone()
    }

    fn extract_bytes(&self, name: &str, b: &[u8]) -> Option<PathBuf> {
        if b.is_empty() {
            return None;
        }
        let dir = self.data_dir.join("engine");
        let p = dir.join(name);
        if std::fs::read(&p).map(|o| o == b).unwrap_or(false) {
            return Some(p);
        }
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.logf(format!("движок Gust: {e}"));
            return None;
        }
        let tmp = dir.join(format!("{name}.tmp"));
        if let Err(e) = std::fs::write(&tmp, b) {
            self.logf(format!("движок Gust: {e}"));
            return None;
        }
        if std::fs::rename(&tmp, &p).is_err() {
            platform::kill_by_name(name);
            util::sleep_ms(300);
            if let Err(e) = std::fs::rename(&tmp, &p) {
                let _ = std::fs::remove_file(&tmp);
                self.logf(format!("движок Gust: не удалось обновить файл: {e}"));
                return None;
            }
        }
        Some(p)
    }

    pub fn is_engine_exe(&self, p: &Path) -> bool {
        let Some(ep) = self.engine_exe() else { return false };
        if p.as_os_str().is_empty() {
            return false;
        }
        match (util::abs(p), util::abs(&ep)) {
            (Ok(x), Ok(y)) => x.to_string_lossy().to_lowercase() == y.to_string_lossy().to_lowercase(),
            _ => false,
        }
    }

    pub fn with_engine(&self, out: Vec<Strategy>, root: &Path, mode: &str) -> Vec<Strategy> {
        if mode != "gust" && mode != "both" {
            return out;
        }
        let Some(ep) = self.engine_exe() else { return out };
        let tw = engine_twins(&out, &ep, root);
        if mode == "gust" && !tw.is_empty() {
            return tw;
        }
        let mut out = out;
        out.extend(tw);
        out
    }
}

