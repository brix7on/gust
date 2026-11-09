use crate::consts::*;
use crate::util::{copy_file, exists, file_sha256};
use crate::zapret::unzip_safe;
use crate::{net, platform, App};
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Serialize, Clone, Default)]
pub struct UpdateState {
    pub latest: String,
    pub busy: bool,
    pub msg: String,
    pub err: String,
}

#[derive(Default)]
struct Upd {
    st: UpdateState,
    zip_url: String,
    sums_url: String,
    zip_name: String,
}

static UPD: Mutex<Upd> = Mutex::new(Upd {
    st: UpdateState { latest: String::new(), busy: false, msg: String::new(), err: String::new() },
    zip_url: String::new(),
    sums_url: String::new(),
    zip_name: String::new(),
});

pub fn update_state() -> UpdateState {
    UPD.lock().unwrap().st.clone()
}

fn set_upd(f: impl FnOnce(&mut UpdateState)) {
    f(&mut UPD.lock().unwrap().st);
}

pub fn newer_version(a: &str, b: &str) -> bool {
    let pa: Vec<&str> = a.trim_start_matches('v').split('.').collect();
    let pb: Vec<&str> = b.trim_start_matches('v').split('.').collect();
    for i in 0..pa.len().max(pb.len()) {
        let x: i64 = pa.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
        let y: i64 = pb.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

pub fn sum_for(sums_path: &Path, name: &str) -> String {
    let Ok(text) = fs::read_to_string(sums_path) else { return String::new() };
    for l in text.lines() {
        let fs: Vec<&str> = l.split_whitespace().collect();
        if fs.len() == 2 && fs[1].trim_start_matches('*') == name {
            return fs[0].to_lowercase();
        }
    }
    String::new()
}

impl App {
    pub fn check_update(&self) {
        let Ok(rel) = net::get_json(&format!("https://api.github.com/repos/{SELF_REPO}/releases/latest")) else { return };
        let tag = rel["tag_name"].as_str().unwrap_or("").to_string();
        if !newer_version(&tag, VERSION) {
            set_upd(|s| s.latest.clear());
            return;
        }
        let (mut zip_url, mut zip_name, mut sums) = (String::new(), String::new(), String::new());
        for a in rel["assets"].as_array().cloned().unwrap_or_default() {
            let n = a["name"].as_str().unwrap_or("");
            let u = a["browser_download_url"].as_str().unwrap_or("");
            if n == "SHA256SUMS" {
                sums = u.into();
            } else if n.starts_with("Gust-") && n.ends_with("-windows-x64.zip") {
                zip_url = u.into();
                zip_name = n.into();
            }
        }
        if zip_url.is_empty() || sums.is_empty() {
            return;
        }
        let t = tag.trim_start_matches('v').to_string();
        let first = {
            let mut u = UPD.lock().unwrap();
            let first = u.st.latest != t;
            u.st.latest = t;
            u.zip_url = zip_url;
            u.sums_url = sums;
            u.zip_name = zip_name;
            first
        };
        if first {
            self.logf(format!("доступна новая версия {tag}"));
        }
    }

    pub fn update_loop(self: &Arc<Self>) {
        if self.wait_quit(Duration::from_secs(20)) {
            return;
        }
        loop {
            self.check_update();
            self.fetch_strategies();
            if self.wait_quit(Duration::from_secs(3600)) {
                return;
            }
        }
    }

    pub fn start_update(self: &Arc<Self>) -> Result<(), String> {
        if self.tuning() {
            return Err("идёт подбор — дождитесь конца".into());
        }
        let (zip_url, sums_url, zip_name, ver) = {
            let mut u = UPD.lock().unwrap();
            if u.st.busy {
                return Err("обновление уже идёт".into());
            }
            if u.st.latest.is_empty() {
                return Err("новых версий нет".into());
            }
            u.st.busy = true;
            u.st.err.clear();
            u.st.msg = "Загрузка…".into();
            (u.zip_url.clone(), u.sums_url.clone(), u.zip_name.clone(), u.st.latest.clone())
        };
        let app = self.clone();
        std::thread::spawn(move || {
            if let Err(e) = app.do_update(&zip_url, &sums_url, &zip_name, &ver) {
                app.logf(format!("обновление: {e}"));
                set_upd(|s| {
                    s.busy = false;
                    s.msg.clear();
                    s.err = e;
                });
            }
        });
        Ok(())
    }

    fn do_update(&self, zip_url: &str, sums_url: &str, zip_name: &str, ver: &str) -> Result<(), String> {
        let exe = std::env::current_exe().and_then(fs::canonicalize).map_err(|e| e.to_string())?;
        let dir = self.data_dir.join("update");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let (zp, sp) = (dir.join(zip_name), dir.join("SHA256SUMS"));
        net::download_file(sums_url, &sp, None)?;
        let prog = |d: u64, t: i64| {
            if t > 0 {
                set_upd(|s| s.msg = format!("Загрузка… {}%", d * 100 / t as u64));
            }
        };
        net::download_file(zip_url, &zp, Some(&prog))?;
        let want = sum_for(&sp, zip_name);
        let got = file_sha256(&zp).map_err(|e| e.to_string())?;
        if want.is_empty() || want != got {
            return Err("контрольная сумма не совпала — файл повреждён".into());
        }
        let ex = dir.join("x");
        unzip_safe(&zp, &ex)?;
        let new_exe = ex.join("Gust.exe");
        if !exists(&new_exe) {
            return Err("в архиве нет Gust.exe".into());
        }
        let old = exe.with_extension("exe.old");
        let _ = fs::remove_file(&old);
        fs::rename(&exe, &old).map_err(|e| format!("не удалось заменить файл: {e}"))?;
        if let Err(e) = copy_file(&new_exe, &exe) {
            let _ = fs::rename(&old, &exe);
            return Err(format!("не удалось заменить файл: {e}"));
        }
        let _ = fs::remove_dir_all(&dir);
        self.logf(format!("обновлено до {ver}, перезапуск"));
        set_upd(|s| s.msg = "Перезапуск…".into());
        let mut args = vec!["--after-update".to_string()];
        for x in std::env::args().skip(1) {
            if x != "--background" && x != "-background" && x != "--after-update" {
                args.push(x);
            }
        }
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        platform::start_detached(&exe.to_string_lossy(), &refs);
        self.request_quit();
        Ok(())
    }
}

pub fn wait_port_free(addr: &str, d: Duration) {
    let end = std::time::Instant::now() + d;
    while std::time::Instant::now() < end {
        let Ok(sa) = addr.parse() else { return };
        match std::net::TcpStream::connect_timeout(&sa, Duration::from_millis(300)) {
            Err(_) => return,
            Ok(_) => std::thread::sleep(Duration::from_millis(300)),
        }
    }
}

pub fn cleanup_old_exe() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = fs::remove_file(exe.with_extension("exe.old"));
    }
}
