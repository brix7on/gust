use crate::platform::{self, Proc};
use crate::state::*;
use crate::tuner::{run_checks, Target};
use crate::util::{exists, now_unix, sleep_ms};
use crate::App;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

#[derive(Serialize)]
pub struct DiscordOut {
    pub checks: CheckState,
    pub targets: Vec<Target>,
    pub running: bool,
}

pub struct Variant {
    pub exe: &'static str,
    pub dir: &'static str,
    pub lnk: &'static str,
}

pub const VARIANTS: [Variant; 3] = [
    Variant { exe: "Discord.exe", dir: "Discord", lnk: "Discord.lnk" },
    Variant { exe: "DiscordPTB.exe", dir: "DiscordPTB", lnk: "Discord PTB.lnk" },
    Variant { exe: "DiscordCanary.exe", dir: "DiscordCanary", lnk: "Discord Canary.lnk" },
];

pub fn images() -> Vec<&'static str> {
    VARIANTS.iter().map(|v| v.exe).collect()
}

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Launch {
    pub exe_name: String,
    pub exe_path: String,
    pub updater: String,
    pub lnk: String,
}

pub fn voice_order(names: &[String], res: &[TuneResult]) -> Vec<String> {
    let have: HashSet<&String> = names.iter().collect();
    let mut out = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    for r in res {
        if r.total > 0 && r.passed == r.total && have.contains(&r.strategy) && !used.contains(&r.strategy) {
            out.push(r.strategy.clone());
            used.insert(r.strategy.clone());
        }
    }
    for n in names {
        if !used.contains(n) {
            out.push(n.clone());
        }
    }
    out
}

fn path_str(p: PathBuf) -> String {
    p.to_string_lossy().into_owned()
}

fn grandparent(p: &str) -> PathBuf {
    Path::new(p).parent().and_then(|x| x.parent()).map(|x| x.to_path_buf()).unwrap_or_default()
}

pub fn plan_discord(procs: &[Proc], appdata: &str, local: &str, has: &dyn Fn(&str) -> bool) -> (Launch, bool) {
    let mut l = Launch::default();
    for p in procs {
        if l.exe_name.is_empty() {
            l.exe_name = p.name.clone();
        }
        if !p.exe.is_empty() {
            l.exe_name = p.name.clone();
            l.exe_path = p.exe.clone();
            let u = path_str(grandparent(&p.exe).join("Update.exe"));
            if has(&u) {
                l.updater = u;
            }
            break;
        }
    }
    for v in &VARIANTS {
        if !l.exe_name.is_empty() && !v.exe.eq_ignore_ascii_case(&l.exe_name) {
            continue;
        }
        if l.updater.is_empty() && !local.is_empty() {
            let u = path_str(Path::new(local).join(v.dir).join("Update.exe"));
            if has(&u) {
                l.updater = u;
            }
        }
        if !appdata.is_empty() {
            let k = path_str(
                Path::new(appdata).join("Microsoft").join("Windows").join("Start Menu").join("Programs").join("Discord Inc").join(v.lnk),
            );
            if has(&k) {
                l.lnk = k;
            }
        }
        if !l.updater.is_empty() || !l.lnk.is_empty() {
            if l.exe_name.is_empty() {
                l.exe_name = v.exe.to_string();
            }
            break;
        }
    }
    let ok = !l.lnk.is_empty() || !l.updater.is_empty() || !l.exe_path.is_empty();
    (l, ok)
}

pub const NO_PROXY_FLAG: &str = "--no-proxy-server";

pub fn env_path(p: &str, env: &HashMap<String, String>) -> String {
    for k in ["LOCALAPPDATA", "APPDATA", "USERPROFILE"] {
        let v = env.get(k).map(|s| s.as_str()).unwrap_or("");
        if !v.is_empty() && p.len() > v.len() {
            if let Some(h) = p.get(..v.len()) {
                let sep = p.as_bytes()[v.len()];
                if h.eq_ignore_ascii_case(v) && (sep == b'\\' || sep == b'/') {
                    return format!("%{k}%{}", &p[v.len()..]);
                }
            }
        }
    }
    p.to_string()
}

pub fn direct_script(l: &Launch, env: &HashMap<String, String>) -> String {
    let cmd = if !l.updater.is_empty() {
        format!(
            "start \"\" \"{}\" --processStart \"{}\" --process-start-args \"{NO_PROXY_FLAG}\"",
            env_path(&l.updater, env),
            l.exe_name
        )
    } else {
        format!("start \"\" \"{}\" {NO_PROXY_FLAG}", env_path(&l.exe_path, env))
    };
    let mut head = String::from("@echo off\r\n");
    if cmd.chars().any(|c| (c as u32) > 127) {
        head.push_str("chcp 65001 >nul\r\n");
    }
    format!("{head}{cmd}\r\n")
}

impl App {
    pub fn check_discord(&self) {
        {
            let mut st = self.st.lock().unwrap();
            if st.dchecks.running {
                return;
            }
            st.dchecks.running = true;
        }
        let no = AtomicBool::new(false);
        let rs = run_checks(&no, &self.scope_targets("discord"), Duration::from_millis(crate::tuner::CHECK_TIMEOUT_MS.load(std::sync::atomic::Ordering::Relaxed)));
        let alive = crate::tuner::check_url(&crate::tuner::INTERNET_PROBE.lock().unwrap().clone().if_empty("https://ya.ru/"), Duration::from_secs(7)).0;
        self.st.lock().unwrap().dchecks = CheckState { running: false, at: now_unix(), internet: alive, results: rs };
    }

    pub fn voice_next(self: &Arc<Self>) -> Result<String, String> {
        if self.tuning() {
            return Err("идёт подбор — дождитесь конца".into());
        }
        let strats = self.load_strategies();
        if strats.len() < 2 {
            return Err("переключаться не на что: стратегий меньше двух".into());
        }
        let names: Vec<String> = strats.iter().map(|s| s.name.clone()).collect();
        let res = self.st.lock().unwrap().tune.results.clone();
        let order = voice_order(&names, &res);
        let cur = self.settings().selected;
        let mut next = order[0].clone();
        for (i, n) in order.iter().enumerate() {
            if *n == cur {
                next = order[(i + 1) % order.len()].clone();
                break;
            }
        }
        let st = strats.iter().find(|s| s.name == next).unwrap().clone();
        self.eng_start(&st, true)?;
        self.update_settings(|s| s.selected = next.clone());
        self.logf(format!("голос Discord: переключился на «{next}»"));
        Ok(next)
    }

    pub fn restart_discord(self: &Arc<Self>) -> Result<(), String> {
        if !cfg!(windows) {
            return Err("работает только в Windows".into());
        }
        let procs = platform::find_procs(&images());
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let (plan, ok) = plan_discord(&procs, &appdata, &local, &|p| exists(p));
        self.logf(format!(
            "Discord: процессов {}, exe={:?}, Update.exe={:?}, ярлык={:?}",
            procs.len(),
            plan.exe_path,
            plan.updater,
            plan.lnk
        ));
        if !ok {
            return Err("не нашёл Discord: он не запущен, и в стандартных папках его нет. Откройте Discord и нажмите ещё раз".into());
        }
        let mut failed = Vec::new();
        for p in &procs {
            if let Err(e) = platform::kill_pid(p.pid) {
                failed.push(e);
            }
        }
        for _ in 0..25 {
            if platform::find_procs(&images()).is_empty() {
                break;
            }
            sleep_ms(200);
        }
        let left = platform::find_procs(&images());
        if !left.is_empty() {
            self.logf(format!("Discord: не закрылся ({} процессов осталось) {}", left.len(), failed.join("; ")));
            return Err("Discord не закрылся. Закройте его вручную (значок у часов → Quit Discord) и откройте снова".into());
        }
        self.invalidate_cache("discordrun");
        sleep_ms(700);

        if self.settings().discord_direct {
            self.launch_discord_direct(&plan)?;
            self.logf("Discord: закрыт, запускаю мимо прокси VPN (--no-proxy-server)".into());
            return Ok(());
        }
        if !plan.lnk.is_empty() {
            platform::open_file_as_user(&plan.lnk);
            self.logf("Discord: закрыт, запускаю через ярлык".into());
        } else if !plan.updater.is_empty() {
            platform::start_detached(&plan.updater, &["--processStart", &plan.exe_name]);
            self.logf("Discord: закрыт, запускаю через Update.exe".into());
        } else {
            platform::start_detached(&plan.exe_path, &[]);
            self.logf(format!("Discord: закрыт, запускаю {}", plan.exe_path));
        }
        Ok(())
    }

    fn launch_discord_direct(&self, l: &Launch) -> Result<(), String> {
        if l.updater.is_empty() && l.exe_path.is_empty() {
            return Err("не нашёл Update.exe Discord — запустить его мимо прокси не получится".into());
        }
        let mut env = HashMap::new();
        for k in ["LOCALAPPDATA", "APPDATA", "USERPROFILE"] {
            env.insert(k.to_string(), std::env::var(k).unwrap_or_default());
        }
        let p = std::env::temp_dir().join("gust-discord.cmd");
        std::fs::write(&p, direct_script(l, &env)).map_err(|e| e.to_string())?;
        platform::open_file_as_user(&p.to_string_lossy());
        Ok(())
    }

    pub fn discord_state(&self, stale: bool) -> DiscordOut {
        let checks = self.st.lock().unwrap().dchecks.clone();
        let mut out = DiscordOut { checks, targets: self.scope_targets("discord"), running: false };
        if cfg!(windows) {
            out.running = self.cached_bool("discordrun", Duration::from_secs(10), stale, || !platform::find_procs(&images()).is_empty());
        }
        out
    }
}

trait IfEmpty {
    fn if_empty(self, d: &str) -> String;
}
impl IfEmpty for String {
    fn if_empty(self, d: &str) -> String {
        if self.is_empty() {
            d.to_string()
        } else {
            self
        }
    }
}
