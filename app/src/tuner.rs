use crate::consts::*;
use crate::state::*;
use crate::strategies::gu_key;
use crate::util::{clamp_dur, now_unix, sleep_ms};
use crate::{services, App};
use serde::Serialize;
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub static CHECK_TIMEOUT_MS: AtomicU64 = AtomicU64::new(7000);
pub static FAST_MIN_MS: AtomicU64 = AtomicU64::new(3000);
pub static FAST_MAX_MS: AtomicU64 = AtomicU64::new(6000);
pub static SETTLE_MS: AtomicU64 = AtomicU64::new(1000);
pub static TARGETS_OVERRIDE: Mutex<Option<Vec<Target>>> = Mutex::new(None);
pub static INTERNET_PROBE: Mutex<String> = Mutex::new(String::new());

fn ms(a: &AtomicU64) -> Duration {
    Duration::from_millis(a.load(Ordering::Relaxed))
}

fn check_timeout() -> Duration {
    ms(&CHECK_TIMEOUT_MS)
}

fn probe_url() -> String {
    let p = INTERNET_PROBE.lock().unwrap();
    if p.is_empty() {
        "https://ya.ru/".into()
    } else {
        p.clone()
    }
}

#[derive(Serialize, Clone)]
pub struct Target {
    pub group: String,
    pub name: String,
    pub url: String,
}

fn t(g: &str, n: &str, u: &str) -> Target {
    Target { group: g.into(), name: n.into(), url: u.into() }
}

pub fn all_targets() -> &'static Vec<Target> {
    static ALL: OnceLock<Vec<Target>> = OnceLock::new();
    ALL.get_or_init(|| {
        let mut v = vec![
            t("discord", "discord.com", "https://discord.com/api/v9/gateway"),
            t("discord", "gateway.discord.gg", "https://gateway.discord.gg/"),
            t("discord", "cdn.discordapp.com", "https://cdn.discordapp.com/"),
            t("discord", "updates.discord.com", "https://updates.discord.com/"),
            t("youtube", "youtube.com", "https://www.youtube.com/"),
            t("youtube", "i.ytimg.com", "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"),
            t("youtube", "googlevideo.com", "https://redirector.googlevideo.com/"),
        ];
        v.extend(services::targets());
        v
    })
}

pub fn extra_targets() -> Vec<Target> {
    vec![t("discord", "media.discordapp.net", "https://media.discordapp.net/")]
}

fn short_err(s: &str) -> String {
    let l = s.to_lowercase();
    if l.contains("timeout") || l.contains("timed out") || l.contains("deadline") || l.contains("10060") {
        "таймаут".into()
    } else if l.contains("reset") || l.contains("forcibly closed") || l.contains("10054") || l.contains("aborted") {
        "сброс соединения".into()
    } else if l.contains("no such host") || l.contains("lookup") || l.contains("resolve") || l.contains("dns") {
        "DNS не ответил".into()
    } else if l.contains("refused") || l.contains("10061") {
        "отказ в соединении".into()
    } else {
        s.chars().take(80).collect()
    }
}

pub fn check_url(url: &str, timeout: Duration) -> (bool, i64, String) {
    let cfg = ureq::config::Config::builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .proxy(None)
        .tls_config(
            ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::PlatformVerifier).build(),
        )
        .build();
    let agent = ureq::Agent::new_with_config(cfg);
    let t0 = Instant::now();
    let mut resp = match agent
        .get(url)
        .header("User-Agent", format!("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gust/{VERSION}"))
        .call()
    {
        Ok(r) => r,
        Err(e) => return (false, 0, short_err(&e.to_string())),
    };
    let mut rd = resp.body_mut().as_reader();
    if let Err(e) = std::io::copy(&mut (&mut rd).take(200 << 10), &mut std::io::sink()) {
        return (false, 0, short_err(&e.to_string()));
    }
    (true, t0.elapsed().as_millis() as i64, String::new())
}

pub fn run_checks(cancel: &AtomicBool, ts: &[Target], timeout: Duration) -> Vec<CheckResult> {
    let mut res: Vec<CheckResult> = ts
        .iter()
        .map(|x| CheckResult { group: x.group.clone(), name: x.name.clone(), ..Default::default() })
        .collect();
    let (tx, rx) = mpsc::channel();
    for (i, x) in ts.iter().enumerate() {
        let tx = tx.clone();
        let x = x.clone();
        std::thread::spawn(move || {
            let (ok, ms, e) = check_url(&x.url, timeout);
            let _ = tx.send((i, ok, ms, e));
        });
    }
    drop(tx);
    let mut got = 0;
    while got < ts.len() {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok((i, ok, ms, e)) => {
                res[i].ok = ok;
                res[i].ms = ms;
                res[i].err = e;
                got += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if cancel.load(Ordering::SeqCst) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    res
}

pub fn count_ok(rs: &[CheckResult]) -> usize {
    rs.iter().filter(|r| r.ok).count()
}

fn internet_alive() -> bool {
    check_url(&probe_url(), check_timeout()).0
}

pub fn tune_checks(cancel: &AtomicBool, ts: &[Target], fast: Duration) -> Vec<CheckResult> {
    let mut res = run_checks(cancel, ts, fast);
    if count_ok(&res) == 0 {
        return res;
    }
    let idx: Vec<usize> = (0..res.len()).filter(|&i| !res[i].ok).collect();
    if idx.is_empty() {
        return res;
    }
    let retry: Vec<Target> = idx.iter().map(|&i| ts[i].clone()).collect();
    for (k, r) in run_checks(cancel, &retry, check_timeout()).into_iter().enumerate() {
        res[idx[k]] = r;
    }
    res
}

impl App {
    pub fn scope_targets(&self, scope: &str) -> Vec<Target> {
        if scope.is_empty() {
            return self.active_targets();
        }
        let src: Vec<Target> = match TARGETS_OVERRIDE.lock().unwrap().clone() {
            Some(o) => o,
            None => all_targets().iter().cloned().chain(extra_targets()).collect(),
        };
        src.into_iter().filter(|x| x.group == scope).collect()
    }

    pub fn active_targets(&self) -> Vec<Target> {
        let src: Vec<Target> = match TARGETS_OVERRIDE.lock().unwrap().clone() {
            Some(o) => o,
            None => all_targets().clone(),
        };
        let g = self.settings().groups;
        src.into_iter().filter(|x| g.get(&x.group).copied().unwrap_or(false)).collect()
    }

    pub fn check_now(&self) {
        {
            let mut st = self.st.lock().unwrap();
            if st.checks.running {
                return;
            }
            st.checks.running = true;
        }
        let ts = self.active_targets();
        let no = AtomicBool::new(false);
        let rs = run_checks(&no, &ts, check_timeout());
        let alive = internet_alive();
        self.st.lock().unwrap().checks = CheckState { running: false, at: now_unix(), internet: alive, results: rs };
    }

    pub fn start_selected(self: &Arc<Self>) -> Result<(), String> {
        let strats = self.load_strategies();
        if strats.is_empty() {
            return Err("сборка zapret не установлена".into());
        }
        let sel = self.settings().selected;
        let mut pick = strats[0].clone();
        let alt = match sel.strip_prefix(TWIN_PREFIX) {
            Some(x) => x.to_string(),
            None => format!("{TWIN_PREFIX}{sel}"),
        };
        let mut found = false;
        for s in &strats {
            if s.name == sel {
                pick = s.clone();
                found = true;
                break;
            }
        }
        for s in &strats {
            if !found && s.name == alt {
                pick = s.clone();
                found = true;
            }
        }
        if !found {
            let k = gu_key(&sel);
            if !k.is_empty() {
                if let Some(s) = strats.iter().find(|s| gu_key(&s.name) == k) {
                    pick = s.clone();
                }
            }
        }
        self.eng_start(&pick, true)?;
        self.update_settings(|s| s.selected = pick.name.clone());
        Ok(())
    }

    pub fn tuning(&self) -> bool {
        self.st.lock().unwrap().tune.running
    }

    pub fn degraded(&self) -> bool {
        self.check_now();
        let ch = self.st.lock().unwrap().checks.clone();
        if !ch.internet || ch.results.is_empty() {
            return false;
        }
        (ch.results.len() - count_ok(&ch.results)) * 2 > ch.results.len()
    }

    fn set_tune(&self, f: impl FnOnce(&mut TuneState)) {
        f(&mut self.st.lock().unwrap().tune);
    }

    pub fn start_tune(self: &Arc<Self>) -> Result<(), String> {
        self.start_tune_scope("")
    }

    pub fn start_tune_scope(self: &Arc<Self>, scope: &str) -> Result<(), String> {
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut st = self.st.lock().unwrap();
            if st.tune.running {
                return Err("подбор уже идёт".into());
            }
            st.tune = TuneState { running: true, scope: scope.into(), msg: "Подготовка…".into(), ..Default::default() };
            st.tune_cancel = Some(cancel.clone());
        }
        let app = self.clone();
        let scope = scope.to_string();
        std::thread::spawn(move || app.run_tune(cancel, &scope));
        Ok(())
    }

    pub fn cancel_tune(&self) {
        if let Some(c) = &self.st.lock().unwrap().tune_cancel {
            c.store(true, Ordering::SeqCst);
        }
    }

    fn tune_finish(&self, msg: &str) {
        self.set_tune(|t| {
            t.running = false;
            t.current.clear();
            t.msg = msg.into();
        });
        self.logf(format!("подбор: {msg}"));
    }

    fn run_tune(self: &Arc<Self>, cancel: Arc<AtomicBool>, scope: &str) {
        let strats = self.load_strategies();
        if strats.is_empty() {
            return self.tune_finish("сборка zapret не установлена");
        }
        let targets = self.scope_targets(scope);
        if targets.is_empty() {
            return self.tune_finish("не выбрано ни одного сервиса для проверки");
        }
        self.eng_stop();
        sleep_ms(500);
        self.set_tune(|t| {
            t.total = strats.len();
            t.msg = "Проверяю, что блокируется без обхода…".into();
        });
        let never = AtomicBool::new(false);
        let (net_ok, lat_ms, _) = check_url(&probe_url(), check_timeout());
        if !net_ok {
            return self.tune_finish("нет интернета (ya.ru не открывается) — подбор невозможен");
        }
        let fast = clamp_dur(Duration::from_millis(lat_ms as u64 * 4), ms(&FAST_MIN_MS), ms(&FAST_MAX_MS));
        self.logf(format!("быстрый отсев: {fast:?} на стратегию"));
        let base = run_checks(&never, &targets, check_timeout());
        let base_ok = count_ok(&base);
        self.logf(format!("без обхода доступно {base_ok} из {}", targets.len()));
        if base_ok == targets.len() {
            self.update_settings(|s| {
                if s.selected.is_empty() {
                    s.selected = strats[0].name.clone();
                }
                s.last_tune = now_unix();
            });
            let _ = self.start_selected();
            return self.tune_finish("всё и так доступно без обхода; включил стратегию по умолчанию на случай голоса/UDP");
        }

        let mut best_idx: Option<usize> = None;
        let mut best_score = base_ok;
        for (i, s) in strats.iter().enumerate() {
            if cancel.load(Ordering::SeqCst) {
                self.eng_stop();
                return self.tune_finish("подбор отменён");
            }
            self.set_tune(|t| {
                t.idx = i + 1;
                t.current = s.name.clone();
                t.msg = format!("Проверяю «{}» ({} из {})…", s.name, i + 1, strats.len());
            });
            let mut res = TuneResult { strategy: s.name.clone(), total: targets.len(), ..Default::default() };
            if let Err(e) = self.eng_start(s, false) {
                res.note = e.clone();
                self.set_tune(|t| t.results.push(res));
                if e.contains("WinDivert") || e.contains("администратора") {
                    self.eng_stop();
                    return self.tune_finish(&format!("не запускается драйвер: {e}"));
                }
                continue;
            }
            sleep_ms(SETTLE_MS.load(Ordering::Relaxed));
            if !self.eng_alive() {
                res.note = "процесс завершился".into();
            } else {
                let rs = tune_checks(&cancel, &targets, fast);
                res.passed = count_ok(&rs);
                let bad: Vec<&str> = rs.iter().filter(|r| !r.ok).map(|r| r.name.as_str()).collect();
                if !bad.is_empty() {
                    res.note = format!("не открылись: {}", bad.join(", "));
                }
            }
            let (passed, total) = (res.passed, res.total);
            self.set_tune(|t| t.results.push(res));
            self.logf(format!("«{}»: {passed} из {total}", s.name));
            if passed > best_score {
                best_score = passed;
                best_idx = Some(i);
            }
            if passed == total {
                break;
            }
        }
        self.eng_stop();
        let Some(bi) = best_idx else {
            return self.tune_finish("ни одна стратегия не помогла. Отключите VPN/другие обходчики, проверьте антивирус и DNS (лучше 1.1.1.1 или 8.8.8.8)");
        };
        let best = strats[bi].clone();
        self.update_settings(|s| {
            s.selected = best.name.clone();
            s.last_tune = now_unix();
        });
        if let Err(e) = self.eng_start(&best, true) {
            return self.tune_finish(&format!("лучшая стратегия не стартовала: {e}"));
        }
        self.st.lock().unwrap().fail_streak = 0;
        self.tune_finish(&format!("выбрана «{}»: открывается {best_score} из {}", best.name, targets.len()));
    }

    pub fn health_loop(self: &Arc<Self>) {
        loop {
            if self.wait_quit(Duration::from_secs(120)) {
                return;
            }
            if self.tuning() || !self.eng_alive() {
                continue;
            }
            let bad = self.degraded();
            let streak = {
                let mut st = self.st.lock().unwrap();
                if bad {
                    st.fail_streak += 1;
                } else {
                    st.fail_streak = 0;
                }
                st.fail_streak
            };
            if streak >= 3 && self.settings().auto_retune {
                self.logf("обход перестал работать — запускаю подбор заново".into());
                let _ = self.start_tune();
            }
        }
    }
}

