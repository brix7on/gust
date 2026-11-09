use crate::consts::*;
use crate::engine::EngineState;
use crate::http::{Req, Resp};
use crate::services::{self, ServiceOut};
use crate::settings::Settings;
use crate::state::*;
use crate::tg::TgOut;
use crate::tuner::Target;
use crate::update::{update_state, UpdateState};
use crate::{discord::DiscordOut, platform, App};
use serde::Serialize;
use serde_json::Value;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

const UI_HTML: &str = include_str!("ui.html");

#[derive(Serialize)]
struct ApiResp {
    ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[derive(Serialize)]
struct StateOut {
    version: &'static str,
    os: &'static str,
    admin: bool,
    setup_ready: bool,
    zap_dir: String,
    setup: SetupState,
    engine: EngineState,
    strategies: Vec<String>,
    settings: Settings,
    tune: TuneState,
    checks: CheckState,
    targets: Vec<Target>,
    autostart: bool,
    tg: TgOut,
    discord: DiscordOut,
    log: Vec<String>,
    services: Vec<ServiceOut>,
    engine_available: bool,
    update: UpdateState,
}

fn body_json(r: &Req) -> Result<Value, String> {
    if r.body.is_empty() {
        return Err("EOF".into());
    }
    serde_json::from_slice(&r.body).map_err(|e| e.to_string())
}

fn field<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    v.as_object()?.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, x)| x).filter(|x| !x.is_null())
}

fn opt_bool(v: &Value, k: &str) -> Result<Option<bool>, String> {
    match field(v, k) {
        None => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(format!("json: поле {k} должно быть true/false")),
    }
}

fn opt_str(v: &Value, k: &str) -> Result<Option<String>, String> {
    match field(v, k) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("json: поле {k} должно быть строкой")),
    }
}

impl App {
    pub fn token_ok(&self, t: &str) -> bool {
        let (a, b) = (t.as_bytes(), self.token.as_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    pub fn route(self: &Arc<Self>, req: &Req, s: &mut TcpStream) -> Option<Resp> {
        let host = req.header("host");
        if host != format!("127.0.0.1:{}", self.port) && host != format!("localhost:{}", self.port) {
            return Some(Resp::text(403, "bad host"));
        }
        let path = req.path.as_str();
        match path {
            "/api/events" => return self.handle_events(req, s),
            "/api/show" => return Some(self.handle_show(req)),
            _ => {}
        }
        if path == "/" {
            let html = UI_HTML.replace("{{TOKEN}}", &self.token).replace("{{LANG}}", &self.lang());
            return Some(Resp::html(html));
        }
        if path != "/api/state" && !self.is_post_route(path) {
            return Some(Resp::text(404, "404 page not found"));
        }
        if !self.token_ok(req.header("x-gu-token")) {
            return Some(Resp::text(403, "bad token"));
        }
        if path == "/api/state" {
            return Some(Resp::json(&self.state_out()));
        }
        if req.method != "POST" {
            return Some(Resp::text(405, "POST only"));
        }
        let r = self.post(path, req);
        Some(Resp::json(&match r {
            Ok(()) => ApiResp { ok: true, error: String::new() },
            Err(e) => ApiResp { ok: false, error: e },
        }))
    }

    fn is_post_route(&self, p: &str) -> bool {
        matches!(
            p,
            "/api/start" | "/api/stop" | "/api/update" | "/api/tune" | "/api/tune/cancel" | "/api/check"
                | "/api/setup/install" | "/api/select" | "/api/settings" | "/api/autostart"
                | "/api/discord/check" | "/api/discord/tune" | "/api/discord/next" | "/api/discord/restart"
                | "/api/tg/start" | "/api/tg/stop" | "/api/tg/open" | "/api/openurl" | "/api/quit"
        )
    }

    fn post(self: &Arc<Self>, path: &str, req: &Req) -> Result<(), String> {
        let a = self.clone();
        match path {
            "/api/start" => {
                if self.tuning() {
                    return Err("идёт подбор — дождитесь конца или остановите его".into());
                }
                self.start_selected()
            }
            "/api/stop" => {
                if self.tuning() {
                    self.cancel_tune();
                } else {
                    self.eng_stop();
                }
                Ok(())
            }
            "/api/update" => self.start_update(),
            "/api/tune" => self.start_tune(),
            "/api/tune/cancel" => {
                self.cancel_tune();
                Ok(())
            }
            "/api/check" => {
                let b = self.clone();
                std::thread::spawn(move || a.check_now());
                std::thread::spawn(move || b.check_update());
                Ok(())
            }
            "/api/setup/install" => {
                if self.st.lock().unwrap().setup.busy {
                    return Err("уже скачивается".into());
                }
                std::thread::spawn(move || a.install_zapret());
                Ok(())
            }
            "/api/select" => {
                let v = body_json(req)?;
                let name = opt_str(&v, "name")?.unwrap_or_default();
                if self.tuning() {
                    return Err("идёт подбор".into());
                }
                let Some(s) = self.find_strategy(&name) else { return Err("нет такой стратегии".into()) };
                self.eng_start(&s, true)?;
                self.update_settings(|st| st.selected = s.name.clone());
                Ok(())
            }
            "/api/settings" => self.handle_settings(req),
            "/api/autostart" => {
                let v = body_json(req)?;
                let on = opt_bool(&v, "enabled")?.unwrap_or(false);
                let r = platform::set_autostart(NAME, on);
                self.invalidate_cache("autostart");
                r
            }
            "/api/discord/check" => {
                std::thread::spawn(move || a.check_discord());
                Ok(())
            }
            "/api/discord/tune" => self.start_tune_scope("discord"),
            "/api/discord/next" => self.voice_next().map(|_| ()),
            "/api/discord/restart" => self.restart_discord(),
            "/api/tg/start" => self.tg_start(),
            "/api/tg/stop" => {
                self.tg_stop(true);
                Ok(())
            }
            "/api/tg/open" => self.tg_open(),
            "/api/openurl" => {
                let v = body_json(&Req { body: req.body.iter().take(1 << 12).cloned().collect(), ..clone_req(req) })?;
                let url = opt_str(&v, "url")?.unwrap_or_default();
                if !valid_https(&url) {
                    return Err("только ссылки https".into());
                }
                platform::open_browser(&url);
                Ok(())
            }
            "/api/quit" => {
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(200));
                    a.request_quit();
                });
                Ok(())
            }
            _ => Err("нет такого метода".into()),
        }
    }

    fn handle_settings(self: &Arc<Self>, req: &Req) -> Result<(), String> {
        let v = body_json(req)?;
        let game = opt_bool(&v, "game_filter")?;
        let retune = opt_bool(&v, "auto_retune")?;
        let extra = opt_bool(&v, "extra_strategies")?;
        let boot = opt_bool(&v, "auto_start_bypass")?;
        let direct = opt_bool(&v, "discord_direct")?;
        let lang = opt_str(&v, "lang")?;
        let engine = opt_str(&v, "engine")?;
        let groups: Vec<(String, bool)> = match field(&v, "groups") {
            None => Vec::new(),
            Some(Value::Object(m)) => {
                let mut out = Vec::new();
                for (k, x) in m {
                    match x {
                        Value::Bool(b) => out.push((k.clone(), *b)),
                        _ => return Err("json: groups должен содержать true/false".into()),
                    }
                }
                out
            }
            Some(_) => return Err("json: groups должен быть объектом".into()),
        };
        let old = self.settings();
        self.update_settings(|s| {
            if let Some(b) = game {
                s.game_filter = b;
            }
            if let Some(b) = retune {
                s.auto_retune = b;
            }
            if let Some(b) = extra {
                s.extra_strategies = b;
            }
            if let Some(b) = direct {
                s.discord_direct = b;
            }
            if let Some(b) = boot {
                s.auto_start_bypass = b;
            }
            if let Some(e) = &engine {
                if matches!(e.as_str(), "zapret" | "gust" | "both") {
                    s.engine = e.clone();
                    s.engine_picked = true;
                }
            }
            if let Some(l) = &lang {
                if matches!(l.as_str(), "auto" | "ru" | "en") {
                    s.lang = l.clone();
                }
            }
            for (g, b) in &groups {
                if services::by_id(g).is_some() {
                    s.groups.insert(g.clone(), *b);
                }
            }
        });
        if !groups.is_empty() {
            let a = self.clone();
            std::thread::spawn(move || a.apply_service_hosts());
        }
        if lang.is_some() {
            self.apply_tray_lang();
        }
        if let Some(g) = game {
            if g != old.game_filter && self.eng_alive() {
                return self.start_selected();
            }
        }
        Ok(())
    }

    fn state_out(self: &Arc<Self>) -> StateOut {
        let names: Vec<String> = self.load_strategies().into_iter().map(|s| s.name).collect();
        let (setup, tune, checks, set) = {
            let st = self.st.lock().unwrap();
            (st.setup.clone(), st.tune.clone(), st.checks.clone(), st.set.clone())
        };
        let tuning = tune.running;
        StateOut {
            version: VERSION,
            update: update_state(),
            os: if cfg!(windows) { "windows" } else { std::env::consts::OS },
            admin: platform::is_admin(),
            setup_ready: !names.is_empty(),
            zap_dir: self.zap_dir.to_string_lossy().into_owned(),
            setup,
            engine: self.eng_state(),
            strategies: names,
            settings: set,
            tune,
            checks,
            targets: self.active_targets(),
            autostart: self.cached_bool("autostart", Duration::from_secs(8), tuning, || platform::autostart_enabled(NAME)),
            tg: self.tg_state(tuning),
            discord: self.discord_state(tuning),
            log: self.log_tail(80),
            services: services::list(),
            engine_available: self.engine_exe().is_some(),
        }
    }
}

fn clone_req(r: &Req) -> Req {
    Req { method: r.method.clone(), path: r.path.clone(), query: r.query.clone(), headers: r.headers.clone(), body: Vec::new() }
}

pub fn valid_https(u: &str) -> bool {
    if u.len() > 2048 || !u.starts_with("https://") {
        return false;
    }
    let rest = &u[8..];
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && !u.chars().any(|c| c.is_control() || c == ' ')
}
