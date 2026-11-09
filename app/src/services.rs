use crate::settings::Settings;
use crate::tuner::Target;
use crate::util::exists;
use crate::App;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::fs;

pub struct Service {
    pub id: &'static str,
    pub name: &'static str,
    pub default: bool,
    pub hosts: &'static [&'static str],
    pub urls: &'static [&'static str],
}

#[derive(Serialize)]
pub struct ServiceOut {
    pub id: &'static str,
    pub name: &'static str,
}

const fn svc(id: &'static str, name: &'static str, hosts: &'static [&'static str], urls: &'static [&'static str]) -> Service {
    Service { id, name, default: false, hosts, urls }
}

pub static SERVICES: &[Service] = &[
    Service { id: "discord", name: "Discord", default: true, hosts: &[], urls: &[] },
    Service { id: "youtube", name: "YouTube", default: true, hosts: &[], urls: &[] },
    svc("roblox", "Roblox", &["roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"], &["https://www.roblox.com/", "https://apis.roblox.com/"]),
    svc("instagram", "Instagram", &["instagram.com", "cdninstagram.com", "fbcdn.net"], &["https://www.instagram.com/"]),
    svc("facebook", "Facebook", &["facebook.com", "facebook.net", "fb.com", "fbcdn.net"], &["https://www.facebook.com/"]),
    svc("x", "X (Twitter)", &["x.com", "twitter.com", "twimg.com", "t.co"], &["https://x.com/", "https://abs.twimg.com/"]),
    svc("whatsapp", "WhatsApp", &["whatsapp.com", "whatsapp.net"], &["https://web.whatsapp.com/"]),
    svc("signal", "Signal", &["signal.org", "signal.art", "whispersystems.org"], &["https://signal.org/"]),
    svc("viber", "Viber", &["viber.com"], &["https://www.viber.com/"]),
    svc("snapchat", "Snapchat", &["snapchat.com", "sc-cdn.net", "snap.com"], &["https://www.snapchat.com/"]),
    svc("linkedin", "LinkedIn", &["linkedin.com", "licdn.com"], &["https://www.linkedin.com/"]),
    svc("twitch", "Twitch", &["twitch.tv", "ttvnw.net", "jtvnw.net"], &["https://www.twitch.tv/"]),
    svc("soundcloud", "SoundCloud", &["soundcloud.com", "sndcdn.com"], &["https://soundcloud.com/"]),
    svc("patreon", "Patreon", &["patreon.com", "patreonusercontent.com"], &["https://www.patreon.com/"]),
    svc("medium", "Medium", &["medium.com"], &["https://medium.com/"]),
    svc("steamcommunity", "Steam Community", &["steamcommunity.com"], &["https://steamcommunity.com/"]),
    svc("rutracker", "RuTracker", &["rutracker.org", "rutracker.cc"], &["https://rutracker.org/"]),
    svc("nnmclub", "NNM-Club", &["nnmclub.to"], &["https://nnmclub.to/"]),
    svc("torproject", "Tor Project", &["torproject.org"], &["https://www.torproject.org/"]),
    svc("proton", "Proton", &["proton.me", "protonmail.com"], &["https://proton.me/"]),
    svc("telegram", "Telegram (сайт)", &["telegram.org", "t.me"], &["https://web.telegram.org/"]),
];

pub fn list() -> Vec<ServiceOut> {
    SERVICES.iter().map(|s| ServiceOut { id: s.id, name: s.name }).collect()
}

pub fn by_id(id: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.id == id)
}

pub fn targets() -> Vec<Target> {
    let mut out = Vec::new();
    for s in SERVICES {
        for u in s.urls {
            let host = u.split('/').nth(2).unwrap_or("");
            out.push(Target { group: s.id.into(), name: host.trim_start_matches("www.").into(), url: (*u).into() });
        }
    }
    out
}

pub fn fill_groups(mut g: HashMap<String, bool>) -> HashMap<String, bool> {
    for s in SERVICES {
        g.entry(s.id.to_string()).or_insert(s.default);
    }
    g
}

impl App {
    pub fn sync_service_hosts(&self) -> std::io::Result<bool> {
        let Some(root) = self.zapret_root() else { return Ok(false) };
        let set = self.settings();
        let mut want = HashSet::new();
        let mut order: Vec<&str> = Vec::new();
        for s in SERVICES {
            for h in s.hosts {
                if set.groups.get(s.id).copied().unwrap_or(false) && want.insert(*h) {
                    order.push(h);
                }
            }
        }
        let mut ours: HashSet<String> = set.added_hosts.iter().cloned().collect();
        let p = root.join("lists").join("list-general-user.txt");
        let text = fs::read_to_string(&p).unwrap_or_default().replace('\r', "");
        let mut keep: Vec<String> = Vec::new();
        let mut have: HashSet<String> = HashSet::new();
        let mut changed = false;
        for l in text.split('\n') {
            let h = l.trim().to_lowercase();
            if h.is_empty() || have.contains(&h) {
                continue;
            }
            if ours.contains(&h) && !want.contains(h.as_str()) {
                ours.remove(&h);
                changed = true;
                continue;
            }
            have.insert(h);
            keep.push(l.trim().to_string());
        }
        for h in &order {
            if !have.contains(*h) {
                have.insert(h.to_string());
                ours.insert(h.to_string());
                keep.push(h.to_string());
                changed = true;
            }
        }
        let added: Vec<String> = order.iter().filter(|h| ours.contains(**h)).map(|h| h.to_string()).collect();
        if added.join(",") != set.added_hosts.join(",") {
            self.update_settings(|s: &mut Settings| s.added_hosts = added.clone());
        }
        if !changed {
            return Ok(false);
        }
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
        fs::write(&p, keep.join("\r\n") + "\r\n")?;
        let _ = exists(&p);
        Ok(true)
    }

    pub fn apply_service_hosts(self: &Arc<Self>) {
        match self.sync_service_hosts() {
            Err(e) => self.logf(format!("список сервисов: {e}")),
            Ok(true) => {
                self.logf("список обхода обновлён под выбранные сервисы".into());
                if self.eng_alive() && !self.tuning() {
                    let _ = self.start_selected();
                }
            }
            Ok(false) => {}
        }
    }
}
