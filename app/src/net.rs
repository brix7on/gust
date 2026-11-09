use crate::consts::NAME;
use crate::util::host_allowed;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;
use ureq::config::Config;
use ureq::tls::{RootCerts, TlsConfig};

pub fn agent(timeout: Duration) -> ureq::Agent {
    let cfg = Config::builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build())
        .build();
    ureq::Agent::new_with_config(cfg)
}

fn host_of(url: &str) -> String {
    url.split("://").nth(1).unwrap_or("").split('/').next().unwrap_or("").to_string()
}

pub fn get_json(url: &str) -> Result<serde_json::Value, String> {
    let a = agent(Duration::from_secs(25));
    let mut r = a
        .get(url)
        .header("User-Agent", NAME)
        .header("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?;
    if r.status().as_u16() != 200 {
        return Err(format!("HTTP {}", r.status().as_u16()));
    }
    r.body_mut().read_json().map_err(|e| e.to_string())
}

pub fn download_file(url: &str, dst: &Path, progress: Option<&dyn Fn(u64, i64)>) -> Result<(), String> {
    if !host_allowed(&host_of(url)) {
        return Err(format!("недоверенный адрес скачивания: {url}"));
    }
    let a = agent(Duration::from_secs(600));
    let mut cur = url.to_string();
    let mut hops = 0;
    let resp = loop {
        let r = a.get(&cur).header("User-Agent", NAME).call().map_err(|e| e.to_string())?;
        let st = r.status().as_u16();
        if (301..=308).contains(&st) && st != 304 {
            hops += 1;
            if hops >= 10 {
                return Err("слишком много редиректов".into());
            }
            let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let next = if loc.starts_with("http") { loc } else { format!("https://{}{}", host_of(&cur), loc) };
            if !host_allowed(&host_of(&next)) {
                return Err(format!("редирект на недоверенный адрес: {}", host_of(&next)));
            }
            cur = next;
            continue;
        }
        if st != 200 {
            return Err(format!("HTTP {st} при скачивании"));
        }
        break r;
    };
    let total = resp.body().content_length().map(|x| x as i64).unwrap_or(-1);
    let mut f = std::fs::File::create(dst).map_err(|e| e.to_string())?;
    let mut body = resp.into_body();
    let mut rd = body.as_reader();
    let mut buf = vec![0u8; 64 << 10];
    let mut done = 0u64;
    loop {
        let n = rd.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(());
        }
        f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        done += n as u64;
        if let Some(p) = progress {
            p(done, total);
        }
    }
}

pub fn latest_zapret_asset() -> Result<(String, String), String> {
    let repo = crate::consts::ZAP_REPO;
    if let Ok(rel) = get_json(&format!("https://api.github.com/repos/{repo}/releases/latest")) {
        let tag = rel["tag_name"].as_str().unwrap_or("").to_string();
        if let Some(assets) = rel["assets"].as_array() {
            for a in assets {
                let name = a["name"].as_str().unwrap_or("").to_lowercase();
                if name.ends_with(".zip") {
                    return Ok((tag, a["browser_download_url"].as_str().unwrap_or("").to_string()));
                }
            }
        }
    }
    let a = agent(Duration::from_secs(25));
    let r = a
        .get(&format!("https://github.com/{repo}/releases/latest"))
        .header("User-Agent", NAME)
        .call()
        .map_err(|e| e.to_string())?;
    let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if let Some(i) = loc.rfind("/tag/") {
        let tag = loc[i + 5..].to_string();
        let url = format!("https://github.com/{repo}/releases/download/{tag}/zapret-discord-youtube-{tag}.zip");
        return Ok((tag, url));
    }
    Err("не нашёл последний релиз (GitHub недоступен?)".into())
}
