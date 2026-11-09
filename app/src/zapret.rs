use crate::consts::*;
use crate::strategies::{builtin_strategies, Strategy};
use crate::util::*;
use crate::{net, platform, App};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf, MAIN_SEPARATOR};
use std::sync::Arc;

pub fn find_root(base: &Path) -> Option<PathBuf> {
    fn walk(dir: &Path, depth: i32) -> Option<PathBuf> {
        let ents: Vec<_> = fs::read_dir(dir).ok()?.flatten().collect();
        let mut ents = ents;
        ents.sort_by_key(|e| e.file_name());
        for e in &ents {
            let name = e.file_name().to_string_lossy().to_lowercase();
            if e.path().is_dir() || !name.ends_with(".bat") {
                continue;
            }
            if let Ok(b) = fs::read(e.path()) {
                let s = String::from_utf8_lossy(&b).into_owned();
                if s.to_lowercase().contains("winws.exe") && s.contains("--") {
                    return Some(dir.to_path_buf());
                }
            }
        }
        if depth > 0 {
            for e in &ents {
                if e.path().is_dir() {
                    if let Some(r) = walk(&e.path(), depth - 1) {
                        return Some(r);
                    }
                }
            }
        }
        None
    }
    walk(base, 2)
}

pub fn exe_allowed(root: Option<&Path>, exe: &Path) -> bool {
    let Some(root) = root else { return false };
    exe.file_name().map(|n| n.to_string_lossy().eq_ignore_ascii_case("winws.exe")).unwrap_or(false) && within(root, exe)
}

pub fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_q, mut has) = (false, false);
    for r in s.chars() {
        match r {
            '"' => {
                in_q = !in_q;
                has = true;
            }
            ' ' | '\t' if !in_q => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            _ => {
                cur.push(r);
                has = true;
            }
        }
    }
    if has {
        out.push(cur);
    }
    out
}

fn find_var(s: &str, from: usize) -> Option<(usize, usize)> {
    let b = s.as_bytes();
    let mut i = from;
    while i < b.len() {
        if b[i] == b'%' {
            let mut j = i + 1;
            while j < b.len() && b[j] != b'%' && !(b[j] as char).is_whitespace() {
                j += 1;
            }
            if j < b.len() && b[j] == b'%' && j > i + 1 {
                return Some((i, j + 1));
            }
        }
        i += 1;
    }
    None
}

fn replace_vars(s: &str, f: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut pos = 0;
    while let Some((a, b)) = find_var(s, pos) {
        out.push_str(&s[pos..a]);
        let m = &s[a..b];
        match f(&m[1..m.len() - 1].to_lowercase()) {
            Some(v) => out.push_str(&v),
            None => out.push_str(m),
        }
        pos = b;
    }
    out.push_str(&s[pos..]);
    out
}

pub fn parse_bat(path: &Path, root: &Path, game_filter: bool) -> Result<Strategy, String> {
    let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let data = fs::read(path).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&data).into_owned();
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text).replace("\r\n", "\n");
    let lines: Vec<&str> = text.split('\n').collect();

    let sep = MAIN_SEPARATOR.to_string();
    let gf = if game_filter {
        format!("1024-10807,10810-{},{}-65535", DEFAULT_PORT - 1, DEFAULT_PORT + 1)
    } else {
        "12".to_string()
    };
    let rs = root.to_string_lossy().into_owned();
    let mut vars: HashMap<String, String> = HashMap::new();
    vars.insert("bin".into(), format!("{}{sep}", root.join("bin").to_string_lossy()));
    vars.insert("lists".into(), format!("{}{sep}", root.join("lists").to_string_lossy()));
    for k in ["gamefiltertcp", "gamefilterudp", "gamefilter"] {
        vars.insert(k.into(), gf.clone());
    }
    let subst = |s: &str, vars: &HashMap<String, String>| -> String {
        let s = s.replace("%~dp0", &format!("{rs}{sep}")).replace("%~n0", &name);
        replace_vars(&s, &|k| vars.get(k).cloned())
    };

    for ln in &lines {
        let t = ln.trim();
        if t.len() < 5 {
            continue;
        }
        match t.get(..4) {
            Some(h) if h.eq_ignore_ascii_case("set ") => {}
            _ => continue,
        }
        let kv = t[4..].trim().trim_matches('"');
        let Some(i) = kv.find('=') else { continue };
        if i == 0 {
            continue;
        }
        let k = kv[..i].trim().to_lowercase();
        if k.starts_with("gamefilter") || k.starts_with('/') {
            continue;
        }
        let val = subst(&kv[i + 1..], &vars);
        vars.insert(k, val);
    }

    let mut logical: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ln in &lines {
        let t = ln.trim_end_matches([' ', '\t', '\r']);
        if let Some(h) = t.strip_suffix('^') {
            cur.push_str(h);
            cur.push(' ');
            continue;
        }
        cur.push_str(t);
        logical.push(std::mem::take(&mut cur));
    }
    let mut cmdline = String::new();
    for l in &logical {
        let low = l.to_lowercase();
        let tl = low.trim();
        if low.contains("winws.exe")
            && l.contains("--")
            && !tl.starts_with("taskkill")
            && !tl.starts_with("echo")
            && !tl.starts_with("rem")
            && !tl.starts_with("::")
        {
            cmdline = l.clone();
            break;
        }
    }
    if cmdline.is_empty() {
        return Err("в файле нет запуска winws".into());
    }
    let cmdline = subst(&cmdline, &vars);
    if let Some((a, b)) = find_var(&cmdline, 0) {
        return Err(format!("неизвестная переменная {}", &cmdline[a..b]));
    }
    let toks = tokenize(&cmdline);
    for (i, t) in toks.iter().enumerate() {
        if t.to_lowercase().ends_with("winws.exe") {
            let args = toks[i + 1..].to_vec();
            if args.is_empty() {
                break;
            }
            return Ok(Strategy { name, exe: PathBuf::from(t), args });
        }
    }
    Err("не удалось разобрать строку запуска".into())
}

pub fn ensure_lists(root: Option<&Path>, args: &[String]) {
    let Some(root) = root else { return };
    for a in args {
        if !a.starts_with("--hostlist") && !a.starts_with("--ipset") {
            continue;
        }
        let Some(i) = a.find('=') else { continue };
        if a.starts_with("--hostlist-domains") {
            continue;
        }
        let p = &a[i + 1..];
        if !p.to_lowercase().ends_with(".txt") {
            continue;
        }
        let pp = Path::new(p);
        if exists(pp) {
            continue;
        }
        if !within(root, pp) {
            continue;
        }
        if let Some(d) = pp.parent() {
            let _ = fs::create_dir_all(d);
        }
        let base = pp.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let stub = if base.contains("ipset") { "203.0.113.113/32\n" } else { "domain.example.abc\n" };
        let _ = fs::write(pp, stub);
    }
}

pub struct ZipLimits {
    pub files: usize,
    pub file: u64,
    pub total: u64,
}

pub const ZIP_LIMITS: ZipLimits = ZipLimits { files: 10000, file: 64 << 20, total: 512 << 20 };

pub fn unzip_safe(zip_path: &Path, dest: &Path) -> Result<(), String> {
    unzip_limited(zip_path, dest, &ZIP_LIMITS)
}

pub fn unzip_limited(zip_path: &Path, dest: &Path, lim: &ZipLimits) -> Result<(), String> {
    let f = fs::File::open(zip_path).map_err(|e| e.to_string())?;
    let mut zr = zip::ZipArchive::new(f).map_err(|e| e.to_string())?;
    if zr.len() > lim.files {
        return Err("в архиве слишком много файлов".into());
    }
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let dest_abs = abs(dest).map_err(|e| e.to_string())?;
    let mut total = 0u64;
    for i in 0..zr.len() {
        let mut zf = zr.by_index(i).map_err(|e| e.to_string())?;
        let rel = zf.name().replace('\\', "/");
        let target = abs(&dest_abs.join(&rel)).map_err(|e| e.to_string())?;
        if target != dest_abs && !target.starts_with(&dest_abs) {
            return Err(format!("небезопасный путь в архиве: {}", zf.name()));
        }
        if zf.is_dir() || rel.ends_with('/') {
            let _ = fs::create_dir_all(&target);
            continue;
        }
        if let Some(d) = target.parent() {
            fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let mut out = fs::File::create(&target).map_err(|e| e.to_string())?;
        let mut lr = (&mut zf).take(lim.file + 1);
        let n = std::io::copy(&mut lr, &mut out).map_err(|e| e.to_string())?;
        out.flush().ok();
        if n > lim.file {
            return Err(format!("файл в архиве слишком большой: {}", zf.name()));
        }
        total += n;
        if total > lim.total {
            return Err("архив распаковывается в слишком большой объём".into());
        }
    }
    Ok(())
}

impl App {
    pub fn zapret_root(&self) -> Option<PathBuf> {
        find_root(&self.zap_dir)
    }

    pub fn load_strategies(&self) -> Vec<Strategy> {
        let Some(root) = self.zapret_root() else { return Vec::new() };
        let set = self.settings();
        let mut ents: Vec<_> = fs::read_dir(&root).map(|r| r.flatten().collect()).unwrap_or_default();
        ents.sort_by_key(|e| e.file_name());
        let mut out: Vec<Strategy> = Vec::new();
        for e in ents {
            let fname = e.file_name().to_string_lossy().into_owned();
            let n = fname.to_lowercase();
            if e.path().is_dir() || !n.ends_with(".bat") || n == "service.bat" {
                continue;
            }
            match parse_bat(&e.path(), &root, set.game_filter) {
                Ok(st) => out.push(st),
                Err(err) => {
                    if self.skip_logged.lock().unwrap().insert(fname.clone()) {
                        self.logf(format!("пропускаю {fname}: {err}"));
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            let ga = a.name.eq_ignore_ascii_case("general");
            let gb = b.name.eq_ignore_ascii_case("general");
            gb.cmp(&ga).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        if set.extra_strategies {
            let exe = out.first().map(|s| s.exe.clone()).unwrap_or_else(|| root.join("bin").join("winws.exe"));
            out.extend(builtin_strategies(&root, &exe));
        }
        self.with_engine(out, &root, &set.engine)
    }

    pub fn find_strategy(&self, name: &str) -> Option<Strategy> {
        self.load_strategies().into_iter().find(|s| s.name == name)
    }

    fn set_setup(&self, busy: bool, msg: &str, err: &str) {
        let mut st = self.st.lock().unwrap();
        st.setup = crate::state::SetupState { busy, msg: msg.into(), err: err.into() };
    }

    pub fn install_zapret(self: &Arc<Self>) {
        self.set_setup(true, "Ищу последний релиз на GitHub…", "");
        if let Err(e) = self.install_zapret_inner() {
            self.logf(format!("установка сборки: {e}"));
            self.set_setup(false, "", &e);
        }
    }

    fn install_zapret_inner(self: &Arc<Self>) -> Result<(), String> {
        let (tag, url) = net::latest_zapret_asset()?;
        self.logf(format!("скачиваю сборку {tag}"));
        let tmp_dir = self.data_dir.join("dl");
        let _ = fs::remove_dir_all(&tmp_dir);
        fs::create_dir_all(&tmp_dir).map_err(|e| e.to_string())?;
        let r = self.install_from(&tag, &url, &tmp_dir);
        let _ = fs::remove_dir_all(&tmp_dir);
        r?;
        self.update_settings(|s| s.zapret_version = tag.clone());
        self.logf(format!("сборка {tag} установлена"));
        let _ = self.sync_service_hosts();
        self.set_setup(false, &format!("Готово: {tag}"), "");
        let _ = self.start_tune();
        Ok(())
    }

    fn install_from(self: &Arc<Self>, tag: &str, url: &str, tmp_dir: &Path) -> Result<(), String> {
        let zip_path = tmp_dir.join("zapret.zip");
        let last = std::sync::Mutex::new(std::time::Instant::now());
        let prog = |done: u64, total: i64| {
            let mut l = last.lock().unwrap();
            if l.elapsed() > std::time::Duration::from_millis(400) {
                *l = std::time::Instant::now();
                if total > 0 {
                    self.set_setup(true, &format!("Скачиваю {tag}: {}%", done * 100 / total as u64), "");
                } else {
                    self.set_setup(true, &format!("Скачиваю {tag}: {} КБ", done >> 10), "");
                }
            }
        };
        net::download_file(url, &zip_path, Some(&prog))?;
        self.set_setup(true, "Распаковываю…", "");
        let ex = tmp_dir.join("x");
        unzip_safe(&zip_path, &ex)?;
        let root = find_root(&ex).ok_or("в архиве нет файлов сборки zapret")?;
        let mut keep: Vec<(String, Vec<u8>)> = Vec::new();
        if let Some(old) = self.zapret_root() {
            if let Ok(rd) = fs::read_dir(old.join("lists")) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if n.ends_with("-user.txt") {
                        if let Ok(b) = fs::read(e.path()) {
                            keep.push((n, b));
                        }
                    }
                }
            }
        }
        self.eng_stop();
        platform::cleanup_divert(true);
        let _ = fs::remove_dir_all(&self.zap_dir);
        fs::rename(&root, &self.zap_dir).map_err(|e| e.to_string())?;
        for (n, b) in keep {
            let _ = fs::write(self.zap_dir.join("lists").join(n), b);
        }
        Ok(())
    }
}
