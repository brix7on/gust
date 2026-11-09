use crate::consts::*;
use crate::util::exists;
use crate::App;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

#[derive(Clone, Debug, PartialEq)]
pub struct Strategy {
    pub name: String,
    pub exe: PathBuf,
    pub args: Vec<String>,
}

#[derive(Clone)]
pub struct TcpVariant {
    pub name: String,
    pub args: Vec<String>,
    pub needs: String,
}

fn v(name: &str, args: &[&str], needs: &str) -> TcpVariant {
    TcpVariant { name: name.into(), args: args.iter().map(|s| s.to_string()).collect(), needs: needs.into() }
}

pub fn builtin_tcp() -> Vec<TcpVariant> {
    vec![
        v("fake+fakedsplit ts", &["--dpi-desync=fake,fakedsplit", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"], ""),
        v("fake+hostfakesplit ya.ru", &["--dpi-desync=fake,hostfakesplit", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru", "--dpi-desync-hostfakesplit-mod=host=ya.ru", "--dpi-desync-fooling=md5sig", "--dpi-desync-autottl=2", "--dpi-desync-repeats=4"], ""),
        v("fake+multidisorder badseq", &["--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=6"], ""),
        v("fake+multidisorder md5sig", &["--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=6"], ""),
        v("multisplit seqovl 652 (google)", &["--dpi-desync=multisplit", "--dpi-desync-split-seqovl=652", "--dpi-desync-split-pos=2", "--dpi-desync-split-seqovl-pattern={G}"], "G"),
        v("multisplit seqovl 568 (4pda)", &["--dpi-desync=multisplit", "--dpi-desync-split-seqovl=568", "--dpi-desync-split-pos=2", "--dpi-desync-split-seqovl-pattern={Y}"], "Y"),
        v("multisplit sni", &["--dpi-desync=multisplit", "--dpi-desync-split-pos=1,sniext+1,midsld"], ""),
        v("fakedsplit md5sig autottl", &["--dpi-desync=fakedsplit", "--dpi-desync-split-pos=midsld", "--dpi-desync-fooling=md5sig", "--dpi-desync-autottl=2"], ""),
        v("fakeddisorder badseq", &["--dpi-desync=fakeddisorder", "--dpi-desync-split-pos=midsld", "--dpi-desync-fooling=badseq"], ""),
        v("fake autottl", &["--dpi-desync=fake", "--dpi-desync-autottl=2", "--dpi-desync-repeats=6"], ""),
        v("fake md5sig", &["--dpi-desync=fake", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=8"], ""),
        v("fake ts", &["--dpi-desync=fake", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"], ""),
        v("fake badseq", &["--dpi-desync=fake", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=8"], ""),
        v("fake файл google md5sig", &["--dpi-desync=fake", "--dpi-desync-fake-tls={G}", "--dpi-desync-fooling=md5sig", "--dpi-desync-autottl=2", "--dpi-desync-repeats=6"], "G"),
        v("fake padencap ts", &["--dpi-desync=fake", "--dpi-desync-fake-tls-mod=rnd,dupsid,padencap", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"], ""),
        v("fake sni google md5sig", &["--dpi-desync=fake", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=6"], ""),
        v("syndata+multisplit", &["--dpi-desync=syndata,multisplit", "--dpi-desync-split-pos=1,midsld"], ""),
        v("syndata+fake ts", &["--dpi-desync=syndata,fake", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"], ""),
        v("hostfakesplit google ts", &["--dpi-desync=hostfakesplit", "--dpi-desync-hostfakesplit-mod=host=www.google.com", "--dpi-desync-fooling=ts"], ""),
        v("fakedsplit sniext badseq", &["--dpi-desync=fakedsplit", "--dpi-desync-split-pos=sniext+1", "--dpi-desync-fooling=badseq"], ""),
        v("multidisorder", &["--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,midsld"], ""),
        v("wssize+multisplit", &["--wssize=1:6", "--wssize-cutoff=d3", "--dpi-desync=multisplit", "--dpi-desync-split-pos=1,midsld"], ""),
        v("wssize+fake md5sig", &["--wssize=1:6", "--wssize-cutoff=d3", "--dpi-desync=fake", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=6"], ""),
        v("fake ttl 6", &["--dpi-desync=fake", "--dpi-desync-ttl=6", "--dpi-desync-repeats=6"], ""),
    ]
}

struct Remote {
    list: Vec<TcpVariant>,
    ver: i64,
}

static REMOTE: RwLock<Remote> = RwLock::new(Remote { list: Vec::new(), ver: 0 });

pub fn current_tcp() -> Vec<TcpVariant> {
    let r = REMOTE.read().unwrap();
    if !r.list.is_empty() {
        return r.list.clone();
    }
    builtin_tcp()
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RemoteFile {
    version: i64,
    tcp: Vec<RemoteItem>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RemoteItem {
    name: String,
    args: Vec<String>,
    needs: String,
}

const ALLOWED_ARG: [&str; 4] = ["--dpi-desync=", "--dpi-desync-", "--wssize=", "--wssize-cutoff="];

pub fn parse_remote(b: &[u8]) -> Result<(i64, Vec<TcpVariant>), String> {
    let f: RemoteFile = serde_json::from_slice(b).map_err(|e| e.to_string())?;
    if f.tcp.is_empty() || f.tcp.len() > 200 {
        return Err("пустой или слишком большой список".into());
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for it in f.tcp {
        if it.name.is_empty() || it.name.chars().count() > 60 || !seen.insert(it.name.clone()) {
            return Err(format!("плохое имя {:?}", it.name));
        }
        if !it.needs.is_empty() && it.needs != "G" && it.needs != "Y" {
            return Err(format!("{}: needs", it.name));
        }
        let mut desync = false;
        for a in &it.args {
            let ok = ALLOWED_ARG.iter().any(|p| a.starts_with(p));
            if !ok || a.chars().any(|c| " \t\"'&|<>^%\r\n".contains(c)) {
                return Err(format!("{}: аргумент {:?}", it.name, a));
            }
            let rest = a.replace("{G}", "").replace("{Y}", "");
            if rest.contains('{') || rest.contains('}') {
                return Err(format!("{}: аргумент {:?}", it.name, a));
            }
            if a.starts_with("--dpi-desync=") {
                desync = true;
            }
        }
        if !desync {
            return Err(format!("{}: нет --dpi-desync", it.name));
        }
        out.push(TcpVariant { name: it.name, args: it.args, needs: it.needs });
    }
    Ok((f.version, out))
}

pub fn set_remote(ver: i64, list: Vec<TcpVariant>) {
    let mut r = REMOTE.write().unwrap();
    r.list = list;
    r.ver = ver;
}

pub fn remote_ver() -> i64 {
    REMOTE.read().unwrap().ver
}

pub fn gu_key(name: &str) -> String {
    let tw = name.starts_with(TWIN_PREFIX);
    let n = name.strip_prefix(TWIN_PREFIX).unwrap_or(name);
    if !n.starts_with("GU-") {
        return String::new();
    }
    let Some(i) = n.find(' ') else { return String::new() };
    if tw {
        format!("{TWIN_PREFIX}{}", &n[i + 1..])
    } else {
        n[i + 1..].to_string()
    }
}

fn pick_bin(root: &Path, glob: &str, prefer: &str) -> String {
    let (pre, suf) = glob.split_once('*').unwrap_or((glob, ""));
    let Ok(rd) = fs::read_dir(root.join("bin")) else { return String::new() };
    let mut ms: Vec<String> = rd
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.len() >= pre.len() + suf.len() && n.starts_with(pre) && n.ends_with(suf))
        .collect();
    ms.sort();
    for m in ms {
        if prefer.is_empty() || m.to_lowercase().contains(prefer) {
            return root.join("bin").join(m).to_string_lossy().into_owned();
        }
    }
    String::new()
}

fn list_file(root: &Path, name: &str) -> String {
    let p = root.join("lists").join(name);
    if exists(&p) {
        p.to_string_lossy().into_owned()
    } else {
        String::new()
    }
}

fn host_args(root: &Path, with_google: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut add = |flag: &str, name: &str, always: bool| {
        let mut p = list_file(root, name);
        if p.is_empty() && always {
            p = root.join("lists").join(name).to_string_lossy().into_owned();
        }
        if !p.is_empty() {
            out.push(format!("{flag}={p}"));
        }
    };
    add("--hostlist", "list-general.txt", false);
    add("--hostlist", "list-general-user.txt", true);
    if with_google {
        add("--hostlist", "list-google.txt", false);
    }
    add("--hostlist-exclude", "list-exclude.txt", false);
    add("--hostlist-exclude", "list-exclude-user.txt", true);
    out
}

fn subst(args: &[String], g: &str, y: &str) -> Vec<String> {
    args.iter().map(|a| a.replace("{G}", g).replace("{Y}", y)).collect()
}

fn s(a: &[&str]) -> Vec<String> {
    a.iter().map(|x| x.to_string()).collect()
}

pub fn builtin_strategies(root: &Path, exe: &Path) -> Vec<Strategy> {
    if list_file(root, "list-general.txt").is_empty() || !exists(exe) {
        return Vec::new();
    }
    let g = pick_bin(root, "tls_clienthello*.bin", "www_google");
    let y = pick_bin(root, "tls_clienthello*.bin", "4pda");
    let mut q = pick_bin(root, "quic_initial*.bin", "www_google");
    if q.is_empty() {
        q = pick_bin(root, "quic_initial*.bin", "");
    }
    let st = pick_bin(root, "stun*.bin", "");

    let mut voice = vec![s(&["--dpi-desync=fake", "--dpi-desync-repeats=6"])];
    if !q.is_empty() {
        voice.push(vec![
            "--dpi-desync=fake".into(),
            "--dpi-desync-repeats=6".into(),
            format!("--dpi-desync-fake-discord={q}"),
            format!("--dpi-desync-fake-stun={q}"),
        ]);
    }
    if !st.is_empty() {
        voice.push(vec![
            "--dpi-desync=fake".into(),
            "--dpi-desync-repeats=8".into(),
            format!("--dpi-desync-fake-discord={st}"),
            format!("--dpi-desync-fake-stun={st}"),
        ]);
    }

    let mut out = Vec::new();
    let mut n = 0usize;
    for var in current_tcp() {
        if (var.needs == "G" && g.is_empty()) || (var.needs == "Y" && y.is_empty()) {
            continue;
        }
        let tcp = subst(&var.args, &g, &y);
        let mut blocks: Vec<Vec<String>> = Vec::new();
        if !q.is_empty() {
            let mut b = s(&["--filter-udp=443"]);
            b.extend(host_args(root, true));
            b.extend(s(&["--dpi-desync=fake", "--dpi-desync-repeats=6"]));
            b.push(format!("--dpi-desync-fake-quic={q}"));
            blocks.push(b);
        }
        let mut b = s(&["--filter-udp=19294-19344,50000-50100", "--filter-l7=discord,stun"]);
        b.extend(voice[n % voice.len()].clone());
        blocks.push(b);
        let mut b = s(&["--filter-tcp=2053,2083,2087,2096,8443", "--hostlist-domains=discord.media"]);
        b.extend(tcp.clone());
        blocks.push(b);
        let mut b = s(&["--filter-tcp=443"]);
        b.extend(host_args(root, true));
        b.extend(tcp.clone());
        blocks.push(b);
        let mut b = s(&["--filter-tcp=80"]);
        b.extend(host_args(root, false));
        b.extend(s(&["--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=method+2", "--dpi-desync-fooling=md5sig"]));
        blocks.push(b);

        let mut args = s(&["--wf-tcp=80,443,2053,2083,2087,2096,8443", "--wf-udp=443,19294-19344,50000-50100"]);
        for (i, b) in blocks.into_iter().enumerate() {
            if i > 0 {
                args.push("--new".into());
            }
            args.extend(b);
        }
        n += 1;
        out.push(Strategy { name: format!("GU-{n:02} {}", var.name), exe: exe.to_path_buf(), args });
    }
    out
}

impl App {
    fn remote_path(&self) -> PathBuf {
        self.data_dir.join("strategies.json")
    }

    pub fn load_cached_strategies(&self) {
        let Ok(b) = fs::read(self.remote_path()) else { return };
        if let Ok((ver, list)) = parse_remote(&b) {
            set_remote(ver, list);
        }
    }

    pub fn fetch_strategies(&self) {
        let url = format!("https://raw.githubusercontent.com/{SELF_REPO}/main/strategies.json");
        let tmp = self.remote_path().with_extension("json.tmp");
        if crate::net::download_file(&url, &tmp, None).is_err() {
            let _ = fs::remove_file(&tmp);
            return;
        }
        let Ok(b) = fs::read(&tmp) else { return };
        let (ver, list) = match parse_remote(&b) {
            Ok(x) => x,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.logf(format!("список стратегий с GitHub отклонён: {e}"));
                return;
            }
        };
        let old = remote_ver();
        if ver < old || fs::rename(&tmp, self.remote_path()).is_err() {
            let _ = fs::remove_file(&tmp);
            return;
        }
        let n = list.len();
        set_remote(ver, list);
        if ver != old {
            self.logf(format!("список стратегий обновлён (версия {ver}, {n} шт.)"));
        }
    }
}
