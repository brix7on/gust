#![cfg(unix)]

use crate::discord::*;
use crate::engine::*;
use crate::http::{Req, Resp};
use crate::platform::Proc;
use crate::services;
use crate::state::*;
use crate::strategies::*;
use crate::tuner::*;
use crate::update::*;
use crate::util::*;
use crate::zapret::*;
use crate::App;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

static LOCK: Mutex<()> = Mutex::new(());

struct Timing {
    _g: MutexGuard<'static, ()>,
}

impl Drop for Timing {
    fn drop(&mut self) {
        CHECK_TIMEOUT_MS.store(7000, Ordering::Relaxed);
        FAST_MIN_MS.store(3000, Ordering::Relaxed);
        FAST_MAX_MS.store(6000, Ordering::Relaxed);
        SETTLE_MS.store(1000, Ordering::Relaxed);
        STARTUP_WAIT_MS.store(1000, Ordering::Relaxed);
        *TARGETS_OVERRIDE.lock().unwrap() = None;
        INTERNET_PROBE.lock().unwrap().clear();
    }
}

fn timing(srv: &str) -> Timing {
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    CHECK_TIMEOUT_MS.store(700, Ordering::Relaxed);
    SETTLE_MS.store(100, Ordering::Relaxed);
    STARTUP_WAIT_MS.store(300, Ordering::Relaxed);
    FAST_MIN_MS.store(300, Ordering::Relaxed);
    FAST_MAX_MS.store(300, Ordering::Relaxed);
    *INTERNET_PROBE.lock().unwrap() = format!("{srv}/probe-always");
    *TARGETS_OVERRIDE.lock().unwrap() = Some(vec![tg("discord", "a", &format!("{srv}/a")), tg("discord", "b", &format!("{srv}/b"))]);
    Timing { _g: g }
}

fn lock_only() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn tg(g: &str, n: &str, u: &str) -> Target {
    Target { group: g.into(), name: n.into(), url: u.into() }
}

enum Act {
    Ok,
    Hang,
    Delay(u64),
}

fn spawn_server(h: impl Fn(&str) -> Act + Send + Sync + 'static) -> String {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    let h = Arc::new(h);
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut s) = c else { continue };
            let h = h.clone();
            std::thread::spawn(move || {
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    return;
                }
                let path = line.split(' ').nth(1).unwrap_or("/").to_string();
                match h(&path) {
                    Act::Ok => ok(&mut s),
                    Act::Delay(ms) => {
                        std::thread::sleep(Duration::from_millis(ms));
                        ok(&mut s);
                    }
                    Act::Hang => {
                        let t0 = Instant::now();
                        let mut b = [0u8; 1];
                        let _ = s.set_read_timeout(Some(Duration::from_millis(50)));
                        while t0.elapsed() < Duration::from_secs(20) {
                            if matches!(s.read(&mut b), Ok(0)) {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn ok(s: &mut TcpStream) {
    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
}

fn fake_net(state: &Path) -> String {
    let state = state.to_path_buf();
    spawn_server(move |p| {
        if p.starts_with("/probe-always") {
            return Act::Ok;
        }
        if p.starts_with("/never") {
            return Act::Hang;
        }
        if fs::read_to_string(&state).unwrap_or_default().trim() == "good" {
            Act::Ok
        } else {
            Act::Hang
        }
    })
}

fn write_exec(p: &Path, body: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
    fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
}

fn fake_zapret(state: &Path, modes: &[(&str, &str)]) -> tempfile::TempDir {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("zapret");
    fs::create_dir_all(root.join("lists")).unwrap();
    let sp = state.display();
    let script = format!(
        "#!/bin/sh\nfor a in \"$@\"; do\n [ \"$a\" = \"--mode=good\" ] && echo good > \"{sp}\"\n [ \"$a\" = \"--mode=bad\" ] && echo bad > \"{sp}\"\ndone\nexec sleep 60\n"
    );
    write_exec(&root.join("bin").join("winws.exe"), &script);
    fs::write(root.join("service.bat"), "@echo off\r\n").unwrap();
    for (name, mode) in modes {
        let bat = format!("@echo off\r\nset \"BIN=%~dp0bin/\"\r\nstart \"zapret: %~n0\" /min \"%BIN%winws.exe\" --mode={mode} --wf-tcp=80,%GameFilterTCP%\r\n");
        fs::write(root.join(format!("{name}.bat")), bat).unwrap();
    }
    data
}

fn wait_tune(a: &App) {
    let end = Instant::now() + Duration::from_secs(40);
    while Instant::now() < end {
        if !a.st.lock().unwrap().tune.running {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("подбор завис");
}

fn wait_until(c: impl Fn() -> bool) {
    for _ in 0..400 {
        if c() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("условие не выполнилось");
}

fn state_file(v: &str) -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("state");
    fs::write(&p, v).unwrap();
    (d, p)
}

fn log_text(a: &App) -> String {
    a.log_tail(40).join("\n")
}

// ---------- разбор .bat ----------

#[test]
fn tokenize_cmd_style() {
    let got = tokenize(r#"start "zapret: x" /min "C:\my dir\winws.exe" --a=1 --b="C:\p q\r.txt" --c="""#);
    let want = vec!["start", "zapret: x", "/min", r"C:\my dir\winws.exe", "--a=1", r"--b=C:\p q\r.txt", "--c="];
    assert_eq!(got, want);
}

#[test]
fn parse_real_general_bat() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().join("my zapret");
    fs::create_dir_all(&root).unwrap();
    let b = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/general.bat")).unwrap();
    let p = root.join("general.bat");
    fs::write(&p, b.replace('\\', "/")).unwrap();

    let st = parse_bat(&p, &root, false).unwrap();
    let exe = st.exe.to_string_lossy().into_owned();
    assert!(exe.ends_with("winws.exe") && exe.starts_with(root.to_str().unwrap()), "exe: {exe}");
    let mut n = 0;
    for a in &st.args {
        if a == "--new" {
            n += 1;
        }
        assert!(!a.contains('%') && !a.contains('"') && !a.contains('^'), "осталась неразобранная часть: {a}");
    }
    assert_eq!(n, 8);
    assert_eq!(st.args[0], "--wf-tcp=80,443,2053,2083,2087,2096,8443,12");
    assert_eq!(st.args[1], "--wf-udp=443,19294-19344,50000-50100,12");
    assert!(st.args.iter().any(|a| a.starts_with("--hostlist=") && a.contains("list-general.txt") && a.contains("my zapret")));
    let st2 = parse_bat(&p, &root, true).unwrap();
    assert_eq!(st2.args[0], "--wf-tcp=80,443,2053,2083,2087,2096,8443,1024-10807,10810-18764,18766-65535");
    ensure_lists(Some(&root), &st.args);
    assert!(root.join("lists").join("list-general-user.txt").exists());
    let b2 = fs::read_to_string(root.join("lists").join("ipset-exclude-user.txt")).unwrap();
    assert!(b2.contains("203.0.113.113"));
}

// ---------- автоподбор ----------

#[test]
fn auto_tune_picks_working_strategy() {
    let (_sd, state) = state_file("bad");
    let data = fake_zapret(&state, &[("general", "bad"), ("general (ALT)", "bad"), ("general (ALT2)", "good"), ("general (ALT3)", "good")]);
    let srv = fake_net(&state);
    let _t = timing(&srv);
    let a = App::new(data.path().to_path_buf(), 0);
    assert_eq!(a.load_strategies().len(), 4);
    assert_eq!(a.load_strategies()[0].name, "general");
    a.start_tune().unwrap();
    wait_tune(&a);
    assert_eq!(a.settings().selected, "general (ALT2)", "лог:\n{}", log_text(&a));
    assert!(a.eng_alive());
    let res = a.st.lock().unwrap().tune.results.clone();
    assert_eq!(res.len(), 3, "{res:?}");
    assert_eq!(res[0].passed, 0);
    assert_eq!(res[2].passed, 2);
    a.shutdown();
}

#[test]
fn tune_no_bypass_needed() {
    let (_sd, state) = state_file("good");
    let data = fake_zapret(&state, &[("general", "bad")]);
    let srv = fake_net(&state);
    let _t = timing(&srv);
    let a = App::new(data.path().to_path_buf(), 0);
    let _ = a.start_tune();
    wait_tune(&a);
    let msg = a.st.lock().unwrap().tune.msg.clone();
    assert!(msg.contains("и так доступно"), "{msg}");
    assert!(a.eng_alive());
    a.shutdown();
}

#[test]
fn tune_nothing_works() {
    let (_sd, state) = state_file("bad");
    let data = fake_zapret(&state, &[("general", "bad"), ("general (ALT)", "bad")]);
    let srv = fake_net(&state);
    let _t = timing(&srv);
    let a = App::new(data.path().to_path_buf(), 0);
    let _ = a.start_tune();
    wait_tune(&a);
    let msg = a.st.lock().unwrap().tune.msg.clone();
    assert!(msg.contains("ни одна стратегия не помогла"), "{msg}");
    assert!(!a.eng_alive());
    a.shutdown();
}

#[test]
fn watchdog_restarts_crashed_winws() {
    let (_sd, state) = state_file("");
    let data = fake_zapret(&state, &[("general", "good")]);
    let _t = timing("http://127.0.0.1:1");
    let a = App::new(data.path().to_path_buf(), 0);
    a.start_selected().unwrap();
    let first = a.eng_pid().unwrap();
    a.eng_kill_current();
    let end = Instant::now() + Duration::from_secs(8);
    while Instant::now() < end {
        if let Some(p) = a.eng_pid() {
            if p != first {
                a.shutdown();
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("watchdog не перезапустил процесс; лог:\n{}", log_text(&a));
}

#[test]
fn start_fails_when_winws_exits_immediately() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("zapret");
    write_exec(&root.join("bin").join("winws.exe"), "#!/bin/sh\necho 'windivert: error 1275 driver blocked' >&2\nexit 1\n");
    fs::write(root.join("general.bat"), "@echo off\r\nset \"BIN=%~dp0bin/\"\r\nstart \"x\" /min \"%BIN%winws.exe\" --wf-tcp=80\r\n").unwrap();
    let _t = timing("http://127.0.0.1:1");
    let a = App::new(data.path().to_path_buf(), 0);
    let e = a.start_selected().unwrap_err();
    assert!(e.contains("заблокирован"), "{e}");
    assert!(!a.eng_alive());
    a.shutdown();
}

#[test]
fn tune_checks_reject_hopeless_fast() {
    let _g = lock_only();
    let srv = spawn_server(|_| Act::Hang);
    CHECK_TIMEOUT_MS.store(5000, Ordering::Relaxed);
    let ts = vec![tg("d", "a", &format!("{srv}/a")), tg("d", "b", &format!("{srv}/b"))];
    let no = std::sync::atomic::AtomicBool::new(false);
    let t0 = Instant::now();
    let res = tune_checks(&no, &ts, Duration::from_millis(300));
    CHECK_TIMEOUT_MS.store(7000, Ordering::Relaxed);
    assert!(t0.elapsed() < Duration::from_secs(2), "отсев занял {:?}", t0.elapsed());
    assert_eq!(count_ok(&res), 0);
}

#[test]
fn tune_checks_keep_slow_but_working() {
    let _g = lock_only();
    let srv = spawn_server(|p| if p.ends_with("/b") { Act::Delay(600) } else { Act::Ok });
    CHECK_TIMEOUT_MS.store(3000, Ordering::Relaxed);
    let ts = vec![tg("d", "a", &format!("{srv}/a")), tg("d", "b", &format!("{srv}/b"))];
    let no = std::sync::atomic::AtomicBool::new(false);
    let res = tune_checks(&no, &ts, Duration::from_millis(300));
    CHECK_TIMEOUT_MS.store(7000, Ordering::Relaxed);
    assert_eq!(count_ok(&res), 2, "{:?}", res.iter().map(|r| (r.ok, &r.err)).collect::<Vec<_>>());
    assert!(res[0].ok && res[0].ms <= 300);
}

#[test]
fn tune_of_hopeless_strategies_is_fast() {
    let (_sd, state) = state_file("bad");
    let data = fake_zapret(&state, &[("general", "bad"), ("general (ALT)", "bad"), ("general (ALT2)", "bad"), ("general (ALT3)", "bad")]);
    let srv = fake_net(&state);
    let _t = timing(&srv);
    CHECK_TIMEOUT_MS.store(2000, Ordering::Relaxed);
    let a = App::new(data.path().to_path_buf(), 0);
    let t0 = Instant::now();
    let _ = a.start_tune();
    wait_tune(&a);
    assert!(t0.elapsed() < Duration::from_secs(8), "подбор занял {:?}", t0.elapsed());
    a.shutdown();
}

// ---------- API ----------

fn dummy_stream() -> TcpStream {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let c = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    let _ = ln.accept();
    c
}

fn call(a: &Arc<App>, method: &str, path: &str, host: &str, token: &str) -> Resp {
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), host.to_string());
    if !token.is_empty() {
        headers.insert("x-gu-token".to_string(), token.to_string());
    }
    let (p, q) = path.split_once('?').unwrap_or((path, ""));
    let req = Req { method: method.into(), path: p.into(), query: q.into(), headers, body: Vec::new() };
    a.route(&req, &mut dummy_stream()).unwrap()
}

#[test]
fn api_guard() {
    let td = tempfile::tempdir().unwrap();
    let a = App::new(td.path().to_path_buf(), 18765);
    let h = "127.0.0.1:18765";
    assert_eq!(call(&a, "GET", "/api/state", h, "").status, 403);
    assert_eq!(call(&a, "GET", "/api/state", "evil.com:18765", &a.token).status, 403);
    assert_eq!(call(&a, "GET", "/api/state", h, &a.token).status, 200);
    assert_eq!(call(&a, "GET", "/api/start", h, &a.token).status, 405);
    assert_eq!(call(&a, "GET", "/", h, "").status, 200);
    assert_eq!(call(&a, "GET", "/nope", h, "").status, 404);
    let r = call(&a, "GET", "/", "localhost:18765", "");
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert!(body.contains(&a.token) && !body.contains("{{TOKEN}}"));
    a.shutdown();
}

#[test]
fn state_json_shape() {
    let td = tempfile::tempdir().unwrap();
    let a = App::new(td.path().to_path_buf(), 18765);
    let r = call(&a, "GET", "/api/state", "127.0.0.1:18765", &a.token);
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    for k in [
        "version", "os", "admin", "setup_ready", "zap_dir", "setup", "engine", "strategies", "settings", "tune", "checks", "targets",
        "autostart", "tg", "discord", "log", "services", "engine_available", "update",
    ] {
        assert!(v.get(k).is_some(), "нет поля {k}");
    }
    for k in ["selected", "game_filter", "auto_retune", "extra_strategies", "auto_start_bypass", "groups", "zapret_version", "tg_secret", "discord_direct", "tg_enabled", "last_tune", "lang", "engine", "engine_picked", "added_hosts"] {
        assert!(v["settings"].get(k).is_some(), "нет settings.{k}");
    }
    assert_eq!(v["settings"]["groups"]["discord"], true);
    assert_eq!(v["settings"]["groups"]["roblox"], false);
    a.shutdown();
}

#[test]
fn settings_roundtrip_and_validation() {
    let td = tempfile::tempdir().unwrap();
    let dir = td.path().to_path_buf();
    {
        let a = App::new(dir.clone(), 18765);
        let h = "127.0.0.1:18765";
        let post = |body: &str| {
            let mut headers = HashMap::new();
            headers.insert("host".to_string(), h.to_string());
            headers.insert("x-gu-token".to_string(), a.token.clone());
            let req = Req { method: "POST".into(), path: "/api/settings".into(), query: String::new(), headers, body: body.as_bytes().to_vec() };
            let r = a.route(&req, &mut dummy_stream()).unwrap();
            String::from_utf8_lossy(&r.body).into_owned()
        };
        assert!(post(r#"{"engine":"both","lang":"en","auto_retune":false,"groups":{"roblox":true,"nope":true}}"#).contains(r#""ok":true"#));
        assert!(post(r#"{"engine":"evil","lang":"xx"}"#).contains(r#""ok":true"#));
        assert!(post(r#"{"auto_retune":"yes"}"#).contains(r#""ok":false"#));
        let s = a.settings();
        assert_eq!((s.engine.as_str(), s.lang.as_str(), s.auto_retune, s.engine_picked), ("both", "en", false, true));
        assert_eq!(s.groups.get("roblox"), Some(&true));
        assert!(!s.groups.contains_key("nope"));
        a.shutdown();
    }
    let b = App::new(dir, 18765);
    let s = b.settings();
    assert_eq!((s.engine.as_str(), s.lang.as_str(), s.auto_retune), ("both", "en", false));
    b.shutdown();
}

#[test]
fn go_config_loads() {
    let td = tempfile::tempdir().unwrap();
    fs::write(
        td.path().join("config.json"),
        r#"{"selected":"general (ALT2)","game_filter":true,"auto_retune":true,"extra_strategies":true,"auto_start_bypass":true,"groups":null,"zapret_version":"v1","tg_secret":"","discord_direct":false,"tg_enabled":true,"last_tune":5,"lang":"auto","engine":"zapret","engine_picked":false,"added_hosts":null}"#,
    )
    .unwrap();
    let a = App::new(td.path().to_path_buf(), 0);
    let s = a.settings();
    assert_eq!(s.selected, "general (ALT2)");
    assert!(s.game_filter && s.tg_enabled);
    assert_eq!(s.engine, "gust");
    assert_eq!(s.groups.get("discord"), Some(&true));
    a.shutdown();
}

// ---------- архивы и безопасность ----------

fn write_zip(path: &Path, files: &[(&str, usize)]) {
    let f = fs::File::create(path).unwrap();
    let mut zw = zip::ZipWriter::new(f);
    for (n, size) in files {
        zw.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
        zw.write_all(&vec![0u8; *size]).unwrap();
    }
    zw.finish().unwrap();
}

#[test]
fn unzip_rejects_path_traversal() {
    let d = tempfile::tempdir().unwrap();
    let zp = d.path().join("evil.zip");
    write_zip(&zp, &[("../escape.txt", 1)]);
    assert!(unzip_safe(&zp, &d.path().join("out")).is_err());
    assert!(!d.path().join("escape.txt").exists());
}

#[test]
fn unzip_rejects_too_many_files() {
    let d = tempfile::tempdir().unwrap();
    let zp = d.path().join("many.zip");
    write_zip(&zp, &[("a", 1), ("b", 1), ("c", 1)]);
    let e = unzip_limited(&zp, &d.path().join("out"), &ZipLimits { files: 2, file: 1 << 20, total: 1 << 30 }).unwrap_err();
    assert!(e.contains("много файлов"), "{e}");
}

#[test]
fn unzip_rejects_oversize_file() {
    let d = tempfile::tempdir().unwrap();
    let zp = d.path().join("big.zip");
    write_zip(&zp, &[("big.bin", 5000)]);
    let e = unzip_limited(&zp, &d.path().join("out"), &ZipLimits { files: 100, file: 1000, total: 1 << 30 }).unwrap_err();
    assert!(e.contains("слишком большой"), "{e}");
}

#[test]
fn unzip_rejects_oversize_total() {
    let d = tempfile::tempdir().unwrap();
    let zp = d.path().join("t.zip");
    write_zip(&zp, &[("a", 800), ("b", 800)]);
    let e = unzip_limited(&zp, &d.path().join("out"), &ZipLimits { files: 100, file: 1000, total: 1000 }).unwrap_err();
    assert!(e.contains("слишком большой объём"), "{e}");
}

#[test]
fn unzip_ok() {
    let d = tempfile::tempdir().unwrap();
    let zp = d.path().join("ok.zip");
    write_zip(&zp, &[("dir/a.txt", 10), ("b.txt", 5)]);
    unzip_safe(&zp, &d.path().join("out")).unwrap();
    assert_eq!(fs::metadata(d.path().join("out/dir/a.txt")).unwrap().len(), 10);
}

#[test]
fn exe_allowed_cases() {
    let td = tempfile::tempdir().unwrap();
    let root = td.path();
    assert!(exe_allowed(Some(root), &root.join("bin").join("winws.exe")));
    assert!(exe_allowed(Some(root), &root.join("bin").join("WinWS.EXE")));
    assert!(!exe_allowed(Some(root), &root.join("bin").join("evil.exe")));
    assert!(!exe_allowed(Some(root), Path::new("/bin/sh")));
    assert!(!exe_allowed(Some(root), &root.join("..").join("winws.exe")));
    assert!(!exe_allowed(None, &root.join("winws.exe")));
}

#[test]
fn engine_refuses_foreign_exe() {
    let (_sd, state) = state_file("");
    let data = fake_zapret(&state, &[("general", "good")]);
    let _g = lock_only();
    let a = App::new(data.path().to_path_buf(), 0);
    let e = a.eng_start(&Strategy { name: "evil".into(), exe: "/bin/sh".into(), args: vec!["-c".into(), "echo".into()] }, false).unwrap_err();
    assert!(e.contains("небезопасный"), "{e}");
    assert!(!a.eng_alive());
    a.shutdown();
}

#[test]
fn host_allowed_list() {
    for h in ["github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "github.com:443"] {
        assert!(host_allowed(h), "{h}");
    }
    for h in ["evil.com", "github.com.evil.com", "githubusercontent.com.evil.com", "raw.evil.io"] {
        assert!(!host_allowed(h), "{h}");
    }
}

#[test]
fn download_rejects_foreign_host() {
    let d = tempfile::tempdir().unwrap();
    let e = crate::net::download_file("http://evil.com/x.zip", &d.path().join("x"), None).unwrap_err();
    assert!(e.contains("недоверенный"), "{e}");
}

// ---------- стратегии ----------

fn desync_phase(m: &str) -> Option<i32> {
    Some(match m {
        "synack" | "syndata" => 0,
        "fake" | "fakeknown" | "rst" | "rstack" => 1,
        "multisplit" | "multidisorder" | "fakedsplit" | "hostfakesplit" | "fakeddisorder" => 2,
        _ => return None,
    })
}

fn pos_ok(p: &str) -> bool {
    let num = |s: &str| !s.is_empty() && s.trim_start_matches('-').chars().all(|c| c.is_ascii_digit()) && s.trim_start_matches('-').len() > 0;
    if num(p) {
        return true;
    }
    for k in ["method", "host", "endhost", "sld", "endsld", "midsld", "sniext"] {
        if let Some(rest) = p.strip_prefix(k) {
            return rest.is_empty() || ((rest.starts_with('+') || rest.starts_with('-')) && rest.len() > 1 && rest[1..].chars().all(|c| c.is_ascii_digit()));
        }
    }
    false
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn autottl_ok(v: &str) -> bool {
    let v = v.trim_start_matches(['+', '-']);
    let (a, b) = v.split_once(':').unwrap_or((v, ""));
    digits(a) && (b.is_empty() || b.split('-').all(digits))
}

fn wssize_ok(v: &str) -> bool {
    v.split(':').count() <= 2 && v.split(':').all(digits)
}

fn cutoff_ok(v: &str) -> bool {
    let v = v.strip_prefix(['n', 'd', 's']).unwrap_or(v);
    digits(v)
}

fn opt<'a>(block: &'a [String], name: &str) -> Option<&'a str> {
    block.iter().find_map(|a| a.strip_prefix(&format!("{name}=")))
}

fn split_blocks(args: &[String]) -> Vec<Vec<String>> {
    assert!(args.len() >= 3 && args[0].starts_with("--wf-tcp=") && args[1].starts_with("--wf-udp="), "начало: {args:?}");
    let mut blocks = Vec::new();
    let mut cur = Vec::new();
    for a in &args[2..] {
        if a == "--new" {
            blocks.push(std::mem::take(&mut cur));
        } else {
            cur.push(a.clone());
        }
    }
    blocks.push(cur);
    blocks
}

fn validate_strategy(st: &Strategy) {
    for (bi, b) in split_blocks(&st.args).iter().enumerate() {
        assert!(!b.is_empty(), "{}: пустой блок {bi}", st.name);
        assert!(b[0].starts_with("--filter-"), "{}: блок {bi}: {}", st.name, b[0]);
        let is_tcp = b[0].starts_with("--filter-tcp=");
        for a in b {
            assert!(a.starts_with("--") && !a.contains(['%', '{', '}', '"']), "{}: аргумент {a}", st.name);
            if let Some((_, v)) = a.split_once('=') {
                if (v.ends_with(".bin") || v.ends_with(".txt")) && !v.contains("-user.txt") {
                    assert!(Path::new(v).exists(), "{}: файл {v} не существует", st.name);
                }
            }
        }
        let mut modes: Vec<&str> = Vec::new();
        if let Some(v) = opt(b, "--dpi-desync") {
            modes = v.split(',').collect();
            assert!(modes.len() <= 3, "{}: режимов больше трёх", st.name);
            let mut last = -1;
            for m in &modes {
                let p = desync_phase(m).unwrap_or_else(|| panic!("{}: режим {m}", st.name));
                assert!(p > last, "{}: порядок фаз {v}", st.name);
                last = p;
            }
        }
        if let Some(v) = opt(b, "--dpi-desync-split-pos") {
            let ps: Vec<&str> = v.split(',').collect();
            for p in &ps {
                assert!(pos_ok(p), "{}: позиция {p}", st.name);
            }
            for m in &modes {
                if (*m == "fakedsplit" || *m == "fakeddisorder") && ps.len() != 1 {
                    panic!("{}: для {m} одна позиция", st.name);
                }
            }
        }
        let mut has_fool = false;
        if let Some(v) = opt(b, "--dpi-desync-fooling") {
            for f in v.split(',') {
                assert!(["none", "md5sig", "badseq", "badsum", "datanoack", "ts"].contains(&f), "{}: fooling {f}", st.name);
                if f != "none" {
                    has_fool = true;
                }
            }
        }
        if let Some(v) = opt(b, "--dpi-desync-autottl") {
            assert!(autottl_ok(v), "{}: autottl {v}", st.name);
            has_fool = true;
        }
        if let Some(v) = opt(b, "--dpi-desync-ttl") {
            assert!(v.parse::<i32>().is_ok(), "{}: ttl {v}", st.name);
            has_fool = true;
        }
        if let Some(v) = opt(b, "--dpi-desync-repeats") {
            let n: i32 = v.parse().unwrap_or(0);
            assert!((1..=50).contains(&n), "{}: repeats {v}", st.name);
        }
        if let Some(v) = opt(b, "--dpi-desync-fake-tls-mod") {
            for m in v.split(',') {
                let known = ["none", "rnd", "rndsni", "dupsid", "padencap"].contains(&m);
                let sni = m.starts_with("sni=") && m.len() > 4 && m.len() <= 4 + 63;
                assert!(known || sni, "{}: fake-tls-mod {m}", st.name);
            }
        }
        if let Some(v) = opt(b, "--dpi-desync-hostfakesplit-mod") {
            assert!(v.starts_with("host="), "{}: hostfakesplit-mod", st.name);
        }
        if let Some(v) = opt(b, "--wssize") {
            assert!(wssize_ok(v), "{}: wssize {v}", st.name);
        }
        if let Some(v) = opt(b, "--wssize-cutoff") {
            assert!(cutoff_ok(v), "{}: cutoff {v}", st.name);
        }
        if is_tcp {
            for m in &modes {
                if ["fake", "fakedsplit", "hostfakesplit", "fakeddisorder"].contains(m) {
                    assert!(has_fool, "{}: режим {m} без fooling/ttl", st.name);
                }
            }
        }
    }
}

fn mk_root(bins: &[&str], with_general: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().join("zap ret");
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("lists")).unwrap();
    let exe = root.join("bin").join("winws.exe");
    write_exec(&exe, "#!/bin/sh\nexec sleep 60\n");
    for f in bins {
        fs::write(root.join("bin").join(f), [0u8]).unwrap();
    }
    if with_general {
        for l in ["list-general.txt", "list-google.txt", "list-exclude.txt"] {
            fs::write(root.join("lists").join(l), "example.com\n").unwrap();
        }
    }
    (td, root, exe)
}

const ALL_BINS: [&str; 4] = ["quic_initial_www_google_com.bin", "tls_clienthello_www_google_com.bin", "tls_clienthello_4pda_to.bin", "stun.bin"];

#[test]
fn builtin_strategies_valid() {
    let _g = lock_only();
    let (_t, root, exe) = mk_root(&ALL_BINS, true);
    let ss = builtin_strategies(&root, &exe);
    assert!(ss.len() >= 20, "мало стратегий: {}", ss.len());
    let (mut names, mut seen, mut voice) = (std::collections::HashSet::new(), std::collections::HashSet::new(), std::collections::HashSet::new());
    for st in &ss {
        validate_strategy(st);
        assert!(names.insert(st.name.clone()), "повтор имени {}", st.name);
        assert!(seen.insert(st.args.join("\0")), "{}: повторяет другую", st.name);
        assert_eq!(st.exe, exe);
        assert!(st.name.starts_with("GU-"));
        let blocks = split_blocks(&st.args);
        assert_eq!(blocks.len(), 5, "{}", st.name);
        voice.insert(opt(&blocks[1], "--dpi-desync-fake-discord").unwrap_or("").to_string());
    }
    assert_eq!(voice.len(), 3, "{voice:?}");
    ensure_lists(Some(&root), &ss[0].args);
    assert!(root.join("lists").join("list-general-user.txt").exists());
}

#[test]
fn builtin_strategies_without_optional_files() {
    let _g = lock_only();
    let (_t, root, exe) = mk_root(&[], true);
    let ss = builtin_strategies(&root, &exe);
    let want = builtin_tcp().iter().filter(|v| v.needs.is_empty()).count();
    assert_eq!(ss.len(), want);
    for st in &ss {
        validate_strategy(st);
        assert_eq!(split_blocks(&st.args).len(), 4, "{}", st.name);
    }
}

#[test]
fn builtin_strategies_need_general_list() {
    let _g = lock_only();
    let (_t, root, exe) = mk_root(&ALL_BINS, false);
    assert!(builtin_strategies(&root, &exe).is_empty());
    let (_t2, root2, _) = mk_root(&ALL_BINS, true);
    assert!(builtin_strategies(&root2, &root2.join("nope.exe")).is_empty());
}

#[test]
fn extra_strategies_appended_and_runnable() {
    let (_sd, state) = state_file("");
    let data = fake_zapret(&state, &[("general", "good"), ("general (ALT)", "good")]);
    let root = data.path().join("zapret");
    fs::write(root.join("lists").join("list-general.txt"), "example.com\n").unwrap();
    let _t = timing("http://127.0.0.1:1");
    let a = App::new(data.path().to_path_buf(), 0);
    let all = a.load_strategies();
    assert!(all.len() >= 22, "{}", all.len());
    assert_eq!((all[0].name.as_str(), all[1].name.as_str()), ("general", "general (ALT)"));
    assert!(all[2..].iter().all(|s| s.name.starts_with("GU-")));
    a.update_settings(|s| s.extra_strategies = false);
    assert_eq!(a.load_strategies().len(), 2);
    a.update_settings(|s| s.extra_strategies = true);
    let st = a.find_strategy("GU-01 fake+fakedsplit ts").expect("GU-01 не найдена");
    a.eng_start(&st, false).unwrap();
    assert!(a.eng_alive());
    assert!(root.join("lists").join("list-general-user.txt").exists());
    a.shutdown();
}

#[test]
fn skipped_bat_logged_once() {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("zapret");
    write_exec(&root.join("bin").join("winws.exe"), "#!/bin/sh\nexec sleep 60\n");
    fs::write(root.join("general.bat"), "@echo off\r\nstart \"x\" /min \"%~dp0bin/winws.exe\" --wf-tcp=80\r\n").unwrap();
    fs::write(root.join("broken.bat"), "@echo off\r\nstart \"x\" /min \"%~dp0bin/winws.exe\" --wf-tcp=%NOPE%\r\n").unwrap();
    let a = App::new(data.path().to_path_buf(), 0);
    for _ in 0..5 {
        a.load_strategies();
    }
    let n = a.log_tail(100).iter().filter(|l| l.contains("пропускаю broken.bat")).count();
    assert_eq!(n, 1);
    a.shutdown();
}

// ---------- remote ----------

#[test]
fn repo_strategies_json() {
    let b = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../strategies.json")).unwrap();
    let (_, list) = parse_remote(&b).unwrap();
    assert!(!list.is_empty());
}

#[test]
fn parse_remote_rejects() {
    for s in [
        r#"{"tcp":[]}"#,
        r#"{"tcp":[{"name":"a","args":["--hostlist=C:\\x"]}]}"#,
        r#"{"tcp":[{"name":"a","args":["--dpi-desync=fake & calc"]}]}"#,
        r#"{"tcp":[{"name":"a","args":["--dpi-desync-fooling=ts"]}]}"#,
        r#"{"tcp":[{"name":"a","args":["--dpi-desync=fake"]},{"name":"a","args":["--dpi-desync=fake"]}]}"#,
        r#"{"tcp":[{"name":"a","args":["--dpi-desync=fake","--dpi-desync-fake-tls={X}"]}]}"#,
        r#"{"tcp":[{"name":"a","needs":"Z","args":["--dpi-desync=fake"]}]}"#,
    ] {
        assert!(parse_remote(s.as_bytes()).is_err(), "принял: {s}");
    }
}

#[test]
fn gu_key_strips_number() {
    assert_eq!(gu_key("GU-05 fake ts"), "fake ts");
    assert_eq!(gu_key(&format!("{}GU-12 fake ts", crate::consts::TWIN_PREFIX)), format!("{}fake ts", crate::consts::TWIN_PREFIX));
    assert_eq!(gu_key("general"), "");
}

// ---------- обновление ----------

#[test]
fn newer_version_cases() {
    for (a, b, w) in [("v0.7.3", "0.7.2", true), ("0.7.10", "0.7.9", true), ("v0.7.2", "0.7.2", false), ("0.7", "0.7.1", false), ("1.0.0", "0.9.9", true), ("0.9.0", "0.8.0", true)] {
        assert_eq!(newer_version(a, b), w, "{a} > {b}");
    }
}

#[test]
fn sum_for_reads_checksums() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("SHA256SUMS");
    fs::write(&p, "ABC  Gust-0.7.3-windows-x64.zip\ndef *gust-engine-0.7.3-windows-x64.zip\n").unwrap();
    assert_eq!(sum_for(&p, "Gust-0.7.3-windows-x64.zip"), "abc");
    assert_eq!(sum_for(&p, "gust-engine-0.7.3-windows-x64.zip"), "def");
    assert_eq!(sum_for(&p, "x.zip"), "");
}

// ---------- Discord ----------

#[test]
fn voice_order_prefers_full_passes() {
    let names: Vec<String> = ["general", "ALT", "ALT2", "ALT3", "GU-01"].iter().map(|s| s.to_string()).collect();
    let r = |s: &str, p, t| TuneResult { strategy: s.into(), passed: p, total: t, note: String::new() };
    let res = vec![r("general", 1, 4), r("ALT2", 4, 4), r("gone", 4, 4), r("GU-01", 4, 4)];
    assert_eq!(voice_order(&names, &res), vec!["ALT2", "GU-01", "general", "ALT", "ALT3"]);
}

#[test]
fn tune_scope_discord_ignores_other_services() {
    let (_sd, state) = state_file("bad");
    let data = fake_zapret(&state, &[("general", "bad"), ("general (ALT)", "good")]);
    let srv = fake_net(&state);
    let _t = timing(&srv);
    TARGETS_OVERRIDE.lock().unwrap().as_mut().unwrap().push(tg("youtube", "yt", &format!("{srv}/never")));
    let a = App::new(data.path().to_path_buf(), 0);
    a.start_tune_scope("discord").unwrap();
    wait_tune(&a);
    let (res, scope) = {
        let st = a.st.lock().unwrap();
        (st.tune.results.clone(), st.tune.scope.clone())
    };
    assert_eq!(scope, "discord");
    assert_eq!(a.settings().selected, "general (ALT)");
    let last = res.last().unwrap();
    assert_eq!((last.total, last.passed), (2, 2), "{res:?}");
    a.shutdown();
}

#[test]
fn voice_next_cycles() {
    let (_sd, state) = state_file("");
    let data = fake_zapret(&state, &[("general", "good"), ("general (ALT)", "good"), ("general (ALT2)", "good")]);
    let _t = timing("http://127.0.0.1:1");
    let a = App::new(data.path().to_path_buf(), 0);
    a.update_settings(|s| s.selected = "general".into());
    let mut seen = Vec::new();
    for _ in 0..4 {
        let n = a.voice_next().unwrap();
        assert!(a.eng_alive() && a.settings().selected == n);
        seen.push(n);
    }
    assert_eq!(seen.join("|"), "general (ALT)|general (ALT2)|general|general (ALT)");
    a.shutdown();
}

#[test]
fn plan_discord_variants() {
    let files: Vec<&str> = vec!["/L/Discord/Update.exe", "/R/Microsoft/Windows/Start Menu/Programs/Discord Inc/Discord.lnk", "/L/DiscordPTB/Update.exe"];
    let has = |p: &str| files.contains(&p);
    let p = |pid, name: &str, exe: &str| Proc { pid, name: name.into(), exe: exe.into() };

    let (l, ok) = plan_discord(&[p(1, "Discord.exe", "/L/Discord/app-1.0.9200/Discord.exe")], "/R", "/L", &has);
    assert!(ok && l.updater == "/L/Discord/Update.exe" && l.exe_name == "Discord.exe" && !l.lnk.is_empty(), "{l:?}");
    let (l, ok) = plan_discord(&[p(2, "DiscordPTB.exe", "")], "/R", "/L", &has);
    assert!(ok && l.updater == "/L/DiscordPTB/Update.exe" && l.lnk.is_empty() && l.exe_name == "DiscordPTB.exe", "PTB: {l:?}");
    let (l, ok) = plan_discord(&[], "/R", "/L", &has);
    assert!(ok && l.exe_name == "Discord.exe" && !l.lnk.is_empty(), "{l:?}");
    assert!(!plan_discord(&[], "", "", &|_| false).1);
}

#[test]
fn direct_script_text() {
    let mut env = HashMap::new();
    env.insert("LOCALAPPDATA".to_string(), r"C:\Users\Пользователь\AppData\Local".to_string());
    env.insert("APPDATA".to_string(), r"C:\Users\Пользователь\AppData\Roaming".to_string());
    let l = Launch { exe_name: "Discord.exe".into(), updater: r"C:\Users\Пользователь\AppData\Local\Discord\Update.exe".into(), ..Default::default() };
    let want = "@echo off\r\nstart \"\" \"%LOCALAPPDATA%\\Discord\\Update.exe\" --processStart \"Discord.exe\" --process-start-args \"--no-proxy-server\"\r\n";
    assert_eq!(direct_script(&l, &env), want);
    let l = Launch { exe_path: r"D:\Программы\Discord.exe".into(), ..Default::default() };
    let s = direct_script(&l, &env);
    assert!(s.contains("chcp 65001") && s.contains(r#""D:\Программы\Discord.exe" --no-proxy-server"#), "{s}");
    assert!(!env_path(r"C:\Users\Пользователь\AppData\LocalX\a.exe", &env).contains('%'));
}

// ---------- сервисы ----------

#[test]
fn sync_service_hosts_adds_and_removes_only_ours() {
    let td = tempfile::tempdir().unwrap();
    let a = App::new(td.path().to_path_buf(), 0);
    let root = a.zap_dir.clone();
    fs::create_dir_all(root.join("lists")).unwrap();
    fs::write(root.join("general.bat"), "bin\\winws.exe --wf-tcp=443").unwrap();
    let p = root.join("lists").join("list-general-user.txt");
    fs::write(&p, "my.site\r\nx.com\r\n").unwrap();

    a.update_settings(|s| {
        s.groups.insert("roblox".into(), true);
    });
    assert!(a.sync_service_hosts().unwrap());
    let got = fs::read_to_string(&p).unwrap();
    assert!(got.contains("my.site") && got.contains("rbxcdn.com") && got.contains("x.com"), "{got:?}");
    assert!(!a.sync_service_hosts().unwrap());
    a.update_settings(|s| {
        s.groups.insert("roblox".into(), false);
        s.groups.insert("x".into(), true);
    });
    let _ = a.sync_service_hosts();
    a.update_settings(|s| {
        s.groups.insert("x".into(), false);
    });
    let _ = a.sync_service_hosts();
    let got = fs::read_to_string(&p).unwrap();
    assert!(!got.contains("roblox.com") && got.contains("my.site") && got.contains("x.com"), "{got:?}");
    a.shutdown();
}

#[test]
fn default_groups() {
    let g = services::fill_groups(HashMap::new());
    for (id, on) in &g {
        assert_eq!(*on, id == "discord" || id == "youtube", "{id}");
    }
    let mut old = HashMap::new();
    old.insert("youtube".to_string(), false);
    let old = services::fill_groups(old);
    assert!(!old["youtube"] && old["discord"]);
}

// ---------- движок Gust ----------

fn fake_tree() -> (tempfile::TempDir, PathBuf) {
    let data = tempfile::tempdir().unwrap();
    let root = data.path().join("zapret");
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("lists")).unwrap();
    for f in ["winws.exe", "WinDivert.dll", "tls_clienthello_www_google_com.bin", "tls_clienthello_4pda_to.bin", "quic_initial_www_google_com.bin", "stun.bin", "ACTIVE_DISCORD_UDP.bin", "ACTIVE_GAME_UDP.bin"] {
        fs::write(root.join("bin").join(f), b"\x16\x03\x01\x00\x02\x01\x00").unwrap();
    }
    for (f, body) in [("list-general.txt", "discord.com\nyoutube.com\n"), ("list-google.txt", "googlevideo.com\n"), ("list-exclude.txt", "ya.ru\n"), ("ipset-all.txt", "162.159.128.0/19\n"), ("ipset-exclude.txt", "10.0.0.0/8\n")] {
        fs::write(root.join("lists").join(f), body).unwrap();
    }
    let b = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/general.bat")).unwrap();
    fs::write(root.join("general.bat"), b.replace('\\', "/")).unwrap();
    fs::write(root.join("service.bat"), "@echo off\r\n").unwrap();
    (data, root)
}

fn all_strategies(root: &Path, game: bool) -> Vec<Strategy> {
    let st = parse_bat(&root.join("general.bat"), root, game).unwrap();
    let mut out = vec![st.clone()];
    out.extend(builtin_strategies(root, &st.exe));
    for s in &out {
        ensure_lists(Some(root), &s.args);
    }
    out
}

#[test]
fn engine_compatible_with_all_strategies() {
    let _g = lock_only();
    let (_d, root) = fake_tree();
    let all = all_strategies(&root, true);
    assert!(all.len() >= 20);
    for s in &all {
        for a in &s.args {
            let k = a.split('=').next().unwrap();
            assert!(ENGINE_FLAGS.contains(&k), "{}: движок не знает {k}", s.name);
        }
        assert!(engine_compatible(&s.args));
    }
    assert!(!engine_compatible(&["--dpi-desync=fake".into(), "--hostlist-auto=x".into()]));
}

#[test]
fn engine_modes() {
    let _g = lock_only();
    let (data, root) = fake_tree();
    let a = App::new(data.path().to_path_buf(), 0);
    let eng = data.path().join("engine").join(crate::consts::ENGINE_NAME);
    *a.engine_override.lock().unwrap() = Some(eng.clone());
    let names = |mode: &str| -> Vec<String> {
        a.update_settings(|s| s.engine = mode.into());
        a.load_strategies().into_iter().map(|s| s.name).collect()
    };
    let (z, g, b) = (names("zapret"), names("gust"), names("both"));
    assert!(z.len() >= 20 && g.len() == z.len() && b.len() == 2 * z.len(), "{} {} {}", z.len(), g.len(), b.len());
    let tp = crate::consts::TWIN_PREFIX;
    assert!(g[0].starts_with(tp) && g[0] == format!("{tp}{}", z[0]) && b[z.len()] == g[0]);
    let tw = a.find_strategy(&g[0]).unwrap();
    assert_eq!(tw.exe, eng);
    assert!(tw.args[0].starts_with("--windivert=") && tw.args[0].ends_with("WinDivert.dll"));
    fs::remove_file(root.join("bin").join("WinDivert.dll")).unwrap();
    let n = names("gust");
    assert!(n.len() == z.len() && !n[0].starts_with(tp));
    a.shutdown();
}

#[test]
fn engine_exe_may_start() {
    let (_sd, _s) = state_file("");
    let (data, _root) = fake_tree();
    let eng = data.path().join("engine").join(crate::consts::ENGINE_NAME);
    write_exec(&eng, "#!/bin/sh\nexec sleep 60\n");
    let _g = lock_only();
    let a = App::new(data.path().to_path_buf(), 0);
    *a.engine_override.lock().unwrap() = Some(eng.clone());
    a.eng_start(&Strategy { name: format!("{}x", crate::consts::TWIN_PREFIX), exe: eng, args: vec!["--wf-tcp=80".into()] }, false).expect("движок не запустился");
    a.eng_stop();
    let evil = data.path().join("evil.exe");
    write_exec(&evil, "#!/bin/sh\nexec sleep 60\n");
    assert!(a.eng_start(&Strategy { name: "evil".into(), exe: evil, args: vec![] }, false).is_err());
    a.shutdown();
}

#[test]
fn engine_extract() {
    let data = tempfile::tempdir().unwrap();
    let _g = lock_only();
    let a = App::new(data.path().to_path_buf(), 0);
    let p = a.engine_exe();
    if crate::ENGINE_BIN.is_empty() {
        assert!(p.is_none());
        return;
    }
    let p = p.unwrap();
    assert_eq!(p, data.path().join("engine").join(crate::consts::ENGINE_NAME));
    assert_eq!(fs::read(&p).unwrap(), crate::ENGINE_BIN);
    fs::write(&p, "old").unwrap();
    let b = App::new(data.path().to_path_buf(), 0);
    assert_eq!(fs::read(b.engine_exe().unwrap()).unwrap(), crate::ENGINE_BIN);
}

// ---------- страницы (SSE) ----------

fn start_server(a: &Arc<App>, ln: TcpListener) {
    let h: crate::http::Handler = {
        let a = a.clone();
        Arc::new(move |req, s| a.route(req, s))
    };
    std::thread::spawn(move || crate::http::serve(ln, h));
}

fn new_page_app() -> (Arc<App>, String, tempfile::TempDir) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = ln.local_addr().unwrap().port();
    let td = tempfile::tempdir().unwrap();
    let a = App::new(td.path().to_path_buf(), port);
    start_server(&a, ln);
    (a, format!("127.0.0.1:{port}"), td)
}

fn raw(addr: &str, method: &str, path: &str, headers: &[(&str, &str)], host: &str, body: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let code: u16 = out.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    let body = out.split_once("\r\n\r\n").map(|x| x.1).unwrap_or("").to_string();
    (code, body)
}

#[test]
fn show_reuses_open_page() {
    let (a, addr, _td) = new_page_app();
    let (running, open) = crate::pages::show_running(&addr);
    assert!(running && open);
    wait_until(|| a.ui.lock().unwrap().browser_only);

    let mut ev = TcpStream::connect(&addr).unwrap();
    write!(ev, "GET /api/events?t={} HTTP/1.1\r\nHost: {addr}\r\n\r\n", a.token).unwrap();
    let mut rd = BufReader::new(ev.try_clone().unwrap());
    let mut l = String::new();
    rd.read_line(&mut l).unwrap();
    assert!(l.contains("200"), "{l}");
    wait_until(|| a.pages.count() == 1);

    let (running, open) = crate::pages::show_running(&addr);
    assert!(running && open);
    ev.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut got = None;
    for _ in 0..50 {
        let mut line = String::new();
        if rd.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(m) = line.strip_prefix("data: ") {
            got = Some(m.trim().to_string());
            break;
        }
    }
    assert_eq!(got.as_deref(), Some("show"));
    drop(rd);
    drop(ev);
    wait_until(|| a.pages.count() == 0);
}

#[test]
fn open_url_only_https() {
    let (a, addr, _td) = new_page_app();
    let post = |body: &str, token: &str| {
        let hdr: Vec<(&str, &str)> = if token.is_empty() { vec![] } else { vec![("X-GU-Token", token)] };
        raw(&addr, "POST", "/api/openurl", &hdr, &addr, body)
    };
    assert_eq!(post(r#"{"url":"https://example.com/"}"#, "").0, 403);
    for bad in [r#"{"url":"http://example.com"}"#, r#"{"url":"file:///C:/Windows/System32/calc.exe"}"#, r#"{"url":"javascript:alert(1)"}"#, r#"{"url":"tg://resolve?domain=x"}"#, r#"{"url":"https://"}"#] {
        let (_, b) = post(bad, &a.token);
        assert!(b.contains("только ссылки https"), "{bad} принята: {b}");
    }
    let (_, b) = post(r#"{"url":"https://example.com/"}"#, &a.token);
    assert!(b.contains(r#""ok":true"#), "{b}");
}

#[test]
fn show_and_events_are_guarded() {
    let (a, addr, _td) = new_page_app();
    assert_eq!(raw(&addr, "POST", "/api/show", &[], &addr, "").0, 403);
    assert_eq!(raw(&addr, "POST", "/api/show", &[("X-GU-Show", "1")], "evil.example", "").0, 403);
    assert_eq!(raw(&addr, "GET", "/api/show", &[("X-GU-Show", "1")], &addr, "").0, 403);
    assert_eq!(raw(&addr, "GET", "/api/events", &[], &addr, "").0, 403);
    assert_eq!(raw(&addr, "GET", "/api/events?t=wrong", &[], &addr, "").0, 403);
    assert_eq!(a.pages.count(), 0);
}

#[test]
fn http_server_limits() {
    let (_a, addr, _td) = new_page_app();
    let (c, _) = raw(&addr, "POST", "/api/start", &[("Content-Length", "99999999")], &addr, "");
    assert!(c == 413 || c == 400 || c == 403, "{c}");
}

// ---------- прокси Telegram ----------

#[test]
fn tg_proxy_process() {
    let Ok(bin) = std::env::var("GUST_ENGINE_CHECK") else { return };
    let _g = lock_only();
    let addr = format!("127.0.0.1:{}", crate::tg::DEFAULT_PORT);
    let Ok(busy) = TcpListener::bind(&addr) else { return };
    let td = tempfile::tempdir().unwrap();
    let a = App::new(td.path().to_path_buf(), 0);
    *a.engine_override.lock().unwrap() = Some(PathBuf::from(bin));
    let e = a.tg_start().unwrap_err();
    assert!(e.contains("занят"), "{e}");
    drop(busy);
    a.tg_start().unwrap();
    a.tg_start().unwrap();
    let st = a.tg_state(false);
    assert!(st.running && st.port == crate::tg::DEFAULT_PORT && st.link.starts_with("tg://proxy?server=127.0.0.1"));
    let mut c = TcpStream::connect(&addr).unwrap();
    let _ = c.write_all(&[0u8; 64]);
    drop(c);
    wait_until_long(|| a.tg_state(false).stats.bad == 1);
    a.tg_stop(true);
    assert!(!a.tg_state(false).running);
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        if TcpListener::bind(&addr).is_ok() {
            break;
        }
        assert!(Instant::now() < end, "порт не освободился");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_until_long(c: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(6);
    while Instant::now() < end {
        if c() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("условие не выполнилось");
}

#[test]
fn tg_helpers() {
    assert!(crate::tg::valid_secret(&"ab".repeat(16)));
    assert!(!crate::tg::valid_secret("zz"));
    assert!(!crate::tg::valid_secret(&"ab".repeat(15)));
    assert_eq!(crate::tg::link(1443, "00"), "tg://proxy?server=127.0.0.1&port=1443&secret=dd00");
}

#[test]
fn util_within_and_abs() {
    assert!(within(Path::new("/a/b"), Path::new("/a/b/c")));
    assert!(within(Path::new("/a/b"), Path::new("/a/b")));
    assert!(!within(Path::new("/a/b"), Path::new("/a/bc")));
    assert!(!within(Path::new("/a/b"), Path::new("/a/b/../c")));
}

#[test]
fn strategies_accepted_by_engine() {
    let Ok(bin) = std::env::var("GUST_ENGINE_CHECK") else { return };
    let _g = lock_only();
    for game in [false, true] {
        let (_d, root) = fake_tree();
        let all = all_strategies(&root, game);
        let tw = engine_twins(&all, Path::new(&bin), &root);
        assert_eq!(tw.len(), all.len());
        for s in &tw {
            let out = std::process::Command::new(&s.exe).args(&s.args).arg("--check").output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success() && text.starts_with("ok:"), "{} (game={game}): {text}", s.name);
        }
    }
}
