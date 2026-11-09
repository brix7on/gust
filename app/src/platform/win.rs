use super::icon::icon_cover;
use super::*;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(b: &[u16]) -> String {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf16_lossy(&b[..n])
}

pub fn hide_window(cmd: &mut Command) {
    cmd.creation_flags(0x0800_0000);
}

fn run_hidden(name: &str, args: &[&str]) -> (String, bool) {
    let mut c = Command::new(name);
    c.args(args).stdin(Stdio::null());
    hide_window(&mut c);
    match c.output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (s, o.status.success())
        }
        Err(e) => (e.to_string(), false),
    }
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn escape_arg(s: &str) -> String {
    if !s.is_empty() && !s.contains([' ', '\t', '"']) {
        return s.to_string();
    }
    let mut out = String::from("\"");
    let mut bs = 0;
    for c in s.chars() {
        match c {
            '\\' => bs += 1,
            '"' => {
                out.push_str(&"\\".repeat(bs * 2 + 1));
                out.push('"');
                bs = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(bs));
                bs = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(bs * 2));
    out.push('"');
    out
}

pub fn relaunch_as_admin(args: &[String]) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let params = args.iter().map(|a| escape_arg(a)).collect::<Vec<_>>().join(" ");
    let (verb, file, par) = (wide("runas"), wide(&exe.to_string_lossy()), wide(&params));
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), par.as_ptr(), null(), 1) };
    (r as isize) > 32
}

pub fn kill_winws() {
    run_hidden("taskkill", &["/F", "/IM", "winws.exe"]);
    run_hidden("taskkill", &["/F", "/IM", "gust-engine.exe"]);
}

pub fn cleanup_divert(remove: bool) {
    for s in ["WinDivert", "WinDivert14"] {
        run_hidden("sc", &["stop", s]);
        if remove {
            run_hidden("sc", &["delete", s]);
        }
    }
}

pub fn secure_dir(dir: &Path) {
    run_hidden("icacls", &[&dir.to_string_lossy(), "/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]);
}

pub fn kill_by_name(image: &str) {
    run_hidden("taskkill", &["/F", "/IM", image]);
}

pub fn proc_running(image: &str) -> bool {
    let (out, ok) = run_hidden("tasklist", &["/FI", &format!("IMAGENAME eq {image}"), "/NH"]);
    ok && out.to_lowercase().contains(&image.to_lowercase())
}

pub fn open_browser(url: &str) {
    let _ = Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn();
}

pub fn open_as_user(url: &str) {
    let _ = Command::new("rundll32").args(["url.dll,FileProtocolHandler", url]).spawn();
}

pub fn open_file_as_user(path: &str) {
    let _ = Command::new("explorer.exe").arg(path).spawn();
}

pub fn start_detached(exe: &str, args: &[&str]) {
    if let Ok(mut c) = Command::new(exe).args(args).spawn() {
        std::thread::spawn(move || {
            let _ = c.wait();
        });
    }
}

pub fn autostart_enabled(task: &str) -> bool {
    run_hidden("schtasks", &["/Query", "/TN", task]).1
}

fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&#34;").replace('\'', "&#39;")
}

pub fn set_autostart(task: &str, on: bool) -> Result<(), String> {
    if !on {
        let (out, ok) = run_hidden("schtasks", &["/Delete", "/TN", task, "/F"]);
        return if ok { Ok(()) } else { Err(out.trim().to_string()) };
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let dir = exe.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let doc = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="A"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="A"><Exec><Command>{}</Command><Arguments>--background</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions>
</Task>"#,
        xml_esc(&exe.to_string_lossy()),
        xml_esc(&dir)
    );
    let mut buf = vec![0xFFu8, 0xFE];
    for c in doc.encode_utf16() {
        buf.extend_from_slice(&c.to_le_bytes());
    }
    let tmp = std::env::temp_dir().join(format!("nb-task-{}.xml", crate::util::rand_hex(6)));
    std::fs::write(&tmp, buf).map_err(|e| e.to_string())?;
    let (out, ok) = run_hidden("schtasks", &["/Create", "/TN", task, "/XML", &tmp.to_string_lossy(), "/F"]);
    let _ = std::fs::remove_file(&tmp);
    if ok {
        Ok(())
    } else {
        Err(out.trim().to_string())
    }
}

pub fn ui_lang() -> String {
    let l = unsafe { GetUserDefaultUILanguage() } & 0x3ff;
    if matches!(l, 0x19 | 0x22 | 0x23 | 0x3f) {
        "ru".into()
    } else {
        "en".into()
    }
}

pub fn downloads_dir() -> Option<PathBuf> {
    unsafe {
        let mut p: *mut u16 = null_mut();
        let hr = SHGetKnownFolderPath(&FOLDERID_Downloads, 0, null_mut(), &mut p);
        if hr != 0 || p.is_null() {
            return None;
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        CoTaskMemFree(p as *const _);
        Some(PathBuf::from(s))
    }
}

fn exe_path(pid: u32) -> String {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return String::new();
        }
        let mut buf = vec![0u16; 1024];
        let mut n = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n);
        CloseHandle(h);
        if ok == 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

pub fn find_procs(images: &[&str]) -> Vec<Proc> {
    let want: Vec<String> = images.iter().map(|s| s.to_lowercase()).collect();
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            let name = from_wide(&e.szExeFile);
            if want.contains(&name.to_lowercase()) {
                out.push(Proc { pid: e.th32ProcessID, exe: exe_path(e.th32ProcessID), name });
            }
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
    }
    out
}

pub fn kill_pid(pid: u32) -> Result<(), String> {
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return Err(format!("PID {pid}: код {}", GetLastError()));
        }
        let ok = TerminateProcess(h, 0);
        CloseHandle(h);
        if ok == 0 {
            return Err(format!("PID {pid}: не завершён"));
        }
    }
    Ok(())
}

pub fn allow_foreground() {
    unsafe {
        AllowSetForegroundWindow(0xFFFF_FFFF);
    }
}

pub fn start_window(helper: &Path, url: &str, data_path: &str, log_path: &str) -> Result<Child, String> {
    let mut cmd = Command::new(helper);
    cmd.args(["--window", url, "--wdata", data_path, "--parent", &std::process::id().to_string()]).stdin(Stdio::null()).stdout(Stdio::null());
    if let Some(d) = helper.parent() {
        cmd.current_dir(d);
    }
    match std::fs::File::create(log_path) {
        Ok(f) => cmd.stderr(f),
        Err(_) => cmd.stderr(Stdio::null()),
    };
    Child::start(cmd).map_err(|e| e.to_string())
}

pub fn focus_window(pid: u32) {
    struct Find {
        pid: u32,
        found: HWND,
    }
    unsafe extern "system" fn cb(hwnd: HWND, lp: LPARAM) -> i32 {
        let f = &mut *(lp as *mut Find);
        let mut p = 0u32;
        GetWindowThreadProcessId(hwnd, &mut p);
        if p != f.pid {
            return 1;
        }
        let mut t = [0u16; 16];
        let n = GetWindowTextW(hwnd, t.as_mut_ptr(), t.len() as i32);
        if n > 0 && from_wide(&t) == "Gust" {
            f.found = hwnd;
            return 0;
        }
        1
    }
    let mut f = Find { pid, found: null_mut() };
    unsafe {
        EnumWindows(Some(cb), &mut f as *mut Find as LPARAM);
        if f.found.is_null() {
            return;
        }
        if IsIconic(f.found) != 0 {
            ShowWindow(f.found, SW_RESTORE);
        } else {
            ShowWindow(f.found, SW_SHOW);
        }
        SetForegroundWindow(f.found);
    }
}

// ---------- трей ----------

const WM_TRAY: u32 = WM_APP + 1;
const RETRY_TIMER: usize = 1;
const MENU_OPEN: usize = 1;
const MENU_QUIT: usize = 2;

type Cb = std::sync::Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
struct Tray {
    hwnd: isize,
    hicon: isize,
    taskbar_msg: u32,
    tip: String,
    added: bool,
    notice: Option<(String, String)>,
    on_open: Option<Cb>,
    on_quit: Option<Cb>,
}

static TRAY: std::sync::Mutex<Tray> = std::sync::Mutex::new(Tray {
    hwnd: 0,
    hicon: 0,
    taskbar_msg: 0,
    tip: String::new(),
    added: false,
    notice: None,
    on_open: None,
    on_quit: None,
});

fn copy_w(dst: &mut [u16], s: &str) {
    for (i, c) in s.encode_utf16().enumerate() {
        if i >= dst.len() - 1 {
            break;
        }
        dst[i] = c;
    }
}

fn base_nid() -> NOTIFYICONDATAW {
    let t = TRAY.lock().unwrap();
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = t.hwnd as HWND;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = t.hicon as HICON;
    copy_w(&mut nid.szTip, &t.tip);
    nid
}

fn balloon(title: &str, text: &str) {
    let mut nid = base_nid();
    nid.uFlags = NIF_INFO;
    copy_w(&mut nid.szInfo, text);
    copy_w(&mut nid.szInfoTitle, title);
    nid.dwInfoFlags = 1;
    unsafe {
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

fn tray_add() -> bool {
    let nid = base_nid();
    if unsafe { Shell_NotifyIconW(NIM_ADD, &nid) } == 0 {
        return false;
    }
    let n = {
        let mut t = TRAY.lock().unwrap();
        t.added = true;
        t.notice.take()
    };
    if let Some((a, b)) = n {
        balloon(&a, &b);
    }
    true
}

pub fn tray_notice(title: &str, text: &str) {
    {
        let mut t = TRAY.lock().unwrap();
        if !t.added {
            t.notice = Some((title.into(), text.into()));
            return;
        }
    }
    balloon(title, text);
}

fn run_cb(f: Option<Cb>) {
    if let Some(f) = f {
        std::thread::spawn(move || f());
    }
}

unsafe extern "system" fn tray_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            match lp as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => run_cb(TRAY.lock().unwrap().on_open.clone()),
                WM_RBUTTONUP => tray_menu(hwnd),
                _ => {}
            }
            return 0;
        }
        WM_TIMER => {
            if tray_add() {
                KillTimer(hwnd, RETRY_TIMER);
            }
            return 0;
        }
        WM_DESTROY => {
            let nid = base_nid();
            Shell_NotifyIconW(NIM_DELETE, &nid);
            PostQuitMessage(0);
            return 0;
        }
        _ => {}
    }
    let tb = TRAY.lock().unwrap().taskbar_msg;
    if tb != 0 && msg == tb {
        tray_add();
        return 0;
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}

unsafe fn tray_menu(hwnd: HWND) {
    let menu = CreatePopupMenu();
    if menu.is_null() {
        return;
    }
    let open = wide(&TRAY_OPEN.lock().unwrap());
    let quit = wide(&TRAY_QUIT.lock().unwrap());
    AppendMenuW(menu, 0, MENU_OPEN, open.as_ptr());
    AppendMenuW(menu, 0, MENU_QUIT, quit.as_ptr());
    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);
    SetForegroundWindow(hwnd);
    let cmd = TrackPopupMenu(menu, 0x0100 | 0x0002 | 0x0020, pt.x, pt.y, 0, hwnd, null());
    PostMessageW(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
    let (o, q) = {
        let t = TRAY.lock().unwrap();
        (t.on_open.clone(), t.on_quit.clone())
    };
    match cmd as usize {
        MENU_OPEN => run_cb(o),
        MENU_QUIT => run_cb(q),
        _ => {}
    }
}

fn make_icon(size: i32) -> isize {
    let size = size.max(16) as usize;
    let stride = size.div_ceil(16) * 2;
    let and = vec![0u8; stride * size];
    let mut xor = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let (bg, fg) = icon_cover(size, x, y);
            let o = ((size - 1 - y) * size + x) * 4;
            xor[o] = (11.0 + (202.0 - 11.0) * fg) as u8;
            xor[o + 1] = (10.0 + (216.0 - 10.0) * fg) as u8;
            xor[o + 2] = (10.0 + (222.0 - 10.0) * fg) as u8;
            xor[o + 3] = (bg * 255.0) as u8;
        }
    }
    unsafe { CreateIcon(null_mut(), size as i32, size as i32, 1, 32, and.as_ptr(), xor.as_ptr()) as isize }
}

fn metric(idx: i32, def: i32) -> i32 {
    let v = unsafe { GetSystemMetrics(idx) };
    if v == 0 {
        def
    } else {
        v
    }
}

pub fn run_tray(tip: &str, on_open: Cb, on_quit: Cb) -> Box<dyn FnOnce() + Send> {
    let (tx, rx) = std::sync::mpsc::channel::<isize>();
    let tip = tip.to_string();
    std::thread::spawn(move || unsafe {
        SetProcessDPIAware();
        let hinst = GetModuleHandleW(null());
        let class = wide("GustTray");
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(tray_proc);
        wc.hInstance = hinst;
        wc.lpszClassName = class.as_ptr();
        RegisterClassExW(&wc);
        let hwnd = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), 0, 0, 0, 0, 0, null_mut(), null_mut(), hinst, null());
        if hwnd.is_null() {
            let _ = tx.send(0);
            return;
        }
        {
            let mut t = TRAY.lock().unwrap();
            t.on_open = Some(on_open);
            t.on_quit = Some(on_quit);
            t.hwnd = hwnd as isize;
            t.tip = tip;
            t.hicon = make_icon(metric(SM_CXSMICON, 16));
            t.taskbar_msg = RegisterWindowMessageW(wide("TaskbarCreated").as_ptr());
        }
        if !tray_add() {
            SetTimer(hwnd, RETRY_TIMER, 5000, None);
        }
        let _ = tx.send(hwnd as isize);
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    });
    let hwnd = rx.recv_timeout(std::time::Duration::from_secs(3)).unwrap_or(0);
    Box::new(move || {
        if hwnd != 0 {
            unsafe {
                PostMessageW(hwnd as HWND, WM_CLOSE, 0, 0);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })
}
