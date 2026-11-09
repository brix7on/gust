use super::*;
use std::process::Command;

pub fn hide_window(_: &mut Command) {}
pub fn is_admin() -> bool {
    true
}
pub fn relaunch_as_admin(_: &[String]) -> bool {
    false
}
pub fn kill_winws() {}
pub fn cleanup_divert(_: bool) {}
pub fn secure_dir(_: &std::path::Path) {}
pub fn kill_by_name(_: &str) {}
pub fn proc_running(_: &str) -> bool {
    false
}
pub fn open_browser(_: &str) {}
pub fn open_as_user(_: &str) {}
pub fn open_file_as_user(_: &str) {}
pub fn start_detached(_: &str, _: &[&str]) {}
pub fn autostart_enabled(_: &str) -> bool {
    false
}
pub fn set_autostart(_: &str, _: bool) -> Result<(), String> {
    Err("автозапуск работает только в Windows".into())
}
pub fn find_procs(_: &[&str]) -> Vec<Proc> {
    Vec::new()
}
pub fn kill_pid(_: u32) -> Result<(), String> {
    Err("только в Windows".into())
}
pub fn ui_lang() -> String {
    let v = std::env::var("LANG").unwrap_or_default().to_lowercase();
    if ["ru", "uk", "be", "kk"].iter().any(|p| v.starts_with(p)) {
        "ru".into()
    } else {
        "en".into()
    }
}
pub fn downloads_dir() -> Option<std::path::PathBuf> {
    None
}
pub fn allow_foreground() {}
pub fn start_window(_: &std::path::Path, _: &str, _: &str, _: &str) -> Result<Child, String> {
    Err("окно работает только в Windows".into())
}
pub fn tray_notice(_: &str, _: &str) {}
pub fn run_tray(_: &str, _: std::sync::Arc<dyn Fn() + Send + Sync>, _: std::sync::Arc<dyn Fn() + Send + Sync>) -> Box<dyn FnOnce() + Send> {
    Box::new(|| {})
}
pub fn focus_window(_: u32) {}
