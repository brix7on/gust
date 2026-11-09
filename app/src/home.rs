use crate::consts::NAME;
use crate::platform;
use crate::util::{copy_file, file_sha256};
use std::fs;
use std::path::PathBuf;

fn home_exe() -> Option<PathBuf> {
    platform::downloads_dir().map(|d| d.join(format!("{NAME}.exe")))
}

pub fn move_home() -> bool {
    let Some(dst) = home_exe() else { return false };
    let Ok(mut exe) = std::env::current_exe() else { return false };
    if let Ok(e) = fs::canonicalize(&exe) {
        exe = e;
    }
    let norm = |p: &PathBuf| p.to_string_lossy().replace('/', "\\").trim_start_matches(r"\\?\").to_lowercase();
    if norm(&exe) == norm(&dst) {
        return false;
    }
    let (a, b) = (size(&exe), size(&dst));
    if a < 0 || a != b || !same_file(&exe, &dst) {
        let tmp = dst.with_extension("exe.tmp");
        if copy_file(&exe, &tmp).is_err() {
            let _ = fs::remove_file(&tmp);
            return false;
        }
        if fs::rename(&tmp, &dst).is_err() {
            let _ = fs::remove_file(&tmp);
            return false;
        }
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    platform::start_detached(&dst.to_string_lossy(), &refs);
    true
}

fn size(p: &PathBuf) -> i64 {
    fs::metadata(p).map(|m| m.len() as i64).unwrap_or(-1)
}

fn same_file(a: &PathBuf, b: &PathBuf) -> bool {
    matches!((file_sha256(a), file_sha256(b)), (Ok(x), Ok(y)) if x == y)
}
