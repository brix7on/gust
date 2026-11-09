use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("system random");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn exists(p: impl AsRef<Path>) -> bool {
    fs::metadata(p).is_ok()
}

pub fn file_sha256(p: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|x| format!("{x:02x}")).collect())
}

pub fn copy_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::copy(src, dst).map(|_| ())
}

pub fn within(root: &Path, p: &Path) -> bool {
    let (Ok(r), Ok(p)) = (abs(root), abs(p)) else { return false };
    p == r || p.starts_with(&r)
}

pub fn abs(p: &Path) -> std::io::Result<PathBuf> {
    let p = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir()?.join(p) };
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    Ok(out)
}

pub fn host_allowed(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or("").to_lowercase();
    h == "github.com" || h.ends_with(".github.com") || h.ends_with(".githubusercontent.com")
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn clamp_dur(d: std::time::Duration, lo: std::time::Duration, hi: std::time::Duration) -> std::time::Duration {
    d.max(lo).min(hi)
}

pub fn sleep_ms(ms: u64) {
    std::thread::sleep(std::time::Duration::from_millis(ms));
}
