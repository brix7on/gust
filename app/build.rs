use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    for (src, dst) in [
        ("enginebin/gust-engine.exe", "engine.bin"),
        ("enginebin/gust-window.exe", "window.bin"),
        ("enginebin/WebView2Loader.dll", "loader.bin"),
    ] {
        println!("cargo:rerun-if-changed={src}");
        if fs::copy(src, out.join(dst)).is_err() {
            fs::write(out.join(dst), []).unwrap();
        }
    }
    println!("cargo:rerun-if-env-changed=GUST_VERSION");
    println!("cargo:rerun-if-changed=gust.rc");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("gust.rc", embed_resource::NONE).manifest_required().unwrap();
    }
}
