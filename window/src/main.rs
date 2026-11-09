#![cfg_attr(windows, windows_subsystem = "windows")]

const EXIT_NO_RUNTIME: i32 = 3;
const EXIT_NO_WINDOW: i32 = 4;

#[allow(dead_code)]
mod icon;

#[cfg(windows)]
fn run(url: &str, data_path: &str, parent: u32) -> i32 {
    use tao::dpi::{LogicalSize, PhysicalPosition};
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::{Icon, WindowBuilder};
    use windows_sys::Win32::System::Threading::{OpenProcess, WaitForSingleObject, INFINITE};
    use wry::{WebContext, WebViewBuilder};

    if !url.starts_with("http://127.0.0.1:") {
        return EXIT_NO_WINDOW;
    }
    if wry::webview_version().map(|v| v.is_empty()).unwrap_or(true) {
        return EXIT_NO_RUNTIME;
    }
    let _ = std::fs::create_dir_all(data_path);
    let el = EventLoop::new();
    let icon = Icon::from_rgba(icon::rgba(32), 32, 32).ok();
    let Ok(window) = WindowBuilder::new()
        .with_title("Gust")
        .with_inner_size(LogicalSize::new(1120.0, 780.0))
        .with_window_icon(icon)
        .build(&el)
    else {
        return EXIT_NO_WINDOW;
    };
    if let Some(m) = window.primary_monitor() {
        let (ms, ws, mp) = (m.size(), window.outer_size(), m.position());
        let x = mp.x + (ms.width as i32 - ws.width as i32).max(0) / 2;
        let y = mp.y + (ms.height as i32 - ws.height as i32).max(0) / 2;
        window.set_outer_position(PhysicalPosition::new(x, y));
    }
    let mut ctx = WebContext::new(Some(std::path::PathBuf::from(data_path)));
    let wv = match WebViewBuilder::new_with_web_context(&mut ctx).with_url(url).build(&window) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("webview: {e}");
            return EXIT_NO_WINDOW;
        }
    };
    if parent != 0 {
        std::thread::spawn(move || unsafe {
            let h = OpenProcess(0x0010_0000, 0, parent);
            if !h.is_null() {
                WaitForSingleObject(h, INFINITE);
            }
            std::process::exit(0);
        });
    }
    el.run(move |ev, _, cf| {
        let _keep = (&wv, &ctx);
        *cf = ControlFlow::Wait;
        if let Event::WindowEvent { event: WindowEvent::CloseRequested, .. } = ev {
            *cf = ControlFlow::Exit;
        }
    })
}

#[cfg(not(windows))]
fn run(_: &str, _: &str, _: u32) -> i32 {
    EXIT_NO_WINDOW
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mut url, mut data, mut parent) = (String::new(), String::new(), 0u32);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.trim_start_matches('-') {
            "window" => url = it.next().cloned().unwrap_or_default(),
            "wdata" => data = it.next().cloned().unwrap_or_default(),
            "parent" => parent = it.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    std::process::exit(run(&url, &data, parent));
}
