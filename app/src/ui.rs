use crate::consts::NAME;
use crate::platform;
use crate::App;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const WINDOW_FAIL_WINDOW: Duration = Duration::from_secs(15);

fn webview_data_dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").ok().filter(|s| !s.is_empty()).map(PathBuf::from)
    } else {
        std::env::var("HOME").ok().filter(|s| !s.is_empty()).map(|h| PathBuf::from(h).join(".cache"))
    };
    match base {
        Some(d) => d.join(NAME).join("webview"),
        None => std::env::temp_dir().join(format!("{NAME}-webview")),
    }
}

#[derive(Default)]
pub struct Ui {
    pub child: Option<Arc<platform::Child>>,
    pub browser_only: bool,
}

impl App {
    pub fn ui_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    pub fn open_ui(self: &Arc<Self>) {
        let mut ui = self.ui.lock().unwrap();
        if let Some(c) = &ui.child {
            if c.alive() {
                platform::focus_window(c.pid);
                return;
            }
        }
        if ui.browser_only {
            platform::open_browser(&self.ui_url());
            return;
        }
        if self.quitting() {
            return;
        }
        let log = self.data_dir.join("window.log");
        let started = match self.window_exe() {
            Some(h) => platform::start_window(&h, &self.ui_url(), &webview_data_dir().to_string_lossy(), &log.to_string_lossy()),
            None => Err("в этой сборке нет окна".to_string()),
        };
        let c = match started {
            Ok(c) => Arc::new(c),
            Err(e) => {
                self.logf(format!("окно интерфейса недоступно ({e}) — открываю в браузере"));
                ui.browser_only = true;
                platform::open_browser(&self.ui_url());
                return;
            }
        };
        ui.child = Some(c.clone());
        drop(ui);
        let started = Instant::now();
        let app = self.clone();
        std::thread::spawn(move || {
            let code = c.wait();
            if app.quitting() {
                return;
            }
            if code == 0 || started.elapsed() > WINDOW_FAIL_WINDOW {
                return;
            }
            if code == platform::EXIT_NO_RUNTIME {
                app.logf("на этом ПК нет WebView2 — интерфейс открывается в браузере".into());
                app.ui.lock().unwrap().browser_only = true;
            } else {
                app.logf(format!("окно интерфейса закрылось с ошибкой (код {code}) — открываю в браузере"));
            }
            platform::open_browser(&app.ui_url());
        });
    }

    pub fn ui_window_alive(&self) -> bool {
        self.ui.lock().unwrap().child.as_ref().map(|c| c.alive()).unwrap_or(false)
    }

    pub fn close_ui(&self) {
        let c = self.ui.lock().unwrap().child.clone();
        if let Some(c) = c {
            c.kill();
        }
    }

    pub fn lang(&self) -> String {
        let l = self.settings().lang;
        if l == "ru" || l == "en" {
            l
        } else {
            platform::ui_lang()
        }
    }

    pub fn apply_tray_lang(&self) {
        if self.lang() == "en" {
            platform::set_tray_labels("Open Gust", "Quit");
        } else {
            platform::set_tray_labels("Открыть Gust", "Выход");
        }
    }
}
