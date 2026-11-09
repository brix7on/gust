#[cfg(windows)]
mod icon;
#[cfg(not(windows))]
mod other;
#[cfg(windows)]
mod win;

#[cfg(not(windows))]
pub use other::*;
#[cfg(windows)]
pub use win::*;

use std::process::{Child as StdChild, Command};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const EXIT_NO_RUNTIME: i32 = 3;

pub static TRAY_OPEN: Mutex<String> = Mutex::new(String::new());
pub static TRAY_QUIT: Mutex<String> = Mutex::new(String::new());

pub fn set_tray_labels(open: &str, quit: &str) {
    *TRAY_OPEN.lock().unwrap() = open.into();
    *TRAY_QUIT.lock().unwrap() = quit.into();
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
    pub exe: String,
}

pub struct Child {
    pub pid: u32,
    child: Arc<Mutex<StdChild>>,
    done: Arc<AtomicBool>,
    code: Arc<AtomicI32>,
}

impl Child {
    pub fn start(mut cmd: Command) -> std::io::Result<Child> {
        let c = cmd.spawn()?;
        let pid = c.id();
        let child = Arc::new(Mutex::new(c));
        let done = Arc::new(AtomicBool::new(false));
        let code = Arc::new(AtomicI32::new(0));
        {
            let (child, done, code) = (child.clone(), done.clone(), code.clone());
            std::thread::spawn(move || loop {
                let r = child.lock().unwrap().try_wait();
                match r {
                    Ok(Some(st)) => {
                        code.store(st.code().unwrap_or(-1), Ordering::SeqCst);
                        done.store(true, Ordering::SeqCst);
                        return;
                    }
                    Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                    Err(_) => {
                        code.store(-1, Ordering::SeqCst);
                        done.store(true, Ordering::SeqCst);
                        return;
                    }
                }
            });
        }
        Ok(Child { pid, child, done, code })
    }

    pub fn alive(&self) -> bool {
        !self.done.load(Ordering::SeqCst)
    }

    pub fn wait(&self) -> i32 {
        while !self.done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.code.load(Ordering::SeqCst)
    }

    pub fn kill(&self) {
        if self.alive() {
            let _ = self.child.lock().unwrap().kill();
        }
    }
}
