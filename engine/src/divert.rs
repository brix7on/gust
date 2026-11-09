// WinDivert: DLL грузится динамически (берётся из сборки zapret).

#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct Addr(pub [u8; 80]);

impl Addr {
    // Пакет собран заново: контрольные суммы IP/TCP/UDP уже посчитаны.
    pub fn mark_checksums(mut self) -> Addr {
        self.0[10] |= 0xe0;
        self
    }

    pub fn outbound(&self) -> bool {
        self.0[10] & 0x02 != 0
    }
}

#[cfg(windows)]
mod imp {
    use super::Addr;
    use std::ffi::c_void;

    type Handle = *mut c_void;
    type OpenFn = unsafe extern "C" fn(*const u8, i32, i16, u64) -> Handle;
    type RecvFn = unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut Addr) -> i32;
    type SendFn = unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const Addr) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(m: *mut c_void, name: *const u8) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    pub struct Divert {
        h: Handle,
        recv: RecvFn,
        send: SendFn,
    }

    fn explain(code: u32) -> String {
        let why = match code {
            2 => "WinDivert64.sys not found next to WinDivert.dll",
            5 => "administrator rights required",
            87 => "invalid filter",
            577 => "driver signature rejected (Secure Boot / Memory Integrity)",
            654 | 1275 => "driver blocked by antivirus or system policy",
            1753 => "Base Filtering Engine service is not running",
            _ => "WinDivertOpen failed",
        };
        format!("{why} (error {code})")
    }

    impl Divert {
        pub fn open(dll: &str, filter: &str) -> Result<Divert, String> {
            unsafe {
                let w: Vec<u16> = dll.encode_utf16().chain([0]).collect();
                let m = LoadLibraryW(w.as_ptr());
                if m.is_null() {
                    return Err(format!("cannot load {dll} (error {})", GetLastError()));
                }
                let sym = |n: &[u8]| {
                    let p = GetProcAddress(m, n.as_ptr());
                    if p.is_null() {
                        Err(format!(
                            "{dll}: missing {}",
                            String::from_utf8_lossy(&n[..n.len() - 1])
                        ))
                    } else {
                        Ok(p)
                    }
                };
                let open: OpenFn = std::mem::transmute(sym(b"WinDivertOpen\0")?);
                let recv: RecvFn = std::mem::transmute(sym(b"WinDivertRecv\0")?);
                let send: SendFn = std::mem::transmute(sym(b"WinDivertSend\0")?);
                let f: Vec<u8> = filter.bytes().chain([0]).collect();
                let h = open(f.as_ptr(), 0, 0, 0);
                if h.is_null() || h as isize == -1 {
                    return Err(explain(GetLastError()));
                }
                Ok(Divert { h, recv, send })
            }
        }

        pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, Addr), String> {
            let mut n = 0u32;
            let mut a = Addr([0; 80]);
            let ok = unsafe {
                (self.recv)(
                    self.h,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut n,
                    &mut a,
                )
            };
            if ok == 0 {
                return Err(format!("WinDivertRecv error {}", unsafe { GetLastError() }));
            }
            Ok((n as usize, a))
        }

        pub fn send(&self, pkt: &[u8], a: &Addr) -> bool {
            let mut n = 0u32;
            unsafe { (self.send)(self.h, pkt.as_ptr().cast(), pkt.len() as u32, &mut n, a) != 0 }
        }
    }
}

#[cfg(windows)]
pub use imp::Divert;

#[cfg(test)]
mod tests {
    #[test]
    fn addr_layout() {
        assert_eq!(std::mem::size_of::<super::Addr>(), 80);
        let a = super::Addr([0; 80]).mark_checksums();
        let flags = u32::from_le_bytes([a.0[8], a.0[9], a.0[10], a.0[11]]);
        assert_eq!(flags, (1 << 21) | (1 << 22) | (1 << 23));
        let mut b = super::Addr([0; 80]);
        b.0[8..12].copy_from_slice(&(1u32 << 17).to_le_bytes());
        assert!(b.outbound() && !a.outbound());
    }
}
