// Наборы адресов/подсетей (CIDR) для --ipset.

use std::net::IpAddr;

#[derive(Debug, Default, Clone)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy>(v: &mut Vec<(T, T)>, succ: impl Fn(T) -> Option<T>) {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for &(a, b) in v.iter() {
        match out.last_mut() {
            Some(l) if succ(l.1).is_none_or(|n| a <= n) => l.1 = l.1.max(b),
            _ => out.push((a, b)),
        }
    }
    *v = out;
}

impl IpSet {
    pub fn add(&mut self, s: &str) -> Result<(), String> {
        let s = s.split('#').next().unwrap_or("").trim();
        if s.is_empty() {
            return Ok(());
        }
        let (a, bits) = match s.split_once('/') {
            Some((a, b)) => (
                a,
                Some(b.parse::<u32>().map_err(|_| format!("bad prefix: {s}"))?),
            ),
            None => (s, None),
        };
        match a
            .parse::<IpAddr>()
            .map_err(|_| format!("bad address: {s}"))?
        {
            IpAddr::V4(ip) => {
                let bits = bits.unwrap_or(32);
                if bits > 32 {
                    return Err(format!("bad prefix: {s}"));
                }
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                let lo = u32::from(ip) & mask;
                self.v4.push((lo, lo | !mask));
            }
            IpAddr::V6(ip) => {
                let bits = bits.unwrap_or(128);
                if bits > 128 {
                    return Err(format!("bad prefix: {s}"));
                }
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                let lo = u128::from(ip) & mask;
                self.v6.push((lo, lo | !mask));
            }
        }
        Ok(())
    }

    pub fn load(&mut self, path: &str) -> Result<(), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        for l in text.lines() {
            self.add(l).map_err(|e| format!("{path}: {e}"))?;
        }
        self.finish();
        Ok(())
    }

    pub fn finish(&mut self) {
        merge(&mut self.v4, |x: u32| x.checked_add(1));
        merge(&mut self.v6, |x: u128| x.checked_add(1));
    }

    pub fn contains(&self, ip: &[u8]) -> bool {
        fn find<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
            let i = v.partition_point(|r| r.0 <= x);
            i > 0 && x <= v[i - 1].1
        }
        match ip.len() {
            4 => find(&self.v4, u32::from_be_bytes(ip.try_into().unwrap())),
            16 => find(&self.v6, u128::from_be_bytes(ip.try_into().unwrap())),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        let mut s = IpSet::default();
        for l in [
            "162.159.128.0/19",
            "162.159.160.0/19",
            "1.1.1.1",
            "# c",
            "2606:4700::/32",
            "0.0.0.0/32",
        ] {
            s.add(l).unwrap();
        }
        s.finish();
        assert_eq!(s.v4.len(), 3);
        assert!(s.contains(&[162, 159, 130, 5]));
        assert!(s.contains(&[162, 159, 191, 255]));
        assert!(!s.contains(&[162, 159, 192, 0]));
        assert!(s.contains(&[1, 1, 1, 1]) && !s.contains(&[1, 1, 1, 2]));
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x26, 0x06, 0x47, 0x00]);
        assert!(s.contains(&v6));
        v6[3] = 1;
        assert!(!s.contains(&v6));
        assert!(s.add("1.2.3.4/33").is_err());
        assert!(s.add("nope").is_err());
    }
}
