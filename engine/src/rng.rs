// Быстрый некриптографический генератор для фейков (xorshift64*).

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

thread_local! {
    static STATE: Cell<u64> = Cell::new(seed());
}

fn seed() -> u64 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    t ^ (std::process::id() as u64).rotate_left(32) | 1
}

pub fn next() -> u64 {
    STATE.with(|s| {
        let mut x = s.get();
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        s.set(x);
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    })
}

pub fn fill(buf: &mut [u8]) {
    for c in buf.chunks_mut(8) {
        let v = next().to_le_bytes();
        c.copy_from_slice(&v[..c.len()]);
    }
}

pub fn bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    fill(&mut v);
    v
}

pub fn letters(n: usize) -> String {
    (0..n)
        .map(|_| (b'a' + (next() % 26) as u8) as char)
        .collect()
}
