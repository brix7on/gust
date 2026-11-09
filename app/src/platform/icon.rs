pub fn icon_cover(size: usize, x: usize, y: usize) -> (f64, f64) {
    const SS: usize = 4;
    let (mut nb, mut nf) = (0u32, 0u32);
    for sy in 0..SS {
        for sx in 0..SS {
            let u = (x as f64 + (sx as f64 + 0.5) / SS as f64) / size as f64 * 64.0;
            let v = (y as f64 + (sy as f64 + 0.5) / SS as f64) / size as f64 * 64.0;
            if !in_box(u, v) {
                continue;
            }
            nb += 1;
            if in_mark(u, v) {
                nf += 1;
            }
        }
    }
    (nb as f64 / SS as f64 / SS as f64, nf as f64 / (nb.max(1)) as f64)
}

fn in_box(u: f64, v: f64) -> bool {
    const R: f64 = 13.0;
    let qx = ((u - 32.0).abs() - (32.0 - R)).max(0.0);
    let qy = ((v - 32.0).abs() - (32.0 - R)).max(0.0);
    qx.hypot(qy) <= R
}

fn in_mark(u: f64, v: f64) -> bool {
    let (dx, dy) = (u - 32.0, v - 30.0);
    let d = dx.hypot(dy);
    let a = dy.atan2(dx) * 180.0 / std::f64::consts::PI;
    if (d - 17.0).abs() <= 3.4 && !(a < 0.0 && a > -62.0) {
        return true;
    }
    if (33.0..=47.0).contains(&u) && (v - 33.0).abs() <= 3.0 {
        return true;
    }
    if (u - 24.0).abs() <= 1.4 && (44.0..=55.0).contains(&v) {
        return true;
    }
    (u - 24.0).hypot(v - 55.0) <= 2.6
}
