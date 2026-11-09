package platform

import "math"

// iconCover — покрытие фона и рисунка значка в пикселе (x, y), сглаживание 4×4.
func iconCover(size, x, y int) (bg, fg float64) {
	const ss = 4
	var nb, nf int
	for sy := 0; sy < ss; sy++ {
		for sx := 0; sx < ss; sx++ {
			u := (float64(x) + (float64(sx)+.5)/ss) / float64(size) * 64
			v := (float64(y) + (float64(sy)+.5)/ss) / float64(size) * 64
			if !iconInBox(u, v) {
				continue
			}
			nb++
			if iconInMark(u, v) {
				nf++
			}
		}
	}
	return float64(nb) / ss / ss, float64(nf) / math.Max(float64(nb), 1)
}

func iconInBox(u, v float64) bool {
	const r = 13.0
	qx := math.Max(math.Abs(u-32)-(32-r), 0)
	qy := math.Max(math.Abs(v-32)-(32-r), 0)
	return math.Hypot(qx, qy) <= r
}

func iconInMark(u, v float64) bool {
	dx, dy := u-32, v-30
	d := math.Hypot(dx, dy)
	a := math.Atan2(dy, dx) * 180 / math.Pi
	if math.Abs(d-17) <= 3.4 && !(a < 0 && a > -62) {
		return true
	}
	if u >= 33 && u <= 47 && math.Abs(v-33) <= 3 {
		return true
	}
	if math.Abs(u-24) <= 1.4 && v >= 44 && v <= 55 {
		return true
	}
	if math.Hypot(u-24, v-55) <= 2.6 {
		return true
	}
	return false
}
