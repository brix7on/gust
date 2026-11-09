package app

import (
	"os"
	"path/filepath"
	"strings"

	"gust/internal/platform"
)

// Постоянное место exe — «Загрузки»\Gust.exe

func homeExe() string {
	d := platform.DownloadsDir()
	if d == "" {
		return ""
	}
	return filepath.Join(d, Name+".exe")
}

// moveHome копирует exe в «Загрузки» и запускает оттуда; true — эту копию нужно закрыть
func moveHome() bool {
	dst := homeExe()
	if dst == "" {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if e, err := filepath.EvalSymlinks(exe); err == nil {
		exe = e
	}
	if strings.EqualFold(filepath.Clean(exe), filepath.Clean(dst)) {
		return false
	}
	if a, b := fileSize(exe), fileSize(dst); a < 0 || a != b || !sameFile(exe, dst) {
		tmp := dst + ".tmp"
		if copyFile(exe, tmp) != nil {
			_ = os.Remove(tmp)
			return false
		}
		if os.Rename(tmp, dst) != nil {
			_ = os.Remove(tmp)
			return false
		}
	}
	platform.StartDetached(dst, os.Args[1:]...)
	return true
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return st.Size()
}

func sameFile(a, b string) bool {
	x, e1 := fileSHA256(a)
	y, e2 := fileSHA256(b)
	return e1 == nil && e2 == nil && x == y
}
