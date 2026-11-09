package app

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gust/internal/platform"
)

// Самообновление из релизов GitHub

const selfRepo = "brix7on/gust"

type UpdateState struct {
	Latest string `json:"latest"`
	Busy   bool   `json:"busy"`
	Msg    string `json:"msg"`
	Err    string `json:"err"`
}

var upd struct {
	sync.Mutex
	st      UpdateState
	zipURL  string
	sumsURL string
	zipName string
}

func updateState() UpdateState {
	upd.Lock()
	defer upd.Unlock()
	return upd.st
}

func setUpd(f func(*UpdateState)) {
	upd.Lock()
	f(&upd.st)
	upd.Unlock()
}

// newerVersion: a > b по числам через точку
func newerVersion(a, b string) bool {
	pa, pb := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func (a *App) checkUpdate() {
	var rel struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := httpGetJSON("https://api.github.com/repos/"+selfRepo+"/releases/latest", &rel); err != nil {
		return
	}
	if !newerVersion(rel.Tag, Version) {
		setUpd(func(s *UpdateState) { s.Latest = "" })
		return
	}
	var zipURL, zipName, sums string
	for _, as := range rel.Assets {
		n := as.Name
		switch {
		case n == "SHA256SUMS":
			sums = as.URL
		case strings.HasPrefix(n, "Gust-") && strings.HasSuffix(n, "-windows-x64.zip"):
			zipURL, zipName = as.URL, n
		}
	}
	if zipURL == "" || sums == "" {
		return
	}
	upd.Lock()
	tag := strings.TrimPrefix(rel.Tag, "v")
	first := upd.st.Latest != tag
	upd.st.Latest = tag
	upd.zipURL, upd.sumsURL, upd.zipName = zipURL, sums, zipName
	upd.Unlock()
	if first {
		a.logf("доступна новая версия %s", rel.Tag)
	}
}

func (a *App) updateLoop() {
	time.Sleep(20 * time.Second)
	for {
		a.checkUpdate()
		a.fetchStrategies()
		select {
		case <-a.quit:
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sumFor(sumsPath, name string) string {
	f, err := os.Open(sumsPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) == 2 && strings.TrimPrefix(fs[1], "*") == name {
			return strings.ToLower(fs[0])
		}
	}
	return ""
}

func (a *App) startUpdate() error {
	if a.tuning() {
		return fmt.Errorf("идёт подбор — дождитесь конца")
	}
	upd.Lock()
	if upd.st.Busy {
		upd.Unlock()
		return fmt.Errorf("обновление уже идёт")
	}
	if upd.st.Latest == "" {
		upd.Unlock()
		return fmt.Errorf("новых версий нет")
	}
	upd.st.Busy, upd.st.Err, upd.st.Msg = true, "", "Загрузка…"
	zipURL, sumsURL, zipName, ver := upd.zipURL, upd.sumsURL, upd.zipName, upd.st.Latest
	upd.Unlock()
	go func() {
		err := a.doUpdate(zipURL, sumsURL, zipName, ver)
		if err != nil {
			a.logf("обновление: %v", err)
			setUpd(func(s *UpdateState) { s.Busy, s.Msg, s.Err = false, "", err.Error() })
		}
	}()
	return nil
}

func (a *App) doUpdate(zipURL, sumsURL, zipName, ver string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	dir := filepath.Join(a.dataDir, "update")
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	zp, sp := filepath.Join(dir, zipName), filepath.Join(dir, "SHA256SUMS")
	if err := downloadFile(sumsURL, sp, nil); err != nil {
		return err
	}
	if err := downloadFile(zipURL, zp, func(d, t int64) {
		if t > 0 {
			setUpd(func(s *UpdateState) { s.Msg = fmt.Sprintf("Загрузка… %d%%", d*100/t) })
		}
	}); err != nil {
		return err
	}
	want := sumFor(sp, zipName)
	got, err := fileSHA256(zp)
	if err != nil {
		return err
	}
	if want == "" || want != got {
		return fmt.Errorf("контрольная сумма не совпала — файл повреждён")
	}
	ex := filepath.Join(dir, "x")
	if err := unzipSafe(zp, ex); err != nil {
		return err
	}
	newExe := filepath.Join(ex, "Gust.exe")
	if !exists(newExe) {
		return fmt.Errorf("в архиве нет Gust.exe")
	}
	// подмена: запущенный exe можно переименовать, но не перезаписать
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return fmt.Errorf("не удалось заменить файл: %v", err)
	}
	if err := copyFile(newExe, exe); err != nil {
		_ = os.Rename(old, exe)
		return fmt.Errorf("не удалось заменить файл: %v", err)
	}
	_ = os.RemoveAll(dir)
	a.logf("обновлено до %s, перезапуск", ver)
	setUpd(func(s *UpdateState) { s.Msg = "Перезапуск…" })
	args := []string{"--after-update"}
	for _, x := range os.Args[1:] {
		if x != "--background" && x != "-background" && x != "--after-update" {
			args = append(args, x)
		}
	}
	platform.StartDetached(exe, args...)
	a.requestQuit()
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// waitPortFree: новая копия ждёт, пока старая отпустит порт
func waitPortFree(addr string, d time.Duration) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			return
		}
		c.Close()
		time.Sleep(300 * time.Millisecond)
	}
}

// cleanupOldExe удаляет exe, оставшийся от прошлого обновления
func cleanupOldExe() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
