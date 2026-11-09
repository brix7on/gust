package app

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gust/internal/platform"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Strategy — одна готовая стратегия: строка запуска winws из .bat-файла сборки.
type Strategy struct {
	Name string   // имя .bat без расширения
	Exe  string   // путь к winws.exe
	Args []string // аргументы после подстановки переменных
	Err  string   // почему стратегию нельзя использовать
}

var varRe = regexp.MustCompile(`%([^%\s]+)%`)

// findRoot ищет папку сборки: в ней лежат .bat, внутри которых вызывается winws.exe.
func findRoot(base string) string {
	var walk func(dir string, depth int) string
	walk = func(dir string, depth int) string {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return ""
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".bat") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err == nil && strings.Contains(strings.ToLower(string(b)), "winws.exe") &&
				strings.Contains(string(b), "--") {
				return dir
			}
		}
		if depth > 0 {
			for _, e := range ents {
				if e.IsDir() {
					if r := walk(filepath.Join(dir, e.Name()), depth-1); r != "" {
						return r
					}
				}
			}
		}
		return ""
	}
	return walk(base, 2)
}

func (a *App) zapretRoot() string { return findRoot(a.zapDir) }

// within сообщает, лежит ли p внутри root (после приведения к абсолютным путям).
func within(root, p string) bool {
	root, err1 := filepath.Abs(root)
	p, err2 := filepath.Abs(p)
	if err1 != nil || err2 != nil || root == "" {
		return false
	}
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// exeAllowed разрешает запуск только winws.exe из папки сборки — защита от подменённого .bat,
// который мог бы подсунуть сторонний exe на запуск с правами администратора.
func exeAllowed(root, exe string) bool {
	return root != "" && strings.EqualFold(filepath.Base(exe), "winws.exe") && within(root, exe)
}

// hostAllowed — доверенные хосты для скачивания (GitHub и его CDN).
func hostAllowed(host string) bool {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	return host == "github.com" ||
		strings.HasSuffix(host, ".github.com") ||
		strings.HasSuffix(host, ".githubusercontent.com")
}

// tokenize разбирает командную строку в стиле cmd: пробелы разделяют, кавычки группируют и убираются.
func tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			has = true
		case (r == ' ' || r == '\t') && !inQ:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

// parseBat достаёт из .bat строку запуска winws и подставляет переменные.
func parseBat(path, root string, gameFilter bool) Strategy {
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	st := Strategy{Name: name}
	data, err := os.ReadFile(path)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	sep := string(filepath.Separator)
	gf := "12" // «порт-пустышка», когда игровой фильтр выключен (как в service.bat)
	if gameFilter {
		// без порта самого приложения (и локальных прокси VPN-клиентов): иначе winws
		// перехватывает управляющий трафик, и страница теряет связь с программой
		gf = fmt.Sprintf("1024-10807,10810-%d,%d-65535", DefaultPort-1, DefaultPort+1)
	}
	vars := map[string]string{
		"bin":           filepath.Join(root, "bin") + sep,
		"lists":         filepath.Join(root, "lists") + sep,
		"gamefiltertcp": gf,
		"gamefilterudp": gf,
		"gamefilter":    gf,
	}
	subst := func(s string) string {
		s = strings.ReplaceAll(s, "%~dp0", root+sep)
		s = strings.ReplaceAll(s, "%~n0", name)
		return varRe.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := vars[strings.ToLower(m[1:len(m)-1])]; ok {
				return v
			}
			return m
		})
	}

	// переменные, объявленные в самом .bat (set "BIN=...")
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if len(t) < 5 || !strings.EqualFold(t[:4], "set ") {
			continue
		}
		kv := strings.Trim(strings.TrimSpace(t[4:]), `"`)
		i := strings.Index(kv, "=")
		if i <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[:i]))
		if strings.HasPrefix(k, "gamefilter") || strings.HasPrefix(k, "/") {
			continue
		}
		vars[k] = subst(kv[i+1:])
	}

	// склейка строк, оканчивающихся на ^
	var logical []string
	cur := ""
	for _, ln := range lines {
		t := strings.TrimRight(ln, " \t\r")
		if strings.HasSuffix(t, "^") {
			cur += strings.TrimSuffix(t, "^") + " "
			continue
		}
		cur += t
		logical = append(logical, cur)
		cur = ""
	}
	var cmdline string
	for _, l := range logical {
		low := strings.ToLower(l)
		if strings.Contains(low, "winws.exe") && strings.Contains(l, "--") &&
			!strings.HasPrefix(strings.TrimSpace(low), "taskkill") &&
			!strings.HasPrefix(strings.TrimSpace(low), "echo") &&
			!strings.HasPrefix(strings.TrimSpace(low), "rem") &&
			!strings.HasPrefix(strings.TrimSpace(low), "::") {
			cmdline = l
			break
		}
	}
	if cmdline == "" {
		st.Err = "в файле нет запуска winws"
		return st
	}
	cmdline = subst(cmdline)
	if m := varRe.FindString(cmdline); m != "" {
		st.Err = "неизвестная переменная " + m
		return st
	}
	toks := tokenize(cmdline)
	for i, t := range toks {
		if strings.HasSuffix(strings.ToLower(t), "winws.exe") {
			st.Exe = t
			st.Args = toks[i+1:]
			break
		}
	}
	if st.Exe == "" || len(st.Args) == 0 {
		st.Err = "не удалось разобрать строку запуска"
	}
	return st
}

// loadStrategies читает все .bat сборки (кроме service.bat), "general" первым.
func (a *App) loadStrategies() []Strategy {
	root := a.zapretRoot()
	if root == "" {
		return nil
	}
	set := a.settings()
	gf := set.GameFilter
	ents, _ := os.ReadDir(root)
	var out []Strategy
	for _, e := range ents {
		n := strings.ToLower(e.Name())
		if e.IsDir() || !strings.HasSuffix(n, ".bat") || n == "service.bat" {
			continue
		}
		st := parseBat(filepath.Join(root, e.Name()), root, gf)
		if st.Err != "" {
			// loadStrategies зовут каждую секунду из интерфейса — пишем про файл один раз
			if _, seen := a.skipLogged.LoadOrStore(e.Name(), true); !seen {
				a.logf("пропускаю %s: %s", e.Name(), st.Err)
			}
			continue
		}
		out = append(out, st)
	}
	sort.SliceStable(out, func(i, j int) bool {
		gi, gj := strings.EqualFold(out[i].Name, "general"), strings.EqualFold(out[j].Name, "general")
		if gi != gj {
			return gi
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	// свои стратегии идут после готовых: сначала пробуем проверенные
	if set.ExtraStrategies {
		exe := filepath.Join(root, "bin", "winws.exe")
		if len(out) > 0 {
			exe = out[0].Exe
		}
		out = append(out, builtinStrategies(root, exe)...)
	}
	return a.withEngine(out, root, set.Engine)
}

func (a *App) findStrategy(name string) (Strategy, bool) {
	for _, s := range a.loadStrategies() {
		if s.Name == name {
			return s, true
		}
	}
	return Strategy{}, false
}

// ensureLists создаёт отсутствующие пользовательские списки (service.bat делает то же самое).
func ensureLists(root string, args []string) {
	for _, a := range args {
		if !strings.HasPrefix(a, "--hostlist") && !strings.HasPrefix(a, "--ipset") {
			continue
		}
		i := strings.Index(a, "=")
		if i < 0 || strings.HasPrefix(a, "--hostlist-domains") {
			continue
		}
		p := a[i+1:]
		if !strings.HasSuffix(strings.ToLower(p), ".txt") {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			continue
		}
		if !strings.HasPrefix(filepath.Clean(p), filepath.Clean(root)) {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		stub := "domain.example.abc\n"
		if strings.Contains(strings.ToLower(filepath.Base(p)), "ipset") {
			stub = "203.0.113.113/32\n"
		}
		_ = os.WriteFile(p, []byte(stub), 0o644)
	}
}

// ---------- скачивание сборки ----------

const zapRepo = "Flowseal/zapret-discord-youtube"

func (a *App) setSetup(busy bool, msg, errS string) {
	a.mu.Lock()
	a.setup = SetupState{Busy: busy, Msg: msg, Err: errS}
	a.mu.Unlock()
}

func httpGetJSON(url string, v any) error {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", Name)
	req.Header.Set("Accept", "application/vnd.github+json")
	c := &http.Client{Timeout: 25 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func latestZapretAsset() (tag, url string, err error) {
	var rel struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if e := httpGetJSON("https://api.github.com/repos/"+zapRepo+"/releases/latest", &rel); e == nil {
		for _, as := range rel.Assets {
			if strings.HasSuffix(strings.ToLower(as.Name), ".zip") {
				return rel.Tag, as.URL, nil
			}
		}
	}
	// запасной путь: без API, через редирект /releases/latest -> /releases/tag/X
	c := &http.Client{Timeout: 25 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := c.Get("https://github.com/" + zapRepo + "/releases/latest")
	if e != nil {
		return "", "", e
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if i := strings.LastIndex(loc, "/tag/"); i >= 0 {
		tag = loc[i+5:]
		return tag, fmt.Sprintf("https://github.com/%s/releases/download/%s/zapret-discord-youtube-%s.zip", zapRepo, tag, tag), nil
	}
	return "", "", fmt.Errorf("не нашёл последний релиз (GitHub недоступен?)")
}

func downloadFile(rawurl, dst string, progress func(done, total int64)) error {
	u, err := neturl.Parse(rawurl)
	if err != nil || !hostAllowed(u.Host) {
		return fmt.Errorf("недоверенный адрес скачивания: %s", rawurl)
	}
	req, _ := http.NewRequest("GET", rawurl, nil)
	req.Header.Set("User-Agent", Name)
	c := &http.Client{
		Timeout: 10 * time.Minute,
		// редиректы GitHub на CDN разрешаем, на посторонние хосты — нет
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("слишком много редиректов")
			}
			if !hostAllowed(r.URL.Host) {
				return fmt.Errorf("редирект на недоверенный адрес: %s", r.URL.Host)
			}
			return nil
		},
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d при скачивании", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	var done int64
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			done += int64(n)
			if progress != nil {
				progress(done, resp.ContentLength)
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// Лимиты от zip-бомбы (сборка zapret ~5 МБ, так что запас большой). Переменные — для тестов.
var (
	maxZipFiles = 10000
	maxZipFile  = int64(64 << 20)  // на один файл
	maxZipTotal = int64(512 << 20) // суммарно распакованных
)

// unzipSafe распаковывает архив, защищаясь от выхода за папку (zip slip) и от zip-бомбы.
func unzipSafe(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > maxZipFiles {
		return fmt.Errorf("в архиве слишком много файлов")
	}
	destAbs, _ := filepath.Abs(dest)
	var total int64
	for _, f := range zr.File {
		target := filepath.Join(destAbs, f.Name)
		if target != destAbs && !strings.HasPrefix(target, destAbs+string(filepath.Separator)) {
			return fmt.Errorf("небезопасный путь в архиве: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		// копируем не больше maxZipFile+1, чтобы поймать превышение, не раздувая память
		n, cerr := io.CopyN(out, rc, maxZipFile+1)
		out.Close()
		rc.Close()
		if cerr != nil && cerr != io.EOF {
			return cerr
		}
		if n > maxZipFile {
			return fmt.Errorf("файл в архиве слишком большой: %s", f.Name)
		}
		total += n
		if total > maxZipTotal {
			return fmt.Errorf("архив распаковывается в слишком большой объём")
		}
	}
	return nil
}

// installZapret скачивает и распаковывает сборку, сохраняя пользовательские списки.
func (a *App) installZapret() {
	a.setSetup(true, "Ищу последний релиз на GitHub…", "")
	fail := func(err error) {
		a.logf("установка сборки: %v", err)
		a.setSetup(false, "", err.Error())
	}
	tag, url, err := latestZapretAsset()
	if err != nil {
		fail(err)
		return
	}
	a.logf("скачиваю сборку %s", tag)
	tmpDir := filepath.Join(a.dataDir, "dl")
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		fail(err)
		return
	}
	defer os.RemoveAll(tmpDir)
	zipPath := filepath.Join(tmpDir, "zapret.zip")
	last := time.Now()
	err = downloadFile(url, zipPath, func(done, total int64) {
		if time.Since(last) > 400*time.Millisecond {
			last = time.Now()
			if total > 0 {
				a.setSetup(true, fmt.Sprintf("Скачиваю %s: %d%%", tag, done*100/total), "")
			} else {
				a.setSetup(true, fmt.Sprintf("Скачиваю %s: %d КБ", tag, done>>10), "")
			}
		}
	})
	if err != nil {
		fail(err)
		return
	}
	a.setSetup(true, "Распаковываю…", "")
	ex := filepath.Join(tmpDir, "x")
	if err := unzipSafe(zipPath, ex); err != nil {
		fail(err)
		return
	}
	root := findRoot(ex)
	if root == "" {
		fail(fmt.Errorf("в архиве нет файлов сборки zapret"))
		return
	}
	// сохраняем пользовательские списки старой установки
	keep := map[string][]byte{}
	if old := a.zapretRoot(); old != "" {
		ms, _ := filepath.Glob(filepath.Join(old, "lists", "*-user.txt"))
		for _, m := range ms {
			if b, e := os.ReadFile(m); e == nil {
				keep[filepath.Base(m)] = b
			}
		}
	}
	a.eng.Stop()
	platform.CleanupDivert(true)
	_ = os.RemoveAll(a.zapDir)
	if err := os.Rename(root, a.zapDir); err != nil {
		fail(err)
		return
	}
	for n, b := range keep {
		_ = os.WriteFile(filepath.Join(a.zapDir, "lists", n), b, 0o644)
	}
	a.updateSettings(func(s *Settings) { s.ZapretVersion = tag })
	a.logf("сборка %s установлена", tag)
	_, _ = a.syncServiceHosts()
	a.setSetup(false, "Готово: "+tag, "")
	// «одна кнопка»: сразу подбираем рабочую стратегию
	_ = a.startTune()
}
