package app

import (
	"bytes"
	"embed"
	"gust/internal/platform"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Собственный движок gust-engine (Rust, папка engine/). Встраивается в exe при сборке,
// распаковывается в защищённую папку данных и запускает те же стратегии, что и winws.

//go:embed all:enginebin
var engineFS embed.FS

const engineName = "gust-engine.exe"

// TwinPrefix — приставка к имени стратегии, запущенной через собственный движок.
const TwinPrefix = "Gust · "

var engineOverride string // для тестов

// engineFlags — опции, которые понимает gust-engine (engine/src/config.rs).
var engineFlags = map[string]bool{
	"--wf-tcp": true, "--wf-udp": true, "--windivert": true, "--new": true,
	"--filter-tcp": true, "--filter-udp": true, "--filter-l7": true,
	"--hostlist": true, "--hostlist-domains": true, "--hostlist-exclude": true, "--hostlist-exclude-domains": true,
	"--ipset": true, "--ipset-ip": true, "--ipset-exclude": true, "--ipset-exclude-ip": true, "--ip-id": true,
	"--dpi-desync": true, "--dpi-desync-repeats": true, "--dpi-desync-split-pos": true,
	"--dpi-desync-split-seqovl": true, "--dpi-desync-split-seqovl-pattern": true,
	"--dpi-desync-fakedsplit-pattern": true, "--dpi-desync-hostfakesplit-mod": true, "--dpi-desync-hostfakesplit-midhost": true,
	"--dpi-desync-fooling": true, "--dpi-desync-ttl": true, "--dpi-desync-ttl6": true,
	"--dpi-desync-autottl": true, "--dpi-desync-autottl6": true,
	"--dpi-desync-badseq-increment": true, "--dpi-desync-badack-increment": true, "--dpi-desync-ts-increment": true,
	"--dpi-desync-fake-tls": true, "--dpi-desync-fake-tls-mod": true, "--dpi-desync-fake-http": true,
	"--dpi-desync-fake-quic": true, "--dpi-desync-fake-discord": true, "--dpi-desync-fake-stun": true,
	"--dpi-desync-fake-unknown": true, "--dpi-desync-fake-unknown-udp": true, "--dpi-desync-fake-syndata": true,
	"--dpi-desync-any-protocol": true, "--dpi-desync-cutoff": true, "--wssize": true, "--wssize-cutoff": true,
}

func engineCompatible(args []string) bool {
	for _, a := range args {
		k, _, _ := strings.Cut(a, "=")
		if !engineFlags[k] {
			return false
		}
	}
	return true
}

// engineExe — путь к распакованному движку; "" — движок в эту сборку не встроен.
func (a *App) engineExe() string {
	if engineOverride != "" {
		return engineOverride
	}
	a.engOnce.Do(func() { a.enginePath = a.extractEngine() })
	return a.enginePath
}

func (a *App) extractEngine() string {
	b, err := engineFS.ReadFile("enginebin/" + engineName)
	if err != nil || len(b) == 0 {
		return ""
	}
	dir := filepath.Join(a.dataDir, "engine")
	p := filepath.Join(dir, engineName)
	if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, b) {
		return p
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		a.logf("движок Gust: %v", err)
		return ""
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		a.logf("движок Gust: %v", err)
		return ""
	}
	if err := os.Rename(tmp, p); err != nil {
		platform.KillByName(engineName)
		time.Sleep(300 * time.Millisecond)
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			a.logf("движок Gust: не удалось обновить файл: %v", err)
			return ""
		}
	}
	return p
}

func (a *App) isEngineExe(p string) bool {
	ep := a.engineExe()
	if ep == "" || p == "" {
		return false
	}
	x, err1 := filepath.Abs(p)
	y, err2 := filepath.Abs(ep)
	return err1 == nil && err2 == nil && strings.EqualFold(x, y)
}

// engineTwins — те же стратегии, но через собственный движок.
func engineTwins(in []Strategy, exe, root string) []Strategy {
	dll := filepath.Join(root, "bin", "WinDivert.dll")
	if !exists(dll) {
		return nil
	}
	var out []Strategy
	for _, s := range in {
		if !engineCompatible(s.Args) {
			continue
		}
		args := append([]string{"--windivert=" + dll}, s.Args...)
		out = append(out, Strategy{Name: TwinPrefix + s.Name, Exe: exe, Args: args})
	}
	return out
}

// withEngine применяет настройку «Движок обхода» к списку стратегий.
func (a *App) withEngine(out []Strategy, root, mode string) []Strategy {
	if mode != "gust" && mode != "both" {
		return out
	}
	ep := a.engineExe()
	if ep == "" {
		return out
	}
	tw := engineTwins(out, ep, root)
	if mode == "gust" && len(tw) > 0 {
		return tw
	}
	return append(out, tw...)
}
