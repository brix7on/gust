package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Список стратегий, который подтягивается из репозитория без нового exe

const remoteStrategiesURL = "https://raw.githubusercontent.com/" + selfRepo + "/main/strategies.json"

type remoteFile struct {
	Version int `json:"version"`
	TCP     []struct {
		Name  string   `json:"name"`
		Args  []string `json:"args"`
		Needs string   `json:"needs,omitempty"`
	} `json:"tcp"`
}

var remoteTCP struct {
	sync.RWMutex
	list []tcpVariant
	ver  int
}

func currentTCP() []tcpVariant {
	remoteTCP.RLock()
	defer remoteTCP.RUnlock()
	if len(remoteTCP.list) > 0 {
		return remoteTCP.list
	}
	return tcpVariants
}

var allowedArg = []string{"--dpi-desync=", "--dpi-desync-", "--wssize=", "--wssize-cutoff="}

func parseRemote(b []byte) (int, []tcpVariant, error) {
	var f remoteFile
	if err := json.Unmarshal(b, &f); err != nil {
		return 0, nil, err
	}
	if len(f.TCP) == 0 || len(f.TCP) > 200 {
		return 0, nil, fmt.Errorf("пустой или слишком большой список")
	}
	seen := map[string]bool{}
	var out []tcpVariant
	for _, v := range f.TCP {
		if v.Name == "" || len(v.Name) > 60 || seen[v.Name] {
			return 0, nil, fmt.Errorf("плохое имя %q", v.Name)
		}
		seen[v.Name] = true
		if v.Needs != "" && v.Needs != "G" && v.Needs != "Y" {
			return 0, nil, fmt.Errorf("%s: needs", v.Name)
		}
		desync := false
		for _, a := range v.Args {
			ok := false
			for _, p := range allowedArg {
				if strings.HasPrefix(a, p) {
					ok = true
				}
			}
			if !ok || strings.ContainsAny(a, " \t\"'&|<>^%\r\n") {
				return 0, nil, fmt.Errorf("%s: аргумент %q", v.Name, a)
			}
			rest := strings.NewReplacer("{G}", "", "{Y}", "").Replace(a)
			if strings.ContainsAny(rest, "{}") {
				return 0, nil, fmt.Errorf("%s: аргумент %q", v.Name, a)
			}
			if strings.HasPrefix(a, "--dpi-desync=") {
				desync = true
			}
		}
		if !desync {
			return 0, nil, fmt.Errorf("%s: нет --dpi-desync", v.Name)
		}
		out = append(out, tcpVariant{name: v.Name, args: v.Args, needs: v.Needs})
	}
	return f.Version, out, nil
}

func setRemote(ver int, list []tcpVariant) {
	remoteTCP.Lock()
	remoteTCP.list, remoteTCP.ver = list, ver
	remoteTCP.Unlock()
}

func (a *App) remotePath() string { return filepath.Join(a.dataDir, "strategies.json") }

// loadCachedStrategies — то, что скачали в прошлый раз
func (a *App) loadCachedStrategies() {
	b, err := os.ReadFile(a.remotePath())
	if err != nil {
		return
	}
	if ver, list, err := parseRemote(b); err == nil {
		setRemote(ver, list)
	}
}

func (a *App) fetchStrategies() {
	tmp := a.remotePath() + ".tmp"
	if err := downloadFile(remoteStrategiesURL, tmp, nil); err != nil {
		_ = os.Remove(tmp)
		return
	}
	b, err := os.ReadFile(tmp)
	if err != nil {
		return
	}
	ver, list, err := parseRemote(b)
	if err != nil {
		_ = os.Remove(tmp)
		a.logf("список стратегий с GitHub отклонён: %v", err)
		return
	}
	remoteTCP.RLock()
	old := remoteTCP.ver
	remoteTCP.RUnlock()
	if ver < old {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, a.remotePath()); err != nil {
		_ = os.Remove(tmp)
		return
	}
	setRemote(ver, list)
	if ver != old {
		a.logf("список стратегий обновлён (версия %d, %d шт.)", ver, len(list))
	}
}

// guKey — имя своей стратегии без номера «GU-NN»: номера сдвигаются, когда меняется список
func guKey(name string) string {
	tw := strings.HasPrefix(name, TwinPrefix)
	n := strings.TrimPrefix(name, TwinPrefix)
	if !strings.HasPrefix(n, "GU-") {
		return ""
	}
	i := strings.IndexByte(n, ' ')
	if i < 0 {
		return ""
	}
	if tw {
		return TwinPrefix + n[i+1:]
	}
	return n[i+1:]
}
