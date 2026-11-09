package app

import (
	"os"
	"path/filepath"
	"strings"
)

// Service — сервис для проверки; Hosts добавляются в list-general-user.txt, пока сервис включён.
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Default bool     `json:"-"`
	Hosts   []string `json:"-"`
	URLs    []string `json:"-"`
}

var services = []Service{
	{ID: "discord", Name: "Discord", Default: true},
	{ID: "youtube", Name: "YouTube", Default: true},
	{ID: "roblox", Name: "Roblox", Hosts: []string{"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"},
		URLs: []string{"https://www.roblox.com/", "https://apis.roblox.com/"}},
	{ID: "instagram", Name: "Instagram", Hosts: []string{"instagram.com", "cdninstagram.com", "fbcdn.net"},
		URLs: []string{"https://www.instagram.com/"}},
	{ID: "facebook", Name: "Facebook", Hosts: []string{"facebook.com", "facebook.net", "fb.com", "fbcdn.net"},
		URLs: []string{"https://www.facebook.com/"}},
	{ID: "x", Name: "X (Twitter)", Hosts: []string{"x.com", "twitter.com", "twimg.com", "t.co"},
		URLs: []string{"https://x.com/", "https://abs.twimg.com/"}},
	{ID: "whatsapp", Name: "WhatsApp", Hosts: []string{"whatsapp.com", "whatsapp.net"},
		URLs: []string{"https://web.whatsapp.com/"}},
	{ID: "signal", Name: "Signal", Hosts: []string{"signal.org", "signal.art", "whispersystems.org"},
		URLs: []string{"https://signal.org/"}},
	{ID: "viber", Name: "Viber", Hosts: []string{"viber.com"},
		URLs: []string{"https://www.viber.com/"}},
	{ID: "snapchat", Name: "Snapchat", Hosts: []string{"snapchat.com", "sc-cdn.net", "snap.com"},
		URLs: []string{"https://www.snapchat.com/"}},
	{ID: "linkedin", Name: "LinkedIn", Hosts: []string{"linkedin.com", "licdn.com"},
		URLs: []string{"https://www.linkedin.com/"}},
	{ID: "twitch", Name: "Twitch", Hosts: []string{"twitch.tv", "ttvnw.net", "jtvnw.net"},
		URLs: []string{"https://www.twitch.tv/"}},
	{ID: "soundcloud", Name: "SoundCloud", Hosts: []string{"soundcloud.com", "sndcdn.com"},
		URLs: []string{"https://soundcloud.com/"}},
	{ID: "patreon", Name: "Patreon", Hosts: []string{"patreon.com", "patreonusercontent.com"},
		URLs: []string{"https://www.patreon.com/"}},
	{ID: "medium", Name: "Medium", Hosts: []string{"medium.com"},
		URLs: []string{"https://medium.com/"}},
	{ID: "steamcommunity", Name: "Steam Community", Hosts: []string{"steamcommunity.com"},
		URLs: []string{"https://steamcommunity.com/"}},
	{ID: "rutracker", Name: "RuTracker", Hosts: []string{"rutracker.org", "rutracker.cc"},
		URLs: []string{"https://rutracker.org/"}},
	{ID: "nnmclub", Name: "NNM-Club", Hosts: []string{"nnmclub.to"},
		URLs: []string{"https://nnmclub.to/"}},
	{ID: "torproject", Name: "Tor Project", Hosts: []string{"torproject.org"},
		URLs: []string{"https://www.torproject.org/"}},
	{ID: "proton", Name: "Proton", Hosts: []string{"proton.me", "protonmail.com"},
		URLs: []string{"https://proton.me/"}},
	{ID: "telegram", Name: "Telegram (сайт)", Hosts: []string{"telegram.org", "t.me"},
		URLs: []string{"https://web.telegram.org/"}},
}

func serviceByID(id string) (Service, bool) {
	for _, s := range services {
		if s.ID == id {
			return s, true
		}
	}
	return Service{}, false
}

// serviceTargets — цели проверки для сервисов из каталога (Discord и YouTube описаны в allTargets).
func serviceTargets() []Target {
	var out []Target
	for _, s := range services {
		for _, u := range s.URLs {
			out = append(out, Target{Group: s.ID, Name: strings.TrimPrefix(strings.Split(u, "/")[2], "www."), URL: u})
		}
	}
	return out
}

// fillGroups дописывает в настройки недостающие сервисы со значением по умолчанию.
func fillGroups(g map[string]bool) map[string]bool {
	if g == nil {
		g = map[string]bool{}
	}
	for _, s := range services {
		if _, ok := g[s.ID]; !ok {
			g[s.ID] = s.Default
		}
	}
	return g
}

// syncServiceHosts приводит list-general-user.txt к включённым сервисам; true — файл изменился.
// Убираются только домены, которые программа добавила сама (Settings.AddedHosts).
func (a *App) syncServiceHosts() (bool, error) {
	root := a.zapretRoot()
	if root == "" {
		return false, nil
	}
	set := a.settings()
	want := map[string]bool{}
	var order []string
	for _, s := range services {
		for _, h := range s.Hosts {
			if set.Groups[s.ID] && !want[h] {
				want[h] = true
				order = append(order, h)
			}
		}
	}
	ours := map[string]bool{}
	for _, h := range set.AddedHosts {
		ours[h] = true
	}
	p := filepath.Join(root, "lists", "list-general-user.txt")
	b, _ := os.ReadFile(p)
	var keep []string
	have := map[string]bool{}
	changed := false
	for _, l := range strings.Split(strings.ReplaceAll(string(b), "\r", ""), "\n") {
		h := strings.ToLower(strings.TrimSpace(l))
		if h == "" || have[h] {
			continue
		}
		if ours[h] && !want[h] {
			delete(ours, h)
			changed = true
			continue
		}
		have[h] = true
		keep = append(keep, strings.TrimSpace(l))
	}
	for _, h := range order {
		if !have[h] {
			have[h] = true
			ours[h] = true
			keep = append(keep, h)
			changed = true
		}
	}
	var added []string
	for _, h := range order {
		if ours[h] {
			added = append(added, h)
		}
	}
	if strings.Join(added, ",") != strings.Join(set.AddedHosts, ",") {
		a.updateSettings(func(s *Settings) { s.AddedHosts = added })
	}
	if !changed {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(p, []byte(strings.Join(keep, "\r\n")+"\r\n"), 0o644)
}

// applyServiceHosts синхронизирует список и перезапускает winws, если он работает.
func (a *App) applyServiceHosts() {
	ch, err := a.syncServiceHosts()
	if err != nil {
		a.logf("список сервисов: %v", err)
		return
	}
	if ch {
		a.logf("список обхода обновлён под выбранные сервисы")
		if a.eng.Alive() && !a.tuning() {
			_ = a.startSelected()
		}
	}
}
