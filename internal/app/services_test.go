package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncServiceHosts(t *testing.T) {
	data := t.TempDir()
	a := newApp(data, 0)
	root := a.zapDir
	_ = os.MkdirAll(filepath.Join(root, "lists"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "general.bat"), []byte("bin\\winws.exe --wf-tcp=443"), 0o644)
	p := filepath.Join(root, "lists", "list-general-user.txt")
	_ = os.WriteFile(p, []byte("my.site\r\nx.com\r\n"), 0o644)

	a.updateSettings(func(s *Settings) { s.Groups["roblox"] = true })
	if ch, err := a.syncServiceHosts(); err != nil || !ch {
		t.Fatal(ch, err)
	}
	b, _ := os.ReadFile(p)
	got := string(b)
	if !strings.Contains(got, "my.site") || !strings.Contains(got, "rbxcdn.com") || !strings.Contains(got, "x.com") {
		t.Fatalf("после включения: %q", got)
	}
	if ch, _ := a.syncServiceHosts(); ch {
		t.Fatal("повторная синхронизация не должна менять файл")
	}
	a.updateSettings(func(s *Settings) { s.Groups["roblox"] = false; s.Groups["x"] = true })
	_, _ = a.syncServiceHosts()
	a.updateSettings(func(s *Settings) { s.Groups["x"] = false })
	_, _ = a.syncServiceHosts()
	b, _ = os.ReadFile(p)
	if strings.Contains(string(b), "roblox.com") || !strings.Contains(string(b), "my.site") || !strings.Contains(string(b), "x.com") {
		t.Fatalf("после выключения: %q", b)
	}
}

func TestDefaultGroups(t *testing.T) {
	g := fillGroups(nil)
	for id, on := range g {
		if on != (id == "discord" || id == "youtube") {
			t.Fatalf("%s по умолчанию %v", id, on)
		}
	}
	if old := fillGroups(map[string]bool{"youtube": false}); old["youtube"] || !old["discord"] {
		t.Fatal("старые настройки должны сохраняться")
	}
}
