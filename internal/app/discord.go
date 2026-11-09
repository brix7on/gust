package app

import (
	"context"
	"fmt"
	"gust/internal/platform"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Вкладка Discord: его собственные проверки, подбор только под него, переключение
// стратегии для голоса (голос идёт по UDP и сам не проверяется) и перезапуск клиента.

type discordOut struct {
	Checks  CheckState `json:"checks"`
	Targets []Target   `json:"targets"`
	Running bool       `json:"running"` // запущен ли клиент Discord
}

// CheckDiscord проверяет все адреса Discord, независимо от галочек в настройках.
func (a *App) CheckDiscord() {
	a.mu.Lock()
	if a.dchecks.Running {
		a.mu.Unlock()
		return
	}
	a.dchecks.Running = true
	a.mu.Unlock()
	rs := runChecks(context.Background(), a.scopeTargets("discord"), checkTimeout)
	alive := internetAlive()
	a.mu.Lock()
	a.dchecks = CheckState{At: time.Now().Unix(), Internet: alive, Results: rs}
	a.mu.Unlock()
}

// voiceOrder — в каком порядке перебирать стратегии, когда не работает голос:
// сначала те, с которыми при подборе открылось всё, потом остальные по списку.
func voiceOrder(names []string, res []TuneResult) []string {
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	var out []string
	used := map[string]bool{}
	for _, r := range res {
		if r.Total > 0 && r.Passed == r.Total && have[r.Strategy] && !used[r.Strategy] {
			out = append(out, r.Strategy)
			used[r.Strategy] = true
		}
	}
	for _, n := range names {
		if !used[n] {
			out = append(out, n)
		}
	}
	return out
}

// voiceNext включает следующую стратегию после текущей.
func (a *App) voiceNext() (string, error) {
	if a.tuning() {
		return "", fmt.Errorf("идёт подбор — дождитесь конца")
	}
	strats := a.loadStrategies()
	if len(strats) < 2 {
		return "", fmt.Errorf("переключаться не на что: стратегий меньше двух")
	}
	names := make([]string, len(strats))
	byName := map[string]Strategy{}
	for i, s := range strats {
		names[i] = s.Name
		byName[s.Name] = s
	}
	a.mu.Lock()
	res := append([]TuneResult(nil), a.tune.Results...)
	a.mu.Unlock()
	order := voiceOrder(names, res)
	cur := a.settings().Selected
	next := order[0]
	for i, n := range order {
		if n == cur {
			next = order[(i+1)%len(order)]
			break
		}
	}
	if err := a.eng.Start(byName[next], true); err != nil {
		return "", err
	}
	a.updateSettings(func(s *Settings) { s.Selected = next })
	a.logf("голос Discord: переключился на «%s»", next)
	return next, nil
}

// Сборки Discord: имя процесса, папка в %LOCALAPPDATA%, ярлык в меню «Пуск».
var discordVariants = []struct{ exe, dir, lnk string }{
	{"Discord.exe", "Discord", "Discord.lnk"},
	{"DiscordPTB.exe", "DiscordPTB", "Discord PTB.lnk"},
	{"DiscordCanary.exe", "DiscordCanary", "Discord Canary.lnk"},
}

func discordImages() []string {
	var out []string
	for _, v := range discordVariants {
		out = append(out, v.exe)
	}
	return out
}

// discordLaunch — чем запускать Discord после закрытия.
type discordLaunch struct {
	exeName string // Discord.exe / DiscordPTB.exe / …
	exePath string // сам exe (последний вариант)
	updater string // Update.exe --processStart <exeName> (так запускает ярлык)
	lnk     string // ярлык из «Пуска»: через проводник Discord стартует без прав администратора
}

// planDiscord выясняет, где стоит Discord: сначала по пути запущенного процесса
// (…\Discord\app-1.0.9xxx\Discord.exe → …\Discord\Update.exe), иначе по стандартным папкам.
func planDiscord(procs []platform.Proc, appdata, local string, has func(string) bool) (discordLaunch, bool) {
	var l discordLaunch
	for _, p := range procs {
		if l.exeName == "" {
			l.exeName = p.Name
		}
		if p.Exe != "" {
			l.exeName, l.exePath = p.Name, p.Exe
			if u := filepath.Join(filepath.Dir(filepath.Dir(p.Exe)), "Update.exe"); has(u) {
				l.updater = u
			}
			break
		}
	}
	for _, v := range discordVariants {
		if l.exeName != "" && !strings.EqualFold(v.exe, l.exeName) {
			continue
		}
		if l.updater == "" && local != "" {
			if u := filepath.Join(local, v.dir, "Update.exe"); has(u) {
				l.updater = u
			}
		}
		if appdata != "" {
			if k := filepath.Join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Discord Inc", v.lnk); has(k) {
				l.lnk = k
			}
		}
		if l.updater != "" || l.lnk != "" {
			if l.exeName == "" {
				l.exeName = v.exe
			}
			break
		}
	}
	return l, l.lnk != "" || l.updater != "" || l.exePath != ""
}

// restartDiscord закрывает Discord и открывает заново — чтобы он переподключился уже через обход.
func (a *App) restartDiscord() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("работает только в Windows")
	}
	procs := platform.FindProcs(discordImages()...)
	plan, ok := planDiscord(procs, os.Getenv("APPDATA"), os.Getenv("LOCALAPPDATA"), exists)
	a.logf("Discord: процессов %d, exe=%q, Update.exe=%q, ярлык=%q", len(procs), plan.exePath, plan.updater, plan.lnk)
	if !ok {
		return fmt.Errorf("не нашёл Discord: он не запущен, и в стандартных папках его нет. Откройте Discord и нажмите ещё раз")
	}

	var failed []string
	for _, p := range procs {
		if err := platform.KillPID(p.PID); err != nil {
			failed = append(failed, err.Error())
		}
	}
	for i := 0; i < 25 && len(platform.FindProcs(discordImages()...)) > 0; i++ {
		time.Sleep(200 * time.Millisecond)
	}
	if left := platform.FindProcs(discordImages()...); len(left) > 0 {
		a.logf("Discord: не закрылся (%d процессов осталось) %s", len(left), strings.Join(failed, "; "))
		return fmt.Errorf("Discord не закрылся. Закройте его вручную (значок у часов → Quit Discord) и откройте снова")
	}
	a.invalidateCache("discordrun")
	time.Sleep(700 * time.Millisecond)

	if a.settings().DiscordDirect {
		if err := a.launchDiscordDirect(plan); err != nil {
			return err
		}
		a.logf("Discord: закрыт, запускаю мимо прокси VPN (--no-proxy-server)")
		return nil
	}
	switch {
	case plan.lnk != "":
		platform.OpenFileAsUser(plan.lnk)
		a.logf("Discord: закрыт, запускаю через ярлык")
	case plan.updater != "":
		platform.StartDetached(plan.updater, "--processStart", plan.exeName)
		a.logf("Discord: закрыт, запускаю через Update.exe")
	default:
		platform.StartDetached(plan.exePath)
		a.logf("Discord: закрыт, запускаю %s", plan.exePath)
	}
	return nil
}

// Флаг Chromium: не пользоваться системным прокси. Happ в режиме «Прокси» ставит себя системным
// прокси, и Discord уводит чат и сигнализацию звонка в VPN, а голос (UDP) идёт мимо — звонок висит
// на «Подключение к RTC». С флагом весь Discord идёт напрямую, через обход.
const noProxyFlag = "--no-proxy-server"

// envPath заменяет начало пути на переменную окружения (%LOCALAPPDATA% и т.п.):
// в .cmd-файле так не будет кириллицы из имени профиля, с которой cmd путается.
func envPath(p string, env map[string]string) string {
	for _, k := range []string{"LOCALAPPDATA", "APPDATA", "USERPROFILE"} {
		v := env[k]
		if v != "" && len(p) > len(v) && strings.EqualFold(p[:len(v)], v) && (p[len(v)] == '\\' || p[len(v)] == '/') {
			return "%" + k + "%" + p[len(v):]
		}
	}
	return p
}

// directScript — .cmd, который запускает Discord с флагом. Запускаем его через проводник,
// чтобы Discord стартовал с правами пользователя, а не администратора.
func directScript(l discordLaunch, env map[string]string) string {
	var cmd string
	if l.updater != "" {
		cmd = fmt.Sprintf(`start "" "%s" --processStart "%s" --process-start-args "%s"`, envPath(l.updater, env), l.exeName, noProxyFlag)
	} else {
		cmd = fmt.Sprintf(`start "" "%s" %s`, envPath(l.exePath, env), noProxyFlag)
	}
	head := "@echo off\r\n"
	for _, r := range cmd {
		if r > 127 { // остался не-ASCII путь — переключаем консоль на UTF-8
			head += "chcp 65001 >nul\r\n"
			break
		}
	}
	return head + cmd + "\r\n"
}

func (a *App) launchDiscordDirect(l discordLaunch) error {
	if l.updater == "" && l.exePath == "" {
		return fmt.Errorf("не нашёл Update.exe Discord — запустить его мимо прокси не получится")
	}
	env := map[string]string{}
	for _, k := range []string{"LOCALAPPDATA", "APPDATA", "USERPROFILE"} {
		env[k] = os.Getenv(k)
	}
	// TEMP пользователя: проводник (без прав администратора) должен суметь прочитать файл
	p := filepath.Join(os.TempDir(), "gust-discord.cmd")
	if err := os.WriteFile(p, []byte(directScript(l, env)), 0o644); err != nil {
		return err
	}
	platform.OpenFileAsUser(p)
	return nil
}

func (a *App) discordState(stale bool) discordOut {
	a.mu.Lock()
	ch := a.dchecks
	ch.Results = append([]CheckResult(nil), a.dchecks.Results...)
	a.mu.Unlock()
	out := discordOut{Checks: ch, Targets: a.scopeTargets("discord")}
	if runtime.GOOS == "windows" {
		out.Running = a.cachedBool("discordrun", 10*time.Second, stale, func() bool { return len(platform.FindProcs(discordImages()...)) > 0 })
	}
	return out
}
