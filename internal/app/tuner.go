package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Пакетные переменные — чтобы тесты могли подменять цели и тайминги.
var (
	checkTimeout    = 7 * time.Second // обычная проверка (кнопка, мониторинг, база без обхода)
	fastMin         = 3 * time.Second // быстрый отсев при подборе: нижняя граница
	fastMax         = 6 * time.Second // и верхняя (на медленном интернете отсев растягивается)
	settleAfterBoot = 1 * time.Second
	targetsOverride []Target
	internetProbe   = "https://ya.ru/"
)

type Target struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	URL   string `json:"url"`
}

type CheckResult struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Ms    int    `json:"ms"`
	Err   string `json:"err,omitempty"`
}

var allTargets = []Target{
	{"discord", "discord.com", "https://discord.com/api/v9/gateway"},
	{"discord", "gateway.discord.gg", "https://gateway.discord.gg/"},
	{"discord", "cdn.discordapp.com", "https://cdn.discordapp.com/"},
	{"discord", "updates.discord.com", "https://updates.discord.com/"},
	{"youtube", "youtube.com", "https://www.youtube.com/"},
	{"youtube", "i.ytimg.com", "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"},
	{"youtube", "googlevideo.com", "https://redirector.googlevideo.com/"},
}

func init() { allTargets = append(allTargets, serviceTargets()...) }

// extraTargets — проверяются только на вкладке своего сервиса и при подборе под него,
// в общий подбор не входят (чтобы он не становился дольше).
var extraTargets = []Target{
	{"discord", "media.discordapp.net", "https://media.discordapp.net/"},
}

// scopeTargets: "" — сервисы из настроек; иначе все цели одного сервиса.
func (a *App) scopeTargets(scope string) []Target {
	if scope == "" {
		return a.activeTargets()
	}
	src := append(append([]Target(nil), allTargets...), extraTargets...)
	if targetsOverride != nil {
		src = targetsOverride
	}
	var out []Target
	for _, t := range src {
		if t.Group == scope {
			out = append(out, t)
		}
	}
	return out
}

func (a *App) activeTargets() []Target {
	src := allTargets
	if targetsOverride != nil {
		src = targetsOverride
	}
	g := a.settings().Groups
	var out []Target
	for _, t := range src {
		if g[t.Group] {
			out = append(out, t)
		}
	}
	return out
}

// checkURL: успех = пришёл HTTP-ответ любого статуса и тело дочиталось без таймаута.
// DPI-блокировка проявляется зависанием/сбросом после ClientHello, а замедление — долгим телом.
func checkURL(parent context.Context, url string, timeout time.Duration) (bool, int, string) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	tr := &http.Transport{
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gust/"+Version)
	t0 := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return false, 0, shortErr(err)
	}
	defer resp.Body.Close()
	if _, err := io.CopyN(io.Discard, resp.Body, 200<<10); err != nil && err != io.EOF {
		return false, 0, shortErr(err)
	}
	return true, int(time.Since(t0) / time.Millisecond), ""
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "deadline exceeded") || strings.Contains(s, "timeout"):
		return "таймаут"
	case strings.Contains(s, "reset"):
		return "сброс соединения"
	case strings.Contains(s, "no such host") || strings.Contains(s, "lookup"):
		return "DNS не ответил"
	case strings.Contains(s, "refused"):
		return "отказ в соединении"
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// runChecks проверяет все цели одновременно, так что общее время = самая медленная цель (максимум timeout).
func runChecks(ctx context.Context, ts []Target, timeout time.Duration) []CheckResult {
	res := make([]CheckResult, len(ts))
	var wg sync.WaitGroup
	for i, t := range ts {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			ok, ms, e := checkURL(ctx, t.URL, timeout)
			res[i] = CheckResult{Group: t.Group, Name: t.Name, OK: ok, Ms: ms, Err: e}
		}(i, t)
	}
	wg.Wait()
	return res
}

func countOK(rs []CheckResult) int {
	n := 0
	for _, r := range rs {
		if r.OK {
			n++
		}
	}
	return n
}

func internetAlive() bool {
	ok, _, _ := checkURL(context.Background(), internetProbe, checkTimeout)
	return ok
}

func clampDur(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// tuneChecks — проверка стратегии в два этапа.
// 1) все цели разом с коротким таймаутом: безнадёжная стратегия отсеивается за секунды;
// 2) если хоть что-то открылось, медленным целям даём полный таймаут, чтобы не потерять рабочую,
// но медленную стратегию (YouTube под замедлением, плохой канал).
func tuneChecks(ctx context.Context, ts []Target, fast time.Duration) []CheckResult {
	res := runChecks(ctx, ts, fast)
	if countOK(res) == 0 {
		return res
	}
	var idx []int
	var retry []Target
	for i, r := range res {
		if !r.OK {
			idx = append(idx, i)
			retry = append(retry, ts[i])
		}
	}
	if len(retry) == 0 {
		return res
	}
	for k, r := range runChecks(ctx, retry, checkTimeout) {
		res[idx[k]] = r
	}
	return res
}

// CheckNow — ручная проверка по кнопке.
func (a *App) CheckNow() {
	a.mu.Lock()
	if a.checks.Running {
		a.mu.Unlock()
		return
	}
	a.checks.Running = true
	a.mu.Unlock()
	ts := a.activeTargets()
	rs := runChecks(context.Background(), ts, checkTimeout)
	alive := internetAlive()
	a.mu.Lock()
	a.checks = CheckState{Running: false, At: time.Now().Unix(), Internet: alive, Results: rs}
	a.mu.Unlock()
}

// startSelected запускает выбранную (или первую) стратегию и включает watchdog.
func (a *App) startSelected() error {
	strats := a.loadStrategies()
	if len(strats) == 0 {
		return fmt.Errorf("сборка zapret не установлена")
	}
	sel := a.settings().Selected
	pick := strats[0]
	alt := strings.TrimPrefix(sel, TwinPrefix)
	if alt == sel {
		alt = TwinPrefix + sel
	}
	found := false
	for _, s := range strats {
		if s.Name == sel {
			pick, found = s, true
			break
		}
	}
	for _, s := range strats {
		if !found && s.Name == alt {
			pick, found = s, true
		}
	}
	if !found {
		if k := guKey(sel); k != "" {
			for _, s := range strats {
				if guKey(s.Name) == k {
					pick = s
					break
				}
			}
		}
	}
	if err := a.eng.Start(pick, true); err != nil {
		return err
	}
	a.updateSettings(func(s *Settings) { s.Selected = pick.Name })
	return nil
}

// ---------- автоподбор ----------

func (a *App) tuning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tune.Running
}

// degraded: интернет есть, но больше половины выбранных сервисов не открываются.
func (a *App) degraded() bool {
	a.CheckNow()
	a.mu.Lock()
	ch := a.checks
	a.mu.Unlock()
	if !ch.Internet || len(ch.Results) == 0 {
		return false
	}
	return (len(ch.Results)-countOK(ch.Results))*2 > len(ch.Results)
}

func (a *App) setTune(f func(t *TuneState)) {
	a.mu.Lock()
	f(&a.tune)
	a.mu.Unlock()
}

func (a *App) startTune() error { return a.startTuneScope("") }

// startTuneScope: scope="" — подбор по сервисам из настроек, "discord" — только под Discord.
func (a *App) startTuneScope(scope string) error {
	a.mu.Lock()
	if a.tune.Running {
		a.mu.Unlock()
		return fmt.Errorf("подбор уже идёт")
	}
	a.tune = TuneState{Running: true, Scope: scope, Msg: "Подготовка…"}
	cancel := make(chan struct{})
	a.tuneCancel = cancel
	a.mu.Unlock()
	go a.runTune(cancel, scope)
	return nil
}

func (a *App) cancelTune() {
	a.mu.Lock()
	if a.tuneCancel != nil {
		select {
		case <-a.tuneCancel:
		default:
			close(a.tuneCancel)
		}
	}
	a.mu.Unlock()
}

func cancelled(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func (a *App) runTune(cancel chan struct{}, scope string) {
	finish := func(msg string) {
		a.setTune(func(t *TuneState) { t.Running = false; t.Current = ""; t.Msg = msg })
		a.logf("подбор: %s", msg)
	}
	strats := a.loadStrategies()
	if len(strats) == 0 {
		finish("сборка zapret не установлена")
		return
	}
	targets := a.scopeTargets(scope)
	if len(targets) == 0 {
		finish("не выбрано ни одного сервиса для проверки")
		return
	}
	a.eng.Stop()
	time.Sleep(500 * time.Millisecond)
	a.setTune(func(t *TuneState) {
		t.Total = len(strats)
		t.Msg = "Проверяю, что блокируется без обхода…"
	})

	netOK, latMs, _ := checkURL(context.Background(), internetProbe, checkTimeout)
	if !netOK {
		finish("нет интернета (ya.ru не открывается) — подбор невозможен")
		return
	}
	// быстрый отсев подстраиваем под скорость канала: ~4 отклика обычного сайта, но не меньше fastMin
	fast := clampDur(time.Duration(latMs)*time.Millisecond*4, fastMin, fastMax)
	a.logf("быстрый отсев: %s на стратегию", fast)
	base := runChecks(context.Background(), targets, checkTimeout)
	baseOK := countOK(base)
	a.logf("без обхода доступно %d из %d", baseOK, len(targets))
	if baseOK == len(targets) {
		a.updateSettings(func(s *Settings) {
			if s.Selected == "" {
				s.Selected = strats[0].Name
			}
			s.LastTune = time.Now().Unix()
		})
		_ = a.startSelected()
		finish("всё и так доступно без обхода; включил стратегию по умолчанию на случай голоса/UDP")
		return
	}

	bestIdx, bestScore := -1, baseOK
	for i, s := range strats {
		if cancelled(cancel) {
			a.eng.Stop()
			finish("подбор отменён")
			return
		}
		a.setTune(func(t *TuneState) {
			t.Idx = i + 1
			t.Current = s.Name
			t.Msg = fmt.Sprintf("Проверяю «%s» (%d из %d)…", s.Name, i+1, len(strats))
		})
		res := TuneResult{Strategy: s.Name, Total: len(targets)}
		if err := a.eng.Start(s, false); err != nil {
			res.Note = err.Error()
			a.setTune(func(t *TuneState) { t.Results = append(t.Results, res) })
			if strings.Contains(err.Error(), "WinDivert") || strings.Contains(err.Error(), "администратора") {
				a.eng.Stop()
				finish("не запускается драйвер: " + err.Error())
				return
			}
			continue
		}
		time.Sleep(settleAfterBoot)
		if !a.eng.Alive() {
			res.Note = "процесс завершился"
		} else {
			rs := tuneChecks(context.Background(), targets, fast)
			res.Passed = countOK(rs)
			var bad []string
			for _, r := range rs {
				if !r.OK {
					bad = append(bad, r.Name)
				}
			}
			if len(bad) > 0 {
				res.Note = "не открылись: " + strings.Join(bad, ", ")
			}
		}
		a.setTune(func(t *TuneState) { t.Results = append(t.Results, res) })
		a.logf("«%s»: %d из %d", s.Name, res.Passed, res.Total)
		if res.Passed > bestScore {
			bestScore, bestIdx = res.Passed, i
		}
		if res.Passed == res.Total {
			break
		}
	}
	a.eng.Stop()
	if bestIdx < 0 {
		finish("ни одна стратегия не помогла. Отключите VPN/другие обходчики, проверьте антивирус и DNS (лучше 1.1.1.1 или 8.8.8.8)")
		return
	}
	best := strats[bestIdx]
	a.updateSettings(func(s *Settings) { s.Selected = best.Name; s.LastTune = time.Now().Unix() })
	if err := a.eng.Start(best, true); err != nil {
		finish("лучшая стратегия не стартовала: " + err.Error())
		return
	}
	a.mu.Lock()
	a.failStreak = 0
	a.mu.Unlock()
	finish(fmt.Sprintf("выбрана «%s»: открывается %d из %d", best.Name, bestScore, len(targets)))
}

// healthLoop раз в пару минут проверяет доступность и при серии сбоев запускает переподбор.
func (a *App) healthLoop() {
	for {
		select {
		case <-a.quit:
			return
		case <-time.After(2 * time.Minute):
		}
		a.mu.Lock()
		busy := a.tune.Running
		a.mu.Unlock()
		if busy || !a.eng.Alive() {
			continue
		}
		bad := a.degraded()
		a.mu.Lock()
		if bad {
			a.failStreak++
		} else {
			a.failStreak = 0
		}
		streak := a.failStreak
		a.mu.Unlock()
		if streak >= 3 && a.settings().AutoRetune {
			a.logf("обход перестал работать — запускаю подбор заново")
			_ = a.startTune()
		}
	}
}
