package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Собственные стратегии Gust («GU-xx»).
//
// Готовые .bat из сборки покрывают самые частые случаи, но у каждого провайдера DPI устроен по-своему.
// Здесь собирается расширенный набор вариантов: другие способы дробления ClientHello, другие «фейки»,
// другие приёмы маскировки (fooling) и разные полезные нагрузки для голоса Discord по UDP.
// Гарантии, что какой-то из них пробьёт конкретного провайдера, нет — отбирает автоподбор на самой машине.
//
// Все параметры взяты из документации zapret (nfqws/winws). Файлы из bin/ и списки из lists/ подставляются
// только если они реально есть в сборке, иначе вариант собирается без них или пропускается.

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func nz(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

type fileSet struct{ root string }

// pickBin возвращает первый файл bin/<glob>, в имени которого есть prefer (пусто — любой).
func (f fileSet) pickBin(glob, prefer string) string {
	ms, _ := filepath.Glob(filepath.Join(f.root, "bin", glob))
	sort.Strings(ms)
	for _, m := range ms {
		if prefer == "" || strings.Contains(strings.ToLower(filepath.Base(m)), prefer) {
			return m
		}
	}
	return ""
}

func (f fileSet) list(name string) string {
	p := filepath.Join(f.root, "lists", name)
	if exists(p) {
		return p
	}
	return ""
}

// hostArgs — списки сайтов, к которым применяется правило. Пользовательские списки подключаются всегда
// (ensureLists создаст пустую заглушку), чтобы добавленные пользователем сайты тоже обрабатывались.
func (f fileSet) hostArgs(withGoogle bool) []string {
	var out []string
	add := func(flag, name string, always bool) {
		p := f.list(name)
		if p == "" && always {
			p = filepath.Join(f.root, "lists", name)
		}
		if p != "" {
			out = append(out, flag+"="+p)
		}
	}
	add("--hostlist", "list-general.txt", false)
	add("--hostlist", "list-general-user.txt", true)
	if withGoogle {
		add("--hostlist", "list-google.txt", false)
	}
	add("--hostlist-exclude", "list-exclude.txt", false)
	add("--hostlist-exclude", "list-exclude-user.txt", true)
	return out
}

type tcpVariant struct {
	name  string
	args  []string
	needs string // "G" — нужен tls_clienthello_www_google_com.bin, "Y" — tls_clienthello_4pda_to.bin
}

// Порядок = примерная вероятность успеха: сначала приёмы, которые чаще всего работают у российских провайдеров.
var tcpVariants = []tcpVariant{
	{"fake+fakedsplit ts", []string{"--dpi-desync=fake,fakedsplit", "--dpi-desync-split-pos=1", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"}, ""},
	{"fake+hostfakesplit ya.ru", []string{"--dpi-desync=fake,hostfakesplit", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=ya.ru", "--dpi-desync-hostfakesplit-mod=host=ya.ru", "--dpi-desync-fooling=md5sig", "--dpi-desync-autottl=2", "--dpi-desync-repeats=4"}, ""},
	{"fake+multidisorder badseq", []string{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=6"}, ""},
	{"fake+multidisorder md5sig", []string{"--dpi-desync=fake,multidisorder", "--dpi-desync-split-pos=1,midsld", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=6"}, ""},
	{"multisplit seqovl 652 (google)", []string{"--dpi-desync=multisplit", "--dpi-desync-split-seqovl=652", "--dpi-desync-split-pos=2", "--dpi-desync-split-seqovl-pattern={G}"}, "G"},
	{"multisplit seqovl 568 (4pda)", []string{"--dpi-desync=multisplit", "--dpi-desync-split-seqovl=568", "--dpi-desync-split-pos=2", "--dpi-desync-split-seqovl-pattern={Y}"}, "Y"},
	{"multisplit sni", []string{"--dpi-desync=multisplit", "--dpi-desync-split-pos=1,sniext+1,midsld"}, ""},
	{"fakedsplit md5sig autottl", []string{"--dpi-desync=fakedsplit", "--dpi-desync-split-pos=midsld", "--dpi-desync-fooling=md5sig", "--dpi-desync-autottl=2"}, ""},
	{"fakeddisorder badseq", []string{"--dpi-desync=fakeddisorder", "--dpi-desync-split-pos=midsld", "--dpi-desync-fooling=badseq"}, ""},
	{"fake autottl", []string{"--dpi-desync=fake", "--dpi-desync-autottl=2", "--dpi-desync-repeats=6"}, ""},
	{"fake md5sig", []string{"--dpi-desync=fake", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=8"}, ""},
	{"fake ts", []string{"--dpi-desync=fake", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"}, ""},
	{"fake badseq", []string{"--dpi-desync=fake", "--dpi-desync-fooling=badseq", "--dpi-desync-repeats=8"}, ""},
	{"fake файл google md5sig", []string{"--dpi-desync=fake", "--dpi-desync-fake-tls={G}", "--dpi-desync-fooling=md5sig", "--dpi-desync-autottl=2", "--dpi-desync-repeats=6"}, "G"},
	{"fake padencap ts", []string{"--dpi-desync=fake", "--dpi-desync-fake-tls-mod=rnd,dupsid,padencap", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"}, ""},
	{"fake sni google md5sig", []string{"--dpi-desync=fake", "--dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=6"}, ""},
	{"syndata+multisplit", []string{"--dpi-desync=syndata,multisplit", "--dpi-desync-split-pos=1,midsld"}, ""},
	{"syndata+fake ts", []string{"--dpi-desync=syndata,fake", "--dpi-desync-fooling=ts", "--dpi-desync-repeats=6"}, ""},
	{"hostfakesplit google ts", []string{"--dpi-desync=hostfakesplit", "--dpi-desync-hostfakesplit-mod=host=www.google.com", "--dpi-desync-fooling=ts"}, ""},
	{"fakedsplit sniext badseq", []string{"--dpi-desync=fakedsplit", "--dpi-desync-split-pos=sniext+1", "--dpi-desync-fooling=badseq"}, ""},
	{"multidisorder", []string{"--dpi-desync=multidisorder", "--dpi-desync-split-pos=1,midsld"}, ""},
	{"wssize+multisplit", []string{"--wssize=1:6", "--wssize-cutoff=d3", "--dpi-desync=multisplit", "--dpi-desync-split-pos=1,midsld"}, ""},
	{"wssize+fake md5sig", []string{"--wssize=1:6", "--wssize-cutoff=d3", "--dpi-desync=fake", "--dpi-desync-fooling=md5sig", "--dpi-desync-repeats=6"}, ""},
	{"fake ttl 6", []string{"--dpi-desync=fake", "--dpi-desync-ttl=6", "--dpi-desync-repeats=6"}, ""},
}

func subst(args []string, g, y string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		a = strings.ReplaceAll(a, "{G}", g)
		out[i] = strings.ReplaceAll(a, "{Y}", y)
	}
	return out
}

func join(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// builtinStrategies собирает наш набор поверх распакованной сборки. nil — если собрать не из чего.
func builtinStrategies(root, exe string) []Strategy {
	f := fileSet{root}
	if f.list("list-general.txt") == "" || !exists(exe) {
		return nil
	}
	g := f.pickBin("tls_clienthello*.bin", "www_google")
	y := f.pickBin("tls_clienthello*.bin", "4pda")
	q := nz(f.pickBin("quic_initial*.bin", "www_google"), f.pickBin("quic_initial*.bin", ""))
	s := f.pickBin("stun*.bin", "")

	// варианты полезной нагрузки для голоса Discord (UDP); чередуем по стратегиям
	voice := [][]string{{"--dpi-desync=fake", "--dpi-desync-repeats=6"}}
	if q != "" {
		voice = append(voice, []string{"--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fake-discord=" + q, "--dpi-desync-fake-stun=" + q})
	}
	if s != "" {
		voice = append(voice, []string{"--dpi-desync=fake", "--dpi-desync-repeats=8", "--dpi-desync-fake-discord=" + s, "--dpi-desync-fake-stun=" + s})
	}

	var out []Strategy
	n := 0
	for _, v := range tcpVariants {
		if (v.needs == "G" && g == "") || (v.needs == "Y" && y == "") {
			continue
		}
		tcp := subst(v.args, g, y)
		var blocks [][]string
		if q != "" { // QUIC (YouTube по UDP 443)
			blocks = append(blocks, join([]string{"--filter-udp=443"}, f.hostArgs(true),
				[]string{"--dpi-desync=fake", "--dpi-desync-repeats=6", "--dpi-desync-fake-quic=" + q}))
		}
		blocks = append(blocks,
			// голос Discord
			join([]string{"--filter-udp=19294-19344,50000-50100", "--filter-l7=discord,stun"}, voice[n%len(voice)]),
			// голосовые серверы Discord по TCP
			join([]string{"--filter-tcp=2053,2083,2087,2096,8443", "--hostlist-domains=discord.media"}, tcp),
			// основной HTTPS
			join([]string{"--filter-tcp=443"}, f.hostArgs(true), tcp),
			// HTTP
			join([]string{"--filter-tcp=80"}, f.hostArgs(false),
				[]string{"--dpi-desync=fake,multisplit", "--dpi-desync-split-pos=method+2", "--dpi-desync-fooling=md5sig"}),
		)
		args := []string{"--wf-tcp=80,443,2053,2083,2087,2096,8443", "--wf-udp=443,19294-19344,50000-50100"}
		for i, b := range blocks {
			if i > 0 {
				args = append(args, "--new")
			}
			args = append(args, b...)
		}
		n++
		out = append(out, Strategy{Name: fmt.Sprintf("GU-%02d %s", n, v.name), Exe: exe, Args: args})
	}
	return out
}
