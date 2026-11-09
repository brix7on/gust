// Команда gust: разбор флагов и запуск приложения. Вся логика — в internal/app.
package main

import (
	"flag"
	"os"

	"gust/internal/app"
	"gust/internal/platform"
)

func main() {
	opt := app.Options{}
	flag.BoolVar(&opt.Background, "background", false, "не открывать окно при запуске, только значок в трее (для автозапуска)")
	flag.BoolVar(&opt.NoAdmin, "no-admin", false, "не требовать права администратора (для отладки)")
	flag.BoolVar(&opt.AfterUpdate, "after-update", false, "служебный: запуск после самообновления")
	flag.IntVar(&opt.Port, "port", app.DefaultPort, "порт локального интерфейса")
	flag.StringVar(&opt.DataDir, "data", app.DefaultDataDir(), "папка с данными")
	// служебные ключи: эта же программа, запущенная как окно интерфейса (его открывает основная копия)
	window := flag.String("window", "", "служебный: открыть окно интерфейса по адресу")
	wdata := flag.String("wdata", "", "служебный: папка данных окна")
	parent := flag.Int("parent", 0, "служебный: PID основной копии")
	flag.Parse()
	if *window != "" {
		os.Exit(platform.RunWindow(*window, *wdata, uint32(*parent)))
	}
	app.Run(opt)
}
