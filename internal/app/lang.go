package app

import "gust/internal/platform"

// lang — язык интерфейса: из настроек или из Windows.
func (a *App) lang() string {
	if l := a.settings().Lang; l == "ru" || l == "en" {
		return l
	}
	return platform.UILang()
}

func (a *App) applyTrayLang() {
	if a.lang() == "en" {
		platform.TrayOpen, platform.TrayQuit = "Open Gust", "Quit"
	} else {
		platform.TrayOpen, platform.TrayQuit = "Открыть Gust", "Выход"
	}
}
