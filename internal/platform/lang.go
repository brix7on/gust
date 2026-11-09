package platform

import "strings"

// Подписи меню в трее, задаются приложением под выбранный язык.
var TrayOpen, TrayQuit = "Открыть Gust", "Выход"

// russianUI — языки, для которых интерфейс показывается по-русски.
func russianUI(primary uint16) bool {
	switch primary {
	case 0x19, 0x22, 0x23, 0x3f: // ru, uk, be, kk
		return true
	}
	return false
}

func langFromEnv(v string) string {
	v = strings.ToLower(v)
	for _, p := range []string{"ru", "uk", "be", "kk"} {
		if strings.HasPrefix(v, p) {
			return "ru"
		}
	}
	return "en"
}
