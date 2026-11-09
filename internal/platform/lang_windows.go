//go:build windows

package platform

import "syscall"

// UILang — язык интерфейса Windows: "ru" или "en".
func UILang() string {
	r, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultUILanguage").Call()
	if russianUI(uint16(r) & 0x3ff) {
		return "ru"
	}
	return "en"
}
