//go:build windows

// Package platform собирает все вызовы, специфичные для ОС: права администратора,
// запуск/остановка процессов, драйвер WinDivert, автозапуск. Остальной код от ОС не зависит.
package platform

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
)

// HideWindow прячет консольное окно дочернего процесса (winws и системные утилиты).
func HideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

func runHidden(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	HideWindow(cmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// IsAdmin сообщает, запущены ли мы с правами администратора (нужны для WinDivert).
func IsAdmin() bool {
	r, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin").Call()
	return r != 0
}

// RelaunchAsAdmin перезапускает exe с запросом UAC. true — новая копия запущена.
func RelaunchAsAdmin(args []string) bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	var q []string
	for _, a := range args {
		q = append(q, syscall.EscapeArg(a))
	}
	params, _ := syscall.UTF16PtrFromString(strings.Join(q, " "))
	r, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0, uintptr(ptr(verb)), uintptr(ptr(file)), uintptr(ptr(params)), 0, 1)
	return r > 32
}

// KillWinws снимает процессы winws и gust-engine, оставшиеся от прошлого запуска.
func KillWinws() {
	_, _ = runHidden("taskkill", "/F", "/IM", "winws.exe")
	_, _ = runHidden("taskkill", "/F", "/IM", "gust-engine.exe")
}

// CleanupDivert останавливает драйвер WinDivert (как service.bat). Между пробами стратегий
// службу только останавливаем; удаляем (remove=true) лишь при выходе/переустановке —
// иначе быстрая смена стратегий упирается в «служба помечена на удаление».
func CleanupDivert(remove bool) {
	for _, s := range []string{"WinDivert", "WinDivert14"} {
		_, _ = runHidden("sc", "stop", s)
		if remove {
			_, _ = runHidden("sc", "delete", s)
		}
	}
}

// SecureDir оставляет доступ к папке только администраторам и SYSTEM: из неё запускаются
// exe с повышенными правами, и обычный пользователь не должен мочь подменить файл или подложить DLL.
func SecureDir(dir string) {
	_, _ = runHidden("icacls", dir, "/inheritance:r", "/grant:r",
		"*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
}

// KillByName снимает процесс по имени образа.
func KillByName(image string) { _, _ = runHidden("taskkill", "/F", "/IM", image) }

// ProcRunning сообщает, запущен ли процесс с таким именем образа.
func ProcRunning(image string) bool {
	out, err := runHidden("tasklist", "/FI", "IMAGENAME eq "+image, "/NH")
	return err == nil && strings.Contains(strings.ToLower(out), strings.ToLower(image))
}

// OpenBrowser открывает URL в браузере по умолчанию.
func OpenBrowser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// OpenAsUser открывает ссылку своего протокола (tg://) в программе, которая его обрабатывает.
// Через explorer.exe нельзя: ссылки с «?» и «&» он не понимает и открывает «Документы».
// Если Telegram уже запущен, ссылка уходит в него; если нет — он стартует от нашего имени.
func OpenAsUser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}

// OpenFileAsUser открывает файл (например, ярлык .lnk) через проводник — программа
// запускается с правами обычного пользователя, а не администратора, как Gust.
func OpenFileAsUser(path string) {
	_ = exec.Command("explorer.exe", path).Start()
}

// StartDetached запускает программу и не ждёт её.
func StartDetached(exe string, args ...string) {
	c := exec.Command(exe, args...)
	if c.Start() == nil {
		go func() { _ = c.Wait() }()
	}
}

// AutostartEnabled сообщает, заведена ли задача автозапуска с таким именем.
func AutostartEnabled(taskName string) bool {
	_, err := runHidden("schtasks", "/Query", "/TN", taskName)
	return err == nil
}

// SetAutostart включает/выключает автозапуск при входе в систему через планировщик задач.
func SetAutostart(taskName string, on bool) error {
	if !on {
		out, err := runHidden("schtasks", "/Delete", "/TN", taskName, "/F")
		if err != nil {
			return fmt.Errorf("%s", strings.TrimSpace(out))
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// XML вместо флагов schtasks: иначе задача получает лимит 72 часа, остановку на батарее
	// и рабочую папку System32.
	doc := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled><Delay>PT10S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="A"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="A"><Exec><Command>` + xmlEsc(exe) + `</Command><Arguments>--background</Arguments><WorkingDirectory>` + xmlEsc(filepath.Dir(exe)) + `</WorkingDirectory></Exec></Actions>
</Task>`
	// schtasks читает XML в UTF-16 LE с BOM
	u := utf16.Encode([]rune(doc))
	buf := []byte{0xFF, 0xFE}
	for _, c := range u {
		buf = append(buf, byte(c), byte(c>>8))
	}
	f, err := os.CreateTemp("", "nb-task-*.xml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, werr := f.Write(buf)
	f.Close()
	if werr != nil {
		return werr
	}
	out, err := runHidden("schtasks", "/Create", "/TN", taskName, "/XML", f.Name(), "/F")
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(out))
	}
	return nil
}

func xmlEsc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
