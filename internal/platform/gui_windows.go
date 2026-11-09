//go:build windows

package platform

// Окно интерфейса (встроенный WebView2) и значок в трее. Всё на системных вызовах Windows,
// кроме самого окна — его даёт go-webview2 (без cgo, без сети, без запуска процессов).

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/webviewloader"
)

var (
	guiUser32   = syscall.NewLazyDLL("user32.dll")
	guiKernel32 = syscall.NewLazyDLL("kernel32.dll")
	guiShell32  = syscall.NewLazyDLL("shell32.dll")

	pCreateIcon         = guiUser32.NewProc("CreateIcon")
	pSendMessageW       = guiUser32.NewProc("SendMessageW")
	pPostMessageW       = guiUser32.NewProc("PostMessageW")
	pGetSystemMetrics   = guiUser32.NewProc("GetSystemMetrics")
	pSetProcessDPIAware = guiUser32.NewProc("SetProcessDPIAware")
	pRegisterClassExW   = guiUser32.NewProc("RegisterClassExW")
	pCreateWindowExW    = guiUser32.NewProc("CreateWindowExW")
	pDefWindowProcW     = guiUser32.NewProc("DefWindowProcW")
	pGetMessageW        = guiUser32.NewProc("GetMessageW")
	pTranslateMessage   = guiUser32.NewProc("TranslateMessage")
	pDispatchMessageW   = guiUser32.NewProc("DispatchMessageW")
	pPostQuitMessage    = guiUser32.NewProc("PostQuitMessage")
	pRegisterWindowMsgW = guiUser32.NewProc("RegisterWindowMessageW")
	pCreatePopupMenu    = guiUser32.NewProc("CreatePopupMenu")
	pAppendMenuW        = guiUser32.NewProc("AppendMenuW")
	pTrackPopupMenu     = guiUser32.NewProc("TrackPopupMenu")
	pDestroyMenu        = guiUser32.NewProc("DestroyMenu")
	pGetCursorPos       = guiUser32.NewProc("GetCursorPos")
	pSetForegroundWnd   = guiUser32.NewProc("SetForegroundWindow")
	pAllowSetForeground = guiUser32.NewProc("AllowSetForegroundWindow")
	pSetTimer           = guiUser32.NewProc("SetTimer")
	pKillTimer          = guiUser32.NewProc("KillTimer")
	pEnumWindows        = guiUser32.NewProc("EnumWindows")
	pGetWindowThreadPID = guiUser32.NewProc("GetWindowThreadProcessId")
	pGetClassNameW      = guiUser32.NewProc("GetClassNameW")
	pIsIconic           = guiUser32.NewProc("IsIconic")
	pShowWindow         = guiUser32.NewProc("ShowWindow")

	pGetModuleHandleW    = guiKernel32.NewProc("GetModuleHandleW")
	pOpenProcess         = guiKernel32.NewProc("OpenProcess")
	pWaitForSingleObject = guiKernel32.NewProc("WaitForSingleObject")

	pShellNotifyIconW = guiShell32.NewProc("Shell_NotifyIconW")
)

const (
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmNull          = 0x0000
	wmTimer         = 0x0113
	wmApp           = 0x8000
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 0x1
	nifIcon   = 0x2
	nifTip    = 0x4
	nifInfo   = 0x10

	trayCallbackMsg = wmApp + 1
	trayRetryTimer  = 1

	menuOpen = 1
	menuQuit = 2
)

// ---------- значок ----------

// iconPixels — значок: тёмный квадрат, разорванное кольцо и стрелка сквозь разрыв.
// Строки снизу вверх (формат CreateIcon), BGRA.
func iconPixels(size int) []byte {
	px := make([]byte, size*size*4)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			bg, fg := iconCover(size, x, y)
			o := ((size-1-y)*size + x) * 4
			r := 10 + (222-10)*fg
			g := 10 + (216-10)*fg
			b := 11 + (202-11)*fg
			px[o+0], px[o+1], px[o+2], px[o+3] = byte(b), byte(g), byte(r), byte(bg*255)
		}
	}
	return px
}

func makeIcon(size int) uintptr {
	if size < 16 {
		size = 16
	}
	stride := ((size + 15) / 16) * 2
	and := make([]byte, stride*size) // маска нулевая: рисуем цвет, прозрачность — из альфа-канала
	xor := iconPixels(size)
	h, _, _ := pCreateIcon.Call(0, uintptr(size), uintptr(size), 1, 32,
		uintptr(unsafe.Pointer(&and[0])), uintptr(unsafe.Pointer(&xor[0])))
	return h
}

func metric(idx uintptr, def int) int {
	v, _, _ := pGetSystemMetrics.Call(idx)
	if v == 0 {
		return def
	}
	return int(v)
}

// ---------- окно интерфейса ----------

// AllowForeground разрешает любому процессу вывести своё окно на передний план. Её зовёт вторая
// копия программы: у неё есть это право (пользователь только что её запустил), у первой — нет.
func AllowForeground() { _, _, _ = pAllowSetForeground.Call(0xFFFFFFFF) }

// StartWindow запускает окно интерфейса отдельным процессом (эта же программа с ключом --window).
func StartWindow(url, dataPath, logPath string) (*Child, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "--window", url, "--wdata", dataPath, "--parent", strconv.Itoa(os.Getpid()))
	// Ошибки окна (их пишет сама библиотека перед выходом) — в файл: у GUI-программы консоли нет.
	if f, ferr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); ferr == nil {
		cmd.Stderr = f
		defer f.Close()
	}
	return startChild(cmd)
}

// RunWindow — тело процесса-окна: открывает страницу во встроенном WebView2 и работает, пока
// окно не закроют. Возвращает код выхода.
func RunWindow(url, dataPath string, parentPID uint32) int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !strings.HasPrefix(url, "http://127.0.0.1:") { // окно показывает только нашу локальную страницу
		return ExitNoWindow
	}
	if ver, err := webviewloader.GetInstalledVersion(); err != nil || ver == "" {
		return ExitNoRuntime
	}
	_, _, _ = pSetProcessDPIAware.Call() // без этого Windows растягивает окно и текст мылится
	_ = os.MkdirAll(dataPath, 0o755)

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  dataPath,
		WindowOptions: webview2.WindowOptions{
			Title:  "Gust",
			Width:  1120,
			Height: 780,
			Center: true,
		},
	})
	if w == nil {
		return ExitNoWindow
	}
	hwnd := uintptr(w.Window())
	big := makeIcon(metric(11, 32))   // SM_CXICON
	small := makeIcon(metric(49, 16)) // SM_CXSMICON
	_, _, _ = pSendMessageW.Call(hwnd, 0x0080, 1, big)
	_, _, _ = pSendMessageW.Call(hwnd, 0x0080, 0, small)

	if parentPID != 0 {
		go func() {
			// Основная программа закрылась (или упала) — окно с мёртвой страницей не нужно.
			h, _, _ := pOpenProcess.Call(0x00100000, 0, uintptr(parentPID)) // SYNCHRONIZE
			if h == 0 {
				os.Exit(0)
			}
			_, _, _ = pWaitForSingleObject.Call(h, 0xFFFFFFFF)
			os.Exit(0)
		}()
	}

	w.Navigate(url)
	w.Run()
	return 0
}

var (
	focusMu    sync.Mutex
	focusPID   uint32
	focusFound uintptr
	focusEnum  = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		var pid uint32
		_, _, _ = pGetWindowThreadPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		if pid != focusPID {
			return 1
		}
		var cls [32]uint16
		_, _, _ = pGetClassNameW.Call(hwnd, uintptr(unsafe.Pointer(&cls[0])), uintptr(len(cls)))
		if syscall.UTF16ToString(cls[:]) != "webview" {
			return 1
		}
		focusFound = hwnd
		return 0
	})
)

// FocusWindow выводит окно процесса pid на передний план (разворачивает, если свёрнуто).
func FocusWindow(pid uint32) {
	focusMu.Lock()
	focusPID, focusFound = pid, 0
	_, _, _ = pEnumWindows.Call(focusEnum, 0)
	h := focusFound
	focusMu.Unlock()
	if h == 0 {
		return
	}
	if r, _, _ := pIsIconic.Call(h); r != 0 {
		_, _, _ = pShowWindow.Call(h, 9) // SW_RESTORE
	} else {
		_, _, _ = pShowWindow.Call(h, 5) // SW_SHOW
	}
	_, _, _ = pSetForegroundWnd.Call(h)
}

// ---------- значок в трее ----------

type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         [16]byte
	HBalloonIcon     uintptr
}

// Размер структуры в 64-разрядной Windows — 976 байт; если не сойдётся, сборка остановится здесь.
var (
	_ [unsafe.Sizeof(notifyIconData{}) - 976]byte
	_ [976 - unsafe.Sizeof(notifyIconData{})]byte
)

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

var (
	_ [unsafe.Sizeof(wndClassEx{}) - 80]byte
	_ [80 - unsafe.Sizeof(wndClassEx{})]byte
)

type guiMsg struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	PtX     int32
	PtY     int32
}

var tray struct {
	nid        notifyIconData
	taskbarMsg uint32
	onOpen     func()
	onQuit     func()

	mu    sync.Mutex // added/title/text трогают из двух потоков
	added bool       // значок уже стоит в трее
	title string     // уведомление, ждущее, пока значок появится
	text  string
}

var trayProcCB = syscall.NewCallback(trayProc)

func trayAdd() bool {
	r, _, _ := pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&tray.nid)))
	if r == 0 {
		return false
	}
	tray.mu.Lock()
	title, text := tray.title, tray.text
	tray.title, tray.text = "", ""
	tray.added = true
	tray.mu.Unlock()
	if text != "" {
		trayBalloon(title, text)
	}
	return true
}

func trayBalloon(title, text string) {
	nid := tray.nid // копия: основную структуру трогает только поток трея
	nid.UFlags = nifInfo
	for i, c := range syscall.StringToUTF16(text) {
		if i >= len(nid.SzInfo)-1 {
			break
		}
		nid.SzInfo[i] = c
	}
	for i, c := range syscall.StringToUTF16(title) {
		if i >= len(nid.SzInfoTitle)-1 {
			break
		}
		nid.SzInfoTitle[i] = c
	}
	nid.DwInfoFlags = 1 // NIIF_INFO
	_, _, _ = pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

// TrayNotice показывает всплывающее уведомление у значка в трее. Если значок ещё не поставлен
// (проводник не поднялся после входа в систему), уведомление покажется, когда он появится.
func TrayNotice(title, text string) {
	tray.mu.Lock()
	if !tray.added {
		tray.title, tray.text = title, text
		tray.mu.Unlock()
		return
	}
	tray.mu.Unlock()
	trayBalloon(title, text)
}

func trayProc(hwnd, msg, wp, lp uintptr) uintptr {
	switch uint32(msg) {
	case trayCallbackMsg:
		switch uint32(lp) {
		case wmLButtonUp, wmLButtonDblClk:
			if f := tray.onOpen; f != nil {
				go f()
			}
		case wmRButtonUp:
			trayMenu(hwnd)
		}
		return 0
	case wmTimer:
		if trayAdd() {
			_, _, _ = pKillTimer.Call(hwnd, trayRetryTimer)
		}
		return 0
	case wmDestroy:
		_, _, _ = pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&tray.nid)))
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	if tray.taskbarMsg != 0 && uint32(msg) == tray.taskbarMsg {
		trayAdd() // проводник перезапустился — значок надо вернуть
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, msg, wp, lp)
	return r
}

func trayMenu(hwnd uintptr) {
	menu, _, _ := pCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer pDestroyMenu.Call(menu)
	open, _ := syscall.UTF16PtrFromString(TrayOpen)
	quit, _ := syscall.UTF16PtrFromString(TrayQuit)
	_, _, _ = pAppendMenuW.Call(menu, 0, menuOpen, uintptr(unsafe.Pointer(open)))
	_, _, _ = pAppendMenuW.Call(menu, 0, menuQuit, uintptr(unsafe.Pointer(quit)))
	var pt struct{ X, Y int32 }
	_, _, _ = pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = pSetForegroundWnd.Call(hwnd) // иначе меню не закрывается кликом мимо
	// TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN
	cmd, _, _ := pTrackPopupMenu.Call(menu, 0x0100|0x0002|0x0020, uintptr(int(pt.X)), uintptr(int(pt.Y)), 0, hwnd, 0)
	_, _, _ = pPostMessageW.Call(hwnd, wmNull, 0, 0)
	switch cmd {
	case menuOpen:
		if f := tray.onOpen; f != nil {
			go f()
		}
	case menuQuit:
		if f := tray.onQuit; f != nil {
			go f()
		}
	}
}

// RunTray ставит значок в трей: щелчок — открыть окно, меню по правой кнопке — «Открыть» и «Выход».
// Возвращает функцию, которая убирает значок.
func RunTray(tip string, onOpen, onQuit func()) (stop func()) {
	ready := make(chan uintptr, 1)
	go func() {
		runtime.LockOSThread()
		_, _, _ = pSetProcessDPIAware.Call()
		hInst, _, _ := pGetModuleHandleW.Call(0)
		className, _ := syscall.UTF16PtrFromString("GustTray")
		wc := wndClassEx{
			CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
			LpfnWndProc:   trayProcCB,
			HInstance:     hInst,
			LpszClassName: className,
		}
		_, _, _ = pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
		// Обычное скрытое окно, а не message-only: только такое получает «TaskbarCreated».
		hwnd, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)),
			0, 0, 0, 0, 0, 0, 0, hInst, 0)
		if hwnd == 0 {
			ready <- 0
			return
		}
		tray.onOpen, tray.onQuit = onOpen, onQuit
		m, _, _ := pRegisterWindowMsgW.Call(uintptr(unsafe.Pointer(syscallStr("TaskbarCreated"))))
		tray.taskbarMsg = uint32(m)
		tray.nid.CbSize = uint32(unsafe.Sizeof(tray.nid))
		tray.nid.HWnd = hwnd
		tray.nid.UID = 1
		tray.nid.UFlags = nifMsg | nifIcon | nifTip
		tray.nid.UCallbackMessage = trayCallbackMsg
		tray.nid.HIcon = makeIcon(metric(49, 16))
		for i, c := range syscall.StringToUTF16(tip) {
			if i >= len(tray.nid.SzTip)-1 {
				break
			}
			tray.nid.SzTip[i] = c
		}
		if !trayAdd() {
			// проводник мог ещё не подняться (автозапуск сразу после входа) — пробуем позже
			_, _, _ = pSetTimer.Call(hwnd, trayRetryTimer, 5000, 0)
		}
		ready <- hwnd

		var msg guiMsg
		for {
			r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
			if int32(r) <= 0 {
				return
			}
			_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
			_, _, _ = pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
		}
	}()
	var hwnd uintptr
	select {
	case hwnd = <-ready:
	case <-time.After(3 * time.Second):
	}
	return func() {
		if hwnd != 0 {
			_, _, _ = pPostMessageW.Call(hwnd, wmClose, 0, 0)
			time.Sleep(100 * time.Millisecond) // дать убрать значок до выхода процесса
		}
	}
}

func syscallStr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}
