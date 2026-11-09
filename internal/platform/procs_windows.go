//go:build windows

package platform

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Proc — запущенный процесс.
type Proc struct {
	PID  uint32
	Name string
	Exe  string // полный путь; "" — если Windows не дала его прочитать
}

var procQueryName = syscall.NewLazyDLL("kernel32.dll").NewProc("QueryFullProcessImageNameW")

const (
	processTerminate               = 0x0001
	processQueryLimitedInformation = 0x1000
)

func exePath(pid uint32) string {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, pid)
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	r, _, _ := procQueryName.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}

// FindProcs ищет процессы по именам образов (без учёта регистра).
func FindProcs(images ...string) []Proc {
	want := map[string]bool{}
	for _, im := range images {
		want[strings.ToLower(im)] = true
	}
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var out []Proc
	for err = syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		name := syscall.UTF16ToString(e.ExeFile[:])
		if want[strings.ToLower(name)] {
			out = append(out, Proc{PID: e.ProcessID, Name: name, Exe: exePath(e.ProcessID)})
		}
	}
	return out
}

// KillPID завершает процесс.
func KillPID(pid uint32) error {
	h, err := syscall.OpenProcess(processTerminate, false, pid)
	if err != nil {
		return fmt.Errorf("PID %d: %w", pid, err)
	}
	defer syscall.CloseHandle(h)
	if err := syscall.TerminateProcess(h, 0); err != nil {
		return fmt.Errorf("PID %d: %w", pid, err)
	}
	return nil
}
