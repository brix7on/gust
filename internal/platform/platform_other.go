//go:build !windows

// Package platform: заглушки для сборки и тестов вне Windows. В бою код работает только под Windows.
package platform

import (
	"fmt"
	"os/exec"
)

func HideWindow(*exec.Cmd)            {}
func IsAdmin() bool                   { return true }
func RelaunchAsAdmin([]string) bool   { return false }
func KillWinws()                      {}
func CleanupDivert(bool)              {}
func SecureDir(string)                {}
func KillByName(string)               {}
func ProcRunning(string) bool         { return false }
func OpenBrowser(string)              {}
func OpenAsUser(string)               {}
func OpenFileAsUser(string)           {}
func StartDetached(string, ...string) {}
func AutostartEnabled(string) bool    { return false }

func SetAutostart(string, bool) error {
	return fmt.Errorf("автозапуск работает только в Windows")
}

type Proc struct {
	PID  uint32
	Name string
	Exe  string
}

func FindProcs(...string) []Proc { return nil }
func KillPID(uint32) error       { return fmt.Errorf("только в Windows") }
