//go:build !windows

package platform

import "errors"

// Заглушки: окно и трей есть только в Windows.

func AllowForeground() {}
func StartWindow(string, string, string) (*Child, error) {
	return nil, errors.New("окно работает только в Windows")
}
func RunWindow(string, string, uint32) int  { return ExitNoWindow }
func TrayNotice(string, string)             {}
func RunTray(string, func(), func()) func() { return func() {} }

func FocusWindow(uint32) {}
