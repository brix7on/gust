//go:build windows

package platform

import "unsafe"

func ptr(p *uint16) unsafe.Pointer { return unsafe.Pointer(p) }
