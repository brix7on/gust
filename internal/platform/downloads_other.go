//go:build !windows

package platform

func DownloadsDir() string { return "" }
