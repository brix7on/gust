package platform

import "golang.org/x/sys/windows"

// DownloadsDir — папка «Загрузки» текущего пользователя
func DownloadsDir() string {
	p, err := windows.KnownFolderPath(windows.FOLDERID_Downloads, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return ""
	}
	return p
}
