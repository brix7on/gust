package app

import (
	"archive/zip"
	"os"
)

func newZipWriter(f *os.File) func(name, content string) {
	zw := zip.NewWriter(f)
	return func(name, content string) {
		w, _ := zw.Create(name)
		_, _ = w.Write([]byte(content))
		_ = zw.Close()
	}
}
