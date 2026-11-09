//go:build !windows

package platform

import "os"

func UILang() string {
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return langFromEnv(v)
		}
	}
	return "en"
}
