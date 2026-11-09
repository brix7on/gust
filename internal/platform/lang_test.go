package platform

import "testing"

func TestLang(t *testing.T) {
	for in, want := range map[string]string{"ru_RU.UTF-8": "ru", "uk_UA": "ru", "en_US.UTF-8": "en", "de_DE": "en", "kk_KZ": "ru", "C": "en"} {
		if got := langFromEnv(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	if !russianUI(0x0419&0x3ff) || russianUI(0x0409&0x3ff) {
		t.Fatal("LANGID")
	}
}
