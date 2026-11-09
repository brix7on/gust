package app

import (
	"os"
	"testing"
)

func TestRepoStrategiesJSON(t *testing.T) {
	b, err := os.ReadFile("../../strategies.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, list, err := parseRemote(b); err != nil || len(list) == 0 {
		t.Fatalf("strategies.json: %v", err)
	}
}

func TestParseRemoteRejects(t *testing.T) {
	for _, s := range []string{
		`{"tcp":[]}`,
		`{"tcp":[{"name":"a","args":["--hostlist=C:\\x"]}]}`,
		`{"tcp":[{"name":"a","args":["--dpi-desync=fake & calc"]}]}`,
		`{"tcp":[{"name":"a","args":["--dpi-desync-fooling=ts"]}]}`,
		`{"tcp":[{"name":"a","args":["--dpi-desync=fake"]},{"name":"a","args":["--dpi-desync=fake"]}]}`,
		`{"tcp":[{"name":"a","args":["--dpi-desync=fake","--dpi-desync-fake-tls={X}"]}]}`,
		`{"tcp":[{"name":"a","needs":"Z","args":["--dpi-desync=fake"]}]}`,
	} {
		if _, _, err := parseRemote([]byte(s)); err == nil {
			t.Errorf("принял: %s", s)
		}
	}
}

func TestGuKey(t *testing.T) {
	if guKey("GU-05 fake ts") != "fake ts" || guKey(TwinPrefix+"GU-12 fake ts") != TwinPrefix+"fake ts" || guKey("general") != "" {
		t.Fatal("guKey")
	}
}
