package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var avTestStore = struct {
	sync.Mutex
	values map[string][]byte
}{values: make(map[string][]byte)}

func init() {
	avCredential = func(path string, action string, input []byte) ([]byte, error) {
		avTestStore.Lock()
		defer avTestStore.Unlock()
		switch action {
		case "get":
			value, ok := avTestStore.values[path]
			if !ok {
				return nil, errors.New("missing test ordercli credential")
			}
			return append([]byte(nil), value...), nil
		case "store":
			avTestStore.values[path] = append([]byte(nil), input...)
			return nil, nil
		case "forget":
			delete(avTestStore.values, path)
			return nil, nil
		default:
			return nil, errors.New("unsupported test ordercli credential action")
		}
	}
}

func TestAVRoundTripNeverWritesPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := New()
	foodora := cfg.Foodora()
	foodora.AccessToken = "access-secret"
	foodora.RefreshToken = "refresh-secret"
	foodora.ClientSecret = "client-secret"
	foodora.CookiesByHost = map[string]string{"example.com": "cookie-secret"}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"access-secret", "refresh-secret", "client-secret", "cookie-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("plaintext credential written: %s", secret)
		}
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Foodora().AccessToken != "access-secret" || loaded.Foodora().CookiesByHost["example.com"] != "cookie-secret" {
		t.Fatal("credential did not round trip through custody")
	}
}
