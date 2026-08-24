package config

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoad_LegacyFoodoraConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.json")

	legacy := FoodoraConfig{
		BaseURL:         "https://hu.fd-api.com/api/v5/",
		AccessToken:     avMarker,
		RefreshToken:    avMarker,
		ClientSecret:    avMarker,
		PendingMfaToken: avMarker,
		CookiesByHost:   map[string]string{avMarker: avMarker},
	}
	b, _ := json.Marshal(legacy)
	stored, _ := json.Marshal(avCredentials{AccessToken: "a", RefreshToken: "r"})
	avTestStore.values[path] = stored
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Providers.Foodora == nil || cfg.Providers.Foodora.BaseURL != legacy.BaseURL {
		t.Fatalf("unexpected cfg: %#v", cfg)
	}
	if cfg.Providers.Foodora.DeviceID == "" {
		t.Fatalf("expected device id")
	}
}

func TestFoodoraConfig_HasSession_TokenLikelyExpired(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	c := FoodoraConfig{}
	if c.HasSession() {
		t.Fatalf("expected false")
	}
	c.AccessToken = "a"
	c.RefreshToken = "r"
	if !c.HasSession() {
		t.Fatalf("expected true")
	}

	c.ExpiresAt = now.Add(-time.Second)
	if !c.TokenLikelyExpired(now) {
		t.Fatalf("expected expired")
	}
	c.ExpiresAt = now.Add(10 * time.Minute)
	if c.TokenLikelyExpired(now) {
		t.Fatalf("expected not expired")
	}
}

func TestAccessTokenExpiresAt_FromJWT(t *testing.T) {
	payload := map[string]any{"exp": float64(123)}
	b, _ := json.Marshal(payload)
	tok := "x." + base64.RawURLEncoding.EncodeToString(b) + ".y"

	exp, ok := AccessTokenExpiresAt(tok)
	if !ok || exp.Unix() != 123 {
		t.Fatalf("exp=%v ok=%v", exp, ok)
	}
}

func TestDefaultPath(t *testing.T) {
	p, err := DefaultPath()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !strings.HasSuffix(p, string(filepath.Separator)+"ordercli"+string(filepath.Separator)+"config.json") {
		t.Fatalf("unexpected path: %q", p)
	}
}
