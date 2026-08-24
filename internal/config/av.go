package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
)

const avMarker = "@av"
const maxAVCredentialBytes = 256 * 1024

var avCredential = runAVCredential

// SetAVCredentialForTests replaces the process-local helper used by package tests.
func SetAVCredentialForTests(helper func(string, string, []byte) ([]byte, error)) {
	avCredential = helper
}

type avCredentials struct {
	AccessToken     string            `json:"access_token"`
	RefreshToken    string            `json:"refresh_token"`
	ClientSecret    string            `json:"client_secret"`
	PendingMfaToken string            `json:"pending_mfa_token"`
	CookiesByHost   map[string]string `json:"cookies_by_host"`
}

func (c avCredentials) validate() error {
	values := []string{c.AccessToken, c.RefreshToken, c.ClientSecret, c.PendingMfaToken}
	for _, value := range values {
		if bytes.IndexByte([]byte(value), 0) >= 0 {
			return errors.New("ordercli credentials contain NUL")
		}
	}
	for host, cookie := range c.CookiesByHost {
		if host == "" || cookie == "" || len(host) > 2048 || len(cookie) > 64*1024 ||
			bytes.IndexByte([]byte(host), 0) >= 0 || bytes.IndexByte([]byte(cookie), 0) >= 0 {
			return errors.New("ordercli cookies are invalid")
		}
	}
	if len(c.CookiesByHost) > 256 {
		return errors.New("ordercli has too many cookie hosts")
	}
	if c.empty() {
		return errors.New("ordercli credential bundle is empty")
	}
	return nil
}

func (c avCredentials) empty() bool {
	return c.AccessToken == "" && c.RefreshToken == "" && c.ClientSecret == "" &&
		c.PendingMfaToken == "" && len(c.CookiesByHost) == 0
}

func credentialsFromFoodora(foodora *FoodoraConfig) avCredentials {
	return avCredentials{
		AccessToken: foodora.AccessToken, RefreshToken: foodora.RefreshToken,
		ClientSecret: foodora.ClientSecret, PendingMfaToken: foodora.PendingMfaToken,
		CookiesByHost: foodora.CookiesByHost,
	}
}

func hydrateAV(path string, cfg *Config) error {
	foodora := cfg.Providers.Foodora
	if foodora == nil {
		return nil
	}
	credentials := credentialsFromFoodora(foodora)
	markers := foodora.AccessToken == avMarker || foodora.RefreshToken == avMarker ||
		foodora.ClientSecret == avMarker || foodora.PendingMfaToken == avMarker ||
		isCookieMarker(foodora.CookiesByHost)
	if !markers {
		if !credentials.empty() {
			return errors.New("plaintext ordercli credentials are disabled; run `av harden ordercli`")
		}
		return nil
	}
	if foodora.AccessToken != avMarker || foodora.RefreshToken != avMarker ||
		foodora.ClientSecret != avMarker || foodora.PendingMfaToken != avMarker ||
		!isCookieMarker(foodora.CookiesByHost) {
		return errors.New("ordercli credential state is only partially migrated")
	}
	raw, err := avCredential(path, "get", nil)
	if err != nil {
		return err
	}
	if len(raw) > maxAVCredentialBytes {
		return errors.New("ordercli credential bundle exceeds 256 KiB")
	}
	var stored avCredentials
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return fmt.Errorf("invalid Automic Vault ordercli credential: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid trailing ordercli credential data")
	}
	if err := stored.validate(); err != nil {
		return err
	}
	foodora.AccessToken = stored.AccessToken
	foodora.RefreshToken = stored.RefreshToken
	foodora.ClientSecret = stored.ClientSecret
	foodora.PendingMfaToken = stored.PendingMfaToken
	foodora.CookiesByHost = stored.CookiesByHost
	return nil
}

func prepareAV(path string, cfg Config) (Config, error) {
	foodora := cfg.Providers.Foodora
	if foodora == nil {
		return cfg, nil
	}
	credentials := credentialsFromFoodora(foodora)
	if credentials.empty() {
		if diskHasAVMarker(path) {
			if _, err := avCredential(path, "forget", nil); err != nil {
				return cfg, err
			}
		}
		return cfg, nil
	}
	if err := credentials.validate(); err != nil {
		return cfg, err
	}
	raw, err := json.Marshal(credentials)
	if err != nil {
		return cfg, err
	}
	if len(raw) > maxAVCredentialBytes {
		return cfg, errors.New("ordercli credential bundle exceeds 256 KiB")
	}
	if _, err := avCredential(path, "store", raw); err != nil {
		return cfg, err
	}
	copy := *foodora
	copy.AccessToken = avMarker
	copy.RefreshToken = avMarker
	copy.ClientSecret = avMarker
	copy.PendingMfaToken = avMarker
	copy.CookiesByHost = map[string]string{avMarker: avMarker}
	cfg.Providers.Foodora = &copy
	return cfg, nil
}

func diskHasAVMarker(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil {
		return false
	}
	foodoraRaw := raw
	if providersRaw, ok := root["providers"]; ok {
		var providers map[string]json.RawMessage
		if json.Unmarshal(providersRaw, &providers) != nil {
			return false
		}
		var ok bool
		foodoraRaw, ok = providers["foodora"]
		if !ok {
			return false
		}
	}
	var foodora FoodoraConfig
	return json.Unmarshal(foodoraRaw, &foodora) == nil &&
		(foodora.AccessToken == avMarker || foodora.RefreshToken == avMarker ||
			foodora.ClientSecret == avMarker || foodora.PendingMfaToken == avMarker ||
			isCookieMarker(foodora.CookiesByHost))
}

func isCookieMarker(cookies map[string]string) bool {
	return len(cookies) == 1 && cookies[avMarker] == avMarker
}

func runAVCredential(_ string, action string, input []byte) ([]byte, error) {
	cmd := exec.Command("/usr/local/bin/av", "ordercli-credential", action)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		return nil, errors.New("Automic Vault ordercli credential helper failed")
	}
	if len(output) > maxAVCredentialBytes+1 {
		return nil, errors.New("ordercli credential bundle exceeds 256 KiB")
	}
	return bytes.TrimSuffix(output, []byte("\n")), nil
}
