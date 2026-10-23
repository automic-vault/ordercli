package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steipete/ordercli/internal/config"
)

func TestAuthedRefreshKeepsTokenAndSaves(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)

	path := filepath.Join(t.TempDir(), "config.json")
	stored := &config.FoodoraConfig{
		BaseURL:       srv.URL + "/",
		AccessToken:   "old-access",
		RefreshToken:  "old-refresh",
		ExpiresAt:     time.Now().Add(-time.Hour),
		OAuthClientID: "android",
		ClientSecret:  "sec",
	}
	if err := config.Save(path, config.Config{Version: 1, Providers: config.Providers{Foodora: stored}}); err != nil {
		t.Fatal(err)
	}
	st := &state{}
	st.configPath = path
	if err := st.load(); err != nil {
		t.Fatal(err)
	}
	if _, err := newAuthedClient(st); err != nil {
		t.Fatal(err)
	}
	if got := st.foodora().RefreshToken; got != "old-refresh" {
		t.Fatalf("refresh token = %q; want old-refresh", got)
	}
	if got := st.foodora().AccessToken; got != "new-access" {
		t.Fatalf("access token = %q; want new-access", got)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got := reloaded.Foodora()
	if got.AccessToken != "new-access" || got.RefreshToken != "old-refresh" {
		t.Fatalf("saved access=%q refresh=%q; want new-access and old-refresh", got.AccessToken, got.RefreshToken)
	}
}

func TestOrdersRefreshSurvivesRequestFailure(t *testing.T) {
	for _, tc := range []struct{ name, response, refresh string }{
		{"omitted", `{"access_token":"new-access","expires_in":3600}`, "old-refresh"},
		{"rotated", `{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`, "new-refresh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var refreshes, orders atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/oauth2/token":
					refreshes.Add(1)
					if err := r.ParseForm(); err != nil || r.FormValue("refresh_token") != "old-refresh" {
						t.Error("refresh request did not use the stored token")
					}
					_, _ = w.Write([]byte(tc.response))
				case "/tracking/active-orders":
					if r.Header.Get("Authorization") != "Bearer new-access" {
						t.Error("request did not use refreshed access token")
					}
					if orders.Add(1) == 1 {
						http.Error(w, "synthetic downstream failure", http.StatusBadGateway)
						return
					}
					_, _ = w.Write([]byte(`{"status":200,"data":{"active_orders":[]}}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			path := filepath.Join(t.TempDir(), "config.json")
			stored := config.Config{Version: 1, Providers: config.Providers{
				Foodora:   &config.FoodoraConfig{BaseURL: srv.URL + "/", DeviceID: "synthetic-device", AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresAt: time.Now().Add(-time.Hour), OAuthClientID: "android", ClientSecret: "synthetic-secret"},
				Deliveroo: &config.DeliverooConfig{Market: "uk"},
				Glovo:     &config.GlovoConfig{CityCode: "MAD"},
			}}
			if err := config.Save(path, stored); err != nil {
				t.Fatal(err)
			}
			if _, _, err := runCLI(path, []string{"foodora", "orders"}, ""); err == nil {
				t.Fatal("expected downstream request failure")
			}
			saved, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if saved.Foodora().AccessToken != "new-access" || saved.Foodora().RefreshToken != tc.refresh || !saved.Foodora().ExpiresAt.After(time.Now()) {
				t.Fatal("refreshed session was not saved before the failed request")
			}
			if saved.Foodora().DeviceID != "synthetic-device" || saved.Deliveroo().Market != "uk" || saved.Glovo().CityCode != "MAD" {
				t.Fatal("unrelated settings changed")
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatal("stored credentials are not private")
			}
			out, _, err := runCLI(path, []string{"foodora", "orders"}, "")
			if err != nil || !strings.Contains(out, "no active orders") {
				t.Fatalf("second command failed: %v", err)
			}
			if refreshes.Load() != 1 {
				t.Fatal("second command did not reuse the saved session")
			}
		})
	}
}
