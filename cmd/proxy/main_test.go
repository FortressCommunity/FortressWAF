package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/config"
)

// writeTestConfig writes a minimal config file returning an admin section
// with the given api_keys, and returns the path plus a ready config.Manager.
func writeTestConfig(t *testing.T, apiKeys []string) (*config.Manager, func()) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	var b strings.Builder
	b.WriteString("sites:\n  - name: test\n    domains: [localhost]\n    upstream: http://127.0.0.1:18081\n    waf_enabled: true\n")
	b.WriteString("admin:\n  enabled: true\n  port: 8443\n")
	for _, k := range apiKeys {
		b.WriteString("  api_keys:\n    - " + k + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfgMgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	return cfgMgr, func() { _ = cfgMgr.Close() }
}

func postLogin(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Regression test: logging in without configured API keys used to reach
// cfg.Admin.APIKeys[0] and panic, crashing the connection (the dashboard
// login page turned into a bare "connection reset").
func TestHandleAuthLogin_NoAPIKeys_Returns503(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, nil)
	defer cleanup()

	rec := postLogin(t, handleAuthLogin(cfgMgr), `{"email":"admin@example.com","password":"x"}`)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (credentials not configured), got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !strings.Contains(body["error"], "not configured") {
		t.Fatalf("unexpected error message: %q", body["error"])
	}
}

func TestHandleAuthLogin_ValidCredentials_ReturnsToken(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	rec := postLogin(t, handleAuthLogin(cfgMgr), `{"email":"admin@example.com","password":"demo-admin-key"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Token != "demo-admin-key" {
		t.Fatalf("expected token demo-admin-key, got %q", body.Token)
	}
}

func TestHandleAuthLogin_InvalidCredentials_Returns401(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	rec := postLogin(t, handleAuthLogin(cfgMgr), `{"email":"admin@example.com","password":"wrong"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAuthLogin_MalformedBody_Returns400(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	rec := postLogin(t, handleAuthLogin(cfgMgr), `{not json`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}
