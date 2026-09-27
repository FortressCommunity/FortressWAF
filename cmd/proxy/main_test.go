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

// /auth/me used to accept any bearer token and reflect it back as an admin
// identity; it must reject tokens that are not configured keys.
func TestHandleAuthMe_InvalidToken_Returns401(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer totally-fake-token")
	rec := httptest.NewRecorder()
	handleAuthMe(cfgMgr).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bogus token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAuthMe_ValidToken_Returns200(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer demo-admin-key")
	rec := httptest.NewRecorder()
	handleAuthMe(cfgMgr).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

// A key that shares a prefix with the real key must not be accepted.
func TestValidAPIKey_RejectsPartialKey(t *testing.T) {
	if validAPIKey("demo-admin", []string{"demo-admin-key"}) {
		t.Fatal("prefix of a valid key was accepted")
	}
	if validAPIKey("demo-admin-key-extra", []string{"demo-admin-key"}) {
		t.Fatal("extension of a valid key was accepted")
	}
	if validAPIKey("demo-admin-key", nil) {
		t.Fatal("key accepted when no keys are configured")
	}
}

// With no keys configured the middleware must deny, not serve the handler.
func TestAdminAuthMiddleware_NoKeys_FailsClosed(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, nil)
	defer cleanup()

	called := false
	mw := adminAuthMiddleware(cfgMgr)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if called {
		t.Fatal("protected handler was called with no keys configured")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when keys are unset, got %d", rec.Code)
	}
}

func TestAdminAuthMiddleware_InvalidKey_Forbidden(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	called := false
	mw := adminAuthMiddleware(cfgMgr)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if called {
		t.Fatal("protected handler was called with an invalid key")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

// CORS must not echo an unconfigured origin back.
func TestCORSMiddleware_UnlistedOrigin_NotAllowed(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()

	corsMiddleware(cfgMgr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unlisted origin was allowed: %q", got)
	}
}

func TestCORSMiddleware_ListedOrigin_Allowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := "sites:\n  - {name: test, domains: [localhost], upstream: http://127.0.0.1:1, waf_enabled: true}\n" +
		"admin:\n  enabled: true\n  port: 8443\n  api_keys: [k]\n  cors_origins: [http://localhost:3000]\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfgMgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer cfgMgr.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	corsMiddleware(cfgMgr)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("expected listed origin echoed, got %q", got)
	}
}

// Preflight must be answered for API paths that only register GET, otherwise
// the browser blocks the real request.
func TestPreflight_AllowedOrigin_Returns204WithCORSHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg := "sites:\n  - {name: test, domains: [localhost], upstream: http://127.0.0.1:1, waf_enabled: true}\n" +
		"admin:\n  enabled: true\n  port: 8443\n  api_keys: [k]\n  cors_origins: [http://localhost:3000]\n"
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfgMgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer cfgMgr.Close()

	router := newAdminRouter(cfgMgr, nil, nil, nil, 8443)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/status", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 preflight, got %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("expected ACAO for listed origin, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
		t.Fatalf("preflight must allow the Authorization header, got %q", got)
	}
}

func TestPreflight_UnlistedOrigin_NoAllowHeaders(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"k"})
	defer cleanup()

	router := newAdminRouter(cfgMgr, nil, nil, nil, 8443)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/audit", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unlisted origin got ACAO %q", got)
	}
}
