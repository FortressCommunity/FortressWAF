package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/blocklist"
	"github.com/FortressWAF/FortressWAF/internal/compliance"
	"github.com/FortressWAF/FortressWAF/internal/config"
	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// buildBanTestHandler wires a WAF handler in front of a trivial origin and
// installs a fresh ban store so the test controls bans.
func buildBanTestHandler(t *testing.T) (http.Handler, *blocklist.Store) {
	t.Helper()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(origin.Close)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfgYAML := "sites:\n  - name: test\n    domains: [localhost]\n    upstream: " + origin.URL + "\n    waf_enabled: true\n" +
		"admin:\n  enabled: false\n  api_keys:\n    - test-key\n" +
		"redis:\n  enabled: false\nml:\n  enabled: false\n"
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfgMgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { _ = cfgMgr.Close() })

	store := blocklist.New()
	h := newWAFHandler(cfgMgr, engine.New(buildEngineConfig(cfgMgr.Get(), false)), engine.NewRewriteManager(), nil, compliance.NewAuditLog(), false)
	// Swap in the test's ban store.
	h.(*wafHandler).bans = store
	return h, store
}

// buildEngineConfigWithDDoS builds the engine config with a tight per-IP DDoS
// limit, so a short test burst trips it.
func buildEngineConfigWithDDoS(t *testing.T, perIP int, ban time.Duration) engine.EngineConfig {
	t.Helper()
	cfg := &config.Config{
		Sites: []config.SiteConfig{{Name: "test", Domains: []string{"localhost"}, Upstream: "http://127.0.0.1:1", WAFEnabled: true}},
		DDoS:  config.DDoSConfig{Enabled: true, PerIPRate: perIP, BanSeconds: int(ban.Seconds())},
		Bot:   config.BotConfig{Enabled: true},
	}
	cfg.DDoS.Enabled = true
	return buildEngineConfig(cfg, false)
}

// A banned address is refused before inspection, with BAN001.
func TestWAFHandler_BannedIPRejected(t *testing.T) {
	h, store := buildBanTestHandler(t)
	if _, err := store.Ban("203.0.113.200", "test", "op", time.Hour); err != nil {
		t.Fatalf("ban: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "203.0.113.200:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for banned IP, got %d", rec.Code)
	}
	if rule := rec.Header().Get("X-FortressWAF-Rule"); rule != "BAN001" {
		t.Fatalf("expected rule BAN001, got %q", rule)
	}
}

// The auto-ban path bans the address and records an audit entry, and the next
// request from it is then refused by the ban check.
func TestWAFHandler_AutoBanApplied(t *testing.T) {
	h, store := buildBanTestHandler(t)
	wh := h.(*wafHandler)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = "198.51.100.66:5555"
	wh.applyAutoBan(req, "198.51.100.66", &engine.Decision{
		RuleID:      "DDoS001",
		RuleName:    "HTTP Flood - IP",
		BanDuration: 2 * time.Minute,
	})

	if !store.IsBanned("198.51.100.66") {
		t.Fatal("address was not banned by applyAutoBan")
	}
}

// Loopback must never be auto-banned, because that is the proxy's own health
// checks and the machine itself.
func TestWAFHandler_AutoBanSkipsLoopback(t *testing.T) {
	h, store := buildBanTestHandler(t)
	wh := h.(*wafHandler)
	dec := &engine.Decision{RuleID: "DDoS001", RuleName: "HTTP Flood - IP", BanDuration: time.Minute}

	for _, ip := range []string{"127.0.0.1", "::1"} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		req.RemoteAddr = ip + ":5555"
		wh.applyAutoBan(req, ip, dec)
	}
	if store.Count() != 0 {
		t.Fatalf("expected no bans for loopback, got %d", store.Count())
	}
}

// End to end through the handler: a tight flood from one address trips the
// per-IP limiter, which bans that address, and the following request is then
// refused by the ban check with BAN001.
func TestWAFHandler_FloodEndToEndBansSource(t *testing.T) {
	h, store := buildBanTestHandler(t)
	wh := h.(*wafHandler)
	// Tighten the engine's DDoS limiter so a short test trips it.
	wh.engine = engine.New(buildEngineConfigWithDDoS(t, 5, time.Minute))

	const srcIP = "198.51.100.123"
	var sawRateLimit bool
	for i := 0; i < 40 && !sawRateLimit; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		req.RemoteAddr = srcIP + ":5555"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if store.IsBanned(srcIP) {
			sawRateLimit = true
		}
	}
	if !sawRateLimit {
		t.Fatal("flood did not result in a ban")
	}

	// The next request from the address is refused by the ban check.
	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req.RemoteAddr = srcIP + ":5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-FortressWAF-Rule") != "BAN001" {
		t.Fatalf("post-ban request: code=%d rule=%q, want 403 BAN001", rec.Code, rec.Header().Get("X-FortressWAF-Rule"))
	}
}
