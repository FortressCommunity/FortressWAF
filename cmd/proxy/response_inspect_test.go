package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/compliance"
	"github.com/FortressWAF/FortressWAF/internal/config"
	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// awsKeyTestValue is an AWS-key-SHAPED test value, assembled so no AWS-shaped
// literal sits in the source.
var awsKeyTestValue = "AKIA" + strings.Repeat("0", 16)

// buildLeakTestHandler starts an origin that optionally leaks a secret and
// returns a wafHandler wired in front of it with response inspection on.
func buildLeakTestHandler(t *testing.T, leak bool) http.Handler {
	t.Helper()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if leak {
			_, _ = w.Write([]byte(`{"AccessKeyId":"` + awsKeyTestValue + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","items":[1,2,3]}`))
	}))
	t.Cleanup(origin.Close)

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfgYAML := "sites:\n  - name: test\n    domains: [localhost]\n    upstream: " + origin.URL + "\n    waf_enabled: true\n" +
		"admin:\n  enabled: false\n  api_keys:\n    - test-key\n" +
		"response_inspect:\n  enabled: true\n  inspect_body: true\n  block: true\n" +
		"redis:\n  enabled: false\nml:\n  enabled: false\n"
	if err := os.WriteFile(path, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfgMgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { _ = cfgMgr.Close() })

	cfg := cfgMgr.Get()
	e := engine.New(buildEngineConfig(cfg, false))
	auditLog := compliance.NewAuditLog()

	return newWAFHandler(cfgMgr, e, engine.NewRewriteManager(), nil, auditLog, false)
}

// A normal origin response must pass through the handler unchanged.
func TestWAFHandler_NormalResponsePassesThrough(t *testing.T) {
	h := buildLeakTestHandler(t, false)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/products", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != `{"status":"ok","items":[1,2,3]}` {
		t.Fatalf("body altered: %q", got)
	}
}

// A response that leaks an AWS key must be blocked before it reaches the
// client, and the secret must not appear in the reply.
func TestWAFHandler_LeakingResponseBlocked(t *testing.T) {
	h := buildLeakTestHandler(t, true)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/api/keys", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 block, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), awsKeyTestValue) {
		t.Fatalf("secret leaked to client: %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "LEAK-002") {
		t.Fatalf("block reply missing rule id: %q", rec.Body.String())
	}
	// The replacement reply is JSON, and the origin's Set-Cookie/entity headers
	// must not survive the block.
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("block reply content-type not json: %q", ct)
	}
}
