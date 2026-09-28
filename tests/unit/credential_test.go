package unit

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// credentialRequest builds a request as the proxy sees it: a real client
// address, a browser User-Agent, and parameters in the query string.
func credentialRequest(method, path, ip string, params map[string]string) *engine.RequestContext {
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	req := &http.Request{
		Method:     method,
		URL:        &url.URL{Path: path, RawQuery: q.Encode()},
		Header:     make(http.Header),
		Host:       "example.com",
		RemoteAddr: ip + ":44321",
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	return engine.NewRequestContext(req)
}

func credentialEngine(loginPaths []string) *engine.Engine {
	return engine.New(engine.EngineConfig{
		DevMode:    false,
		Credential: engine.NewCredentialProtection(false, 5, 300, 900, loginPaths),
	})
}

// TestFalsePositive_BrowsingBurstIsNotRateLimited guards the regression where
// brute-force protection counted every request from an IP. A browser fetches
// the page plus its CSS/JS in the same second, which tripped CRED006 by the
// third request and blocked ordinary users on every path.
func TestFalsePositive_BrowsingBurstIsNotRateLimited(t *testing.T) {
	e := credentialEngine([]string{"/login", "/api/v1/login"})
	for i := 0; i < 30; i++ {
		path := []string{"/", "/assets/app.js", "/assets/theme.css", "/api/products"}[i%4]
		dec, err := e.Inspect(credentialRequest("GET", path, "203.0.113.7", nil))
		if err != nil {
			t.Fatalf("inspect request %d: %v", i+1, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Fatalf("benign GET %s #%d blocked by %s: %s", path, i+1, dec.RuleID, dec.Evidence)
		}
	}
}

// TestFalsePositive_LoginPageReadsAreNotAuthAttempts pins the same boundary
// from the other side: loading the login form is a GET, not an attempt to
// authenticate, so it must never feed the brute-force counter.
func TestFalsePositive_LoginPageReadsAreNotAuthAttempts(t *testing.T) {
	e := credentialEngine([]string{"/login"})
	for i := 0; i < 20; i++ {
		dec, err := e.Inspect(credentialRequest("GET", "/login", "203.0.113.8", nil))
		if err != nil {
			t.Fatalf("inspect request %d: %v", i+1, err)
		}
		if dec != nil && dec.RuleID == "CRED006" {
			t.Fatalf("GET /login #%d was counted as a brute-force attempt", i+1)
		}
	}
}

// TestBruteForce_BlocksRepeatedLoginAttempts proves the scoped rule still
// does its job: repeated POSTs to a configured login path are blocked.
func TestBruteForce_BlocksRepeatedLoginAttempts(t *testing.T) {
	e := credentialEngine([]string{"/login"})
	blocked := false
	for i := 0; i < 8; i++ {
		dec, err := e.Inspect(credentialRequest("POST", "/login", "198.51.100.4", map[string]string{
			"username": "admin",
			"password": "wrong-password",
		}))
		if err != nil {
			t.Fatalf("inspect attempt %d: %v", i+1, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock && dec.RuleID == "CRED006" {
			blocked = true
			break
		}
	}
	if !blocked {
		t.Error("repeated POSTs to /login were not blocked by CRED006")
	}
}

// TestBruteForce_IgnoresNonAuthPostTraffic makes sure the fix did not simply
// move the false positive: busy POST endpoints that carry no credentials must
// not be counted as authentication attempts.
func TestBruteForce_IgnoresNonAuthPostTraffic(t *testing.T) {
	e := credentialEngine([]string{"/login"})
	for i := 0; i < 30; i++ {
		dec, err := e.Inspect(credentialRequest("POST", "/api/orders", "198.51.100.9", map[string]string{
			"item": "42",
		}))
		if err != nil {
			t.Fatalf("inspect request %d: %v", i+1, err)
		}
		if dec != nil && dec.RuleID == "CRED006" {
			t.Fatalf("POST /api/orders #%d was counted as a brute-force attempt", i+1)
		}
	}
}

// TestBruteForce_WindowResetsBurst verifies the configured window is honoured:
// once the client has been quiet for longer than window_sec, the earlier burst
// no longer counts against it.
func TestBruteForce_WindowResetsBurst(t *testing.T) {
	e := engine.New(engine.EngineConfig{
		Credential: engine.NewCredentialProtection(false, 5, 1, 900, []string{"/login"}),
	})
	for i := 0; i < 6; i++ {
		if _, err := e.Inspect(credentialRequest("POST", "/login", "192.0.2.55", map[string]string{
			"username": "user" + string(rune('a'+i)),
			"password": "pw",
		})); err != nil {
			t.Fatalf("warm-up attempt %d: %v", i+1, err)
		}
	}

	time.Sleep(1100 * time.Millisecond)

	dec, err := e.Inspect(credentialRequest("POST", "/login", "192.0.2.55", map[string]string{
		"username": "fresh",
		"password": "pw",
	}))
	if err != nil {
		t.Fatalf("post-window inspect: %v", err)
	}
	if dec != nil && dec.RuleID == "CRED006" {
		t.Errorf("burst was not reset after the %s window: %s", time.Second, dec.Evidence)
	}
}
