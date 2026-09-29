package unit

import (
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// Regression tests for false positives found during live demo testing. Each
// one blocks legitimate traffic if it regresses, so they are intentionally
// strict: the WAF must let these through.

// browserCtx builds a RequestContext shaped like a real browser request, with
// the User-Agent and headers set on the context itself (which is what the
// inspectors read).
func browserCtx(method, path, ua string) *engine.RequestContext {
	req := newTestRequest(method, path, nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	ctx := engine.NewRequestContext(req)
	ctx.UserAgent = ua
	ctx.Headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	ctx.Headers["Accept-Language"] = "en-US,en;q=0.9"
	return ctx
}

// A browser sends OPTIONS (CORS preflight), HEAD, and REST verbs on every page
// load and API call. None of these are "verb tampering".
func TestFalsePositive_StandardHTTPMethods(t *testing.T) {
	e := fullEngine()
	methods := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	for _, m := range methods {
		ctx := browserCtx(m, "/api/v1/resource", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36")
		ctx.Headers["Origin"] = "https://app.example.com"
		ctx.Headers["Access-Control-Request-Method"] = m
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Fatalf("inspect %s: %v", m, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: standard method %s blocked by %s: %s",
				m, dec.RuleID, dec.Evidence)
		}
	}
}

// Real browser and mobile-browser User-Agents must never be treated as bots.
func TestFalsePositive_RealBrowserUserAgents(t *testing.T) {
	e := fullEngine()
	uas := []string{
		// Desktop Chrome / Firefox / Safari / Edge
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0",
		// Mobile: iPhone Safari, Android Chrome, Samsung Internet
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
		// A UA containing the substring "java" via "JavaScript" must not trip
		// a "java" bot signature.
		"Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 JavaScriptEnabled Chrome/120 Mobile Safari/537.36",
	}
	for _, ua := range uas {
		dec, err := e.Inspect(browserCtx("GET", "/", ua))
		if err != nil {
			t.Fatalf("inspect %q: %v", ua, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: browser UA blocked by %s: %q (evidence %s)",
				dec.RuleID, ua, dec.Evidence)
		}
	}
}

// HTTP client libraries used for legitimate automation (the exhibition script
// itself uses curl) must not be classified as attack bots.
func TestFalsePositive_CommonHTTPClientsNotBots(t *testing.T) {
	e := fullEngine()
	uas := []string{
		"curl/8.0.1",
		"Wget/1.21",
		"python-requests/2.31.0",
		"PostmanRuntime/7.36.0",
		"axios/1.6.0",
		"okhttp/4.9.0",
		"Go-http-client/1.1",
	}
	for _, ua := range uas {
		ctx := browserCtx("GET", "/api/v1/health", ua)
		ctx.Headers["Accept"] = "*/*"
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Fatalf("inspect %q: %v", ua, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: HTTP client UA blocked by %s: %q", dec.RuleID, ua)
		}
	}
}

// Real attack tooling must still be caught (this is the other half of the
// story: fixing FPs must not disable detection).
func TestTruePositive_AttackToolsStillBlocked(t *testing.T) {
	e := fullEngine()
	uas := []string{
		"sqlmap/1.7#stable (https://sqlmap.org)",
		"Nikto/2.1.6",
		"masscan/1.3",
		"gobuster/3.6",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine)",
	}
	for _, ua := range uas {
		dec, err := e.Inspect(browserCtx("GET", "/", ua))
		if err != nil {
			t.Fatalf("inspect %q: %v", ua, err)
		}
		if dec == nil || dec.Action != engine.ActionBlock {
			t.Errorf("EXPECTED BLOCK: attack tool %q was not blocked (decision %+v)", ua, dec)
		}
	}
}

// A normal contact/signup form carries "email", "phone", "address" fields.
// Those are not honeypots.
func TestFalsePositive_ContactFormFieldsNotHoneypot(t *testing.T) {
	d := engine.NewBotDetector(false)
	for _, field := range []string{"email", "phone", "address", "website", "user_email", "phone_number", "message"} {
		ctx := browserCtx("POST", "/contact", "Mozilla/5.0 Chrome/120")
		ctx.FormParams[field] = []string{"value"}

		dec, err := d.Inspect(ctx)
		if err != nil {
			t.Fatalf("inspect field %q: %v", field, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: contact field %q blocked by %s", field, dec.RuleID)
		}
	}
}

// A hidden decoy field is still detected.
func TestTruePositive_HoneypotFieldStillBlocked(t *testing.T) {
	d := engine.NewBotDetector(false)
	ctx := browserCtx("POST", "/contact", "Mozilla/5.0 Chrome/120")
	ctx.FormParams["honeypot_email"] = []string{"x"}

	dec, err := d.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if dec == nil || dec.Action != engine.ActionBlock || dec.RuleID != "BOT005" {
		t.Errorf("EXPECTED BLOCK: honeypot field not detected (decision %+v)", dec)
	}
}

// Non-ASCII text in a URL, cookie, or header is ordinary (accented city names,
// transliterated names, emoji). A phone browsing a page with such a value must
// not be blocked as an "overlong UTF-8" or "normalization bypass" attack.
func TestFalsePositive_Parser_NonASCIIAndDoubleSlash(t *testing.T) {
	p := engine.NewParserHardener(false)
	cases := []struct {
		name, path string
		headers    map[string]string
	}{
		{"accented path", "/café", nil},
		{"accented search", "/search?q=caf%C3%A9", nil},
		{"german umlaut header", "/", map[string]string{"X-City": "München"}},
		{"utf8 cookie", "/", map[string]string{"Cookie": "name=José"}},
		{"emoji in referer", "/", map[string]string{"Referer": "https://x.com/?q=hello%20%F0%9F%98%80"}},
		{"double slash asset", "//static/logo.png", nil},
		{"encoded space path", "/products/sony%20wh-1000xm5", nil},
		{"percent literal", "/search?q=100%25+off", nil},
	}
	for _, tc := range cases {
		ctx := browserCtx("GET", tc.path, "Mozilla/5.0 Chrome/120")
		for k, v := range tc.headers {
			ctx.Headers[k] = v
		}
		dec, err := p.Inspect(ctx)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: %s blocked by %s (%s)", tc.name, dec.RuleID, dec.Evidence)
		}
	}
}

// Genuine overlong / invalid UTF-8 and traversal must still be blocked.
func TestTruePositive_Parser_OverlongAndTraversal(t *testing.T) {
	p := engine.NewParserHardener(false)
	cases := []struct {
		name, path string
		headers    map[string]string
	}{
		{"overlong slash", "/\xc0\xaf\xc0\xafetc/passwd", nil},
		{"overlong lead C1", "/\xc1\x80", nil},
		{"bare continuation", "/\x80\x80", nil},
		{"beyond unicode range", "/\xf5\x80\x80\x80", nil},
		{"dot-dot traversal", "/../../etc/passwd", nil},
		{"null byte", "/file%00.jpg", nil},
		{"overlong in header", "/", map[string]string{"X-Path": "\xc0\xafadmin"}},
	}
	for _, tc := range cases {
		ctx := browserCtx("GET", tc.path, "Mozilla/5.0 Chrome/120")
		for k, v := range tc.headers {
			ctx.Headers[k] = v
		}
		dec, err := p.Inspect(ctx)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if dec == nil || dec.Action != engine.ActionBlock {
			t.Errorf("MISSED: %s was not blocked (decision %+v)", tc.name, dec)
		}
	}
}
