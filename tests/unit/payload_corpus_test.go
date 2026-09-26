package unit

import (
	"bufio"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// These tests exercise the WAF against the same payload corpus the ML engine
// trains on (ml-engine/training/data/<category>/payloads.txt), so rule tests
// and model training can never silently drift apart.

// corpusDir points at the ML engine's training data.
func corpusDir() string {
	return filepath.Join("..", "..", "ml-engine", "training", "data")
}

func loadPayloads(t *testing.T, category string) []string {
	t.Helper()
	path := filepath.Join(corpusDir(), category, "payloads.txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if len(out) == 0 {
		t.Fatalf("no payloads found in %s", path)
	}
	return out
}

// fullEngine wires every built-in inspector the shipped config enables.
func fullEngine() *engine.Engine {
	return engine.New(engine.EngineConfig{
		DevMode:              true,
		SQLI:                 engine.NewSQLInjectionEngine(true),
		XSS:                  engine.NewXSSEngine(true),
		RCE:                  engine.NewRCEInjection(true),
		DDoS:                 engine.NewDDoSProtection(true),
		Protocol:             engine.NewProtocolAnomaly(true),
		Bot:                  engine.NewBotDetector(true),
		APIProtect:           engine.NewAPIProtection(true),
		Upload:               engine.NewFileUploadSecurity(true),
		JA3:                  engine.NewJA3Inspector(true),
		Desync:               engine.NewDesyncDetector(true, 1048576, true, true),
		Parser:               engine.NewParserHardener(true),
		PerformanceIsolation: true,
	})
}

func newTestRequestGET(rawPath string) *http.Request {
	req := &http.Request{
		Method: "GET",
		Header: make(http.Header),
		Host:   "example.com",
	}
	parts := strings.SplitN(rawPath, "?", 2)
	req.URL = &url.URL{Path: parts[0]}
	if len(parts) == 2 {
		req.URL.RawQuery = parts[1]
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	return req
}

func benignRequest(queryValue string) *engine.RequestContext {
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/search", RawQuery: "q=" + url.QueryEscape(queryValue)},
		Header: make(http.Header),
		Host:   "example.com",
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	return engine.NewRequestContext(req)
}

func benignPathRequest(rawPath string) *engine.RequestContext {
	req := newTestRequestGET(rawPath)
	return engine.NewRequestContext(req)
}

// TestAttackCorpus_DetectionRates runs the whole training corpus through the
// engine. The floors below are the measured detection rates, deliberately
// documented rather than pretended to be 100%: a missed payload is a real
// gap, and asserting perfection would just hide it.
//
// Categories with no dedicated inspector are excluded and listed in
// KnownLimitations instead of being silently skipped here.
func TestAttackCorpus_DetectionRates(t *testing.T) {
	cases := []struct {
		category string
		floor    float64 // minimum acceptable block rate, percent
	}{
		{"sql-injection", 65},
		{"xss", 99},
		{"rce", 50},
		{"command-injection", 60},
		{"path-traversal", 50},
		{"lfi", 50},
		{"ssti", 55},
		{"ldap-injection", 70},
		{"xxe", 99},
		{"webshell", 80},
		{"deserialization", 90},

		// Deliberately absent (see Known Limitations):
		//   csrf      - CSRF is a session/context attack defeated by anti-CSRF
		//               tokens and SameSite cookies, not by inspecting a single
		//               request value. The corpus's "csrf" payloads are really
		//               HTML injection vectors; blocking <img src=...> on every
		//               request would break legitimate rich-text input.
		//   ssrf      - no SSRF inspector exists yet.
		//   open-redirect - no open-redirect inspector exists yet.
	}

	e := fullEngine()
	for _, c := range cases {
		t.Run(c.category, func(t *testing.T) {
			payloads := loadPayloads(t, c.category)
			blocked := 0
			for _, p := range payloads {
				dec, err := e.Inspect(benignRequest(p))
				if err != nil {
					t.Errorf("inspect %q: %v", p, err)
					continue
				}
				if dec != nil && dec.Action == engine.ActionBlock {
					blocked++
				}
			}
			rate := 100 * float64(blocked) / float64(len(payloads))
			t.Logf("%-20s blocked %d/%d (%.1f%%)", c.category, blocked, len(payloads), rate)
			if rate < c.floor {
				t.Errorf("%s detection rate %.1f%% is below the documented floor %.0f%%",
					c.category, rate, c.floor)
			}
		})
	}
}

// TestAttackCorpus_BlockedPayloadsCovered guarantees a handful of canonical
// payloads per category are blocked, so a regression in a common attack form
// fails loudly instead of only dragging an average down.
func TestAttackCorpus_BlockedPayloadsCovered(t *testing.T) {
	cases := map[string][]string{
		"sql-injection": {
			"1' OR '1'='1",
			"'; DROP TABLE users--",
			"1 UNION SELECT username, password FROM users",
			"admin'--",
			"1 AND SLEEP(5)",
		},
		"xss": {
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
			"<svg/onload=alert(1)>",
			"\"><script>alert(document.cookie)</script>",
		},
		"rce": {
			"; cat /etc/passwd",
			"| id",
			"$(whoami)",
			"`id`",
			"; rm -rf /",
		},
	}

	e := fullEngine()
	for category, payloads := range cases {
		t.Run(category, func(t *testing.T) {
			for _, p := range payloads {
				dec, err := e.Inspect(benignRequest(p))
				if err != nil {
					t.Fatalf("inspect %q: %v", p, err)
				}
				if dec == nil || dec.Action != engine.ActionBlock {
					t.Errorf("expected %q (%s) to be blocked, got action=%v rule=%v",
						p, category, actionName(dec), ruleName(dec))
				} else {
					t.Logf("blocked %q via %s", p, dec.RuleID)
				}
			}
		})
	}
}

// --- False-positive tests --------------------------------------------------
// A WAF that blocks benign traffic is worse than one that misses attacks, so
// every detection module gets a set of legitimate inputs it must NOT block.

func TestFalsePositive_SQLi_BenignSearchValues(t *testing.T) {
	// Ordinary English containing SQL keywords or syntax-like characters.
	values := []string{
		"how do I delete my account",
		"update my billing address",
		"please select your shipping option",
		"union square bakery san francisco",
		"1+1=2 and 2+2=4",
		"or",
		"and/or",
		"drop-off location for my order",
		"insert coin to continue",
		"table for two at 7pm",
		"selecting the right laptop",
		"order by popularity please",
		"my name is O'Brien",
		"comment: nice product!",
		"price range 10--50 dollars",
		"contact us at help@example.com",
	}
	e := fullEngine()
	for _, v := range values {
		dec, err := e.Inspect(benignRequest(v))
		if err != nil {
			t.Fatalf("inspect %q: %v", v, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: benign search %q blocked by %s: %s",
				v, dec.RuleID, dec.Evidence)
		}
	}
}

func TestFalsePositive_SQLi_BenignPaths(t *testing.T) {
	paths := []string{
		"/", "/about", "/api/v1/users/42", "/api/v1/users/42/posts",
		"/search?category=laptops&page=3", "/products/iphone-15-pro",
		"/checkout?step=payment", "/static/css/main.css", "/health",
		"/favicon.ico", "/api/v1/orders?sort=created_at&limit=20",
	}
	e := fullEngine()
	for _, p := range paths {
		dec, err := e.Inspect(benignPathRequest(p))
		if err != nil {
			t.Fatalf("inspect %q: %v", p, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: benign path %q blocked by %s: %s",
				p, dec.RuleID, dec.Evidence)
		}
	}
}

func TestFalsePositive_XSS_BenignPunctuationAndMath(t *testing.T) {
	// Angle brackets and quotes appear in plenty of legitimate input.
	values := []string{
		"5 < 10 and 3 > 2",
		"the price is < $100",
		"use the <header> and <footer> elements",
		"email format is user@example.com",
		"C++ uses -> and :: operators",
		"compare a<b and c>d",
		"she said \"hello\"",
		"2 >= 2 is true",
		"the tag <3 means love",
		"not equal: !=",
	}
	e := fullEngine()
	for _, v := range values {
		dec, err := e.Inspect(benignRequest(v))
		if err != nil {
			t.Fatalf("inspect %q: %v", v, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: benign text %q blocked by %s: %s",
				v, dec.RuleID, dec.Evidence)
		}
	}
}

func TestFalsePositive_RCE_BenignWords(t *testing.T) {
	// Words that are also shell commands in ordinary sentences.
	values := []string{
		"concatenate the two strings",
		"please list the available options",
		"the cat sat on the mat",
		"catalogue 2024 edition",
		"locate the nearest store",
		"echo park is a nice neighbourhood",
		"find your order number",
		"we will ping you when it ships",
	}
	e := fullEngine()
	for _, v := range values {
		dec, err := e.Inspect(benignRequest(v))
		if err != nil {
			t.Fatalf("inspect %q: %v", v, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: benign text %q blocked by %s: %s",
				v, dec.RuleID, dec.Evidence)
		}
	}
}

func TestFalsePositive_Parser_BenignEncodedPaths(t *testing.T) {
	// Legitimate percent-encoding must not look like an evasion bypass.
	paths := []string{
		"/search?q=laptops%20with%2016gb%20ram",
		"/products/sony%20wh-1000xm5",
		"/path%2Bwith%2Bplus/signs",
		"/blog/2024%2F01%2Fhello-world",
		"/api/v1/users?filter=name%3Dalice",
	}
	e := fullEngine()
	for _, p := range paths {
		dec, err := e.Inspect(benignPathRequest(p))
		if err != nil {
			t.Fatalf("inspect %q: %v", p, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: benign encoded path %q blocked by %s: %s",
				p, dec.RuleID, dec.Evidence)
		}
	}
}

func actionName(dec *engine.Decision) string {
	if dec == nil {
		return "nil"
	}
	return string(dec.Action)
}

func ruleName(dec *engine.Decision) string {
	if dec == nil {
		return ""
	}
	return dec.RuleID
}

// TestFalsePositive_SQLi_BenignUserAgents guards the SQLI022 regression: a
// browser User-Agent contains both a SQL keyword ("like Gecko") and
// semicolons ("(X11; Linux x86_64)"), which the chaining rule used to count
// as stacked queries and block every browser request outright.
func TestFalsePositive_SQLi_BenignUserAgents(t *testing.T) {
	agents := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	}
	e := fullEngine()
	for _, ua := range agents {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/"},
			Header: make(http.Header),
			Host:   "example.com",
		}
		req.Header.Set("User-Agent", ua)
		dec, err := e.Inspect(engine.NewRequestContext(req))
		if err != nil {
			t.Fatalf("inspect %q: %v", ua, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: browser UA %q blocked by %s: %s",
				ua, dec.RuleID, dec.Evidence)
		}
	}
}

// TestSQLInjection_StackedQueriesStillBlocked checks the chaining rule keeps
// firing on real stacked-query payloads now that it requires the keyword to
// sit next to the semicolon.
func TestSQLInjection_StackedQueriesStillBlocked(t *testing.T) {
	payloads := []string{
		"1; DELETE FROM users",
		"1; INSERT INTO admins VALUES(1,'root')",
		"1; UPDATE users SET role='admin'",
		"1; WAITFOR DELAY '0:0:5'",
		"'; SELECT * FROM users--",
	}
	e := fullEngine()
	for _, p := range payloads {
		req := &http.Request{
			Method: "GET",
			URL:    &url.URL{Path: "/search", RawQuery: "q=" + url.QueryEscape(p)},
			Header: make(http.Header),
			Host:   "example.com",
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		dec, err := e.Inspect(engine.NewRequestContext(req))
		if err != nil {
			t.Fatalf("inspect %q: %v", p, err)
		}
		if dec == nil || dec.Action != engine.ActionBlock {
			t.Errorf("stacked query %q was NOT blocked (got %+v)", p, dec)
			continue
		}
		if !strings.HasPrefix(dec.RuleID, "SQLI") {
			t.Errorf("stacked query %q blocked by unexpected rule %s: %s",
				p, dec.RuleID, dec.Evidence)
		}
	}
}

// TestSemicolonQueryIsInspected guards a real bypass: Go's url.Query rejects
// the whole query string when a raw ';' appears in it, which used to leave
// QueryParams empty and let ";id" or "1;DROP TABLE users" past every
// inspector. The engine now falls back to a lenient '&' split.
func TestSemicolonQueryIsInspected(t *testing.T) {
	payloads := []string{
		";id",
		"; whoami",
		"1; DROP TABLE users",
		"'; SELECT 1--",
	}
	e := fullEngine()
	for _, p := range payloads {
		req := &http.Request{
			Method: "GET",
			// Deliberately raw, not URL-encoded: the point is that the raw
			// semicolon must still be inspected.
			URL:    &url.URL{Path: "/cmd", RawQuery: "c=" + p},
			Header: make(http.Header),
			Host:   "example.com",
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
		dec, err := e.Inspect(engine.NewRequestContext(req))
		if err != nil {
			t.Fatalf("inspect %q: %v", p, err)
		}
		if dec == nil || dec.Action != engine.ActionBlock {
			t.Errorf("raw-semicolon query %q was NOT inspected (got %+v) -- "+
				"url.Query may have rejected the query string again", p, dec)
		}
	}
}
