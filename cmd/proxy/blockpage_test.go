package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// A browser navigation and a plain curl must both get the human-readable block
// page; only a client that explicitly asks for JSON gets JSON. This is the
// behaviour a visitor sees when the WAF blocks them.
func TestWriteBlockedResponse_ContentNegotiation(t *testing.T) {
	decision := &engine.Decision{
		Action:   engine.ActionBlock,
		RuleID:   "SQLI016",
		RuleName: "SQL Pattern Match",
		Severity: "high",
		Evidence: `SQL injection pattern matched in query:q: "1' OR 1=1--"`,
	}

	cases := []struct {
		name     string
		headers  map[string]string
		wantHTML bool
	}{
		{"browser navigation", map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, true},
		{"curl no accept", map[string]string{}, true},
		{"curl wildcard", map[string]string{"Accept": "*/*"}, true},
		{"api json", map[string]string{"Accept": "application/json"}, false},
		{"json content type", map[string]string{"Content-Type": "application/json"}, false},
		{"xhr", map[string]string{"X-Requested-With": "XMLHttpRequest"}, false},
		{"html beats json", map[string]string{"Accept": "text/html, application/json"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/search?q=x", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			writeBlockedResponse(rec, req, decision)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d", rec.Code)
			}
			ct := rec.Header().Get("Content-Type")
			body := rec.Body.String()

			if tc.wantHTML {
				if !strings.HasPrefix(ct, "text/html") {
					t.Fatalf("expected HTML, got content-type %q", ct)
				}
				for _, want := range []string{"kami tahan", "FortressWAF", "SQLI016"} {
					if !strings.Contains(body, want) {
						t.Errorf("block page missing %q", want)
					}
				}
				if strings.Contains(body, `"blocked":true`) {
					t.Error("HTML path leaked a JSON body")
				}
			} else {
				if !strings.HasPrefix(ct, "application/json") {
					t.Fatalf("expected JSON, got content-type %q", ct)
				}
				for _, want := range []string{"SQLI016", `"blocked":true`} {
					if !strings.Contains(body, want) {
						t.Errorf("JSON body missing %q", want)
					}
				}
			}
		})
	}
}

// The block page must not reflect unescaped rule metadata into markup.
func TestBlockPage_EscapesRuleMetadata(t *testing.T) {
	decision := &engine.Decision{
		Action:   engine.ActionBlock,
		RuleID:   `XSS"><script>alert(1)</script>`,
		RuleName: `<img src=x onerror=alert(1)>`,
		Severity: "high",
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	body := string(blockPage(req, decision))
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("rule id injected unescaped into the block page")
	}
	if strings.Contains(body, "<img src=x onerror=alert(1)>") {
		t.Fatal("rule name injected unescaped into the block page")
	}
}
