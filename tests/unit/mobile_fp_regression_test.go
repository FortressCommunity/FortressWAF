package unit

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// mobileRequest builds a context with a full, realistic Android Chrome header
// set -- the headers a phone actually sends. Handy for reproducing
// browser-specific false positives.
func mobileRequest(path string, hdrs map[string]string) *engine.RequestContext {
	u, _ := url.Parse(path)
	r := &http.Request{Method: "GET", URL: u, Header: make(http.Header), Host: "shop.example.com", RemoteAddr: "10.0.0.5:4444"}
	for k, v := range hdrs {
		r.Header.Set(k, v)
	}
	return engine.NewRequestContext(r)
}

func androidHeaders() map[string]string {
	return map[string]string{
		"User-Agent":                "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":           "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
		"Accept-Encoding":           "gzip, deflate, br",
		"Referer":                   "https://shop.example.com/search?q=diskon+50%25",
		"Cookie":                    "session=abc123; promo=SAVE%2520NOW; cart=%5B%7B%22id%22%3A1%7D%5D",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Mode":            "navigate",
	}
}

// A phone browsing a normal site must never be blocked or challenged. Every
// path here is an ordinary page a shopper visits.
func TestFalsePositive_AndroidBrowsing(t *testing.T) {
	e := fullEngine()
	h := androidHeaders()
	paths := []string{
		"/",
		"/product/123",
		"/search?q=sepatu+lari",
		"/search?q=diskon+50%25",
		"/cart",
		"/promo?code=DISKON50%25",
		"/checkout?step=payment",
		"/category/elektronik?page=2&sort=termurah",
		"/track?url=https%3A%2F%2Fshop.example.com%2Fa%25b",
	}
	for _, p := range paths {
		dec, err := e.Inspect(mobileRequest(p, h))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if dec != nil && (dec.Action == engine.ActionBlock || dec.Action == engine.ActionChallenge) {
			t.Errorf("FALSE POSITIVE: %s -> %s (%s)", p, dec.Action, dec.RuleID+" "+dec.Evidence)
		}
	}
}

// Headers and cookies carrying an encoded value (a referring URL, a promo
// cookie) must not be mistaken for double-encoded SQL injection. This was the
// bug that blocked phones: SQLI018 fired on any "%25XX".
func TestFalsePositive_EncodedHeaderValuesNotSQLi(t *testing.T) {
	e := fullEngine()
	cases := []map[string]string{
		{"Referer": "https://a.com/p?u=https%3A%2F%2Fb.com%2Fx%2520y"},
		{"Cookie": "promo=SAVE%2520NOW; sid=abc"},
		{"Cookie": "discount=50%25"},
		{"Referer": "https://shop.example.com/search?q=50%25+off"},
		{"X-Forwarded-Host": "shop.example.com"},
	}
	for _, h := range cases {
		dec, err := e.Inspect(mobileRequest("/", h))
		if err != nil {
			t.Fatalf("%v: %v", h, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: headers %v blocked by %s (%s)", h, dec.RuleID, dec.Evidence)
		}
	}
}

// Genuine double-encoded SQL injection must still be caught.
func TestTruePositive_DoubleEncodedSQLi(t *testing.T) {
	e := fullEngine()
	payloads := []string{
		"/search?q=1%2527%2520OR%25201%253D1--", // double-encoded ' OR 1=1--
		"/item?id=1%2527%2520OR%2520%25271%2527%253D%25271",
	}
	for _, p := range payloads {
		dec, err := e.Inspect(mobileRequest(p, androidHeaders()))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if dec == nil || dec.Action != engine.ActionBlock {
			t.Errorf("MISSED: double-encoded SQLi %q not blocked (%+v)", p, dec)
		}
	}
}

// Regression: a value containing a percent sign that is not a valid escape used
// to send decodePathValue into infinite recursion and crash the proxy with a
// stack overflow -- a remote denial of service. These inputs must return, not
// panic.
func TestRegression_PercentDecodeDoesNotRecurseForever(t *testing.T) {
	e := fullEngine()
	// Each of these made the old decoder recurse without end.
	inputs := []string{
		"%", "%2", "%zz", "%25", "%25%25%25", "%%", "100%", "a%25b%25c", "%2525", "%2541",
	}
	for _, in := range inputs {
		h := map[string]string{"Referer": "https://x.com/?v=" + in}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = e.Inspect(mobileRequest("/", h))
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("decode of %q did not return (possible infinite loop/crash)", in)
		}
	}
}
