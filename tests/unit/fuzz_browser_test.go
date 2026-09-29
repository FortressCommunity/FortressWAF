package unit

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// This file fuzzes the engine with realistic browser traffic across platforms
// and reports every block. A WAF that blocks a real visitor is worse than one
// that misses a payload, so this test must produce zero findings. It is data
// driven: the request shapes below mirror what real browsers and mobile apps
// send, including the "%" characters, encoded values, and non-ASCII text that
// ordinary people type.

// browserProfile is a realistic header set for one client.
type browserProfile struct {
	name    string
	headers map[string]string
}

func browserProfiles() []browserProfile {
	common := func(accept, lang string) map[string]string {
		return map[string]string{"Accept": accept, "Accept-Language": lang, "Accept-Encoding": "gzip, deflate, br"}
	}
	return []browserProfile{
		{"chrome-win", merge(common("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "en-US,en;q=0.9"), map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		})},
		{"chrome-android", merge(common("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7"), map[string]string{
			"User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		})},
		{"safari-iphone", merge(common("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "en-US,en;q=0.9"), map[string]string{
			"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		})},
		{"safari-mac", merge(common("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "en-GB,en;q=0.9"), map[string]string{
			"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		})},
		{"firefox-linux", merge(common("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "en-US,en;q=0.5"), map[string]string{
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		})},
		{"edge-win", merge(common("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "en-US,en;q=0.9"), map[string]string{
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
		})},
		{"samsung-android", merge(common("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "en-US,en;q=0.9"), map[string]string{
			"User-Agent": "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
		})},
	}
}

// trafficPaths are ordinary URLs a shopper, reader, or app user visits. Encoded
// spaces, percent signs, non-ASCII, and query operators that are NOT attacks
// are deliberately included.
func trafficPaths() []string {
	return []string{
		"/", "/index.php", "/home", "/about", "/about-us", "/contact", "/faq",
		"/products", "/products?category=laptops&sort=price_asc&page=2",
		"/products/laptop-15-inch",
		"/product/sony-wh-1000xm5",
		"/search?q=sepatu+lari",
		"/search?q=diskon+50%25",
		"/search?q=100%25+original",
		"/search?q=caf%C3%A9+latte",
		"/search?q=user%40example.com",
		"/search?q=how+to+select+a+monitor",
		"/search?q=drop+in+the+bucket",
		"/search?q=union+square+bakery",
		"/search?q=statement+of+the+union+address",
		"/search?q=buy+and+or+not",
		"/cart", "/checkout", "/checkout?step=shipping", "/checkout?step=payment",
		"/orders/10023", "/orders?page=1&per_page=20",
		"/account/profile", "/account/settings", "/account/orders",
		"/blog/how-to-select-a-monitor", "/blog/understanding-sql-basics",
		"/blog/delete-your-account-guide", "/blog/update-your-address",
		"/category/elektronik?page=2&sort=termurah",
		"/track?url=https%3A%2F%2Fshop.example.com%2Fa%25b",
		"/redirect?to=%2Faccount%2Forders",
		"/api/v1/products", "/api/v1/products?limit=20&offset=0",
		"/api/v1/user/me", "/api/v1/search?q=%E6%97%A5%E6%9C%AC%E8%AA%9E",
		"/api/v1/orders?filter=status%3D%22shipped%22",
		"/static/js/app.4f2a1b.js", "/static/css/main.8e3c.css",
		"/assets/logo.svg", "/images/hero@2x.webp", "/fonts/inter.woff2",
		"/favicon.ico", "/apple-touch-icon.png", "/manifest.webmanifest",
		"/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
		"/health", "/language/en-US", "/currency/IDR?to=USD",
		"/promo?code=DISKON50%25", "/promo?code=SAVE%2520NOW",
		"/voucher/birthday%20special", "/user/admin-profile",
		"/pages/info.html", "/configuration", "/information",
		"/search?q=best+deals+%26+offers", "/search?q=C%2B%2B+tutorial",
		"/search?q=100%25+coffee", "/download?file=report%2F2024.pdf",
		"/share?text=Check%20this%20out", "/share?url=https%3A%2F%2Fexample.com",
	}
}

// realisticCookies are cookie values a real session carries: base64 tokens,
// URL-encoded JSON, percent signs, non-ASCII names.
func realisticCookies() []string {
	return []string{
		"session=abc123; theme=dark",
		"promo=SAVE%2520NOW; sid=abc",
		"cart=%5B%7B%22id%22%3A1%2C%22qty%22%3A2%7D%5D",
		"discount=50%25",
		"last_search=kopi%20susu",
		"_ga=GA1.2.1234567890.1700000000; _gid=GA1.2.987.1700000000",
		"name=Jos%C3%A9; city=M%C3%BCnchen",
		"token=eyJhbGciOiJIUzI1NiJ9.test.sig",
	}
}

// realisticReferers are referring URLs, often carrying an encoded nested URL.
func realisticReferers() []string {
	return []string{
		"https://shop.example.com/search?q=50%25+off",
		"https://a.com/p?u=https%3A%2F%2Fb.com%2Fx%2520y",
		"https://www.google.com/",
		"https://m.facebook.com/login.php?next=https%3A%2F%2Fshop.example.com%2F",
		"https://x.com/?utm_source=newsletter&utm_campaign=summer%2Bsale",
	}
}

// TestFuzz_NoFalsePositivesOnBrowserTraffic drives the cross-product of
// profiles, paths, cookies, and referers through the full engine and reports
// every block. The test fails if any realistic request is blocked.
func TestFuzz_NoFalsePositivesOnBrowserTraffic(t *testing.T) {
	e := fullEngine()
	profiles := browserProfiles()
	paths := trafficPaths()
	cookies := realisticCookies()
	referers := realisticReferers()

	type finding struct {
		rule   string
		action string
		path   string
		detail string
	}
	byRule := map[string]int{}
	var findings []finding
	total := 0
	ipSeq := 0

	for _, prof := range profiles {
		for _, p := range paths {
			for _, ck := range cookies {
				for _, ref := range referers {
					total++
					// A distinct source IP per request: this suite measures rule
					// false positives, not the per-IP rate limiter (which would
					// fire on any harness that sends thousands of requests from
					// one address, and which a real visitor never hits).
					ipSeq++
					srcIP := fmt.Sprintf("203.0.113.%d", (ipSeq%250)+1)
					h := merge(prof.headers, map[string]string{"Cookie": ck, "Referer": ref})
					dec, err := e.Inspect(browserCtxFrom("GET", p, h, srcIP))
					if err != nil {
						t.Fatalf("inspect %s: %v", p, err)
					}
					if dec != nil && (dec.Action == engine.ActionBlock || dec.Action == engine.ActionChallenge) {
						byRule[dec.RuleID]++
						if len(findings) < 80 {
							findings = append(findings, finding{dec.RuleID, string(dec.Action), p, prof.name + " | ref=" + ref + " | ck=" + ck})
						}
					}
				}
			}
		}
	}

	if len(findings) > 0 {
		t.Errorf("FALSE POSITIVES: %d/%d blocked", countTotal(byRule), total)
		keys := make([]string, 0, len(byRule))
		for k := range byRule {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("  %-30s %d", k, byRule[k])
		}
		for _, f := range findings {
			t.Logf("    [%s/%s] %s (%s)", f.rule, f.action, f.path, f.detail)
		}
	}
}

func countTotal(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// browserCtxFull builds a RequestContext with the given headers applied to both
// the raw request and the context maps the inspectors read.
func browserCtxFull(method, path string, headers map[string]string) *engine.RequestContext {
	return browserCtxFrom(method, path, headers, "10.0.0.5")
}

func browserCtxFrom(method, path string, headers map[string]string, srcIP string) *engine.RequestContext {
	u, _ := url.Parse(path)
	r := &http.Request{Method: method, URL: u, Header: make(http.Header), Host: "shop.example.com", RemoteAddr: srcIP + ":4444"}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	ctx := engine.NewRequestContext(r)
	for k, v := range headers {
		ctx.Headers[k] = v
	}
	if ua, ok := headers["User-Agent"]; ok {
		ctx.UserAgent = ua
	}
	return ctx
}

func merge(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// TestFuzz_NoFalsePositivesOnFormPosts drives ordinary form and JSON bodies
// through the engine. A contact form with an "email" field, a search box, a
// login with an email address -- none of these may be blocked.
func TestFuzz_NoFalsePositivesOnFormPosts(t *testing.T) {
	e := fullEngine()
	profiles := browserProfiles()

	type post struct {
		path, ctype, body string
	}
	posts := []post{
		{"/contact", "application/x-www-form-urlencoded", "name=John+Doe&email=john%40example.com&phone=%2B62-812-3456&message=Hello%2C+I%27d+like+a+quote"},
		{"/register", "application/x-www-form-urlencoded", "username=alice&email=alice%40example.com&password=Correct-Horse-2024&address=Jl.+Sudirman+No.+1"},
		{"/login", "application/x-www-form-urlencoded", "email=user%40example.com&password=hunter2"},
		{"/search", "application/x-www-form-urlencoded", "q=how+to+select+a+monitor&sort=relevance"},
		{"/api/v1/products", "application/json", `{"query":"diskon 50%","category":"elektronik","sort":"price_asc"}`},
		{"/api/v1/comments", "application/json", `{"text":"Great article! The script was easy to follow.","rating":5}`},
		{"/api/v1/profile", "application/json", `{"name":"José Müller","city":"München","bio":"I love JavaScript & SQL, and I write about it."}`},
		{"/api/v1/orders", "application/json", `{"items":[{"id":1,"qty":2}],"note":"Please drop it at the front desk","total":29.99}`},
		{"/newsletter", "application/x-www-form-urlencoded", "email=subscriber%40mail.com&interests=javascript,sql,security"},
		{"/feedback", "application/x-www-form-urlencoded", "subject=The+drop-down+menu+is+broken&body=When+I+select+an+option+it+does+nothing"},
	}
	ipSeq := 0
	failed := 0
	for _, prof := range profiles {
		for _, p := range posts {
			ipSeq++
			srcIP := fmt.Sprintf("198.51.100.%d", (ipSeq%250)+1)
			u, _ := url.Parse(p.path)
			r := &http.Request{
				Method:     "POST",
				URL:        u,
				Header:     make(http.Header),
				Host:       "shop.example.com",
				RemoteAddr: srcIP + ":4444",
				Body:       io.NopCloser(strings.NewReader(p.body)),
			}
			for k, v := range prof.headers {
				r.Header.Set(k, v)
			}
			r.Header.Set("Content-Type", p.ctype)
			ctx := engine.NewRequestContext(r)
			for k, v := range prof.headers {
				ctx.Headers[k] = v
			}
			ctx.Headers["Content-Type"] = p.ctype
			ctx.UserAgent = prof.headers["User-Agent"]
			ctx.ContentType = p.ctype
			ctx.Body = []byte(p.body)
			// Form parsers populate these for urlencoded bodies.
			if p.ctype == "application/x-www-form-urlencoded" {
				vals, _ := url.ParseQuery(p.body)
				for k, vv := range vals {
					ctx.FormParams[k] = vv
				}
			}

			dec, err := e.Inspect(ctx)
			if err != nil {
				t.Fatalf("%s: %v", p.path, err)
			}
			if dec != nil && (dec.Action == engine.ActionBlock || dec.Action == engine.ActionChallenge) {
				failed++
				t.Errorf("FALSE POSITIVE: POST %s (%s) blocked/challenged by %s (%s) body=%q",
					p.path, prof.name, dec.RuleID, dec.Evidence, p.body)
			}
		}
	}
	if failed == 0 {
		t.Logf("form/post sweep clean across %d requests", len(profiles)*len(posts))
	}
}
