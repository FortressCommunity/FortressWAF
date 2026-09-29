package unit

import (
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

// A broad sweep of what one normal browsing session looks like: a mix of
// paths, methods, headers, and query values. None of it may be blocked.
func TestFalsePositive_NormalBrowsingSweep(t *testing.T) {
	e := fullEngine()

	type req struct {
		method, path string
		extra        map[string]string
	}
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	mua := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"

	reqs := []req{
		{"GET", "/", nil},
		{"GET", "/index.php", nil},
		{"GET", "/about-us", nil},
		{"GET", "/products?category=laptops&page=2", nil},
		{"GET", "/products/laptop-15-inch", nil},
		{"GET", "/search?q=a+good+laptop+for+work", nil},
		{"GET", "/search?q=drop+in+the+ocean", nil},
		{"GET", "/blog/how-to-update-your-profile", nil},
		{"GET", "/blog/understanding-sql-joins", nil},
		{"GET", "/cart", nil},
		{"GET", "/checkout?step=shipping", nil},
		{"GET", "/orders/10023", nil},
		{"GET", "/api/v1/products", nil},
		{"GET", "/api/v1/user/me", nil},
		{"GET", "/static/js/app.4f2a.js", nil},
		{"GET", "/static/css/main.css", nil},
		{"GET", "/images/hero.webp", nil},
		{"GET", "/favicon.ico", nil},
		{"GET", "/manifest.json", nil},
		{"GET", "/robots.txt", nil},
		{"GET", "/sitemap.xml", nil},
		{"HEAD", "/", nil},
		{"OPTIONS", "/api/v1/products", map[string]string{"Origin": "https://shop.example.com", "Access-Control-Request-Method": "GET"}},
		{"GET", "/language/en-US", map[string]string{"Accept-Language": "en-US,en;q=0.9"}},
		{"GET", "/", map[string]string{"User-Agent": mua}},
	}

	for _, rc := range reqs {
		ctx := browserCtx(rc.method, rc.path, ua)
		if m, ok := rc.extra["User-Agent"]; ok {
			ctx.UserAgent = m
		}
		for k, v := range rc.extra {
			ctx.Headers[k] = v
		}
		dec, err := e.Inspect(ctx)
		if err != nil {
			t.Fatalf("inspect %s %s: %v", rc.method, rc.path, err)
		}
		if dec != nil && dec.Action == engine.ActionBlock {
			t.Errorf("FALSE POSITIVE: %s %s blocked by %s (%s): %s",
				rc.method, rc.path, dec.RuleID, dec.RuleName, dec.Evidence)
		}
	}
}
