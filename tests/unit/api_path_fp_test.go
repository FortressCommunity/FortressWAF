package unit

import (
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/engine"
)

func TestFalsePositive_SensitivePathsSegmentAnchored(t *testing.T) {
	p := engine.NewAPIProtection(false)
	benign := []string{"/", "/index.php", "/about", "/contact", "/blog/administrator-tips",
		"/information", "/configuration", "/api/v1/products", "/search", "/user/admin-profile",
		"/pages/info.html", "/product.php", "/metrics-disabled", "/informed", "/administrators"}
	malicious := []string{"/admin", "/admin/", "/config", "/debug", "/.env", "/wp-admin/",
		"/administrator", "/backup/db.sql", "/.git/config", "/graphql", "/swagger", "/actuator/health", "/info"}

	for _, path := range benign {
		dec, _ := p.Inspect(browserCtx("GET", path, "Mozilla/5.0 Chrome/120"))
		if dec != nil && dec.Action == engine.ActionBlock && dec.RuleID == "API002" {
			t.Errorf("FALSE POSITIVE: %-30s blocked by API002", path)
		}
	}
	for _, path := range malicious {
		dec, _ := p.Inspect(browserCtx("GET", path, "Mozilla/5.0 Chrome/120"))
		if dec == nil || dec.RuleID != "API002" {
			t.Errorf("MISSED: %-30s not blocked by API002 (got %+v)", path, dec)
		}
	}
}
