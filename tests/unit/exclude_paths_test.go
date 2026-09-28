package unit

import (
	"strings"
	"testing"

	"github.com/FortressWAF/FortressWAF/internal/config"
)

func TestExcludesPath(t *testing.T) {
	site := &config.SiteConfig{ExcludePaths: []string{"/administrator", "/legacy/"}}

	cases := []struct {
		path string
		want bool
	}{
		{"/administrator", true},
		{"/administrator/index.php", true},
		{"/administrator/cek-login.php", true},
		// The upstream collapses these before routing, so the rule has to as
		// well or a directory request would still be blocked.
		{"/administrator/", true},
		{"/administrator//index.php", true},
		{"/legacy", true},
		{"/legacy/app/index.php", true},
		// A prefix rule must not leak into sibling paths that merely share the
		// same characters.
		{"/administratorX", false},
		{"/legacyX", false},
		{"/users/index.php", false},
		{"/", false},
		// A traversal path is inspected even though it starts with the exempt
		// prefix: the upstream would normalize it back into a protected path.
		{"/administrator/../users/index.php", false},
		{"/users/../administrator/index.php", false},
	}

	for _, c := range cases {
		if got := site.ExcludesPath(c.path); got != c.want {
			t.Errorf("ExcludesPath(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestExcludesPathRootCoversEverything(t *testing.T) {
	site := &config.SiteConfig{ExcludePaths: []string{"/"}}
	for _, p := range []string{"/", "/index.php", "/deep/path"} {
		if !site.ExcludesPath(p) {
			t.Errorf("ExcludesPath(%q) = false with exclude_paths: [/], want true", p)
		}
	}
}

func TestExcludesPathNoEntries(t *testing.T) {
	site := &config.SiteConfig{}
	if site.ExcludesPath("/administrator/index.php") {
		t.Error("a site with no exclude_paths excluded a path")
	}
}

func TestValidateRejectsExcludePathWithoutLeadingSlash(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{Name: "demo", Domains: []string{"demo.example"}, Upstream: "http://127.0.0.1:8080", ExcludePaths: []string{"administrator"}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted an exclude_paths entry without a leading slash")
	}
	if !strings.Contains(err.Error(), "exclude_paths") {
		t.Errorf("error %q does not name the offending field", err)
	}
}

func TestValidateAcceptsExcludePaths(t *testing.T) {
	cfg := &config.Config{
		Sites: []config.SiteConfig{
			{Name: "demo", Domains: []string{"demo.example"}, Upstream: "http://127.0.0.1:8080", ExcludePaths: []string{"/administrator", "/legacy/"}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected valid exclude_paths: %v", err)
	}
}
