package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baseConfig() *Config {
	return &Config{
		Sites: []SiteConfig{
			{Name: "a", Domains: []string{"a.com"}, Upstream: "http://a:80", WAFEnabled: true},
		},
	}
}

func TestValidate_RejectsDuplicateSiteName(t *testing.T) {
	c := baseConfig()
	c.Sites = append(c.Sites, SiteConfig{Name: "a", Domains: []string{"b.com"}, Upstream: "http://b:80"})
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate site name") {
		t.Fatalf("expected duplicate-site-name error, got %v", err)
	}
}

func TestValidate_RejectsDuplicateDomain(t *testing.T) {
	c := baseConfig()
	c.Sites = append(c.Sites, SiteConfig{Name: "b", Domains: []string{"a.com"}, Upstream: "http://b:80"})
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("expected duplicate-domain error, got %v", err)
	}
}

func TestValidate_AcceptsDistinctSites(t *testing.T) {
	c := baseConfig()
	c.Sites = append(c.Sites, SiteConfig{Name: "b", Domains: []string{"b.com"}, Upstream: "http://b:80"})
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

// A save must be atomic and must not leave temp files behind. This is the write
// path that add-domain uses at runtime.
func TestSaveToFile_AtomicAndNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("sites: []\n"), 0o664); err != nil {
		t.Fatal(err)
	}

	c := baseConfig()
	if err := SaveToFile(path, c); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	// The target must parse back and contain the site.
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(reloaded.Sites) != 1 || reloaded.Sites[0].Name != "a" {
		t.Fatalf("reloaded config does not match: %+v", reloaded.Sites)
	}

	// No temp files should remain in the directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

// SaveToFile must preserve the target's mode so the nonroot runtime container
// can keep rewriting a group-writable config.
func TestSaveToFile_PreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("sites: []\n"), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}

	if err := SaveToFile(path, baseConfig()); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o664 {
		t.Fatalf("mode = %o, want 664 (preserve target mode)", info.Mode().Perm())
	}
}
