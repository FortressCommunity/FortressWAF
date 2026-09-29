package sites

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/config"
)

// ManagedDomain is a domain the operator added, with the state of its
// verification recorded so the UI can show what happened.
type ManagedDomain struct {
	Domain      string   `json:"domain"`
	Site        string   `json:"site"`
	Upstream    string   `json:"upstream"`
	Verified    bool     `json:"verified"`
	ResolvedIPs []string `json:"resolved_ips"`
	Reason      string   `json:"reason"`
	AddedAt     string   `json:"added_at"`
}

// Manager owns the set of protected domains and brokers changes into the live
// config. It is the single writer, so an add and a remove cannot race.
type Manager struct {
	mu      sync.Mutex
	cfgMgr  *config.Manager
	records map[string]ManagedDomain // domain -> record
	audit   func(action, detail string)
}

// NewManager builds a domain manager bound to the live config.
func NewManager(cfgMgr *config.Manager, audit func(action, detail string)) *Manager {
	m := &Manager{
		cfgMgr:  cfgMgr,
		records: make(map[string]ManagedDomain),
		audit:   audit,
	}
	m.loadFromConfig()
	return m
}

// loadFromConfig seeds the record set from the domains already present in the
// config, so the UI shows pre-existing sites alongside added ones.
func (m *Manager) loadFromConfig() {
	cfg := m.cfgMgr.Get()
	for _, s := range cfg.Sites {
		for _, d := range s.Domains {
			key := normalizeDomain(d)
			m.records[key] = ManagedDomain{
				Domain:   key,
				Site:     s.Name,
				Upstream: s.Upstream,
				// Pre-existing config domains are trusted (the operator put them
				// in the file by hand).
				Verified: true,
				Reason:   "defined in the config file",
			}
		}
	}
}

// List returns the managed domains, sorted by name.
func (m *Manager) List() []ManagedDomain {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ManagedDomain, 0, len(m.records))
	for _, r := range m.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// Add verifies the domain's DNS and, if it passes, attaches it to a site in the
// live config. It refuses duplicates and unverified domains.
func (m *Manager) Add(d DomainAdd) (ManagedDomain, error) {
	d.Domain = normalizeDomain(d.Domain)
	if err := ValidateDomain(d.Domain); err != nil {
		return ManagedDomain{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.records[d.Domain]; exists {
		return ManagedDomain{}, fmt.Errorf("domain %q is already protected", d.Domain)
	}

	// Validate the upstream before anything is written. An unvalidated URL is
	// stored verbatim in the config and later dialed by the proxy, so a bad
	// scheme (file://, gopher://) or empty host must be rejected at the edge.
	if err := validateUpstream(d.Upstream); err != nil {
		return ManagedDomain{}, err
	}

	// The DNS check runs inside the lock on purpose: it is fast and bounded by
	// the verifier's timeout, and serializing adds keeps the record set and the
	// config in step.
	result := d.Verify.Verify(d.Ctx, d.Domain)
	rec := ManagedDomain{
		Domain:      d.Domain,
		Site:        d.SiteName,
		Upstream:    d.Upstream,
		Verified:    result.Verified,
		ResolvedIPs: result.ResolvedIPs,
		Reason:      result.Reason,
		AddedAt:     nowString(),
	}
	if !result.Verified {
		// A domain that fails verification is NOT stored: it is not protected,
		// and listing it would make it look registered. The caller gets the
		// reason so the UI can show exactly what DNS record is missing.
		return rec, fmt.Errorf("DNS verification failed: %s", result.Reason)
	}

	// Attach the domain to an existing site (by name) or a new one.
	err := m.cfgMgr.UpdateConfig(func(cfg *config.Config) {
		if d.SiteName != "" {
			for i := range cfg.Sites {
				if cfg.Sites[i].Name == d.SiteName {
					if !containsString(cfg.Sites[i].Domains, d.Domain) {
						cfg.Sites[i].Domains = append(cfg.Sites[i].Domains, d.Domain)
					}
					rec.Site = cfg.Sites[i].Name
					rec.Upstream = cfg.Sites[i].Upstream
					return
				}
			}
			// A site name was requested but no such site exists. Silently
			// creating a differently-named site would surprise the caller, so
			// the requested name is used for the new site and recorded as-is.
		}
		// New site entry. Reuse an existing site's upstream unless one is given.
		siteName := d.SiteName
		if siteName == "" {
			siteName = siteNameFor(d.Domain)
		}
		// Guard against colliding with an existing site name.
		for _, existing := range cfg.Sites {
			if existing.Name == siteName {
				return
			}
		}
		upstream := d.Upstream
		if upstream == "" && len(cfg.Sites) > 0 {
			upstream = cfg.Sites[0].Upstream
		}
		cfg.Sites = append(cfg.Sites, config.SiteConfig{
			Name:       siteName,
			Domains:    []string{d.Domain},
			Upstream:   upstream,
			WAFEnabled: true,
		})
		rec.Site = siteName
		rec.Upstream = upstream
	})
	if err != nil {
		delete(m.records, d.Domain)
		return ManagedDomain{}, fmt.Errorf("attach domain to config: %w", err)
	}

	m.records[d.Domain] = rec
	if m.audit != nil {
		m.audit("domain_added", fmt.Sprintf("%s -> site %s (resolved %s)", d.Domain, rec.Site, strings.Join(result.ResolvedIPs, ",")))
	}
	return rec, nil
}

// Remove detaches a domain from every site in the live config.
func (m *Manager) Remove(domain string) error {
	domain = normalizeDomain(domain)
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.records[domain]
	if !exists {
		return fmt.Errorf("domain %q is not managed", domain)
	}
	if rec.Reason == "defined in the config file" {
		// Allow removal, but the config edit below is what makes it stick.
	}

	err := m.cfgMgr.UpdateConfig(func(cfg *config.Config) {
		for i := range cfg.Sites {
			cfg.Sites[i].Domains = removeString(cfg.Sites[i].Domains, domain)
		}
		// Drop sites left with no domains.
		kept := cfg.Sites[:0]
		for _, s := range cfg.Sites {
			if len(s.Domains) > 0 {
				kept = append(kept, s)
			}
		}
		cfg.Sites = kept
	})
	if err != nil {
		return fmt.Errorf("remove domain from config: %w", err)
	}

	delete(m.records, domain)
	if m.audit != nil {
		m.audit("domain_removed", domain)
	}
	return nil
}

// DomainAdd is the input to Add.
type DomainAdd struct {
	Ctx      context.Context
	Domain   string
	SiteName string
	Upstream string
	Verify   *Verifier
}

// validateUpstream rejects an upstream that is not an http(s) URL with a host.
// An empty value is allowed: the caller then reuses an existing site's upstream.
func validateUpstream(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("upstream is not a valid URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream must be an http or https URL (got scheme %q)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream URL has no host")
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func removeString(list []string, s string) []string {
	out := list[:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// siteNameFor derives a site name from a domain (first label, sanitized).
func siteNameFor(domain string) string {
	label := strings.SplitN(domain, ".", 2)[0]
	label = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, label)
	if label == "" {
		return "site"
	}
	return label
}

func nowString() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}
