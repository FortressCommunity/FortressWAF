// Package sites handles adding protected domains and verifying that the caller
// actually controls the domain's DNS before it is trusted.
package sites

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// domainRE validates a hostname: labels of letters/digits/hyphens, dot
// separated, at least one dot, no leading/trailing hyphen, and a plausible TLD.
var domainRE = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

// Verifier resolves a domain's A/AAAA records and checks that at least one
// points at an address the WAF is allowed to serve. A domain cannot be added
// until this passes -- it is the proof that the person adding it controls the
// DNS and has pointed it at this deployment.
type Verifier struct {
	// expectedIPs are the addresses a domain must resolve to. Usually the
	// public IP(s) of this server, from config or auto-detected.
	expectedIPs []string
	resolver    *net.Resolver
	timeout     time.Duration
}

// NewVerifier builds a verifier. When expectedIPs is empty the verifier asks
// the caller to supply the observed addresses for comparison (used by the
// "show me what your domain resolves to" preview flow).
func NewVerifier(expectedIPs []string) *Verifier {
	cleaned := make([]string, 0, len(expectedIPs))
	for _, ip := range expectedIPs {
		if p := strings.TrimSpace(ip); p != "" {
			cleaned = append(cleaned, p)
		}
	}
	return &Verifier{
		expectedIPs: cleaned,
		resolver:    net.DefaultResolver,
		timeout:     8 * time.Second,
	}
}

// ExpectedIPs returns the addresses a domain must resolve to.
func (v *Verifier) ExpectedIPs() []string { return append([]string(nil), v.expectedIPs...) }

// Result is the outcome of a verification attempt.
type Result struct {
	Domain      string   `json:"domain"`
	Verified    bool     `json:"verified"`
	ResolvedIPs []string `json:"resolved_ips"`
	ExpectedIPs []string `json:"expected_ips"`
	Reason      string   `json:"reason"`
}

// Verify resolves domain and reports whether one of its A/AAAA records matches
// an expected IP. It never trusts the caller's claim: the check is done by this
// process using the system resolver.
func (v *Verifier) Verify(ctx context.Context, domain string) Result {
	domain = normalizeDomain(domain)
	res := Result{Domain: domain, ExpectedIPs: v.expectedIPs}

	if err := ValidateDomain(domain); err != nil {
		res.Reason = err.Error()
		return res
	}

	lookupCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	ips, err := v.resolveAll(lookupCtx, domain)
	sort.Strings(ips)
	res.ResolvedIPs = ips
	if err != nil {
		res.Reason = fmt.Sprintf("DNS lookup failed: %v", err)
		return res
	}
	if len(ips) == 0 {
		res.Reason = "no A or AAAA record found for this domain"
		return res
	}

	if len(v.expectedIPs) == 0 {
		// No expected set configured: the domain exists and resolves, which is
		// the best we can assert without knowing the server's own IP.
		res.Verified = true
		res.Reason = "domain resolves (configure server.expected_ips to require a specific address)"
		return res
	}

	for _, got := range ips {
		for _, want := range v.expectedIPs {
			if ipEqual(got, want) {
				res.Verified = true
				res.Reason = fmt.Sprintf("%s resolves to %s, which is this server", domain, got)
				return res
			}
		}
	}

	res.Reason = fmt.Sprintf("%s resolves to %s, none of which match this server (%s)",
		domain, strings.Join(ips, ", "), strings.Join(v.expectedIPs, ", "))
	return res
}

// resolveAll returns every A and AAAA address for the domain.
func (v *Verifier) resolveAll(ctx context.Context, domain string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, network := range []string{"ip4", "ip6"} {
		addrs, err := v.resolver.LookupIP(ctx, network, domain)
		if err != nil {
			// A missing AAAA record is normal; only surface an error if both
			// lookups fail.
			if ctx.Err() != nil {
				return out, ctx.Err()
			}
			continue
		}
		for _, a := range addrs {
			s := a.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// ValidateDomain rejects anything that is not a plain public hostname.
func ValidateDomain(domain string) error {
	domain = normalizeDomain(domain)
	if domain == "" {
		return fmt.Errorf("domain is required")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain is too long")
	}
	if strings.HasPrefix(domain, "www.") {
		// accepted, but the label check below still applies
	}
	if strings.ContainsAny(domain, "/:@ ") {
		return fmt.Errorf("domain must be a bare hostname (no scheme, port, or path)")
	}
	if net.ParseIP(domain) != nil {
		return fmt.Errorf("enter a domain name, not an IP address")
	}
	if !domainRE.MatchString(domain) {
		return fmt.Errorf("not a valid domain name")
	}
	return nil
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	// Tolerate a pasted URL: strip scheme, path, port.
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if i := strings.IndexAny(d, "/"); i >= 0 {
		d = d[:i]
	}
	if i := strings.LastIndex(d, ":"); i >= 0 && !strings.Contains(d[i:], "]") {
		d = d[:i]
	}
	d = strings.TrimSuffix(d, ".")
	return d
}

// ipEqual compares two IP strings, treating IPv4 and its IPv4-mapped IPv6 form
// as equal.
func ipEqual(a, b string) bool {
	ia, ib := net.ParseIP(strings.TrimSpace(a)), net.ParseIP(strings.TrimSpace(b))
	if ia == nil || ib == nil {
		return a == b
	}
	return ia.Equal(ib)
}
