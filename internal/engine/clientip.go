package engine

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// trustedProxy holds parsed CIDRs whose forwarded headers are believed. The
// zero value trusts nothing, which is correct for an edge deployment: a client
// that sends X-Forwarded-For itself must not choose the address its traffic is
// attributed to.
type trustedProxy struct {
	mu      sync.RWMutex
	nets    []*net.IPNet
	enabled bool
}

// SetTrustedProxies replaces the allow list. Each entry must be a valid CIDR;
// invalid entries are skipped and reported by the caller via ParseTrustedProxies.
func (t *trustedProxy) SetTrustedProxies(cidrs []string) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil || ipNet == nil {
			continue
		}
		nets = append(nets, ipNet)
	}

	t.mu.Lock()
	t.nets = nets
	t.enabled = len(nets) > 0
	t.mu.Unlock()
}

// trusts reports whether the immediate peer is a configured proxy.
func (t *trustedProxy) trusts(peer string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if !t.enabled {
		return false
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return false
	}
	for _, n := range t.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies validates each CIDR and returns the entries that could
// not be parsed, so misconfiguration is visible instead of silently ignored.
func ParseTrustedProxies(cidrs []string) (invalid []string) {
	for _, c := range cidrs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
			invalid = append(invalid, c)
		}
	}
	return invalid
}

// ClientIP resolves the requesting peer's address.
//
// The peer is authoritative unless it is a trusted proxy, in which case the
// forwarded header it set is used. When FortressWAF sits at the edge, a
// client-supplied X-Forwarded-For is attacker-controlled and must not win:
// it drives per-IP rate limits, brute-force lockouts and bot scoring, so
// trusting it would make all of those bypassable with a single header.
//
// X-Real-IP is honoured only from a trusted proxy for the same reason.
func (e *Engine) ClientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}

	if !e.proxies.trusts(peer) {
		return peer
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Left-most address is the original client when proxies append in
		// order; each hop is attacker-controlled beyond the trusted one, so
		// take the first entry and validate it parses as an address.
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if ip := net.ParseIP(first); ip != nil {
			return ip.String()
		}
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		if ip := net.ParseIP(strings.TrimSpace(xri)); ip != nil {
			return ip.String()
		}
	}

	return peer
}
