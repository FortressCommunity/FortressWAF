package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func engineWithProxies(t *testing.T, cidrs ...string) *Engine {
	t.Helper()
	e := New(EngineConfig{})
	if invalid := e.SetTrustedProxies(cidrs); len(invalid) > 0 {
		t.Fatalf("invalid test CIDRs: %v", invalid)
	}
	return e
}

func request(remoteAddr, xff, xri string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xri != "" {
		r.Header.Set("X-Real-IP", xri)
	}
	return r
}

// Behind Cloudflare the trusted peer is Caddy, but the left-most XFF entry is
// Cloudflare's edge. CF-Connecting-IP carries the real visitor and must win,
// so rate limits and auto-bans act on the visitor, not on Cloudflare.
func TestClientIP_TrustedProxy_PrefersCloudflareConnectingIP(t *testing.T) {
	e := engineWithProxies(t, "172.18.0.0/16")
	r := request("172.18.0.5:5555", "162.158.162.149", "")
	r.Header.Set("CF-Connecting-IP", "198.51.100.77")
	if got := e.ClientIP(r); got != "198.51.100.77" {
		t.Fatalf("ClientIP = %q, want the CF-Connecting-IP visitor 198.51.100.77", got)
	}
}

// An untrusted peer cannot spoof CF-Connecting-IP.
func TestClientIP_UntrustedPeer_IgnoresCloudflareHeader(t *testing.T) {
	e := engineWithProxies(t, "172.18.0.0/16")
	r := request("203.0.113.9:5555", "", "")
	r.Header.Set("CF-Connecting-IP", "198.51.100.77")
	if got := e.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want the peer 203.0.113.9", got)
	}
}

// Edge deployment: a client-supplied forwarded header must never be trusted.
// This is what makes per-IP rate limits and brute-force lockouts unspoofable.
func TestClientIP_Edge_IgnoresForwardedHeaders(t *testing.T) {
	e := engineWithProxies(t) // no trusted proxies = edge

	r := request("203.0.113.9:5000", "1.2.3.4", "")
	if got := e.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("spoofed X-Forwarded-For was trusted: got %q", got)
	}

	r = request("203.0.113.9:5000", "", "1.2.3.4")
	if got := e.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("spoofed X-Real-IP was trusted: got %q", got)
	}

	r = request("203.0.113.9:5000", "1.2.3.4, 5.6.7.8", "9.9.9.9")
	if got := e.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("forwarded headers were trusted at the edge: got %q", got)
	}
}

// Behind a trusted proxy, the forwarded client address is used.
func TestClientIP_TrustedProxy_UsesForwardedFor(t *testing.T) {
	e := engineWithProxies(t, "10.0.0.0/8")

	r := request("10.0.0.5:40000", "198.51.100.20", "")
	if got := e.ClientIP(r); got != "198.51.100.20" {
		t.Fatalf("expected forwarded client, got %q", got)
	}

	r = request("10.0.0.5:40000", "", "198.51.100.21")
	if got := e.ClientIP(r); got != "198.51.100.21" {
		t.Fatalf("expected X-Real-IP, got %q", got)
	}
}

// An untrusted peer that happens to send a forwarded header is ignored even
// when other proxies are configured.
func TestClientIP_UntrustedPeer_IgnoresHeader(t *testing.T) {
	e := engineWithProxies(t, "10.0.0.0/8")

	r := request("192.0.2.99:40000", "198.51.100.20", "")
	if got := e.ClientIP(r); got != "192.0.2.99" {
		t.Fatalf("untrusted peer's header was trusted: got %q", got)
	}
}

// The left-most entry is the original client; malformed values fall back to
// the peer rather than propagating garbage into rate-limit maps.
func TestClientIP_TrustedProxy_MalformedFallback(t *testing.T) {
	e := engineWithProxies(t, "10.0.0.0/8")

	r := request("10.0.0.5:40000", "not-an-ip, 1.2.3.4", "")
	if got := e.ClientIP(r); got != "10.0.0.5" {
		t.Fatalf("malformed forwarded value trusted: got %q", got)
	}

	r = request("10.0.0.5:40000", "", "garbage")
	if got := e.ClientIP(r); got != "10.0.0.5" {
		t.Fatalf("malformed X-Real-IP trusted: got %q", got)
	}
}

// ContextFromRequest must agree with ClientIP, and NewRequestContext must
// never read forwarded headers.
func TestContextFromRequest_MatchesClientIP(t *testing.T) {
	e := engineWithProxies(t, "10.0.0.0/8")
	r := request("10.0.0.5:40000", "198.51.100.20", "")

	ctx := e.ContextFromRequest(r)
	if ctx.RealIP != "198.51.100.20" {
		t.Fatalf("ContextFromRequest real ip = %q", ctx.RealIP)
	}

	plain := NewRequestContext(r)
	if plain.RealIP != "10.0.0.5" {
		t.Fatalf("NewRequestContext trusted forwarded header: %q", plain.RealIP)
	}
}

// Invalid CIDRs in the allow list are rejected, not silently kept.
func TestParseTrustedProxies_RejectsInvalid(t *testing.T) {
	invalid := ParseTrustedProxies([]string{"10.0.0.0/8", "not-a-cidr", "999.1.1.1/8"})
	if len(invalid) != 2 {
		t.Fatalf("expected 2 invalid entries, got %v", invalid)
	}

	e := New(EngineConfig{})
	e.SetTrustedProxies([]string{"10.0.0.0/8", "garbage"})
	r := request("10.0.0.5:40000", "1.2.3.4", "")
	if got := e.ClientIP(r); got != "1.2.3.4" {
		t.Fatalf("valid CIDR should still be trusted: got %q", got)
	}
}

// A request without a port in RemoteAddr must not panic.
func TestClientIP_NoPortInRemoteAddr(t *testing.T) {
	e := engineWithProxies(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9"
	if got := e.ClientIP(r); got != "203.0.113.9" {
		t.Fatalf("expected peer, got %q", got)
	}
}
