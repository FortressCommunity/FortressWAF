package main

import "testing"

// Header values that carry credentials must never be written to the audit log.
// Header names are case-insensitive, and X-API-Key is the very header this
// system uses for auth, so an exact-case three-name list leaked it.
func TestIsSensitiveHeader(t *testing.T) {
	sensitive := []string{
		"Authorization", "authorization", "AUTHORIZATION",
		"Proxy-Authorization", "Cookie", "cookie", "Set-Cookie",
		"X-API-Key", "x-api-key", "X-Api-Key",
		"X-Auth-Token", "X-Access-Token", "X-CSRF-Token", "X-XSRF-Token",
		"X-Session-Token", "X-Session-Id",
		"X-Custom-Secret", "X-Password", "X-Api-Secret",
	}
	for _, h := range sensitive {
		if !isSensitiveHeader(h) {
			t.Errorf("isSensitiveHeader(%q) = false, want true (credential leak)", h)
		}
	}

	benign := []string{
		"Accept", "Accept-Language", "User-Agent", "Referer", "Origin",
		"Content-Type", "Content-Length", "Host", "Connection",
		"Accept-Encoding", "Cache-Control", "If-None-Match",
	}
	for _, h := range benign {
		if isSensitiveHeader(h) {
			t.Errorf("isSensitiveHeader(%q) = true, want false", h)
		}
	}
}
