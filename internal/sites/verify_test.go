package sites

import (
	"context"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	valid := []string{
		"example.com", "sub.example.co.id", "a-b.example.org", "www.shop.io",
		"https://example.com/path", "HTTP://Example.COM:8443/x", "example.com.",
	}
	for _, d := range valid {
		if err := ValidateDomain(d); err != nil {
			t.Errorf("ValidateDomain(%q) = %v, want nil", d, err)
		}
	}

	invalid := []string{
		"", "localhost", "1.2.3.4", "example", "exa mple.com",
		"http://", "-bad.com", "bad-.com", "a..b.com", "exam ple.com",
	}
	for _, d := range invalid {
		if err := ValidateDomain(d); err == nil {
			t.Errorf("ValidateDomain(%q) = nil, want error", d)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"  Example.COM  ":                "example.com",
		"https://shop.example.com/x?y=1": "shop.example.com",
		"http://a.com:8080/path":         "a.com",
		"a.com.":                         "a.com",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// Verify must reject a domain with no DNS records and accept validation errors
// without panicking. It uses the real resolver, so a made-up TLD must fail.
func TestVerify_UnresolvableDomainFails(t *testing.T) {
	v := NewVerifier([]string{"203.0.113.1"})
	res := v.Verify(context.Background(), "no-such-domain-for-tests.invalid")
	if res.Verified {
		t.Fatalf("expected unverifiable domain to fail, got %+v", res)
	}
	if res.Reason == "" {
		t.Fatal("expected a failure reason")
	}
}

func TestVerify_InvalidDomainRejected(t *testing.T) {
	v := NewVerifier(nil)
	res := v.Verify(context.Background(), "not a domain")
	if res.Verified {
		t.Fatalf("invalid domain should not verify: %+v", res)
	}
}
