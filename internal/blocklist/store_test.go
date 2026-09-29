package blocklist

import (
	"testing"
	"time"
)

func TestBanUnban(t *testing.T) {
	s := New()
	if s.IsBanned("1.2.3.4") {
		t.Fatal("address should not be banned yet")
	}
	if _, err := s.Ban("1.2.3.4", "test", "op", 0); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !s.IsBanned("1.2.3.4") {
		t.Fatal("address should be banned")
	}
	if s.Count() != 1 {
		t.Fatalf("count = %d, want 1", s.Count())
	}
	if !s.Unban("1.2.3.4") {
		t.Fatal("Unban should report true for a banned address")
	}
	if s.IsBanned("1.2.3.4") {
		t.Fatal("address should be unbanned")
	}
	if s.Unban("1.2.3.4") {
		t.Fatal("Unban should report false for an address that is not banned")
	}
}

func TestBanRejectsInvalidIP(t *testing.T) {
	s := New()
	if _, err := s.Ban("not-an-ip", "", "", 0); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestBanExpiry(t *testing.T) {
	s := New()
	now := time.Now()
	s.nowFunc = func() time.Time { return now }
	if _, err := s.Ban("9.9.9.9", "temp", "op", time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if !s.IsBanned("9.9.9.9") {
		t.Fatal("should be banned before expiry")
	}
	// Advance past the window.
	s.nowFunc = func() time.Time { return now.Add(2 * time.Minute) }
	if s.IsBanned("9.9.9.9") {
		t.Fatal("should not be banned after expiry")
	}
	if s.Count() != 0 {
		t.Fatalf("expired ban should be pruned, count = %d", s.Count())
	}
}

func TestIPv6Normalization(t *testing.T) {
	s := New()
	if _, err := s.Ban("2001:db8::1", "v6", "op", 0); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	// A differently-written but equivalent address must match.
	if !s.IsBanned("2001:0db8:0000:0000:0000:0000:0000:0001") {
		t.Fatal("equivalent IPv6 form should be banned")
	}
}
