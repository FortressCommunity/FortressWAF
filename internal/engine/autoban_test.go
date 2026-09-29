package engine

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func ddosReq(ip string) *RequestContext {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ip + ":1234"
	ctx := NewRequestContext(r)
	ctx.RealIP = ip
	return ctx
}

// A per-IP flood must ask for an auto-ban, and the ban duration must be the
// configured one.
func TestDDoS_FloodRequestsBan(t *testing.T) {
	d := NewDDoSProtectionWithOptions(false, DDoSOptions{PerIPRate: 5, PerIPBan: 7 * time.Minute})

	var banReq *Decision
	for i := 0; i < 20; i++ {
		dec, _ := d.Inspect(ddosReq("198.51.100.9"))
		if dec != nil && dec.BanRequest {
			banReq = dec
			break
		}
	}
	if banReq == nil {
		t.Fatal("a flood did not request a ban")
	}
	if banReq.BanDuration != 7*time.Minute {
		t.Fatalf("ban duration = %v, want 7m", banReq.BanDuration)
	}
	if banReq.RuleID != "DDoS001" {
		t.Fatalf("rule = %s, want DDoS001", banReq.RuleID)
	}
}

// Normal browsing traffic must never trip the per-IP flood limit, so a real
// visitor is never auto-banned.
func TestDDoS_NormalTrafficNoBan(t *testing.T) {
	d := NewDDoSProtection(false) // defaults: 30/s per IP
	for i := 0; i < 25; i++ {
		dec, _ := d.Inspect(ddosReq("203.0.113.50"))
		if dec != nil && (dec.Action == ActionRateLimit || dec.Action == ActionBlock) {
			t.Fatalf("ordinary burst of 25 tripped the limiter at request %d: %s", i, dec.RuleID)
		}
	}
}

// A negative ban duration disables auto-ban: the 429 is still returned, but no
// ban is requested.
func TestDDoS_NegativeBanDisablesAutoBan(t *testing.T) {
	d := NewDDoSProtectionWithOptions(false, DDoSOptions{PerIPRate: 3, PerIPBan: -1})
	var sawLimit bool
	for i := 0; i < 12; i++ {
		dec, _ := d.Inspect(ddosReq("198.51.100.20"))
		if dec != nil {
			sawLimit = true
			if dec.BanRequest {
				t.Fatal("auto-ban fired even though it was disabled")
			}
		}
	}
	if !sawLimit {
		t.Fatal("expected the rate limit to trigger at least once")
	}
}

func botReq(ip, ua string) *RequestContext {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = ip + ":1234"
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	ctx := NewRequestContext(r)
	ctx.RealIP = ip
	ctx.UserAgent = ua
	return ctx
}

// A real browser must never be blocked or challenged as a bot, and must not be
// counted toward a ban. A monitor-level note (e.g. a missing optional header)
// is acceptable.
func TestBot_RealBrowserNoFlag(t *testing.T) {
	b := NewBotDetectorWithOptions(false, BotOptions{AutoBanAfter: 3})
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "203.0.113.77:1234"
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		ctx := NewRequestContext(r)
		ctx.RealIP = "203.0.113.77"
		ctx.UserAgent = ua

		dec, _ := b.Inspect(ctx)
		if dec != nil && (dec.Action == ActionBlock || dec.Action == ActionChallenge) {
			t.Fatalf("real browser blocked/challenged: %s (%s)", dec.RuleID, dec.RuleName)
		}
		if dec != nil && dec.BanRequest {
			t.Fatalf("real browser counted toward a ban: %s", dec.RuleID)
		}
	}
}

// A missing User-Agent is challenged (not silently monitored), and repeated
// offences from one address escalate to an auto-ban request.
func TestBot_MissingUAAutoBansRepeatOffender(t *testing.T) {
	b := NewBotDetectorWithOptions(false, BotOptions{AutoBanAfter: 3, AutoBanWindow: time.Minute, AutoBanDuration: 5 * time.Minute})

	var banReq *Decision
	for i := 0; i < 6; i++ {
		dec, _ := b.Inspect(botReq("198.51.100.30", ""))
		if dec == nil {
			t.Fatalf("missing UA not flagged at request %d", i)
		}
		if dec.Action != ActionChallenge {
			t.Fatalf("missing UA action = %s, want challenge", dec.Action)
		}
		if dec.BanRequest {
			banReq = dec
			break
		}
	}
	if banReq == nil {
		t.Fatal("repeat bot offender was never banned")
	}
	if banReq.BanDuration != 5*time.Minute {
		t.Fatalf("ban duration = %v, want 5m", banReq.BanDuration)
	}
}

// A definite attack tool is blocked and counted, so a scanner that keeps coming
// is banned.
func TestBot_AttackToolBlockedAndBanned(t *testing.T) {
	b := NewBotDetectorWithOptions(false, BotOptions{AutoBanAfter: 2, AutoBanWindow: time.Minute, AutoBanDuration: time.Minute})
	var banReq *Decision
	for i := 0; i < 5; i++ {
		dec, _ := b.Inspect(botReq("198.51.100.40", "sqlmap/1.7"))
		if dec == nil {
			t.Fatal("sqlmap not blocked")
		}
		if dec.Action != ActionBlock {
			t.Fatalf("sqlmap action = %s, want block", dec.Action)
		}
		if dec.BanRequest {
			banReq = dec
			break
		}
	}
	if banReq == nil {
		t.Fatal("repeat scanner was never banned")
	}
}

// Auto-ban can be disabled entirely for the bot detector.
func TestBot_AutoBanDisabled(t *testing.T) {
	b := NewBotDetectorWithOptions(false, BotOptions{AutoBanAfter: -1})
	for i := 0; i < 20; i++ {
		dec, _ := b.Inspect(botReq("198.51.100.50", "sqlmap/1.7"))
		if dec != nil && dec.BanRequest {
			t.Fatal("auto-ban fired while disabled")
		}
	}
}
