package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// 5 wrong attempts in the window must lock the address out; the 6th does not
// even reach the credential check.
func TestLoginLimiter_LocksOutAfterMaxFailures(t *testing.T) {
	lim := newLoginLimiter(5, time.Hour, time.Minute)

	for i := 0; i < 5; i++ {
		if locked := lim.recordFailure(loginReq()); locked && i < 4 {
			t.Fatalf("locked too early: attempt %d", i+1)
		}
	}

	locked, retry := lim.isLocked(loginReq())
	if !locked {
		t.Fatal("expected lock after 5 failures")
	}
	if retry <= 0 {
		t.Fatalf("expected positive retry window, got %v", retry)
	}
}

func TestLoginLimiter_SuccessClearsHistory(t *testing.T) {
	lim := newLoginLimiter(3, time.Hour, time.Minute)
	req := loginReq()

	lim.recordFailure(req)
	lim.recordFailure(req)
	lim.recordSuccess(req)

	for i := 0; i < 2; i++ {
		if locked := lim.recordFailure(req); locked {
			t.Fatal("a successful login should have reset the counter")
		}
	}
}

// A locked-out caller must be refused before the handler runs.
func TestHandleAuthLogin_LockedOut_Returns429(t *testing.T) {
	cfgMgr, cleanup := writeTestConfig(t, []string{"demo-admin-key"})
	defer cleanup()

	lim := newLoginLimiter(2, time.Hour, time.Minute)
	h := handleAuthLogin(cfgMgr, lim)

	for i := 0; i < 2; i++ {
		rec := postLogin(t, h, `{"email":"a@b.com","password":"wrong"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}

	rec := postLogin(t, h, `{"email":"a@b.com","password":"demo-admin-key"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while locked out, got %d (the real key leaked through)", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 should advertise a Retry-After")
	}
}

// Locks expire: after the window passes, a valid login works again.
func TestLoginLimiter_LockExpires(t *testing.T) {
	lim := newLoginLimiter(1, 20*time.Millisecond, time.Minute)
	req := loginReq()

	lim.recordFailure(req)
	if locked, _ := lim.isLocked(req); !locked {
		t.Fatal("expected to be locked")
	}

	time.Sleep(30 * time.Millisecond)
	if locked, _ := lim.isLocked(req); locked {
		t.Fatal("lock did not expire")
	}
}

// gc must drop stale entries so the maps do not grow unbounded.
func TestLoginLimiter_GC_DropsStale(t *testing.T) {
	lim := newLoginLimiter(5, time.Hour, 10*time.Millisecond)
	req := loginReq()

	lim.recordFailure(req)
	time.Sleep(30 * time.Millisecond)
	lim.gc()

	if len(lim.failures) != 0 || len(lim.lockedAt) != 0 {
		t.Fatalf("gc left entries behind: failures=%d locked=%d", len(lim.failures), len(lim.lockedAt))
	}
}

func loginReq() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	r.RemoteAddr = "192.0.2.10:40000"
	return r
}
