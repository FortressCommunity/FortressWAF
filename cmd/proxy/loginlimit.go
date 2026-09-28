package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// loginLimiter caps failed login attempts per source address. The admin API
// key is a demo secret that logs in as admin, so an unbounded login endpoint
// would let anyone grind through guesses as fast as they can send requests.
//
// The counter is in-memory and per-process, which matches how the demo runs:
// one proxy, one admin port. It is deliberately simple -- no external store,
// no sliding window -- because the goal is to stop trivial credential
// spraying against the admin console, not to be a distributed limiter.
type loginLimiter struct {
	mu sync.Mutex

	// maxFailures: attempts allowed inside the window before the address is
	// locked out. lockFor: how long the lock lasts. window: how far back
	// failures are counted.
	maxFailures int
	lockFor     time.Duration
	window      time.Duration

	failures map[string][]time.Time
	lockedAt map[string]time.Time
}

func newLoginLimiter(maxFailures int, lockFor, window time.Duration) *loginLimiter {
	return &loginLimiter{
		maxFailures: maxFailures,
		lockFor:     lockFor,
		window:      window,
		failures:    make(map[string][]time.Time),
		lockedAt:    make(map[string]time.Time),
	}
}

// key is the caller's address. X-Forwarded-For is deliberately not consulted:
// the admin API sits on its own port and is reached directly, so trusting a
// client-supplied header would let an attacker reset their own counter.
func (l *loginLimiter) key(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isLocked checks the address without mutating state, for use before handling.
func (l *loginLimiter) isLocked(r *http.Request) (bool, time.Duration) {
	key := l.key(r)
	l.mu.Lock()
	defer l.mu.Unlock()

	until, ok := l.lockedAt[key]
	if !ok || time.Now().After(until) {
		if ok {
			delete(l.lockedAt, key)
		}
		return false, 0
	}
	return true, time.Until(until)
}

// recordFailure notes an unsuccessful attempt and returns whether the address
// has now exhausted its allowance.
func (l *loginLimiter) recordFailure(r *http.Request) bool {
	key := l.key(r)
	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	// Drop failures outside the counting window.
	cut := now.Add(-l.window)
	kept := l.failures[key][:0]
	for _, t := range l.failures[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	l.failures[key] = kept

	if len(kept) >= l.maxFailures {
		l.lockedAt[key] = now.Add(l.lockFor)
		return true
	}
	return false
}

// recordSuccess clears an address's history after a valid login.
func (l *loginLimiter) recordSuccess(r *http.Request) {
	key := l.key(r)
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
	delete(l.lockedAt, key)
}

// gc drops stale entries so the maps cannot grow without bound. Safe to call
// from a slow ticker.
func (l *loginLimiter) gc() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cut := now.Add(-l.window)
	for k, ts := range l.failures {
		kept := ts[:0]
		for _, t := range ts {
			if t.After(cut) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(l.failures, k)
		} else {
			l.failures[k] = kept
		}
	}
	for k, until := range l.lockedAt {
		if now.After(until) {
			delete(l.lockedAt, k)
		}
	}
}
