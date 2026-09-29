// Package blocklist stores banned client IPs and answers whether an address is
// currently blocked. Bans can expire, so an operator can drop a persistent
// attacker for a window without editing a file.
package blocklist

import (
	"net"
	"sort"
	"sync"
	"time"
)

// Entry is a banned address.
type Entry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedBy string    `json:"created_by"`
	// Permanent bans have no expiry.
	Permanent bool `json:"permanent"`
}

// Store holds the ban set. It is safe for concurrent use: the request path
// reads on every request while the admin API mutates.
type Store struct {
	mu      sync.RWMutex
	bans    map[string]Entry
	nowFunc func() time.Time
}

// New builds an empty store.
func New() *Store {
	return &Store{bans: make(map[string]Entry), nowFunc: time.Now}
}

// Ban adds or refreshes a ban. A zero ttl means permanent.
func (s *Store) Ban(ip, reason, by string, ttl time.Duration) (Entry, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return Entry{}, &net.AddrError{Err: "invalid IP", Addr: ip}
	}
	ip = parsed.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFunc()
	e := Entry{
		IP:        ip,
		Reason:    reason,
		CreatedAt: now,
		CreatedBy: by,
		Permanent: ttl <= 0,
	}
	if ttl > 0 {
		e.ExpiresAt = now.Add(ttl)
	}
	s.bans[ip] = e
	return e, nil
}

// Unban removes a ban. It reports whether the address was banned.
func (s *Store) Unban(ip string) bool {
	parsed := net.ParseIP(ip)
	key := ip
	if parsed != nil {
		key = parsed.String()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bans[key]; !ok {
		return false
	}
	delete(s.bans, key)
	return true
}

// IsBanned reports whether ip is currently banned, evicting it first if its
// window has passed.
func (s *Store) IsBanned(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	key := parsed.String()

	s.mu.RLock()
	e, ok := s.bans[key]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	if !e.Permanent && s.nowFunc().After(e.ExpiresAt) {
		// Lazily evict the expired entry.
		s.mu.Lock()
		if cur, still := s.bans[key]; still && !cur.Permanent && s.nowFunc().After(cur.ExpiresAt) {
			delete(s.bans, key)
		}
		s.mu.Unlock()
		return false
	}
	return true
}

// List returns active bans, newest first, pruning expired entries.
func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFunc()
	out := make([]Entry, 0, len(s.bans))
	for k, e := range s.bans {
		if !e.Permanent && now.After(e.ExpiresAt) {
			delete(s.bans, k)
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Count returns the number of active bans.
func (s *Store) Count() int {
	return len(s.List())
}
