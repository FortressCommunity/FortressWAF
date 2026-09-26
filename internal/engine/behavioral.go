package engine

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
)

type BehavioralEngine struct {
	mu          sync.RWMutex
	devMode     bool
	reputation  bool
	velocity    bool
	pathEntropy bool
	threshold   float64
	windowSec   int
	maxRequests int

	ipRequests   map[string]*slidingWindow
	ipReputation map[string]int
	pathCounts   map[string]int
	badIPs       map[string]bool
	blockedIPs   map[string]time.Time
	cleanupTimer *time.Ticker
	entropyRE    *regexp.Regexp
}

type slidingWindow struct {
	mu     sync.Mutex
	times  []time.Time
	window time.Duration
	max    int
}

func newSlidingWindow(window time.Duration, max int) *slidingWindow {
	return &slidingWindow{
		times:  make([]time.Time, 0, max),
		window: window,
		max:    max,
	}
}

func (sw *slidingWindow) add() int {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-sw.window)

	j := 0
	for _, t := range sw.times {
		if t.After(cutoff) {
			sw.times[j] = t
			j++
		}
	}
	sw.times = sw.times[:j+1]
	sw.times[j] = now
	return len(sw.times)
}

func NewBehavioralEngine(devMode, reputation, velocity, pathEntropy bool, threshold float64, windowSec, maxRequests int) *BehavioralEngine {
	e := &BehavioralEngine{
		devMode:      devMode,
		reputation:   reputation,
		velocity:     velocity,
		pathEntropy:  pathEntropy,
		threshold:    threshold,
		windowSec:    windowSec,
		maxRequests:  maxRequests,
		ipRequests:   make(map[string]*slidingWindow),
		ipReputation: make(map[string]int),
		pathCounts:   make(map[string]int),
		badIPs:       make(map[string]bool),
		blockedIPs:   make(map[string]time.Time),
		entropyRE:    regexp.MustCompile(`[0-9a-f]{8,}|[a-z]{20,}|[A-Z]{20,}`),
	}
	e.cleanupTimer = time.NewTicker(5 * time.Minute)
	go e.cleanupLoop()
	return e
}

func (e *BehavioralEngine) Name() string { return "behavioral" }

func (e *BehavioralEngine) Inspect(ctx *RequestContext) (*Decision, error) {
	ip := ctx.RealIP
	if ip == "" {
		return nil, nil
	}

	score := 0.0

	if e.velocity {
		sw := e.getWindow(ip)
		count := sw.add()
		if count > e.maxRequests {
			score += 35
			if e.devMode {
				return &Decision{
					Action:   ActionRateLimit,
					RuleID:   "BEH_001",
					RuleName: "Request Velocity Exceeded",
					Severity: "high",
					Score:    35,
					Evidence: fmt.Sprintf("IP %s exceeded %d requests per %ds window (got %d)", ip, e.maxRequests, e.windowSec, count),
				}, nil
			}
		}
		if count > e.maxRequests*2 {
			score += 30
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "BEH_002",
				RuleName: "High Request Velocity",
				Severity: "critical",
				Score:    65,
				Evidence: fmt.Sprintf("IP %s high velocity: %d requests in %ds", ip, count, e.windowSec),
			}, nil
		}
	}

	if e.reputation {
		e.mu.RLock()
		_, isBad := e.badIPs[ip]
		rep := e.ipReputation[ip]
		e.mu.RUnlock()

		if isBad {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "BEH_010",
				RuleName: "Known Bad IP",
				Severity: "critical",
				Score:    90,
				Evidence: fmt.Sprintf("IP %s has negative reputation", ip),
			}, nil
		}

		if rep > 10 {
			score += 20
		}
		if rep > 50 {
			score += 25
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "BEH_011",
				RuleName: "Poor IP Reputation",
				Severity: "high",
				Score:    45,
				Evidence: fmt.Sprintf("IP %s poor reputation score: %d", ip, rep),
			}, nil
		}
	}

	if e.pathEntropy {
		pathScore := e.checkPathEntropy(ctx.Path)
		score += pathScore
		if pathScore > 20 {
			return &Decision{
				Action:   ActionMonitor,
				RuleID:   "BEH_020",
				RuleName: "High Path Entropy",
				Severity: "medium",
				Score:    pathScore,
				Evidence: fmt.Sprintf("path %q has high entropy (%.2f)", ctx.Path, pathScore),
			}, nil
		}
	}

	if score >= e.threshold {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "BEH_099",
			RuleName: "Behavioral Threat Detected",
			Severity: "medium",
			Score:    score,
			Evidence: fmt.Sprintf("cumulative behavioral score %.0f for IP %s", score, ip),
		}, nil
	}

	return nil, nil
}

func (e *BehavioralEngine) getWindow(ip string) *slidingWindow {
	e.mu.Lock()
	defer e.mu.Unlock()
	sw, ok := e.ipRequests[ip]
	if !ok {
		sw = newSlidingWindow(time.Duration(e.windowSec)*time.Second, e.maxRequests*10)
		e.ipRequests[ip] = sw
	}
	return sw
}

func (e *BehavioralEngine) checkPathEntropy(path string) float64 {
	if path == "" || path == "/" {
		return 0
	}

	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	entropy := 0.0
	for _, part := range parts {
		if len(part) < 4 {
			continue
		}

		if e.entropyRE.MatchString(part) {
			entropy += 15
		}

		freq := make(map[rune]float64)
		for _, c := range part {
			freq[c]++
		}

		partEntropy := 0.0
		l := float64(len(part))
		if l < 2 {
			continue
		}
		for _, count := range freq {
			p := count / l
			if p > 0 {
				partEntropy -= p * math.Log2(p)
			}
		}

		maxEntropy := math.Log2(l)
		if maxEntropy > 0 {
			normalized := partEntropy / maxEntropy
			if normalized > 0.85 && l > 8 {
				entropy += 20
			}
		}

		if len(part) > 16 {
			entropy += 10
		}
	}

	return math.Min(entropy, 50)
}

func (e *BehavioralEngine) ReportBadIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.badIPs[ip] = true
}

func (e *BehavioralEngine) IncrementReputation(ip string, delta int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ipReputation[ip] += delta
	if e.ipReputation[ip] > 100 {
		e.badIPs[ip] = true
	}
}

func (e *BehavioralEngine) BlockIP(ip string, duration time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockedIPs[ip] = time.Now().Add(duration)
	e.badIPs[ip] = true
}

func (e *BehavioralEngine) cleanupLoop() {
	for range e.cleanupTimer.C {
		e.mu.Lock()
		now := time.Now()
		for ip, until := range e.blockedIPs {
			if now.After(until) {
				delete(e.blockedIPs, ip)
				delete(e.badIPs, ip)
				delete(e.ipReputation, ip)
			}
		}
		if len(e.ipRequests) > 10000 {
			cutoff := 0
			for ip := range e.ipRequests {
				if cutoff > 1000 {
					break
				}
				delete(e.ipRequests, ip)
				cutoff++
			}
		}
		e.mu.Unlock()
	}
}

func (e *BehavioralEngine) Close() {
	e.cleanupTimer.Stop()
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	entropy := 0.0
	l := float64(len(s))
	for _, count := range freq {
		p := count / l
		entropy -= p * math.Log2(p)
	}
	return entropy
}
