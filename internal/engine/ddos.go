package engine

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SlidingWindowCounter struct {
	mu         sync.Mutex
	timestamps []time.Time
	window     time.Duration
	maxCount   int
}

// record adds a timestamp now and prunes anything older than the window.
func (c *SlidingWindowCounter) record(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-c.window)
	valid := c.timestamps[:0]
	for _, t := range c.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	c.timestamps = append(valid, now)
}

// count returns the number of timestamps still inside the window.
func (c *SlidingWindowCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := time.Now().Add(-c.window)
	n := 0
	for _, t := range c.timestamps {
		if t.After(cutoff) {
			n++
		}
	}
	return n
}

// lastSeen returns the newest timestamp, or the zero time when empty.
func (c *SlidingWindowCounter) lastSeen() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timestamps) == 0 {
		return time.Time{}
	}
	return c.timestamps[len(c.timestamps)-1]
}

type DDoSProtection struct {
	mu              sync.RWMutex
	devMode         bool
	globalRate      int
	perIPRate       int
	perEndpointRate int
	perSessionRate  int
	burstAllowance  int
	windowSize      time.Duration
	autoBanDuration time.Duration

	ipCounters       map[string]*SlidingWindowCounter
	sessionCounters  map[string]*SlidingWindowCounter
	endpointCounters map[string]*SlidingWindowCounter
	slowLorisTimers  map[string]time.Time
	slowPOSTTimers   map[string]time.Time

	globalMu      sync.RWMutex
	globalCounter *SlidingWindowCounter
	done          chan struct{}
}

// DDoSOptions configures the flood thresholds and the auto-ban behaviour.
// A zero field falls back to the default below; PerIPBan < 0 disables auto-ban.
type DDoSOptions struct {
	GlobalRate      int
	PerIPRate       int
	PerEndpointRate int
	PerSessionRate  int
	// PerIPBan is how long an address that trips the per-IP rate is banned.
	// Zero -> default (10m). Negative -> never auto-ban (429 only).
	PerIPBan time.Duration
}

func NewDDoSProtection(devMode bool) *DDoSProtection {
	return NewDDoSProtectionWithOptions(devMode, DDoSOptions{})
}

func NewDDoSProtectionWithOptions(devMode bool, opts DDoSOptions) *DDoSProtection {
	if opts.GlobalRate <= 0 {
		opts.GlobalRate = 10000
	}
	if opts.PerIPRate <= 0 {
		// 30 req/s per address: comfortably above a real browser's burst
		// (a page load is a few dozen requests over seconds) and low enough
		// that a flood trips it immediately.
		opts.PerIPRate = 30
	}
	if opts.PerEndpointRate <= 0 {
		opts.PerEndpointRate = 200
	}
	if opts.PerSessionRate <= 0 {
		opts.PerSessionRate = 200
	}
	if opts.PerIPBan == 0 {
		opts.PerIPBan = 10 * time.Minute
	}

	d := &DDoSProtection{
		devMode:          devMode,
		globalRate:       opts.GlobalRate,
		perIPRate:        opts.PerIPRate,
		perEndpointRate:  opts.PerEndpointRate,
		perSessionRate:   opts.PerSessionRate,
		burstAllowance:   20,
		windowSize:       time.Second,
		autoBanDuration:  opts.PerIPBan,
		ipCounters:       make(map[string]*SlidingWindowCounter),
		sessionCounters:  make(map[string]*SlidingWindowCounter),
		endpointCounters: make(map[string]*SlidingWindowCounter),
		slowLorisTimers:  make(map[string]time.Time),
		slowPOSTTimers:   make(map[string]time.Time),
		globalCounter: &SlidingWindowCounter{
			timestamps: make([]time.Time, 0, opts.GlobalRate+20),
			window:     time.Second,
			maxCount:   opts.GlobalRate + 20,
		},
		done: make(chan struct{}),
	}
	go d.cleanup()
	return d
}

func (d *DDoSProtection) Name() string { return "ddos_protection" }

func (d *DDoSProtection) Inspect(ctx *RequestContext) (*Decision, error) {
	if dec := d.detectHTTPFlood(ctx); dec != nil {
		return dec, nil
	}

	if dec := d.detectSlowloris(ctx); dec != nil {
		return dec, nil
	}

	if dec := d.detectSlowPOST(ctx); dec != nil {
		return dec, nil
	}

	if dec := d.detectCacheBusting(ctx); dec != nil {
		return dec, nil
	}

	return nil, nil
}

func (d *DDoSProtection) getOrCreateCounter(counters map[string]*SlidingWindowCounter, key string) *SlidingWindowCounter {
	if c, ok := counters[key]; ok {
		return c
	}
	c := &SlidingWindowCounter{
		timestamps: make([]time.Time, 0, d.perIPRate+d.burstAllowance),
		window:     d.windowSize,
		maxCount:   d.perIPRate + d.burstAllowance,
	}
	counters[key] = c
	return c
}

func (d *DDoSProtection) checkRate(counter *SlidingWindowCounter, limit int) bool {
	counter.mu.Lock()
	defer counter.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-d.windowSize)

	var valid []time.Time
	for _, t := range counter.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	counter.timestamps = valid

	if len(valid) >= limit {
		return false
	}

	counter.timestamps = append(counter.timestamps, now)
	return true
}

func (d *DDoSProtection) detectHTTPFlood(ctx *RequestContext) *Decision {
	d.mu.Lock()
	defer d.mu.Unlock()

	if dec := d.checkGlobalRate(ctx); dec != nil {
		return dec
	}

	ipCounter := d.getOrCreateCounter(d.ipCounters, ctx.RealIP)
	if !d.checkRate(ipCounter, d.perIPRate) {
		dec := &Decision{
			Action:   ActionRateLimit,
			RuleID:   "DDoS001",
			RuleName: "HTTP Flood - IP",
			Severity: "high",
			Score:    65,
			Evidence: fmt.Sprintf("IP %s exceeded rate limit: %d req/s", ctx.RealIP, d.perIPRate),
		}
		// A per-IP flood is exactly the case that warrants an auto-ban. A
		// negative duration disables it and only the 429 is returned.
		if d.autoBanDuration > 0 {
			dec.BanRequest = true
			dec.BanDuration = d.autoBanDuration
		}
		return dec
	}

	epCounter := d.getOrCreateCounter(d.endpointCounters, ctx.Path)
	if !d.checkRate(epCounter, d.perEndpointRate) {
		return &Decision{
			Action:   ActionRateLimit,
			RuleID:   "DDoS002",
			RuleName: "HTTP Flood - Endpoint",
			Severity: "high",
			Score:    60,
			Evidence: fmt.Sprintf("Endpoint %s exceeded rate: %d req/s", ctx.Path, d.perEndpointRate),
		}
	}

	if ctx.SessionID != "" {
		sessionCounter := d.getOrCreateCounter(d.sessionCounters, ctx.SessionID)
		if !d.checkRate(sessionCounter, d.perSessionRate) {
			return &Decision{
				Action:   ActionRateLimit,
				RuleID:   "DDoS003",
				RuleName: "HTTP Flood - Session",
				Severity: "medium",
				Score:    50,
				Evidence: fmt.Sprintf("Session %s exceeded rate: %d req/s", ctx.SessionID, d.perSessionRate),
			}
		}
	}

	return nil
}

func (d *DDoSProtection) checkGlobalRate(ctx *RequestContext) *Decision {
	d.globalMu.RLock()
	if !d.checkRate(d.globalCounter, d.globalRate) {
		d.globalMu.RUnlock()
		return &Decision{
			Action:   ActionRateLimit,
			RuleID:   "DDoS000",
			RuleName: "HTTP Flood - Global",
			Severity: "critical",
			Score:    90,
			Evidence: fmt.Sprintf("global rate limit exceeded: %d req/s", d.globalRate),
		}
	}
	d.globalMu.RUnlock()
	return nil
}

func (d *DDoSProtection) detectSlowloris(ctx *RequestContext) *Decision {
	if ctx.Headers["Expect"] != "" {
		d.mu.Lock()
		d.slowLorisTimers[ctx.RealIP] = time.Now()
		d.mu.Unlock()
		return nil
	}

	contentLength := ctx.Request.Header.Get("Content-Length")
	if contentLength == "" && ctx.Method == http.MethodPost {
		d.mu.Lock()
		start, exists := d.slowLorisTimers[ctx.RealIP]
		if !exists {
			d.slowLorisTimers[ctx.RealIP] = time.Now()
			d.mu.Unlock()
			return nil
		}
		elapsed := time.Since(start)
		d.mu.Unlock()

		if elapsed > 30*time.Second {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "DDoS004",
				RuleName: "Slowloris Attack",
				Severity: "high",
				Score:    85,
				Evidence: fmt.Sprintf("slowloris detected from %s, elapsed: %v", ctx.RealIP, elapsed),
			}
		}
	}

	return nil
}

func (d *DDoSProtection) detectSlowPOST(ctx *RequestContext) *Decision {
	if ctx.Method != http.MethodPost || ctx.Body == nil {
		return nil
	}

	contentLengthStr := ctx.Request.Header.Get("Content-Length")
	if contentLengthStr == "" {
		return nil
	}

	var contentLength int64
	fmt.Sscanf(contentLengthStr, "%d", &contentLength)

	if contentLength > 1024*1024 {
		d.mu.Lock()
		start, exists := d.slowPOSTTimers[ctx.RealIP]
		if !exists {
			d.slowPOSTTimers[ctx.RealIP] = time.Now()
			d.mu.Unlock()
			return nil
		}
		received := len(ctx.Body)
		elapsed := time.Since(start)
		d.mu.Unlock()

		rate := float64(received) / elapsed.Seconds()
		if elapsed > 10*time.Second && rate < 1024 {
			return &Decision{
				Action:   ActionBlock,
				RuleID:   "DDoS005",
				RuleName: "Slow POST Attack",
				Severity: "high",
				Score:    80,
				Evidence: fmt.Sprintf("slow POST from %s, rate: %.0f b/s, elapsed: %v", ctx.RealIP, rate, elapsed),
			}
		}
	}

	return nil
}

func (d *DDoSProtection) detectCacheBusting(ctx *RequestContext) *Decision {
	queryKeys := make([]string, 0, len(ctx.QueryParams))
	for k := range ctx.QueryParams {
		queryKeys = append(queryKeys, k)
	}

	paramCount := len(queryKeys)
	randomPatterns := 0
	for k, v := range ctx.QueryParams {
		lowerK := strings.ToLower(k)
		if strings.Contains(lowerK, "cache") || strings.Contains(lowerK, "rand") ||
			strings.Contains(lowerK, "t") || strings.Contains(lowerK, "_") && len(k) <= 3 {
			for _, val := range v {
				if len(val) >= 8 && len(val) <= 32 {
					isHex := true
					for _, c := range val {
						if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
							isHex = false
							break
						}
					}
					if isHex || len(val) >= 16 {
						randomPatterns++
					}
				}
			}
		}
	}

	if paramCount >= 5 && randomPatterns >= paramCount/2 {
		return &Decision{
			Action:   ActionMonitor,
			RuleID:   "DDoS006",
			RuleName: "Cache Busting Attack",
			Severity: "medium",
			Score:    40,
			Evidence: fmt.Sprintf("cache busting detected, params: %d, random: %d", paramCount, randomPatterns),
		}
	}

	return nil
}

func (d *DDoSProtection) GetAdaptiveRate(ip string, currentRate int) int {
	d.mu.RLock()
	counter, exists := d.ipCounters[ip]
	d.mu.RUnlock()

	if !exists {
		return currentRate
	}

	counter.mu.Lock()
	count := len(counter.timestamps)
	counter.mu.Unlock()

	if count > currentRate*2 {
		return int(math.Max(float64(currentRate)*0.5, 10))
	}

	if count > currentRate {
		return int(math.Max(float64(currentRate)*0.8, 10))
	}

	return currentRate
}

func (d *DDoSProtection) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-d.done:
				return
			case <-ticker.C:
				d.mu.Lock()
				now := time.Now()
				for ip, counter := range d.ipCounters {
					counter.mu.Lock()
					if len(counter.timestamps) == 0 || now.Sub(counter.timestamps[len(counter.timestamps)-1]) > 10*time.Minute {
						delete(d.ipCounters, ip)
					}
					counter.mu.Unlock()
				}
				for ip, t := range d.slowLorisTimers {
					if now.Sub(t) > 5*time.Minute {
						delete(d.slowLorisTimers, ip)
					}
				}
				for ip, t := range d.slowPOSTTimers {
					if now.Sub(t) > 5*time.Minute {
						delete(d.slowPOSTTimers, ip)
					}
				}
				d.mu.Unlock()
			}
		}
	}()
}

func (d *DDoSProtection) Close() {
	close(d.done)
}
