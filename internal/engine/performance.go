package engine

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type PerformanceManager struct {
	mu              sync.RWMutex
	regexTimeout    time.Duration
	wasmTimeout     time.Duration
	circuitBreakers map[string]*CircuitBreaker
	activeWorkers   int64
	maxWorkers      int64
	memoryLimit     int64
	watchdogTick    *time.Ticker
	timeoutLog      *slog.Logger
}

type CircuitBreaker struct {
	mu           sync.Mutex
	name         string
	failures     int64
	threshold    int64
	trips        int64
	lastTrip     time.Time
	halfOpen     bool
	halfOpenAt   time.Time
	recoveryTime time.Duration
	resets       int64
}

type CircuitState int

const (
	CircuitClosed   CircuitState = 0
	CircuitHalfOpen CircuitState = 1
	CircuitOpen     CircuitState = 2
)

func NewPerformanceManager(regexTimeoutMs, wasmTimeoutMs int64) *PerformanceManager {
	reTimeout := time.Duration(regexTimeoutMs) * time.Millisecond
	if reTimeout <= 0 {
		reTimeout = 1000 * time.Millisecond
	}
	wasmTimeout := time.Duration(wasmTimeoutMs) * time.Millisecond
	if wasmTimeout <= 0 {
		wasmTimeout = 5000 * time.Millisecond
	}

	pm := &PerformanceManager{
		regexTimeout:    reTimeout,
		wasmTimeout:     wasmTimeout,
		circuitBreakers: make(map[string]*CircuitBreaker),
		maxWorkers:      int64(runtime.GOMAXPROCS(0)) * 4,
		memoryLimit:     int64(512 * 1024 * 1024),
		watchdogTick:    time.NewTicker(30 * time.Second),
	}
	go pm.watchdogLoop()
	return pm
}

func (pm *PerformanceManager) Inspect(inspector Inspector, ctx *RequestContext) (*Decision, error) {
	name := inspector.Name()

	if !pm.canProceed(name) {
		return &Decision{
			Action:          ActionMonitor,
			RuleID:          "PERF_001",
			RuleName:        "Inspector Circuit Open",
			Severity:        "low",
			Score:           0,
			ConfidenceScore: 0.0,
			Evidence:        fmt.Sprintf("inspector %q circuit breaker open, skipping", name),
		}, nil
	}

	atomic.AddInt64(&pm.activeWorkers, 1)

	if atomic.LoadInt64(&pm.activeWorkers) > pm.maxWorkers {
		atomic.AddInt64(&pm.activeWorkers, -1)
		return &Decision{
			Action:          ActionMonitor,
			RuleID:          "PERF_002",
			RuleName:        "Max Concurrent Inspectors Exceeded",
			Severity:        "low",
			Score:           0,
			ConfidenceScore: 0.0,
			Evidence:        fmt.Sprintf("max concurrent workers (%d) exceeded, skipping %q", pm.maxWorkers, name),
		}, nil
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.Alloc > uint64(pm.memoryLimit) {
		atomic.AddInt64(&pm.activeWorkers, -1)
		return &Decision{
			Action:          ActionMonitor,
			RuleID:          "PERF_003",
			RuleName:        "Memory Limit Reached",
			Severity:        "low",
			Score:           0,
			ConfidenceScore: 0.0,
			Evidence:        fmt.Sprintf("memory alloc %d exceeds limit %d, skipping %q", m.Alloc, pm.memoryLimit, name),
		}, nil
	}

	decCh := make(chan *Decision, 1)
	errCh := make(chan error, 1)

	timeout := pm.getTimeout(name)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("panic in inspector %s: %v", name, r)
				pm.recordFailure(name)
			}
		}()
		dec, err := inspector.Inspect(ctx)
		if err != nil {
			errCh <- err
			return
		}
		decCh <- dec
	}()

	select {
	case dec := <-decCh:
		atomic.AddInt64(&pm.activeWorkers, -1)
		pm.recordSuccess(name)
		return dec, nil

	case err := <-errCh:
		atomic.AddInt64(&pm.activeWorkers, -1)
		pm.recordFailure(name)
		return nil, err

	case <-time.After(timeout):
		atomic.AddInt64(&pm.activeWorkers, -1)
		pm.recordFailure(name)
		return &Decision{
			Action:          ActionMonitor,
			RuleID:          "PERF_004",
			RuleName:        "Inspector Timeout",
			Severity:        "medium",
			Score:           20,
			ConfidenceScore: 0.50,
			Evidence:        fmt.Sprintf("inspector %q timed out after %v", name, timeout),
		}, nil
	}
}

func (pm *PerformanceManager) canProceed(name string) bool {
	pm.mu.RLock()
	cb, exists := pm.circuitBreakers[name]
	pm.mu.RUnlock()

	if !exists {
		return true
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.halfOpen && time.Since(cb.halfOpenAt) > cb.recoveryTime {
		cb.halfOpen = false
		cb.failures = 0
		return true
	}

	if time.Since(cb.lastTrip) > cb.recoveryTime {
		cb.halfOpen = true
		cb.halfOpenAt = time.Now()
		return true
	}

	return false
}

func (pm *PerformanceManager) recordFailure(name string) {
	pm.mu.Lock()
	cb, exists := pm.circuitBreakers[name]
	if !exists {
		cb = &CircuitBreaker{
			name:         name,
			threshold:    5,
			recoveryTime: 30 * time.Second,
		}
		pm.circuitBreakers[name] = cb
	}
	pm.mu.Unlock()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	if cb.failures >= cb.threshold {
		cb.lastTrip = time.Now()
		cb.trips++
		slog.Warn("performance: circuit breaker tripped",
			"inspector", name,
			"failures", cb.failures,
			"trips", cb.trips,
		)
	}
}

func (pm *PerformanceManager) recordSuccess(name string) {
	pm.mu.Lock()
	cb, exists := pm.circuitBreakers[name]
	pm.mu.Unlock()

	if !exists {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.failures > 0 {
		cb.failures--
	}
}

func (pm *PerformanceManager) getTimeout(name string) time.Duration {
	switch name {
	case "wasm":
		return pm.wasmTimeout
	default:
		return pm.regexTimeout
	}
}

func (pm *PerformanceManager) watchdogLoop() {
	for range pm.watchdogTick.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		if m.Alloc > uint64(pm.memoryLimit) {
			slog.Warn("performance: memory limit exceeded",
				"alloc_mb", m.Alloc/1024/1024,
				"limit_mb", pm.memoryLimit/1024/1024,
			)
		}

		active := atomic.LoadInt64(&pm.activeWorkers)
		if active > pm.maxWorkers/2 {
			slog.Warn("performance: high concurrent activity",
				"active_workers", active,
				"max_workers", pm.maxWorkers,
			)
		}
	}
}

func (pm *PerformanceManager) CircuitState(name string) CircuitState {
	pm.mu.RLock()
	cb, exists := pm.circuitBreakers[name]
	pm.mu.RUnlock()

	if !exists {
		return CircuitClosed
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.halfOpen {
		return CircuitHalfOpen
	}

	if time.Since(cb.lastTrip) < cb.recoveryTime && cb.failures >= cb.threshold {
		return CircuitOpen
	}

	return CircuitClosed
}

func (pm *PerformanceManager) Stats() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["active_workers"] = atomic.LoadInt64(&pm.activeWorkers)
	stats["max_workers"] = pm.maxWorkers
	stats["regex_timeout_ms"] = pm.regexTimeout.Milliseconds()
	stats["wasm_timeout_ms"] = pm.wasmTimeout.Milliseconds()

	cbStats := make(map[string]interface{})
	for name, cb := range pm.circuitBreakers {
		cb.mu.Lock()
		cbStats[name] = map[string]interface{}{
			"failures": cb.failures,
			"trips":    cb.trips,
			"state":    pm.CircuitState(name),
			"resets":   cb.resets,
		}
		cb.mu.Unlock()
	}
	stats["circuit_breakers"] = cbStats

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	stats["memory_alloc_mb"] = m.Alloc / 1024 / 1024

	return stats
}

func (pm *PerformanceManager) Close() {
	pm.watchdogTick.Stop()
}
