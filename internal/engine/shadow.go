package engine

import (
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"
)

type LearningEngine struct {
	mu         sync.RWMutex
	baselines  map[string]*pathBaseline
	whitelist  map[string]*whitelistEntry
	cleanup    *time.Ticker
	evaluation bool
}

type pathBaseline struct {
	path         string
	totalCount   int64
	allowedCount int64
	meanRate     float64
	stdDev       float64
	sumSquares   float64
	lastSeen     time.Time
	statusCodes  map[int]int64
	methods      map[string]int64
}

type whitelistEntry struct {
	pattern   string
	reason    string
	expiresAt time.Time
	hits      int64
	createdAt time.Time
}

func NewLearningEngine() *LearningEngine {
	le := &LearningEngine{
		baselines:  make(map[string]*pathBaseline),
		whitelist:  make(map[string]*whitelistEntry),
		cleanup:    time.NewTicker(15 * time.Minute),
		evaluation: true,
	}
	go le.cleanupLoop()
	return le
}

func (le *LearningEngine) Record(inspector string, ctx *RequestContext, dec *Decision) {
	path := ctx.Path
	status := 0
	if ctx.Response != nil {
		status = ctx.Response.StatusCode
	}

	le.mu.Lock()
	defer le.mu.Unlock()

	bl, exists := le.baselines[path]
	if !exists {
		bl = &pathBaseline{
			path:        path,
			statusCodes: make(map[int]int64),
			methods:     make(map[string]int64),
			lastSeen:    time.Now(),
		}
		le.baselines[path] = bl
	}

	bl.totalCount++
	bl.lastSeen = time.Now()
	bl.methods[ctx.Method]++
	if status > 0 {
		bl.statusCodes[status]++
	}

	if dec != nil && dec.Action == ActionAllow {
		bl.allowedCount++

		if !le.evaluation {
			return
		}

		rate := float64(bl.allowedCount) / math.Max(1, time.Since(bl.lastSeen).Seconds())
		if bl.meanRate > 0 {
			oldMean := bl.meanRate
			bl.meanRate = oldMean + (rate-oldMean)/float64(bl.totalCount)
			bl.sumSquares += (rate - oldMean) * (rate - bl.meanRate)
			bl.stdDev = math.Sqrt(bl.sumSquares / float64(bl.totalCount))
		} else {
			bl.meanRate = rate
		}
	}

	if le.evaluation && bl.totalCount > 100 && bl.allowedCount > bl.totalCount*90/100 {
		le.autoWhitelist(path, fmt.Sprintf("automatic: %d allowed / %d total for path %s with methods %v and statuses %v",
			bl.allowedCount, bl.totalCount, path, mapKeys(bl.methods), mapKeysInt(bl.statusCodes)))
	}
}

func (le *LearningEngine) Baseline(path string) *pathBaseline {
	le.mu.RLock()
	defer le.mu.RUnlock()
	bl, exists := le.baselines[path]
	if !exists {
		return nil
	}
	cp := *bl
	return &cp
}

func (le *LearningEngine) IsWhitelisted(path string) bool {
	le.mu.RLock()
	defer le.mu.RUnlock()

	entry, exists := le.whitelist[path]
	if !exists {
		return false
	}

	if time.Now().After(entry.expiresAt) {
		return false
	}

	return true
}

func (le *LearningEngine) autoWhitelist(path, reason string) {
	if _, exists := le.whitelist[path]; exists {
		return
	}

	le.whitelist[path] = &whitelistEntry{
		pattern:   path,
		reason:    reason,
		expiresAt: time.Now().Add(7 * 24 * time.Hour),
		hits:      0,
		createdAt: time.Now(),
	}

	slog.Info("learning: auto-whitelisted path", "path", path, "reason", reason)
}

func (le *LearningEngine) cleanupLoop() {
	for range le.cleanup.C {
		le.mu.Lock()
		now := time.Now()

		for path, entry := range le.whitelist {
			if now.After(entry.expiresAt) {
				delete(le.whitelist, path)
				slog.Debug("learning: whitelist entry expired", "path", path)
			}
		}

		for path, bl := range le.baselines {
			if now.After(bl.lastSeen.Add(72 * time.Hour)) {
				delete(le.baselines, path)
			}
		}
		le.mu.Unlock()
	}
}

func (le *LearningEngine) Stats() map[string]interface{} {
	le.mu.RLock()
	defer le.mu.RUnlock()

	return map[string]interface{}{
		"baselines":  len(le.baselines),
		"whitelist":  len(le.whitelist),
		"evaluation": le.evaluation,
	}
}

func (le *LearningEngine) Close() {
	le.cleanup.Stop()
}

func mapKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func mapKeysInt(m map[int]int64) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
