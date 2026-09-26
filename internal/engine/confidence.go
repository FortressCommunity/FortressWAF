package engine

import (
	"math"
	"sync"
	"time"
)

type ConfidenceScorer struct {
	mu        sync.RWMutex
	stability map[string]*ruleConfidence
	cleanup   *time.Ticker
}

type ruleConfidence struct {
	ruleID         string
	totalDecisions int64
	confirmedBad   int64
	falsePositives int64
	baseConfidence float64
	lastUpdated    time.Time
}

func NewConfidenceScorer() *ConfidenceScorer {
	cs := &ConfidenceScorer{
		stability: make(map[string]*ruleConfidence),
		cleanup:   time.NewTicker(10 * time.Minute),
	}
	go cs.cleanupLoop()
	return cs
}

func (cs *ConfidenceScorer) ScoreDecision(dec *Decision) {
	if dec.ConfidenceScore > 0 {
		return
	}

	cs.mu.RLock()
	rc, exists := cs.stability[dec.RuleID]
	cs.mu.RUnlock()

	base := 0.85
	if exists {
		base = rc.baseConfidence
	}

	score := dec.Score / 100.0
	severityWeight := map[string]float64{
		"critical": 1.0,
		"high":     0.85,
		"medium":   0.65,
		"low":      0.40,
		"info":     0.20,
	}

	sw := severityWeight[dec.Severity]
	if sw == 0 {
		sw = 0.50
	}

	evidenceLen := len(dec.Evidence)
	evidenceQuality := 0.5
	if evidenceLen > 10 {
		evidenceQuality = math.Min(1.0, float64(evidenceLen)/200.0)
	}

	confidence := base*0.4 +
		score*0.3 +
		sw*0.2 +
		evidenceQuality*0.1

	confidence = math.Max(0.1, math.Min(1.0, confidence))

	dec.ConfidenceScore = math.Round(confidence*100) / 100
}

func (cs *ConfidenceScorer) RecordTruePositive(ruleID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.getOrCreate(ruleID)
	rc := cs.stability[ruleID]
	rc.totalDecisions++
	rc.confirmedBad++
	rc.lastUpdated = time.Now()
	rc.baseConfidence = math.Min(0.99, rc.baseConfidence+0.01)
}

func (cs *ConfidenceScorer) RecordFalsePositive(ruleID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	rc := cs.getOrCreate(ruleID)
	rc.totalDecisions++
	rc.falsePositives++
	rc.lastUpdated = time.Now()
	penalty := float64(rc.falsePositives) / float64(rc.totalDecisions) * 0.2
	rc.baseConfidence = math.Max(0.5, rc.baseConfidence-penalty)
}

func (cs *ConfidenceScorer) GetConfidence(ruleID string) float64 {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	rc, exists := cs.stability[ruleID]
	if !exists {
		return 0.85
	}

	accuracy := 1.0
	if rc.totalDecisions > 0 {
		accuracy = float64(rc.confirmedBad) / float64(rc.totalDecisions)
	}

	return rc.baseConfidence * accuracy
}

func (cs *ConfidenceScorer) getOrCreate(ruleID string) *ruleConfidence {
	if rc, exists := cs.stability[ruleID]; exists {
		return rc
	}
	cs.stability[ruleID] = &ruleConfidence{
		ruleID:         ruleID,
		baseConfidence: 0.85,
		lastUpdated:    time.Now(),
	}
	return cs.stability[ruleID]
}

func (cs *ConfidenceScorer) cleanupLoop() {
	for range cs.cleanup.C {
		cs.mu.Lock()
		now := time.Now()
		for id, rc := range cs.stability {
			if now.After(rc.lastUpdated.Add(24*time.Hour)) && rc.totalDecisions == 0 {
				delete(cs.stability, id)
			}
		}
		cs.mu.Unlock()
	}
}

func (cs *ConfidenceScorer) Close() {
	cs.cleanup.Stop()
}
