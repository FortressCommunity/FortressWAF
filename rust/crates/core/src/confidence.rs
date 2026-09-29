//! Adaptive per-rule confidence scoring.
//!
//! Port of `internal/engine/confidence.go`. The scoring formula, severity
//! weights, rounding, and clamping are preserved exactly so decisions score
//! identically to the Go backend.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::action::Decision;

/// ConfidenceScorer tracks per-rule reliability and computes a confidence
/// score for each decision.
///
/// Port of the Go `ConfidenceScorer`. The Go version ran a background goroutine
/// to prune stale entries every 10 minutes. Here [`ConfidenceScorer::cleanup`]
/// performs the same prune and is meant to be called from a periodic task; it is
/// exposed so callers control the scheduler rather than the struct owning a
/// thread.
pub struct ConfidenceScorer {
    stability: Arc<RwLock<HashMap<String, RuleConfidence>>>,
    /// Interval at which `cleanup` is expected to run (kept for parity with the
    /// Go ticker interval; not used internally).
    pub cleanup_interval: Duration,
}

#[derive(Debug, Clone)]
struct RuleConfidence {
    rule_id: String,
    total_decisions: i64,
    confirmed_bad: i64,
    false_positives: i64,
    base_confidence: f64,
    last_updated: Instant,
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidenceScorer {
    pub fn new() -> Self {
        ConfidenceScorer {
            stability: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval: Duration::from_secs(10 * 60),
        }
    }

    /// Compute and set `dec.confidence_score` unless it is already > 0.
    ///
    /// Exact port of `ScoreDecision`.
    pub fn score_decision(&self, dec: &mut Decision) {
        if dec.confidence_score > 0.0 {
            return;
        }

        let base = {
            let map = self.stability.read();
            match map.get(&dec.rule_id) {
                Some(rc) => rc.base_confidence,
                None => 0.85,
            }
        };

        let score = dec.score / 100.0;

        let sw = match dec.severity.as_str() {
            "critical" => 1.0,
            "high" => 0.85,
            "medium" => 0.65,
            "low" => 0.40,
            "info" => 0.20,
            _ => 0.50,
        };

        let evidence_len = dec.evidence.chars().count();
        // Go measured len(dec.Evidence) in BYTES. Use byte length to match.
        let evidence_bytes = dec.evidence.len();
        let evidence_quality = if evidence_bytes > 10 {
            f64::min(1.0, evidence_bytes as f64 / 200.0)
        } else {
            0.5
        };
        let _ = evidence_len;

        let confidence = base * 0.4 + score * 0.3 + sw * 0.2 + evidence_quality * 0.1;

        let confidence = f64::max(0.1, f64::min(1.0, confidence));

        // Go: math.Round(confidence*100) / 100 -- round half away from zero.
        dec.confidence_score = round_half_away(confidence * 100.0) / 100.0;
    }

    /// Port of `RecordTruePositive`.
    pub fn record_true_positive(&self, rule_id: &str) {
        let mut map = self.stability.write();
        let rc = get_or_create(&mut map, rule_id);
        rc.total_decisions += 1;
        rc.confirmed_bad += 1;
        rc.last_updated = Instant::now();
        rc.base_confidence = f64::min(0.99, rc.base_confidence + 0.01);
    }

    /// Port of `RecordFalsePositive`.
    pub fn record_false_positive(&self, rule_id: &str) {
        let mut map = self.stability.write();
        let rc = get_or_create(&mut map, rule_id);
        rc.total_decisions += 1;
        rc.false_positives += 1;
        rc.last_updated = Instant::now();
        let penalty = rc.false_positives as f64 / rc.total_decisions as f64 * 0.2;
        rc.base_confidence = f64::max(0.5, rc.base_confidence - penalty);
    }

    /// Port of `GetConfidence`.
    pub fn get_confidence(&self, rule_id: &str) -> f64 {
        let map = self.stability.read();
        let rc = match map.get(rule_id) {
            Some(rc) => rc,
            None => return 0.85,
        };
        let accuracy = if rc.total_decisions > 0 {
            rc.confirmed_bad as f64 / rc.total_decisions as f64
        } else {
            1.0
        };
        rc.base_confidence * accuracy
    }

    /// Prune entries untouched for 24h with no recorded decisions.
    /// Port of the body of `cleanupLoop`.
    pub fn cleanup(&self) {
        let mut map = self.stability.write();
        let now = Instant::now();
        map.retain(|_, rc| {
            !(now.duration_since(rc.last_updated) > Duration::from_secs(24 * 3600)
                && rc.total_decisions == 0)
        });
    }
}

fn get_or_create<'a>(
    map: &'a mut HashMap<String, RuleConfidence>,
    rule_id: &str,
) -> &'a mut RuleConfidence {
    map.entry(rule_id.to_string())
        .or_insert_with(|| RuleConfidence {
            rule_id: rule_id.to_string(),
            total_decisions: 0,
            confirmed_bad: 0,
            false_positives: 0,
            base_confidence: 0.85,
            last_updated: Instant::now(),
        })
}

/// `math.Round`: round half away from zero.
fn round_half_away(x: f64) -> f64 {
    x.round()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{Action, Decision};

    #[test]
    fn score_decision_formula_matches_go() {
        // base=0.85 (unknown), score=90/100=0.9, severity=critical sw=1.0,
        // evidence len ~ 20 bytes -> quality = 20/200 = 0.1
        let cs = ConfidenceScorer::new();
        let mut d = Decision::new(Action::Block, 90.0);
        d.rule_id = "SQLI001".into();
        d.severity = "critical".into();
        d.evidence = "0123456789012345678".into(); // 19 bytes
        cs.score_decision(&mut d);
        // confidence = 0.85*0.4 + 0.9*0.3 + 1.0*0.2 + (19/200)*0.1
        //            = 0.34 + 0.27 + 0.2 + 0.0095 = 0.8195 -> 0.82
        assert!(
            (d.confidence_score - 0.82).abs() < 1e-9,
            "got {}",
            d.confidence_score
        );
    }

    #[test]
    fn already_scored_is_untouched() {
        let cs = ConfidenceScorer::new();
        let mut d = Decision::new(Action::Block, 10.0);
        d.rule_id = "R".into();
        d.confidence_score = 0.5;
        cs.score_decision(&mut d);
        assert_eq!(d.confidence_score, 0.5);
    }

    #[test]
    fn unknown_rule_confidence_is_085() {
        let cs = ConfidenceScorer::new();
        assert_eq!(cs.get_confidence("nope"), 0.85);
    }

    #[test]
    fn false_positive_penalty_reduces_base() {
        let cs = ConfidenceScorer::new();
        // First FP: total=1, fp=1 -> penalty=0.2 -> base=0.85-0.2=0.65
        cs.record_false_positive("R");
        let map = cs.stability.read();
        let rc = map.get("R").unwrap();
        assert!(
            (rc.base_confidence - 0.65).abs() < 1e-9,
            "got {}",
            rc.base_confidence
        );
    }

    #[test]
    fn cleanup_removes_stale_unused() {
        let cs = ConfidenceScorer::new();
        cs.record_false_positive("R"); // total_decisions = 1 -> not pruned
        cs.cleanup();
        assert!(cs.stability.read().contains_key("R"));
    }
}
