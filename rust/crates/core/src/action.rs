//! Enforcement action and decision types.
//!
//! Port of `internal/engine/engine.go` (`Action`, `Decision`).

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Action represents the enforcement action to take for a request.
///
/// The string values match the Go constants exactly, so JSON produced by this
/// crate is byte-compatible with the Go backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Blocks the request immediately.
    Block,
    /// Permits the request to proceed.
    Allow,
    /// Requires browser challenge verification.
    Challenge,
    /// Logs the event without blocking.
    Monitor,
    /// Applies rate limiting to the request.
    RateLimit,
}

impl Action {
    /// The wire string, matching the Go `Action` constant values.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Block => "block",
            Action::Allow => "allow",
            Action::Challenge => "challenge",
            Action::Monitor => "monitor",
            Action::RateLimit => "rate_limit",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Decision is the result of inspecting a request.
///
/// Fields mirror the Go `Decision` struct. `ban_request` and `ban_duration`
/// correspond to the Go fields tagged `json:"-"` (never serialised).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub action: Action,
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub rule_name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub score: f64,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub confidence_score: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub explainability: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inspector_name: String,

    /// When true, asks the caller to auto-ban the source address for
    /// `ban_duration`. Never serialised (Go tag `json:"-"`).
    #[serde(skip)]
    pub ban_request: bool,
    /// A zero duration means "use the caller's default". Never serialised.
    #[serde(skip)]
    pub ban_duration: Duration,
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

impl Default for Decision {
    fn default() -> Self {
        Decision {
            action: Action::Allow,
            rule_id: String::new(),
            rule_name: String::new(),
            severity: String::new(),
            score: 0.0,
            evidence: String::new(),
            blocked: false,
            confidence_score: 0.0,
            explainability: String::new(),
            inspector_name: String::new(),
            ban_request: false,
            ban_duration: Duration::ZERO,
        }
    }
}

impl Decision {
    /// Construct a decision with the given action and score, leaving all other
    /// fields at their zero values. Convenience for the ported inspectors.
    pub fn new(action: Action, score: f64) -> Self {
        Decision {
            action,
            score,
            ..Default::default()
        }
    }

    /// Builder-style helper: set the rule id.
    pub fn with_rule_id(mut self, rule_id: impl Into<String>) -> Self {
        self.rule_id = rule_id.into();
        self
    }

    /// Builder-style helper: set the rule name.
    pub fn with_rule_name(mut self, rule_name: impl Into<String>) -> Self {
        self.rule_name = rule_name.into();
        self
    }

    /// Builder-style helper: set the severity.
    pub fn with_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = severity.into();
        self
    }

    /// Builder-style helper: set the evidence string.
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = evidence.into();
        self
    }

    /// Builder-style helper: set the confidence score.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence_score = confidence;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_wire_strings_match_go() {
        assert_eq!(Action::Block.as_str(), "block");
        assert_eq!(Action::Allow.as_str(), "allow");
        assert_eq!(Action::Challenge.as_str(), "challenge");
        assert_eq!(Action::Monitor.as_str(), "monitor");
        assert_eq!(Action::RateLimit.as_str(), "rate_limit");
    }

    #[test]
    fn decision_serialises_snake_case_and_omits_empty() {
        let d = Decision::new(Action::Block, 90.0)
            .with_rule_id("SQLI001")
            .with_severity("critical");
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["action"], "block");
        assert_eq!(json["rule_id"], "SQLI001");
        assert_eq!(json["score"], 90.0);
        // omitempty fields must be absent when zero/empty.
        assert!(json.get("confidence_score").is_none());
        assert!(json.get("explainability").is_none());
        assert!(json.get("inspector_name").is_none());
        // Ban fields are always skipped.
        assert!(json.get("ban_request").is_none());
        assert!(json.get("ban_duration").is_none());
    }
}
