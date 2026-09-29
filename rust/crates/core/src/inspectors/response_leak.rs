//! Response body leak inspection: secrets and sensitive data leaving the origin.
//!
//! Port of `internal/engine/response_leak.go`. Rule IDs, regexes, scores, and
//! the redaction behaviour are preserved exactly.

use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

/// A single response-body detection rule.
struct LeakRule {
    id: &'static str,
    name: &'static str,
    severity: &'static str,
    score: f64,
    regex: Regex,
    /// Redaction strategy for evidence. `None` means "mask the whole match".
    redact: Redact,
}

#[derive(Clone, Copy)]
enum Redact {
    /// Keep at most the last 4 characters (`maskTail`).
    MaskTail,
    /// Replace the whole match with a fixed placeholder.
    Fixed(&'static str),
    /// Truncate long matches to 40 chars + ellipsis.
    None,
}

/// `maskTail`: keep at most the last 4 characters.
fn mask_tail(m: &str) -> String {
    if m.len() <= 4 {
        return "****".to_string();
    }
    let mut start = m.len() - 4;
    while start > 0 && !m.is_char_boundary(start) {
        start -= 1;
    }
    format!("****{}", &m[start..])
}

static RULES: Lazy<Vec<LeakRule>> = Lazy::new(|| {
    let r = |p: &str| Regex::new(p).expect("valid leak regex");
    vec![
        LeakRule {
            id: "LEAK-001",
            name: "Private key material in response",
            severity: "critical",
            score: 95.0,
            regex: r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            redact: Redact::None,
        },
        LeakRule {
            id: "LEAK-002",
            name: "AWS access key ID in response",
            severity: "critical",
            score: 90.0,
            regex: r(r"\bAKIA[0-9A-Z]{16}\b"),
            redact: Redact::MaskTail,
        },
        LeakRule {
            id: "LEAK-003",
            name: "JSON Web Token in response",
            severity: "high",
            score: 80.0,
            regex: r(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
            redact: Redact::MaskTail,
        },
        LeakRule {
            id: "LEAK-004",
            name: "Generic API key or secret token in response",
            severity: "high",
            score: 75.0,
            regex: r(r"\b(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35})\b"),
            redact: Redact::MaskTail,
        },
        LeakRule {
            id: "LEAK-005",
            name: "Database connection string with credentials",
            severity: "critical",
            score: 85.0,
            regex: r(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:/@]+:[^\s:/@]+@[^\s/]+"),
            redact: Redact::MaskTail,
        },
        LeakRule {
            id: "LEAK-006",
            name: "Password hash in response (bcrypt/argon2)",
            severity: "high",
            score: 80.0,
            regex: r(r"\$(?:2[aby]|argon2(?:id|i|d))\$[0-9]{2}\$[A-Za-z0-9./+]{20,}"),
            redact: Redact::Fixed("$2b$…"),
        },
        LeakRule {
            id: "LEAK-007",
            name: "Stack trace or internal path disclosure",
            severity: "medium",
            score: 40.0,
            regex: r(r"(?m)(?:goroutine \d+ \[|Traceback \(most recent call last\)|at (?:java|org|com)\.[A-Za-z0-9_.]+\(|panic: runtime error)"),
            redact: Redact::None,
        },
        LeakRule {
            id: "LEAK-008",
            name: "Cloud metadata credential in response",
            severity: "critical",
            score: 90.0,
            regex: r("(?i)\"?(?:AccessKeyId|SecretAccessKey|SessionToken)\"?\\s*[:=]\\s*\"?[A-Za-z0-9/+=]{16,}"),
            redact: Redact::MaskTail,
        },
    ]
});

pub struct ResponseLeakInspector {
    enabled: bool,
    block: bool,
    max_scan: usize,
    scanned: Arc<Mutex<u64>>,
    flagged: Arc<Mutex<u64>>,
}

impl ResponseLeakInspector {
    /// Port of `NewResponseLeakInspector`.
    pub fn new(enabled: bool, block: bool, max_scan_bytes: usize) -> Self {
        let max_scan = if max_scan_bytes == 0 {
            1 << 20
        } else {
            max_scan_bytes
        };
        ResponseLeakInspector {
            enabled,
            block,
            max_scan,
            scanned: Arc::new(Mutex::new(0)),
            flagged: Arc::new(Mutex::new(0)),
        }
    }

    /// Port of `InspectResponse`.
    pub fn inspect_response(
        &self,
        content_type: &str,
        status_code: i32,
        body: &[u8],
    ) -> Option<Decision> {
        let _ = status_code; // Go accepted statusCode but did not use it.
        if !self.enabled || body.is_empty() {
            return None;
        }
        if !is_textual_response(content_type) {
            return None;
        }

        let scan = if body.len() > self.max_scan {
            &body[..self.max_scan]
        } else {
            body
        };
        let text = String::from_utf8_lossy(scan);

        *self.scanned.lock() += 1;

        let mut best: Option<Decision> = None;
        for rule in RULES.iter() {
            let loc = match rule.regex.find(&text) {
                Some(m) => m,
                None => continue,
            };
            let matched = &text[loc.start()..loc.end()];
            let evidence = match rule.redact {
                Redact::MaskTail => mask_tail(matched),
                Redact::Fixed(s) => s.to_string(),
                Redact::None => {
                    if matched.len() > 40 {
                        let mut end = 40;
                        while end > 0 && !matched.is_char_boundary(end) {
                            end -= 1;
                        }
                        format!("{}…", &matched[..end])
                    } else {
                        matched.to_string()
                    }
                }
            };

            let action = if self.block {
                Action::Block
            } else {
                Action::Monitor
            };
            let dec = Decision::new(action, rule.score)
                .with_rule_id(rule.id)
                .with_rule_name(rule.name)
                .with_severity(rule.severity)
                .with_evidence(format!("response body leak [{}]: {}", rule.name, evidence));
            let mut dec = dec;
            dec.blocked = self.block;
            dec.inspector_name = "response_inspect".to_string();

            if best.is_none() || dec.score > best.as_ref().unwrap().score {
                best = Some(dec);
            }
        }

        if best.is_some() {
            *self.flagged.lock() += 1;
        }
        best
    }

    /// Port of `Stats`.
    pub fn stats(&self) -> (u64, u64) {
        (*self.scanned.lock(), *self.flagged.lock())
    }

    /// Port of `Enabled`.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Inspector for ResponseLeakInspector {
    fn name(&self) -> &str {
        "response_inspect"
    }

    fn inspect(&self, _ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        // Request-phase inspection is a no-op; leak detection is response-phase.
        Ok(None)
    }
}

/// Port of `isTextualResponse`.
pub fn is_textual_response(content_type: &str) -> bool {
    if content_type.is_empty() {
        return true;
    }
    let ct_lower = content_type.to_lowercase();
    let ct = match ct_lower.find(';') {
        Some(i) => ct_lower[..i].trim(),
        None => ct_lower.trim(),
    };
    match ct {
        "application/json"
        | "application/xml"
        | "text/xml"
        | "application/javascript"
        | "application/x-javascript"
        | "text/javascript"
        | "application/x-pem-file"
        | "application/x-www-form-urlencoded" => true,
        _ => ct.starts_with("text/"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_key_detected_and_redacted() {
        let r = ResponseLeakInspector::new(true, false, 0);
        let body = b"here is AKIAIOSFODNN7EXAMPLE end";
        let dec = r.inspect_response("text/plain", 200, body).unwrap();
        assert_eq!(dec.rule_id, "LEAK-002");
        assert_eq!(dec.action, Action::Monitor);
        // Evidence must be redacted: only last 4 chars kept.
        assert!(dec.evidence.ends_with("MPLE"));
        assert!(!dec.evidence.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn prose_password_not_flagged() {
        let r = ResponseLeakInspector::new(true, false, 0);
        let body = b"This document describes how to set a password for your account.";
        assert!(r.inspect_response("text/plain", 200, body).is_none());
    }

    #[test]
    fn private_key_blocked_when_block_true() {
        let r = ResponseLeakInspector::new(true, true, 0);
        let body = b"-----BEGIN RSA PRIVATE KEY-----\nMII...\n";
        let dec = r.inspect_response("text/plain", 200, body).unwrap();
        assert_eq!(dec.rule_id, "LEAK-001");
        assert_eq!(dec.action, Action::Block);
        assert!(dec.blocked);
    }

    #[test]
    fn binary_content_type_skipped() {
        let r = ResponseLeakInspector::new(true, true, 0);
        let body = b"-----BEGIN RSA PRIVATE KEY-----";
        assert!(r.inspect_response("image/png", 200, body).is_none());
    }

    #[test]
    fn disabled_scanner_returns_none() {
        let r = ResponseLeakInspector::new(false, false, 0);
        let body = b"AKIAIOSFODNN7EXAMPLE";
        assert!(r.inspect_response("text/plain", 200, body).is_none());
    }
}
