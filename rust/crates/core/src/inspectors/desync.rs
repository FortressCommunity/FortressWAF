//! HTTP request smuggling / desync detection.
//!
//! Port of `internal/engine/desync.go`. Rule IDs, scores and the check order
//! are preserved exactly.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

struct Patterns {
    cl_te_re: Regex,
    obs_fold_re: Regex,
    chunked_re: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        cl_te_re: Regex::new(r"(?i)^\s*Content-Length\s*:\s*\d+\s*$").unwrap(),
        obs_fold_re: Regex::new(r"(?m)^\s+(?:[a-zA-Z-]+):").unwrap(),
        chunked_re: Regex::new(r"(?i)Transfer-Encoding\s*:\s*chunked").unwrap(),
    })
}

pub struct DesyncDetector {
    pub dev_mode: bool,
    pub max_body_size: i64,
    pub strict_cl: bool,
    pub detect_obs_fold: bool,
}

impl DesyncDetector {
    pub fn new(dev_mode: bool, max_body_size: i64, strict_cl: bool, detect_obs_fold: bool) -> Self {
        let _ = patterns();
        DesyncDetector {
            dev_mode,
            max_body_size,
            strict_cl,
            detect_obs_fold,
        }
    }

    fn check_cl_te(&self, ctx: &RequestContext) -> Option<Decision> {
        let cl = ctx.request_header("Content-Length");
        let te = ctx.request_header("Transfer-Encoding");

        if !cl.is_empty() && te.to_lowercase().contains("chunked") {
            return Some(
                Decision::new(Action::Block, 95.0)
                    .with_rule_id("DSYNC_001")
                    .with_rule_name("CL.TE Desync")
                    .with_severity("critical")
                    .with_evidence(
                        "Content-Length and Transfer-Encoding: chunked both present (CL.TE smuggling)",
                    ),
            );
        }

        let cls = ctx.request.header.values("Content-Length");
        if cls.len() > 1 {
            let vals: Vec<String> = cls
                .iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect();
            if vals.len() > 1 {
                let first = &vals[0];
                for v in &vals[1..] {
                    if v != first {
                        return Some(
                            Decision::new(Action::Block, 90.0)
                                .with_rule_id("DSYNC_002")
                                .with_rule_name("Multiple Content-Length (CL.CL)")
                                .with_severity("critical")
                                .with_evidence(format!(
                                    "mismatched Content-Length headers: {}",
                                    vals.join(", ")
                                )),
                        );
                    }
                }
            }
        }

        None
    }

    fn check_te_cl(&self, ctx: &RequestContext) -> Option<Decision> {
        let te = ctx.request_header("Transfer-Encoding");
        let cl = ctx.request_header("Content-Length");

        if te.to_lowercase().contains("chunked") && !cl.is_empty() {
            return Some(
                Decision::new(Action::Block, 95.0)
                    .with_rule_id("DSYNC_003")
                    .with_rule_name("TE.CL Desync")
                    .with_severity("critical")
                    .with_evidence(
                        "Transfer-Encoding: chunked with Content-Length present (TE.CL smuggling)",
                    ),
            );
        }

        None
    }

    fn check_obs_fold(&self, ctx: &RequestContext) -> Option<Decision> {
        if !self.detect_obs_fold {
            return None;
        }

        for (k, v) in &ctx.headers {
            if k.starts_with(' ') || v.starts_with(' ') {
                if self.strict_cl {
                    return Some(
                        Decision::new(Action::Block, 75.0)
                            .with_rule_id("DSYNC_004")
                            .with_rule_name("Obs-fold Header")
                            .with_severity("high")
                            .with_evidence(format!("obs-fold header detected: {k:?}")),
                    );
                }
                return Some(
                    Decision::new(Action::Monitor, 40.0)
                        .with_rule_id("DSYNC_004")
                        .with_rule_name("Obs-fold Header")
                        .with_severity("medium")
                        .with_evidence(format!("obs-fold header detected: {k:?}")),
                );
            }
        }

        None
    }

    fn check_content_length_anomaly(&self, ctx: &RequestContext) -> Option<Decision> {
        let cls = ctx.request.header.values("Content-Length");
        if cls.is_empty() {
            return None;
        }

        let cl = cls[0].trim();
        if cl.is_empty() {
            return None;
        }

        let val: i64 = match cl.parse::<i64>() {
            Ok(v) => v,
            Err(_) => {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("DSYNC_005")
                        .with_rule_name("Invalid Content-Length")
                        .with_severity("high")
                        .with_evidence(format!("non-numeric Content-Length: {cl:?}")),
                );
            }
        };

        if val < 0 {
            return Some(
                Decision::new(Action::Block, 80.0)
                    .with_rule_id("DSYNC_006")
                    .with_rule_name("Negative Content-Length")
                    .with_severity("high")
                    .with_evidence(format!("negative Content-Length: {val}")),
            );
        }

        if self.max_body_size > 0 && val > self.max_body_size {
            return Some(
                Decision::new(Action::Block, 30.0)
                    .with_rule_id("DSYNC_007")
                    .with_rule_name("Content-Length Exceeds Limit")
                    .with_severity("medium")
                    .with_evidence(format!(
                        "Content-Length {val} exceeds max {}",
                        self.max_body_size
                    )),
            );
        }

        None
    }

    /// NOTE (faithful dead code): Go iterated `ctx.Headers`, a map that retains
    /// only ONE value per canonical key, so `seen[lower]` can never exceed 1 and
    /// this check never returns a decision. The port preserves that: it counts
    /// entries in the same single-value map, so it likewise never fires.
    fn check_duplicate_headers(&self, ctx: &RequestContext) -> Option<Decision> {
        let mut seen: std::collections::HashMap<String, i32> = std::collections::HashMap::new();
        for k in ctx.headers.keys() {
            *seen.entry(k.to_lowercase()).or_insert(0) += 1;
        }

        for (k, count) in seen {
            if count > 1 {
                if k == "content-length" || k == "transfer-encoding" || k == "host" {
                    continue;
                }
                if self.strict_cl {
                    return Some(
                        Decision::new(Action::Monitor, 20.0)
                            .with_rule_id("DSYNC_008")
                            .with_rule_name("Duplicate Header")
                            .with_severity("medium")
                            .with_evidence(format!(
                                "header {k:?} appears {count} times (potential smuggling)"
                            )),
                    );
                }
            }
        }

        None
    }

    fn check_te_header(&self, ctx: &RequestContext) -> Option<Decision> {
        let te = ctx.request_header("TE");
        if !te.is_empty() {
            let te_lower = te.to_lowercase();
            if te_lower.contains("chunked") || te_lower.contains("trailers") {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("DSYNC_009")
                        .with_rule_name("TE Header Present")
                        .with_severity("high")
                        .with_evidence(format!("TE header with sensitive value: {te:?}")),
                );
            }
        }
        None
    }
}

impl Inspector for DesyncDetector {
    fn name(&self) -> &str {
        "desync"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if let Some(dec) = self.check_cl_te(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.check_te_cl(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.check_obs_fold(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.check_content_length_anomaly(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.check_duplicate_headers(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.check_te_header(ctx) {
            return Ok(Some(dec));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn det() -> DesyncDetector {
        DesyncDetector::new(false, 10 << 20, true, true)
    }

    #[test]
    fn cl_te_desync_blocked() {
        let d = det();
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Content-Length", "10");
        r.header.add("Transfer-Encoding", "chunked");
        let mut ctx = RequestContext::new(r);
        let dec = d.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "DSYNC_001");
    }

    #[test]
    fn mismatched_content_length_blocked() {
        let d = det();
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Content-Length", "10");
        r.header.add("Content-Length", "20");
        let mut ctx = RequestContext::new(r);
        let dec = d.inspect(&mut ctx).unwrap().unwrap();
        // The value multi-map has two CL values; but the engine's first-value
        // map also sees only the first. DSYNC_001/003 won't fire (no TE), so
        // DSYNC_002 must.
        assert_eq!(dec.rule_id, "DSYNC_002");
    }

    #[test]
    fn negative_content_length_blocked() {
        let d = det();
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Content-Length", "-1");
        let mut ctx = RequestContext::new(r);
        let dec = d.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "DSYNC_006");
    }

    #[test]
    fn non_numeric_content_length_blocked() {
        let d = det();
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Content-Length", "abc");
        let mut ctx = RequestContext::new(r);
        let dec = d.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "DSYNC_005");
    }
}
