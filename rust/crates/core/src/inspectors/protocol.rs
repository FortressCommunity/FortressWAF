//! Protocol anomaly detection: malformed requests, smuggling, websocket
//! upgrade validation, verb tampering, header injection, cookie limits.
//!
//! Port of `internal/engine/protocol.go`. Rule IDs, scores and check order are
//! preserved exactly.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

struct Patterns {
    malformed_re: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        // Go: [\x00-\x08\x0b\x0c\x0e-\x1f\x7f]
        malformed_re: Regex::new(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]").unwrap(),
    })
}

const VERB_TAMPERING: &[&str] = &[
    "CONNECT",
    "TRACE",
    "TRACK",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "MOVE",
    "COPY",
    "LOCK",
    "UNLOCK",
    "BIND",
    "REBIND",
    "UNBIND",
    "ACL",
    "REPORT",
    "VERSION-CONTROL",
    "CHECKIN",
    "CHECKOUT",
    "UNCHECKOUT",
    "MERGE",
    "BASELINE-CONTROL",
    "MKCALENDAR",
    "MKREDIRECTREF",
    "UPDATEREDIRECTREF",
];

pub struct ProtocolAnomaly {
    pub dev_mode: bool,
}

impl ProtocolAnomaly {
    pub fn new(dev_mode: bool) -> Self {
        let _ = patterns();
        ProtocolAnomaly { dev_mode }
    }

    fn detect_malformed_request(&self, ctx: &RequestContext) -> Option<Decision> {
        if ctx.method.is_empty() {
            return Some(
                Decision::new(Action::Block, 70.0)
                    .with_rule_id("PROT001")
                    .with_rule_name("Missing HTTP Method")
                    .with_severity("high")
                    .with_evidence("http request missing method"),
            );
        }

        for (k, v) in &ctx.headers {
            if patterns().malformed_re.is_match(k) || patterns().malformed_re.is_match(v) {
                return Some(
                    Decision::new(Action::Block, 75.0)
                        .with_rule_id("PROT002")
                        .with_rule_name("Malformed HTTP Header")
                        .with_severity("high")
                        .with_evidence(format!("malformed header: {k}")),
                );
            }
        }

        if ctx.headers.len() > 100 {
            return Some(
                Decision::new(Action::Block, 40.0)
                    .with_rule_id("PROT003")
                    .with_rule_name("Excessive Headers")
                    .with_severity("medium")
                    .with_evidence(format!("too many headers: {}", ctx.headers.len())),
            );
        }

        // Go summed len(k)+len(v) in BYTES.
        let total_header_size: usize = ctx.headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        if total_header_size > 32000 {
            return Some(
                Decision::new(Action::Block, 65.0)
                    .with_rule_id("PROT004")
                    .with_rule_name("Header Size Exceeded")
                    .with_severity("high")
                    .with_evidence(format!("total header size: {total_header_size} bytes")),
            );
        }

        None
    }

    fn detect_request_smuggling(&self, ctx: &RequestContext) -> Option<Decision> {
        let content_length = ctx
            .headers
            .get("Content-Length")
            .cloned()
            .unwrap_or_default();
        let transfer_encoding = ctx
            .headers
            .get("Transfer-Encoding")
            .cloned()
            .unwrap_or_default();

        if !content_length.is_empty() && !transfer_encoding.is_empty() {
            return Some(
                Decision::new(Action::Block, 90.0)
                    .with_rule_id("PROT005")
                    .with_rule_name("Request Smuggling (CL.TE)")
                    .with_severity("critical")
                    .with_evidence("both content-length and transfer-encoding headers present"),
            );
        }

        if transfer_encoding.to_lowercase().contains("chunked") {
            if transfer_encoding.matches(',').count() > 0 {
                return Some(
                    Decision::new(Action::Block, 90.0)
                        .with_rule_id("PROT006")
                        .with_rule_name("Request Smuggling (TE.TE)")
                        .with_severity("critical")
                        .with_evidence(format!(
                            "obfuscated transfer-encoding: {transfer_encoding}"
                        )),
                );
            }

            if transfer_encoding.to_lowercase().contains("identity") {
                return Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("PROT007")
                        .with_rule_name("Transfer-Encoding Obfuscation")
                        .with_severity("high")
                        .with_evidence("transfer-encoding contains identity"),
                );
            }
        }

        None
    }

    fn detect_websocket_anomaly(&self, ctx: &RequestContext) -> Option<Decision> {
        let upgrade = ctx.headers.get("Upgrade").cloned().unwrap_or_default();
        let connection = ctx.headers.get("Connection").cloned().unwrap_or_default();

        if upgrade.to_lowercase() == "websocket" {
            let ws_version = ctx
                .headers
                .get("Sec-WebSocket-Version")
                .cloned()
                .unwrap_or_default();
            let ws_key = ctx
                .headers
                .get("Sec-WebSocket-Key")
                .cloned()
                .unwrap_or_default();

            if ws_version.is_empty() || ws_key.is_empty() {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("PROT008")
                        .with_rule_name("Malformed WebSocket Request")
                        .with_severity("high")
                        .with_evidence("websocket upgrade missing required headers"),
                );
            }

            if !connection.to_lowercase().contains("upgrade") {
                return Some(
                    Decision::new(Action::Block, 65.0)
                        .with_rule_id("PROT009")
                        .with_rule_name("WebSocket Connection Header Missing")
                        .with_severity("high")
                        .with_evidence("websocket upgrade without connection: upgrade"),
                );
            }
        }

        None
    }

    fn detect_verb_tampering(&self, ctx: &RequestContext) -> Option<Decision> {
        let method = ctx.method.to_uppercase();
        for verb in VERB_TAMPERING {
            if method == *verb {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("PROT010")
                        .with_rule_name("HTTP Verb Tampering")
                        .with_severity("high")
                        .with_evidence(format!("suspicious HTTP method: {method}")),
                );
            }
        }
        None
    }

    fn detect_response_header_injection(&self, ctx: &RequestContext) -> Option<Decision> {
        for (_k, vs) in &ctx.query_params {
            for val in vs {
                if val.contains("\r\n") || val.contains('\n') {
                    return Some(
                        Decision::new(Action::Block, 85.0)
                            .with_rule_id("PROT011")
                            .with_rule_name("Response Header Injection")
                            .with_severity("critical")
                            .with_evidence("header injection payload detected"),
                    );
                }
            }
        }

        for (_k, v) in &ctx.cookies {
            if v.contains("\r\n") || v.contains('\n') {
                return Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("PROT012")
                        .with_rule_name("Cookie Injection")
                        .with_severity("high")
                        .with_evidence("cookie header injection detected"),
                );
            }
        }

        None
    }

    fn detect_cookie_security(&self, ctx: &RequestContext) -> Option<Decision> {
        const MAX_COOKIE_SIZE: usize = 4096;
        for (k, v) in &ctx.cookies {
            if k.len() + v.len() > MAX_COOKIE_SIZE {
                return Some(
                    Decision::new(Action::Block, 40.0)
                        .with_rule_id("PROT013")
                        .with_rule_name("Oversized Cookie")
                        .with_severity("medium")
                        .with_evidence(format!("cookie {k} size exceeds limit")),
                );
            }
        }

        const MAX_COOKIE_COUNT: usize = 50;
        if ctx.cookies.len() > MAX_COOKIE_COUNT {
            return Some(
                Decision::new(Action::Block, 35.0)
                    .with_rule_id("PROT014")
                    .with_rule_name("Excessive Cookies")
                    .with_severity("medium")
                    .with_evidence(format!("too many cookies: {}", ctx.cookies.len())),
            );
        }

        None
    }
}

impl Inspector for ProtocolAnomaly {
    fn name(&self) -> &str {
        "protocol_anomaly"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if let Some(dec) = self.detect_malformed_request(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_request_smuggling(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_websocket_anomaly(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_verb_tampering(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_response_header_injection(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_cookie_security(ctx) {
            return Ok(Some(dec));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn pa() -> ProtocolAnomaly {
        ProtocolAnomaly::new(false)
    }

    #[test]
    fn trace_verb_blocked() {
        let p = pa();
        let r = HttpRequest::new("TRACE", "/");
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "PROT010");
    }

    #[test]
    fn get_is_allowed() {
        let p = pa();
        let r = HttpRequest::new("GET", "/");
        let mut ctx = RequestContext::new(r);
        assert!(p.inspect(&mut ctx).unwrap().is_none());
    }

    #[test]
    fn options_preflight_not_blocked() {
        let p = pa();
        let r = HttpRequest::new("OPTIONS", "/");
        let mut ctx = RequestContext::new(r);
        assert!(p.inspect(&mut ctx).unwrap().is_none());
    }

    #[test]
    fn cl_te_smuggling_blocked() {
        let p = pa();
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Content-Length", "10");
        r.header.add("Transfer-Encoding", "chunked");
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "PROT005");
    }

    #[test]
    fn oversized_cookie_blocked() {
        let p = pa();
        let mut r = HttpRequest::new("GET", "/");
        let big = "a".repeat(5000);
        r.header.add("Cookie", format!("big={big}"));
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "PROT013");
    }
}
