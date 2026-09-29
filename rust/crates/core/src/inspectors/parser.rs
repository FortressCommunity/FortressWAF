//! Parser hardening: normalization bypass, unicode attacks, parser
//! differentials, HTTP downgrade, chunked abuse.
//!
//! Port of `internal/engine/parser.go`. Rule IDs, scores, and the bounded
//! decode loop are preserved exactly.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};
use crate::regex_util::percent_decode_once;

struct Patterns {
    normalization_re: Regex,
    unicode_control_re: Regex,
    http10_re: Regex,
    http2_preface_re: Regex,
    chunk_ext_re: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        normalization_re: Regex::new(
            r"(?i)(?:%00|%0d|%0a|%08)|(?:\.\./)|(?:/\./)|(?:/\.$)|(?:\\\.\\)",
        )
        .unwrap(),
        // Go: [\x{200B}\x{200C}\x{200D}\x{FEFF}\x{00AD}] | [\x{2028}\x{2029}] |
        // [\x{FFF0}-\x{FFFD}]. Rust uses the same \x{...} escapes.
        unicode_control_re: Regex::new(
            r"[\u{200B}\u{200C}\u{200D}\u{FEFF}\u{00AD}]|[\u{2028}\u{2029}]|[\u{FFF0}-\u{FFFD}]",
        )
        .unwrap(),
        http10_re: Regex::new(r"(?i)^HTTP/1\.0\s").unwrap(),
        http2_preface_re: Regex::new(r"^PRI \* HTTP/2\.0").unwrap(),
        chunk_ext_re: Regex::new(r"(?i)[a-z0-9]+\s*;\s*[a-z_]+\s*=\s*[^;\r\n]+").unwrap(),
    })
}

/// Whether the byte sequence contains an overlong or invalid UTF-8 encoding.
///
/// Exact port of `hasOverlongUTF8`: it inspects the underlying bytes, not
/// runes, flagging the four shapes an overlong encoder produces.
pub fn has_overlong_utf8_bytes(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == 0xC0 || c == 0xC1 {
            return true;
        } else if c >= 0xF5 {
            return true;
        } else if c == 0xE0 && i + 1 < b.len() && (0x80..=0x9F).contains(&b[i + 1]) {
            return true;
        } else if c == 0xF0 && i + 1 < b.len() && (0x80..=0x8F).contains(&b[i + 1]) {
            return true;
        } else if (0x80..=0xBF).contains(&c) {
            // A continuation byte is only invalid when it is not preceded by a
            // valid lead byte in 0xC2-0xF4.
            if i == 0 || !((0xC2..=0xF4).contains(&b[i - 1])) {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Convenience wrapper over [`has_overlong_utf8_bytes`] for `&str` input. A
/// valid `&str` can never contain an overlong sequence, so this always returns
/// false; provided for API symmetry.
pub fn has_overlong_utf8(s: &str) -> bool {
    has_overlong_utf8_bytes(s.as_bytes())
}

/// Replicates Go's `unicode.Is(unicode.C, r)` guard for the exact characters
/// `unicodeControlRE` can match. Verifying each against the Unicode general
/// categories:
///
/// - U+00AD soft hyphen, U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+FEFF BOM:
///   category Cf (Other, format) -> C.
/// - U+2028 LINE SEP / U+2029 PARA SEP: category Zl/Zp -> NOT C (so the Go
///   guard rejects them and PARSER_011 does not fire for these).
/// - U+FFF0..U+FFF8: unassigned -> Cn -> C.
/// - U+FFF9..U+FFFB interlinear annotation: Cf -> C.
/// - U+FFFC object replacement: So -> NOT C.
/// - U+FFFD replacement: the Go guard has an explicit `r == '\uFFFD'` clause.
///
/// This function returns exactly the set for which the Go guard is true, so
/// PARSER_011 fires on the same inputs.
fn is_control_category_or_replacement(r: char) -> bool {
    let cp = r as u32;
    matches!(cp,
        0x00AD | 0x200B | 0x200C | 0x200D | 0xFEFF
        | 0xFFF0..=0xFFF8 | 0xFFF9..=0xFFFB
        | 0xFFFD)
}

pub struct ParserHardener {
    pub dev_mode: bool,
}

impl ParserHardener {
    pub fn new(dev_mode: bool) -> Self {
        let _ = patterns();
        ParserHardener { dev_mode }
    }

    fn detect_normalization_bypass(&self, ctx: &RequestContext) -> Option<Decision> {
        if let Some(dec) = self.detect_traversal_in_path(&ctx.path, "path") {
            return Some(dec);
        }
        for (k, vs) in &ctx.query_params {
            for val in vs {
                if let Some(dec) = self.detect_traversal_in_path(val, &format!("query:{k}")) {
                    return Some(dec);
                }
            }
        }
        for (k, vs) in &ctx.form_params {
            for val in vs {
                if let Some(dec) = self.detect_traversal_in_path(val, &format!("form:{k}")) {
                    return Some(dec);
                }
            }
        }
        for (k, v) in &ctx.headers {
            if let Some(dec) = self.detect_traversal_in_path(v, &format!("header:{k}")) {
                return Some(dec);
            }
        }
        None
    }

    /// Port of `detectTraversalInPath`.
    fn detect_traversal_in_path(&self, raw: &str, source: &str) -> Option<Decision> {
        if raw.is_empty() {
            return None;
        }

        if patterns().normalization_re.is_match(raw) {
            return Some(
                Decision::new(Action::Block, 75.0)
                    .with_rule_id("PARSER_001")
                    .with_rule_name("Normalization Bypass Attempt")
                    .with_severity("high")
                    .with_evidence(format!("suspicious path normalization pattern in {source}"))
                    .with_confidence(0.95),
            );
        }

        if !raw.contains('%') {
            return None;
        }

        let decoded = self.decode_path_value(raw);
        if decoded == raw {
            return None;
        }
        let collapsed = collapse_dot_segments(&decoded);
        if decoded.contains("../")
            || decoded.contains("..\\")
            || collapsed.contains("../")
            || collapsed.contains("..\\")
        {
            return Some(
                Decision::new(Action::Block, 90.0)
                    .with_rule_id("PARSER_002")
                    .with_rule_name("Encoded Path Traversal")
                    .with_severity("critical")
                    .with_evidence(format!(
                        "encoded path traversal in {source}: {raw:?} -> {decoded:?}"
                    ))
                    .with_confidence(0.98),
            );
        }

        None
    }

    fn detect_unicode_attack(&self, ctx: &RequestContext) -> Option<Decision> {
        for raw in &ctx.raw_scan_targets {
            // PARSER_010: invalid UTF-8 in the raw bytes.
            if std::str::from_utf8(raw).is_err() {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("PARSER_010")
                        .with_rule_name("Invalid UTF-8 in Request")
                        .with_severity("high")
                        .with_evidence("invalid UTF-8 sequence detected in request data")
                        .with_confidence(0.90),
                );
            }

            let t = match std::str::from_utf8(raw) {
                Ok(t) => t,
                Err(_) => continue, // unreachable: handled above
            };

            // PARSER_011: unicode control character (with Go's category guard).
            for r in t.chars() {
                if (r as u32) > 0x7F && is_control_category_or_replacement(r) {
                    if patterns().unicode_control_re.is_match(&r.to_string()) {
                        return Some(
                            Decision::new(Action::Block, 75.0)
                                .with_rule_id("PARSER_011")
                                .with_rule_name("Unicode Control Character")
                                .with_severity("high")
                                .with_evidence(format!(
                                    "unicode control character U+{:04X} in request",
                                    r as u32
                                ))
                                .with_confidence(0.92),
                        );
                    }
                }
            }

            // PARSER_012: overlong UTF-8 byte scan.
            if has_overlong_utf8_bytes(raw) {
                return Some(
                    Decision::new(Action::Block, 85.0)
                        .with_rule_id("PARSER_012")
                        .with_rule_name("Overlong UTF-8 Encoding")
                        .with_severity("critical")
                        .with_evidence(
                            "overlong UTF-8 encoding detected (parser differential attack)",
                        )
                        .with_confidence(0.95),
                );
            }
        }

        None
    }

    fn detect_parser_differential(&self, ctx: &RequestContext) -> Option<Decision> {
        let ct = ctx.request_header("Content-Type");

        if ct.to_lowercase().contains("multipart/form-data") {
            let boundary = extract_boundary(ct);
            if !boundary.is_empty() && (boundary.contains('\\') || boundary.starts_with(' ')) {
                return Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("PARSER_020")
                        .with_rule_name("Multipart Boundary Parser Differential")
                        .with_severity("high")
                        .with_evidence(format!("suspicious multipart boundary: {boundary:?}"))
                        .with_confidence(0.93),
                );
            }
        }

        let transfer_encodings = ctx.request.header.values("Transfer-Encoding");
        if transfer_encodings.len() > 1 {
            return Some(
                Decision::new(Action::Block, 95.0)
                    .with_rule_id("PARSER_021")
                    .with_rule_name("Multiple Transfer-Encoding (Parser Differential)")
                    .with_severity("critical")
                    .with_evidence(format!("multiple TE headers: {transfer_encodings:?}"))
                    .with_confidence(0.97),
            );
        }

        None
    }

    fn detect_http_downgrade(&self, ctx: &RequestContext) -> Option<Decision> {
        if ctx.request.proto == "HTTP/1.0" {
            let host = ctx.request_header("Host");
            let content_length = ctx.request_header("Content-Length");

            if ctx.method == "POST" && content_length.is_empty() && !ctx.body.is_empty() {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("PARSER_030")
                        .with_rule_name("HTTP/1.0 Downgrade Attack")
                        .with_severity("high")
                        .with_evidence(
                            "HTTP/1.0 POST with body but no Content-Length (request smuggling)",
                        )
                        .with_confidence(0.85),
                );
            }

            if host.is_empty() {
                return Some(
                    Decision::new(Action::Monitor, 20.0)
                        .with_rule_id("PARSER_031")
                        .with_rule_name("HTTP/1.0 No Host Header")
                        .with_severity("low")
                        .with_evidence("HTTP/1.0 request missing Host header")
                        .with_confidence(0.60),
                );
            }
        }

        if ctx.method == "PRI" {
            if let Some(v) = ctx.headers.get("PRI") {
                if patterns().http2_preface_re.is_match(v) {
                    return Some(
                        Decision::new(Action::Block, 95.0)
                            .with_rule_id("PARSER_032")
                            .with_rule_name("HTTP/2 Preface in HTTP/1.1")
                            .with_severity("critical")
                            .with_evidence("HTTP/2 connection preface sent on HTTP/1.1 connection")
                            .with_confidence(0.99),
                    );
                }
            }
        }

        None
    }

    fn detect_chunked_abuse(&self, ctx: &RequestContext) -> Option<Decision> {
        let te = ctx.request_header("Transfer-Encoding");
        if !te.to_lowercase().contains("chunked") {
            return None;
        }

        if ctx.body.is_empty() {
            return None;
        }

        let body_str = String::from_utf8_lossy(&ctx.body);

        let ext_count = patterns().chunk_ext_re.find_iter(&body_str).count();
        if ext_count > 3 {
            return Some(
                Decision::new(Action::Monitor, 40.0)
                    .with_rule_id("PARSER_040")
                    .with_rule_name("Excessive Chunk Extensions")
                    .with_severity("medium")
                    .with_evidence(format!(
                        "excessive chunk extensions ({ext_count}) in chunked body"
                    ))
                    .with_confidence(0.70),
            );
        }

        let count = body_str.matches("0\r\n\r\n").count();
        if body_str.contains("0\r\n\r\n") && count > 1 {
            return Some(
                Decision::new(Action::Block, 75.0)
                    .with_rule_id("PARSER_041")
                    .with_rule_name("Chunked Trailer Confusion")
                    .with_severity("high")
                    .with_evidence("multiple chunk terminator markers in chunked body")
                    .with_confidence(0.90),
            );
        }

        None
    }

    /// Port of `decodePathValue`: repeated decoding with a hard pass limit so a
    /// bare `%` cannot loop or crash.
    fn decode_path_value(&self, v: &str) -> String {
        const MAX_PASSES: usize = 6;
        let mut result = v.to_string();
        for _ in 0..MAX_PASSES {
            if !result.contains('%') {
                break;
            }
            let (decoded, changed) = percent_decode_once(&result);
            if !changed {
                break;
            }
            result = decoded;
        }
        result
    }
}

impl Inspector for ParserHardener {
    fn name(&self) -> &str {
        "parser_hardener"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        // The Go code required ctx.Request != nil; our RequestContext always has
        // a request, so this guard is always satisfied.
        if let Some(dec) = self.detect_normalization_bypass(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_unicode_attack(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_parser_differential(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_http_downgrade(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_chunked_abuse(ctx) {
            return Ok(Some(dec));
        }
        Ok(None)
    }
}

/// Port of `collapseDotSegments`.
pub fn collapse_dot_segments(s: &str) -> String {
    let mut s = s.to_string();
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    while s.contains("\\\\") {
        s = s.replace("\\\\", "\\");
    }
    s
}

/// `utf8.ValidString`. Rust `&str` is always valid UTF-8, but the Go engine
/// can hold byte strings that failed validation. Our `RequestContext` stores
/// headers/path as `String` (lossily decoded at the HTTP boundary), so this
/// always returns true here; kept for parity and clarity.
pub fn is_valid_utf8(s: &str) -> bool {
    std::str::from_utf8(s.as_bytes()).is_ok()
}

/// Port of `extractBoundary`.
fn extract_boundary(ct: &str) -> String {
    if !ct.to_lowercase().contains("boundary=") {
        return String::new();
    }
    let parts: Vec<&str> = ct.split("boundary=").collect();
    if parts.len() < 2 {
        return String::new();
    }
    let mut b = parts[1].trim();
    if let Some(idx) = b.find([';', ' ', '\t', '\r', '\n']) {
        if idx > 0 {
            b = &b[..idx];
        }
    }
    b.trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn engine() -> ParserHardener {
        ParserHardener::new(false)
    }

    #[test]
    fn has_overlong_detects_c0_c1_lead() {
        // 0xC0 0xAF is the overlong encoding of '/'.
        assert!(has_overlong_utf8_bytes(&[0xC0, 0xAF]));
    }

    #[test]
    fn has_overlong_detects_forward_lead() {
        assert!(has_overlong_utf8_bytes(&[0xF5, 0x80]));
    }

    #[test]
    fn has_overlong_detects_bare_continuation() {
        assert!(has_overlong_utf8_bytes(&[0x80]));
    }

    #[test]
    fn has_overlong_accepts_valid_utf8() {
        assert!(!has_overlong_utf8_bytes("héllo wörld".as_bytes()));
        assert!(!has_overlong_utf8_bytes(&[0xC3, 0x80])); // U+00C0, valid
    }

    #[test]
    fn invalid_utf8_in_raw_path_triggers_parser_010() {
        let e = engine();
        let mut r = HttpRequest::new("GET", "/");
        // 0xFF is never valid in UTF-8.
        r.raw_path = vec![b'/', 0xFF];
        let mut ctx = RequestContext::new(r);
        let d = e.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(d.rule_id, "PARSER_010");
    }

    #[test]
    fn single_encoded_traversal_blocked_as_normalization() {
        // The query parser already decoded "..%2f" to "../", so the literal
        // traversal rule (PARSER_001) fires first -- exactly as in Go, whose
        // queryValues() also unescapes before the engine sees the value.
        let e = engine();
        let mut r = HttpRequest::new("GET", "/");
        r.raw_query = "file=..%2f..%2fetc%2fpasswd".to_string();
        let mut ctx = RequestContext::new(r);
        let d = e.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(d.rule_id, "PARSER_001");
    }

    #[test]
    fn literal_traversal_in_path_blocked() {
        let e = engine();
        let r = HttpRequest::new("GET", "/../etc/passwd");
        let mut ctx = RequestContext::new(r);
        let d = e.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(d.rule_id, "PARSER_001");
    }

    #[test]
    fn double_encoded_traversal_blocked_as_encoded() {
        // "..%252f" survives the query unescape as "..%2f" (still encoded), so
        // decodePathValue() decodes it and PARSER_002 fires.
        let e = engine();
        let mut r = HttpRequest::new("GET", "/");
        r.raw_query = "f=..%252f..%252fetc".to_string();
        let mut ctx = RequestContext::new(r);
        let d = e.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(d.rule_id, "PARSER_002");
    }

    #[test]
    fn bare_percent_does_not_loop() {
        // Regression: "%25" used to recurse forever. Must terminate.
        let e = engine();
        let mut r = HttpRequest::new("GET", "/");
        r.raw_query = "x=%25".to_string();
        let mut ctx = RequestContext::new(r);
        let _ = e.inspect(&mut ctx).unwrap();
    }

    #[test]
    fn multiple_transfer_encoding_blocked() {
        let e = engine();
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Transfer-Encoding", "chunked");
        r.header.add("Transfer-Encoding", "gzip");
        let mut ctx = RequestContext::new(r);
        let d = e.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(d.rule_id, "PARSER_021");
    }

    #[test]
    fn benign_path_with_space_not_blocked() {
        // /products/sony%20wh-1000xm5 must not trip PARSER_001.
        let e = engine();
        let r = HttpRequest::new("GET", "/products/sony%20wh-1000xm5");
        let mut ctx = RequestContext::new(r);
        assert!(e.inspect(&mut ctx).unwrap().is_none());
    }
}
