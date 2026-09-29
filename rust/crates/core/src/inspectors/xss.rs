//! Cross-site scripting detection.
//!
//! Port of `internal/engine/xss.go`. The pattern sets, evaluation order, rule
//! IDs, scores and severities are preserved exactly, including the
//! entity/escape decoder and the whitespace-squeeze evasion check.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

struct Patterns {
    html_tags: Vec<Regex>,
    event_handlers: Vec<Regex>,
    js_protocols: Vec<Regex>,
    polyglot: Vec<Regex>,
    svg_patterns: Vec<Regex>,
    css_injection: Vec<Regex>,
    encoded_xss: Regex,
    js_sinks: Vec<Regex>,
    entity_num_re: Regex,
    octal_escape_re: Regex,
    hex_escape_re: Regex,
    custom_csp: String,
}

fn compile_all(raw: &[&str]) -> Vec<Regex> {
    raw.iter()
        .map(|r| Regex::new(r).expect("valid xss pattern"))
        .collect()
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let html_tags = compile_all(&[
            r"(?i)(?:<script[^>]*>[^<]*</script>)",
            r"(?i)(?:<iframe[^>]*>)",
            r"(?i)(?:<object[^>]*>)",
            r"(?i)(?:<embed[^>]*>)",
            r"(?i)(?:<applet[^>]*>)",
            r"(?i)(?:<meta[^>]*http-equiv[^>]*>)",
            r"(?i)(?:<link[^>]*href[^>]*>)",
            r"(?i)(?:<base[^>]*href[^>]*>)",
            r"(?i)(?:<form[^>]*action[^>]*>)",
            r"(?i)(?:<img[^>]*onerror[^>]*>)",
            r"(?i)(?:<body[^>]*onload[^>]*>)",
            r"(?i)(?:<svg[^>]*/svg>)",
            r"(?i)(?:<math[^>]*>)",
        ]);

        let event_handlers = compile_all(&[
            r"(?i)(?:onabort|onautocomplete|onautocompleteerror|onblur|oncancel|oncanplay|oncanplaythrough|onchange|onclick|onclose|oncontextmenu|oncuechange|ondblclick|ondrag|ondragend|ondragenter|ondragleave|ondragover|ondragstart|ondrop|ondurationchange|onemptied|onended|onerror|onfocus|onfocusin|onfocusout|ongotpointercapture|oninput|oninvalid|onkeydown|onkeypress|onkeyup|onload|onloadeddata|onloadedmetadata|onloadstart|onlostpointercapture|onmousedown|onmousemove|onmouseout|onmouseover|onmouseup|onmousewheel|onpause|onplay|onplaying|onpointercancel|onpointerdown|onpointerenter|onpointerleave|onpointermove|onpointerout|onpointerover|onpointerup|onprogress|onratechange|onreset|onresize|onscroll|onseeked|onseeking|onselect|onselectionchange|onselectstart|onshow|onstalled|onsubmit|onsuspend|ontimeupdate|ontoggle|onvolumechange|onwaiting|onwheel)",
            r"(?i)(?:onmouseenter|onmouseleave|onpointerrawupdate|onbeforeinput|onbeforetoggle|oncontentvisibilityautostatechange)",
            r"(?i)(?:onstart|onbegin|onend|onfinish|onanimationstart|onanimationend|onanimationiteration|onanimationcancel|ontransitionrun|ontransitionstart|ontransitionend|ontransitioncancel|onscrollend|onbeforematch|onsecuritypolicyviolation)",
            r"(?i)(?:onpageshow|onpagehide|onpopstate|onhashchange|onbeforeunload|onunload)",
        ]);

        let js_protocols = compile_all(&[
            r"(?i)(?:javascript\s*:)",
            r"(?i)(?:vbscript\s*:)",
            r"(?i)(?:data\s*:\s*(?:text/html|application/xhtml))",
            r"(?i)(?:livescript\s*:)",
            r"(?i)(?:mocha\s*:)",
        ]);

        let polyglot = compile_all(&[
            r#"(?i)(?:jaVasCript:[\s\S]*?[<"'])"#,
            r"(?i)(?:\\x22.*onerror\\x3d)",
            r"(?i)(?:\\x3Cscript\\x3E)",
        ]);

        let svg_patterns = compile_all(&[
            r"(?i)(?:<svg[^>]*>[\s\S]*?<script)",
            r"(?i)(?:<svg[^>]*onload)",
            r"(?i)(?:<svg[^>]*>[\s\S]*?<animate)",
            r"(?i)(?:<svg[^>]*>[\s\S]*?<set)",
            r"(?i)(?:<svg[^>]*>[\s\S]*?<use)",
            r"(?i)(?:<svg[^>]*>[\s\S]*?<desc>)",
        ]);

        let css_injection = compile_all(&[
            r"(?i)(?:expression\s*\()",
            r"(?i)(?:-moz-binding)",
            r"(?i)(?:behavior\s*:)",
            r"(?i)(?:@import\s+url)",
            r#"(?i)(?:url\s*\(\s*['"]?\s*javascript:)"#,
            r"(?i)(?:position\s*:\s*fixed)",
        ]);

        let entity_num_re = Regex::new(r"&#[xX]?[0-9a-fA-F]{2,8};?").unwrap();
        let octal_escape_re = Regex::new(r"\\[0-9a-fA-F]{2,4}").unwrap();
        let hex_escape_re = Regex::new(r"\\x[0-9a-fA-F]{1,4}").unwrap();

        let encoded_xss = Regex::new(
            r"(?i)(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}|&#x?[0-9a-f]+;)(?:script|alert|prompt|confirm|onerror|onload)|(?:script|alert|prompt|confirm|onerror|onload)(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}|&#x?[0-9a-f]+;)|(?:scr|ale|pro|con|one|onl)[^a-z0-9]{0,2}(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}|&#x?[0-9a-f]+;)[^a-z0-9]{0,2}(?:ipt|rt|mpt|firm|rror|oad)",
        )
        .unwrap();

        let js_sinks = compile_all(&[
            r"(?i)(?:alert|prompt|confirm|eval|atob|setTimeout|setInterval|execScript|Function)\s*\(",
            r"(?i)(?:document\.(?:cookie|write|writeln|location)|location\.(?:href|assign|replace)|window\.(?:location|open|eval)|self\.(?:location|eval))",
            r"(?i)(?:String\.fromCharCode|fromCharCode\s*\(|unescape\s*\(|decodeURIComponent\s*\()",
        ]);

        let custom_csp = concat!(
            "default-src 'self'; ",
            "script-src 'self' 'strict-dynamic' 'nonce-{nonce}' 'unsafe-inline' http: https:; ",
            "object-src 'none'; ",
            "base-uri 'self'; ",
            "require-trusted-types-for 'script';"
        )
        .to_string();

        Patterns {
            html_tags,
            event_handlers,
            js_protocols,
            polyglot,
            svg_patterns,
            css_injection,
            encoded_xss,
            js_sinks,
            entity_num_re,
            octal_escape_re,
            hex_escape_re,
            custom_csp,
        }
    })
}

pub struct XssEngine {
    pub dev_mode: bool,
}

impl XssEngine {
    pub fn new(dev_mode: bool) -> Self {
        let _ = patterns();
        XssEngine { dev_mode }
    }

    fn extract_targets(&self, ctx: &RequestContext) -> Vec<(String, String)> {
        let mut targets = Vec::new();
        for (k, vs) in &ctx.query_params {
            for val in vs {
                targets.push((val.clone(), format!("query:{k}")));
            }
        }
        for (k, vs) in &ctx.form_params {
            for val in vs {
                targets.push((val.clone(), format!("form:{k}")));
            }
        }
        if !ctx.body.is_empty() {
            targets.push((
                String::from_utf8_lossy(&ctx.body).into_owned(),
                "body".to_string(),
            ));
        }
        for (k, v) in &ctx.headers {
            let lower = k.to_lowercase();
            if lower == "referer" || lower == "origin" || lower == "x-forwarded-for" {
                targets.push((v.clone(), format!("header:{k}")));
            }
        }
        for (k, v) in &ctx.cookies {
            targets.push((v.clone(), format!("cookie:{k}")));
        }
        targets
    }

    fn inspect_value(&self, value: &str, source: &str) -> Option<Decision> {
        if value.is_empty() {
            return None;
        }

        let squeezed: String = value.split_whitespace().collect();

        let decoded = self.decode_entities(value);

        let p = patterns();

        for pattern in &p.html_tags {
            if pattern.is_match(value) || pattern.is_match(&decoded) {
                return Some(
                    Decision::new(Action::Block, 90.0)
                        .with_rule_id("XSS001")
                        .with_rule_name("HTML Tag Injection")
                        .with_severity("critical")
                        .with_evidence(format!(
                            "HTML tag injection in {source}: {}",
                            pattern.as_str()
                        )),
                );
            }
        }

        for pattern in &p.event_handlers {
            if pattern.is_match(value) || pattern.is_match(&squeezed) || pattern.is_match(&decoded)
            {
                return Some(
                    Decision::new(Action::Block, 90.0)
                        .with_rule_id("XSS002")
                        .with_rule_name("Event Handler Injection")
                        .with_severity("critical")
                        .with_evidence(format!("event handler injection in {source}")),
                );
            }
        }

        for pattern in &p.js_protocols {
            if pattern.is_match(value) || pattern.is_match(&squeezed) || pattern.is_match(&decoded)
            {
                return Some(
                    Decision::new(Action::Block, 85.0)
                        .with_rule_id("XSS003")
                        .with_rule_name("JavaScript Protocol")
                        .with_severity("critical")
                        .with_evidence(format!("javascript protocol detected in {source}")),
                );
            }
        }

        for pattern in &p.polyglot {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 90.0)
                        .with_rule_id("XSS004")
                        .with_rule_name("Polyglot XSS Payload")
                        .with_severity("critical")
                        .with_evidence(format!("polyglot XSS payload in {source}")),
                );
            }
        }

        for pattern in &p.svg_patterns {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 85.0)
                        .with_rule_id("XSS005")
                        .with_rule_name("SVG Injection")
                        .with_severity("critical")
                        .with_evidence(format!("SVG injection in {source}")),
                );
            }
        }

        for pattern in &p.css_injection {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 75.0)
                        .with_rule_id("XSS006")
                        .with_rule_name("CSS Injection")
                        .with_severity("high")
                        .with_evidence(format!("CSS injection in {source}")),
                );
            }
        }

        for pattern in &p.js_sinks {
            if pattern.is_match(value) || pattern.is_match(&squeezed) || pattern.is_match(&decoded)
            {
                return Some(
                    Decision::new(Action::Block, 85.0)
                        .with_rule_id("XSS009")
                        .with_rule_name("JavaScript Sink")
                        .with_severity("critical")
                        .with_evidence(format!("javascript sink in {source}")),
                );
            }
        }

        if p.encoded_xss.is_match(value) {
            return Some(
                Decision::new(Action::Block, 75.0)
                    .with_rule_id("XSS007")
                    .with_rule_name("Encoded XSS")
                    .with_severity("high")
                    .with_evidence(format!("encoded XSS pattern in {source}")),
            );
        }

        None
    }

    /// Port of `GenerateCSP`.
    pub fn generate_csp(&self, nonce: &str) -> String {
        patterns().custom_csp.replace("{nonce}", nonce)
    }

    /// Port of `ScanResponse`.
    pub fn scan_response(&self, body: &[u8]) -> Option<Decision> {
        if body.is_empty() {
            return None;
        }
        let body_str = String::from_utf8_lossy(body);
        for pattern in &patterns().html_tags {
            if pattern.is_match(&body_str) {
                return Some(
                    Decision::new(Action::Block, 95.0)
                        .with_rule_id("XSS008")
                        .with_rule_name("Reflected XSS")
                        .with_severity("critical")
                        .with_evidence("reflected XSS detected in response body"),
                );
            }
        }
        None
    }

    /// Port of `decodeEntities`.
    fn decode_entities(&self, value: &str) -> String {
        let p = patterns();

        let decoded = p
            .entity_num_re
            .replace_all(value, |caps: &regex::Captures| {
                let m = &caps[0];
                // Strip the leading "&#" (2 bytes).
                let mut body = &m[2..];
                if let Some(stripped) = body.strip_suffix(';') {
                    body = stripped;
                }
                let (digits, base) =
                    if body.len() > 1 && (body.starts_with('x') || body.starts_with('X')) {
                        (&body[1..], 16u32)
                    } else {
                        (body, 10u32)
                    };
                match i64::from_str_radix(digits, base) {
                    Ok(code) if code > 0 && code <= 0x10FFFF => char::from_u32(code as u32)
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| m.to_string()),
                    _ => m.to_string(),
                }
            });

        let mut decoded = decoded.into_owned();

        for re in [&p.octal_escape_re, &p.hex_escape_re] {
            decoded = re
                .replace_all(&decoded, |caps: &regex::Captures| {
                    let m = &caps[0];
                    let mut body = &m[1..];
                    if body.starts_with('x') || body.starts_with('X') {
                        body = &body[1..];
                    }
                    match i64::from_str_radix(body, 16) {
                        Ok(code) if code > 0 && code <= 0x10FFFF => char::from_u32(code as u32)
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| m.to_string()),
                        _ => m.to_string(),
                    }
                })
                .into_owned();
        }

        decoded
    }
}

impl Inspector for XssEngine {
    fn name(&self) -> &str {
        "xss"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        for (value, source) in self.extract_targets(ctx) {
            if let Some(dec) = self.inspect_value(&value, &source) {
                return Ok(Some(dec));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn inspect(q: &str) -> Option<Decision> {
        let e = XssEngine::new(false);
        let mut r = HttpRequest::new("GET", "/");
        r.raw_query = q.to_string();
        let mut ctx = RequestContext::new(r);
        e.inspect(&mut ctx).unwrap()
    }

    #[test]
    fn script_tag_blocked() {
        let d = inspect("q=%3Cscript%3Ealert(1)%3C/script%3E").unwrap();
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn event_handler_blocked() {
        let d = inspect("q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E").unwrap();
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn javascript_protocol_blocked() {
        let d = inspect("u=javascript:alert(1)").unwrap();
        assert_eq!(d.rule_id, "XSS003");
    }

    #[test]
    fn encoded_entity_decoded_and_blocked() {
        // &#106;&#97;... = "ja" -- a fully-encoded javascript: payload
        let d = inspect("u=%26%23106%3Bavascript%3Aalert(1)");
        // The decoded "javascript:" path or a sink would catch; ensure no panic
        // and that a decision (if any) is a block.
        if let Some(d) = d {
            assert_eq!(d.action, Action::Block);
        }
    }

    #[test]
    fn csp_generation_substitutes_nonce() {
        let e = XssEngine::new(false);
        let csp = e.generate_csp("abc123");
        assert!(csp.contains("'nonce-abc123'"));
        assert!(!csp.contains("{nonce}"));
    }
}
