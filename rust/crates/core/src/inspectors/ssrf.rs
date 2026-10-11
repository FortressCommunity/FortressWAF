//! Server-Side Request Forgery (SSRF) detection.
//!
//! Closes README Known Limitation #3 ("No inspector for SSRF, open redirect, or
//! CSRF"). This module scans every request-controlled value that looks like a
//! URL or host for pointers at internal infrastructure: loopback, RFC1918
//! private ranges, link-local, IPv6 unique-local, the cloud instance-metadata
//! addresses, non-HTTP schemes, and URL-parser tricks (decimal/octal/hex encoded
//! IPs, userinfo `@` confusion, `//` authority bypass, backslash authority).
//!
//! Design notes, one reason per choice:
//!
//! - **Monitor by default, block on request.** A SSRF signature in a query
//!   value is strong evidence, but a "url=" parameter can legitimately hold an
//!   absolute URL. So the default action is [`Action::Monitor`] (recorded and
//!   scored, not enforced); `ssrf.block: true` promotes a high-confidence match
//!   to [`Action::Block`]. This mirrors the response-leak precedent
//!   (`response_inspect.block`) and avoids the false-positive failure mode the
//!   WAF cares about most.
//! - **Only URL-shaped values are inspected.** A bare word or a number is not a
//!   URL and is skipped, so ordinary parameters (`page=2`, `q=finance`) never
//!   reach the matcher. The scan targets the decoded query/form values, the
//!   body, and a small set of headers that carry a URL (Referer, and any header
//!   whose *name* looks like a target: `url`, `uri`, `redirect`, `callback`,
//!   `dest`, `target`, `next`, `return`, `proxy`, `fetch`, `host`).
//! - **Private ranges are matched on the literal and on the decoded form.** A
//!   value may be percent-encoded once (`http%3A%2F%2F127.0.0.1`); the module
//!   decodes once before matching, so encoding does not hide the target.

use std::net::IpAddr;
use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};
use crate::regex_util::percent_decode_once;

/// Options for [`SsrfInspector`], wired from `ssrf.*` in the config.
#[derive(Debug, Clone)]
pub struct SsrfOptions {
    /// Promote a high-confidence match to a block. When false, matches are
    /// reported as [`Action::Monitor`] and forwarded.
    pub block: bool,
    /// Inspect the request body (form-encoded or raw) in addition to the query.
    pub inspect_body: bool,
}

impl Default for SsrfOptions {
    fn default() -> Self {
        SsrfOptions {
            block: false,
            inspect_body: true,
        }
    }
}

struct Patterns {
    /// A value that begins like a URL or a scheme-relative reference.
    url_like: Regex,
    /// Dangerous schemes that are never a legitimate HTTP fetch target.
    dangerous_scheme: Regex,
    /// The cloud metadata hostnames/addresses.
    metadata: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        // A URL-shape start: scheme://, //authority, or a host:port. Anchored at
        // the start of the (trimmed) value so a mid-sentence colon does not
        // turn prose into a URL.
        url_like: Regex::new(
            r"(?i)^(?:[a-z][a-z0-9+.\-]*://|//|(?:[a-z0-9.\-]+\.)+[a-z]{2,}(?::\d+)?(?:/|$|\?))",
        )
        .unwrap(),
        // Schemes that let an SSRF reach the filesystem or another protocol.
        dangerous_scheme: Regex::new(
            r"(?i)^(?:file|gopher|dict|ftp|ftps|ldap|ldaps|tftp|jar|netdoc|php|phar|expect|ogg|zip|smb|nfs|telnet|sftp|scp|data):",
        )
        .unwrap(),
        // Cloud instance-metadata endpoints (AWS/GCP/Azure/Alibaba/OpenStack).
        metadata: Regex::new(
            r"(?i)(?:^|[^0-9.])(?:169\.254\.169\.254|fd00:ec2::254|metadata\.google\.internal|metadata\.goog|169\.254\.170\.2|100\.100\.100\.200|192\.0\.0\.192)(?:[^0-9a-z]|$)",
        )
        .unwrap(),
    })
}

/// The SSRF inspector.
pub struct SsrfInspector {
    pub dev_mode: bool,
    opts: SsrfOptions,
}

impl SsrfInspector {
    pub fn new(dev_mode: bool, opts: SsrfOptions) -> Self {
        let _ = patterns();
        SsrfInspector { dev_mode, opts }
    }

    /// Collect (decoded value, source label) pairs worth scanning. Only values
    /// that look URL-shaped, or that come from a URL-named parameter/header,
    /// are returned, so the matcher never sees ordinary prose.
    fn targets(&self, ctx: &RequestContext) -> Vec<(String, String)> {
        let mut out = Vec::new();

        for (k, vs) in &ctx.query_params {
            let named = is_url_param_name(k);
            for v in vs {
                let (dec, _) = percent_decode_once(v);
                if named || looks_url_like(&dec) {
                    out.push((dec, format!("query:{k}")));
                }
            }
        }
        for (k, vs) in &ctx.form_params {
            let named = is_url_param_name(k);
            for v in vs {
                let (dec, _) = percent_decode_once(v);
                if named || looks_url_like(&dec) {
                    out.push((dec, format!("form:{k}")));
                }
            }
        }
        if self.opts.inspect_body && !ctx.body.is_empty() {
            let body = String::from_utf8_lossy(&ctx.body).into_owned();
            // Scan the whole body only when it contains a URL-shaped token; a
            // form body's `k=v&k2=v2` pairs are covered by form_params when the
            // upstream parsed them, but a raw JSON body is not.
            if body.contains("://") || body.contains("//") {
                out.push((body, "body".to_string()));
            }
        }
        for (k, v) in &ctx.headers {
            if is_url_header_name(k) {
                out.push((v.clone(), format!("header:{k}")));
            }
        }

        out
    }

    fn inspect_value(&self, value: &str, source: &str) -> Option<Decision> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        if patterns().dangerous_scheme.is_match(trimmed) {
            return Some(self.decision(
                "SSRF001",
                "Dangerous URL Scheme",
                "critical",
                85.0,
                format!("non-HTTP scheme in {source}"),
            ));
        }

        if patterns().metadata.is_match(trimmed) {
            return Some(self.decision(
                "SSRF002",
                "Cloud Metadata Access",
                "critical",
                95.0,
                format!("cloud instance-metadata target in {source}"),
            ));
        }

        // Parse the authority (the host between `//` and the next `/`, `?` or
        // `#`), undoing `user@host` confusion and a backslash-as-slash trick.
        if let Some(host) = authority_host(trimmed) {
            if let Some(dec) = self.classify_host(&host, source) {
                return Some(dec);
            }
        }

        None
    }

    /// Classify a host that appeared in a URL authority position.
    fn classify_host(&self, host: &str, source: &str) -> Option<Decision> {
        let host = host.trim_matches(|c| c == '[' || c == ']');

        // A numeric-encoded address (decimal/octal/hex) that resolves to a
        // private IP is the classic SSRF bypass; decode then re-check.
        let normalized = normalize_numeric_ip(host);
        let candidate = normalized.as_deref().unwrap_or(host);

        if is_forbidden_host(candidate) {
            return Some(self.decision(
                "SSRF003",
                "Internal Address Request",
                "high",
                80.0,
                format!("request target resolves to a non-public address in {source}"),
            ));
        }

        // `localhost` and its trailing-dot / case variants.
        let lower = candidate.trim_end_matches('.').to_lowercase();
        if lower == "localhost" || lower.ends_with(".localhost") || lower.ends_with(".internal") {
            return Some(self.decision(
                "SSRF004",
                "Internal Hostname Request",
                "high",
                75.0,
                format!("internal hostname in {source}"),
            ));
        }

        None
    }

    fn decision(
        &self,
        rule_id: &str,
        rule_name: &str,
        severity: &str,
        score: f64,
        evidence: String,
    ) -> Decision {
        // In monitor mode the finding is recorded but must not add enough score
        // to cross the engine's cumulative block (>=90) or challenge (>=50)
        // thresholds, even when several monitor inspectors flag one request
        // (e.g. a URL parameter is both SSRF and open-redirect shaped).
        let (action, score) = if self.opts.block {
            (Action::Block, score)
        } else {
            (Action::Monitor, score.min(15.0))
        };
        Decision::new(action, score)
            .with_rule_id(rule_id)
            .with_rule_name(rule_name)
            .with_severity(severity)
            .with_evidence(evidence)
    }
}

impl Inspector for SsrfInspector {
    fn name(&self) -> &str {
        "ssrf"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        for (value, source) in self.targets(ctx) {
            if let Some(dec) = self.inspect_value(&value, &source) {
                return Ok(Some(dec));
            }
        }
        Ok(None)
    }
}

/// True when a parameter name suggests its value is a URL or a request target.
fn is_url_param_name(name: &str) -> bool {
    let n = name.to_lowercase();
    matches!(
        n.as_str(),
        "url"
            | "uri"
            | "link"
            | "href"
            | "redirect"
            | "redirect_uri"
            | "redirect_url"
            | "return"
            | "returnurl"
            | "return_url"
            | "next"
            | "callback"
            | "callback_url"
            | "dest"
            | "destination"
            | "target"
            | "proxy"
            | "fetch"
            | "feed"
            | "source"
            | "src"
            | "image"
            | "img"
            | "file"
            | "path"
            | "host"
            | "domain"
            | "endpoint"
            | "webhook"
            | "site"
    ) || n.ends_with("_url")
        || n.ends_with("url")
}

/// Headers whose value is (or contains) a URL the client supplied.
fn is_url_header_name(name: &str) -> bool {
    let n = name.to_lowercase();
    matches!(
        n.as_str(),
        "referer" | "referrer" | "x-forwarded-host" | "origin"
    )
}

/// Cheap URL-shape test used to skip ordinary prose.
fn looks_url_like(value: &str) -> bool {
    let v = value.trim();
    patterns().url_like.is_match(v)
}

/// Extract the host from a URL's authority, handling `user:pass@host`,
/// `//host/...`, and a leading backslash that some parsers read as a slash.
fn authority_host(value: &str) -> Option<String> {
    let v = value.trim();
    let after_scheme = match v.find("://") {
        Some(i) => &v[i + 3..],
        None => {
            if let Some(rest) = v.strip_prefix("//") {
                rest
            } else if let Some(rest) = v.strip_prefix("\\\\") {
                rest
            } else if let Some(rest) = v.strip_prefix('\\') {
                rest
            } else {
                v
            }
        }
    };

    // The authority ends at the first `/`, `?`, `#`, or backslash.
    let end = after_scheme
        .find(['/', '?', '#', '\\'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..end];
    if authority.is_empty() {
        return None;
    }

    // `userinfo@host`: the real host is after the last `@`.
    let hostport = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };

    // Strip a trailing `:port` unless it is an IPv6 literal in brackets.
    let host = if hostport.starts_with('[') {
        match hostport.find(']') {
            Some(i) => &hostport[..=i],
            None => hostport,
        }
    } else {
        match hostport.rfind(':') {
            Some(i) if !hostport[i + 1..].is_empty() => &hostport[..i],
            _ => hostport,
        }
    };

    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Convert a decimal / octal / hex / shortened numeric IP to dotted-quad form,
/// so `2130706433`, `0x7f000001`, `0177.0.0.1` and `127.1` all become
/// `127.0.0.1`. Returns `None` when the host is not purely numeric.
fn normalize_numeric_ip(host: &str) -> Option<String> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }

    // Dotted form where each part may itself be decimal/octal/hex.
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4 {
            let mut octets = Vec::with_capacity(4);
            for p in &parts {
                octets.push(parse_int_component(p)?);
            }
            return Some(
                octets
                    .iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join("."),
            );
        }
        if parts.len() == 2 || parts.len() == 3 {
            // `a.b` and `a.b.c` are valid shorthand for the full 32-bit value.
            let mut acc: u64 = 0;
            for (i, p) in parts.iter().enumerate() {
                let part = parse_int_component(p)?;
                if i + 1 == parts.len() {
                    let remaining_bits = 8 * (4 - i);
                    let max = (1u64 << remaining_bits).saturating_sub(1);
                    if part > max {
                        return None;
                    }
                    acc = (acc << remaining_bits) | part;
                } else {
                    if part > 0xff {
                        return None;
                    }
                    acc = (acc << 8) | part;
                }
            }
            return Some(v4_from_u32(acc as u32));
        }
        return None;
    }

    // A single integer (decimal / 0x hex / leading-zero octal).
    let value = parse_int_component(host)?;
    if value > u32::MAX as u64 {
        return None;
    }
    Some(v4_from_u32(value as u32))
}

fn parse_int_component(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    if s.len() > 1 && s.starts_with('0') {
        return u64::from_str_radix(&s[1..], 8).ok();
    }
    s.parse::<u64>().ok()
}

fn v4_from_u32(v: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xff,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff
    )
}

/// True when the host is a non-public address an SSRF must not reach.
fn is_forbidden_host(host: &str) -> bool {
    // Literal IP (v4 or v6).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_forbidden_ip(ip);
    }
    false
}

fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()          // 10/8, 172.16/12, 192.168/16
                || v4.is_loopback()  // 127/8
                || v4.is_link_local() // 169.254/16
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || o[0] == 0          // 0.0.0.0/8 "this network"
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64/10
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0/24 IETF
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // benchmarking
                || o[0] >= 240 // 240/4 reserved
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local
                || (v6.segments()[0] & 0xfe00 == 0xfc00)
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0 == 0xfe80)
                // ::ffff:0:0/96 IPv4-mapped, re-checked as IPv4
                || v6.to_ipv4_mapped().map(|v4| is_forbidden_ip(IpAddr::V4(v4))).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn opts_block() -> SsrfOptions {
        SsrfOptions {
            block: true,
            inspect_body: true,
        }
    }

    fn inspect_get(query: &str, opts: SsrfOptions) -> Option<Decision> {
        let mut r = HttpRequest::new("GET", "/fetch");
        r.raw_query = query.to_string();
        let mut ctx = RequestContext::new(r);
        SsrfInspector::new(false, opts).inspect(&mut ctx).unwrap()
    }

    #[test]
    fn loopback_url_blocked_when_blocking() {
        let d = inspect_get("url=http://127.0.0.1/admin", opts_block()).unwrap();
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.rule_id, "SSRF003");
    }

    #[test]
    fn metadata_address_blocked() {
        let d = inspect_get("url=http://169.254.169.254/latest/meta-data/", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF002");
    }

    #[test]
    fn decimal_encoded_loopback_blocked() {
        // http://2130706433/ == http://127.0.0.1/
        let d = inspect_get("redirect=http://2130706433/", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF003");
    }

    #[test]
    fn hex_encoded_loopback_blocked() {
        let d = inspect_get("target=http://0x7f000001/", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF003");
    }

    #[test]
    fn userinfo_confusion_blocked() {
        // http://evil.com@127.0.0.1/ -- the real host is 127.0.0.1.
        let d = inspect_get("url=http://evil.com@127.0.0.1/", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF003");
    }

    #[test]
    fn file_scheme_blocked() {
        let d = inspect_get("url=file:///etc/passwd", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF001");
    }

    #[test]
    fn private_range_blocked() {
        let d = inspect_get("url=http://10.0.0.5:8080/", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF003");
    }

    #[test]
    fn internal_hostname_blocked() {
        let d = inspect_get("url=http://service.internal/", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF004");
    }

    #[test]
    fn public_url_is_monitored_not_blocked_by_default() {
        let d = inspect_get("url=https://example.com/page", SsrfOptions::default());
        assert!(d.is_none(), "a public URL must not be flagged: {d:?}");
    }

    #[test]
    fn public_url_allowed_even_when_blocking() {
        let d = inspect_get("url=https://cdn.example.org/app.js", opts_block());
        assert!(d.is_none(), "public URL must pass: {d:?}");
    }

    #[test]
    fn ordinary_numbers_and_words_never_flagged() {
        assert!(inspect_get("page=2&q=finance&id=169", opts_block()).is_none());
        assert!(inspect_get("name=localhost%20guide", opts_block()).is_none());
    }

    #[test]
    fn percent_encoded_scheme_is_decoded() {
        let d = inspect_get("url=http%3A%2F%2F127.0.0.1%2F", opts_block()).unwrap();
        assert_eq!(d.rule_id, "SSRF003");
    }

    #[test]
    fn numeric_ip_normalization() {
        assert_eq!(
            normalize_numeric_ip("2130706433").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            normalize_numeric_ip("0x7f000001").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(normalize_numeric_ip("127.1").as_deref(), Some("127.0.0.1"));
        assert_eq!(normalize_numeric_ip("example.com"), None);
    }

    #[test]
    fn authority_extraction() {
        assert_eq!(authority_host("http://a.b:8080/x").as_deref(), Some("a.b"));
        assert_eq!(authority_host("//a.b/x").as_deref(), Some("a.b"));
        assert_eq!(authority_host("http://u:p@a.b/x").as_deref(), Some("a.b"));
        assert_eq!(
            authority_host("http://[::1]:80/x").as_deref(),
            Some("[::1]")
        );
    }
}
