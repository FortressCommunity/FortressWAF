//! Request and response inspection contexts.
//!
//! Port of `internal/engine/engine.go` (`RequestContext`, `ResponseContext`,
//! `queryValues`, `NewRequestContext`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::action::Decision;
use crate::http::{HttpRequest, HttpResponse};

/// Maximum request body retained for inspection (10 MiB), matching the Go
/// `maxBodySize = 10 << 20`.
pub const MAX_BODY_SIZE: usize = 10 << 20;

/// RequestContext holds all request-derived data and inspection state for a
/// single request.
///
/// Port of the Go struct. Concurrency note: Go guarded the accumulated
/// `decisions` / `threat_score` / `bot_score` with a `sync.RWMutex` because
/// inspectors could in theory be invoked from multiple goroutines. This port is
/// invoked sequentially from a single task per request, so the fields are plain
/// and mutated directly; the lock is unnecessary and its absence is not a
/// behaviour change (the Go code never depended on cross-goroutine visibility
/// within one request's inspection).
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub site: String,
    pub real_ip: String,
    pub user_agent: String,
    pub path: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub query_params: BTreeMap<String, Vec<String>>,
    pub form_params: BTreeMap<String, Vec<String>>,
    pub body: Vec<u8>,
    pub content_type: String,
    pub session_id: String,
    pub user_id: String,
    pub api_key: String,
    pub country: String,
    pub asn: u32,
    pub bot_score: f64,
    pub threat_score: f64,
    pub decisions: Vec<Decision>,
    pub is_bot: bool,
    pub is_known_attack: bool,
    pub started_at: Instant,
    pub request_id: String,
    pub host: String,
    pub tls_version: String,
    pub tls_cipher_suite: String,
    pub ja3_hash: String,

    /// Raw byte targets the parser hardener scans for invalid / overlong UTF-8
    /// (PARSER_010 / PARSER_012). Mirrors the Go set: Path, Method, RealIP, and
    /// every header key and value. Values fall back to the UTF-8 bytes of the
    /// corresponding string field when the request carried no raw bytes.
    pub raw_scan_targets: Vec<Vec<u8>>,
}

impl RequestContext {
    /// Build a context from a request, resolving the client address from
    /// `RemoteAddr` without a trusted-proxy list. Client-supplied forwarded
    /// headers are never honoured here.
    ///
    /// Port of `NewRequestContext`. The body supplied on the `HttpRequest` is
    /// used directly; the Go version read up to 10 MiB + 1 byte from `r.Body`
    /// and truncated to 10 MiB, then replaced `r.Body`. Here the equivalent is:
    /// truncate the provided body to `MAX_BODY_SIZE` and store it.
    pub fn new(request: HttpRequest) -> Self {
        let real_ip = split_host_port(&request.remote_addr)
            .map(|(host, _)| host)
            .unwrap_or_else(|| request.remote_addr.clone());

        let mut headers: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in request.header.first_values() {
            headers.insert(k, v);
        }

        let cookies = parse_cookies(request.header.values("Cookie"));

        let query_params = query_values(&request.raw_query);

        let content_type = request.header.get("Content-Type").unwrap_or("").to_string();

        // Body: the caller has already read the body into `request.body`. Apply
        // the same 10 MiB cap the Go code applied.
        let body = if request.body.len() > MAX_BODY_SIZE {
            request.body[..MAX_BODY_SIZE].to_vec()
        } else {
            request.body.clone()
        };

        let started_at = Instant::now();
        let request_id = format!("{:x}", now_unix_nanos());

        let tls_version = request
            .tls
            .as_ref()
            .map(|t| t.version.clone())
            .unwrap_or_default();
        let tls_cipher_suite = request
            .tls
            .as_ref()
            .map(|t| t.cipher_suite.clone())
            .unwrap_or_default();
        let ja3_hash = request
            .tls
            .as_ref()
            .map(|t| t.ja3_hash.clone())
            .unwrap_or_default();

        // Build the raw byte scan targets for the parser hardener, preferring
        // the request's raw bytes and falling back to the string fields' UTF-8
        // bytes. Order mirrors Go: Path, Method, RealIP, then header pairs.
        let mut raw_scan_targets: Vec<Vec<u8>> = Vec::new();
        if !request.raw_path.is_empty() {
            raw_scan_targets.push(request.raw_path.clone());
        } else {
            raw_scan_targets.push(request.path.as_bytes().to_vec());
        }
        raw_scan_targets.push(request.method.as_bytes().to_vec());
        raw_scan_targets.push(real_ip.as_bytes().to_vec());
        if !request.raw_header.is_empty() {
            for (k, v) in &request.raw_header {
                raw_scan_targets.push(k.clone());
                raw_scan_targets.push(v.clone());
            }
        } else {
            for (k, v) in request.header.iter() {
                raw_scan_targets.push(k.as_bytes().to_vec());
                if let Some(first) = v.first() {
                    raw_scan_targets.push(first.as_bytes().to_vec());
                }
            }
        }

        RequestContext {
            site: String::new(),
            real_ip,
            user_agent: request.user_agent().to_string(),
            path: request.path.clone(),
            method: request.method.clone(),
            host: request.host.clone(),
            headers,
            cookies,
            query_params,
            form_params: BTreeMap::new(),
            body,
            content_type,
            session_id: String::new(),
            user_id: String::new(),
            api_key: String::new(),
            country: String::new(),
            asn: 0,
            bot_score: 0.0,
            threat_score: 0.0,
            decisions: Vec::new(),
            is_bot: false,
            is_known_attack: false,
            started_at,
            request_id,
            tls_version,
            tls_cipher_suite,
            ja3_hash,
            raw_scan_targets,
            request,
            response: None,
        }
    }

    /// Helper: `ctx.Request.Proto`.
    pub fn proto(&self) -> &str {
        &self.request.proto
    }

    /// Helper: first value of a header from the request, as Go's
    /// `ctx.Request.Header.Get` does.
    pub fn request_header(&self, name: &str) -> &str {
        self.request.header.get_or_empty(name)
    }
}

/// ResponseContext holds response-level information for post-response
/// inspection. Port of the Go struct.
#[derive(Debug, Clone)]
pub struct ResponseContext {
    pub status_code: i32,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub request: Arc<RequestContext>,
}

/// Parse a raw query string, tolerating characters Go's strict parser rejects.
///
/// Port of `queryValues`. Splits on `&` only, decodes each key and value with
/// `QueryUnescape` semantics, and skips malformed pairs rather than failing the
/// whole query. A raw `;` is treated as ordinary data (Go's `url.Query` would
/// reject the whole string).
pub fn query_values(raw_query: &str) -> BTreeMap<String, Vec<String>> {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if raw_query.is_empty() {
        return values;
    }

    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }

        let (key, value) = match pair.find('=') {
            Some(idx) => (&pair[..idx], &pair[idx + 1..]),
            None => (pair, ""),
        };

        let k = match query_unescape(key) {
            Some(k) => k,
            None => continue,
        };
        let v = match query_unescape(value) {
            Some(v) => v,
            None => continue,
        };
        values.entry(k).or_default().push(v);
    }

    values
}

/// `url.QueryUnescape`: like path unescape but also turns `+` into a space.
/// Returns `None` on an invalid `%` escape, matching Go returning an error.
pub fn query_unescape(s: &str) -> Option<String> {
    unescape(s, true)
}

/// `url.PathUnescape`: like `QueryUnescape` but leaves `+` as `+`.
pub fn path_unescape(s: &str) -> Option<String> {
    unescape(s, false)
}

fn unescape(s: &str, plus_as_space: bool) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex_val(bytes[i + 1])?;
                let lo = hex_val(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    // Go returns bytes; callers treat them as a string. Use lossy conversion so
    // invalid UTF-8 in a query value does not drop the pair (Go keeps the raw
    // bytes in a Go string).
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `net.SplitHostPort` for the common `host:port` case. Returns `None` when the
/// address has no port or is malformed, matching the Go error path (callers
/// fall back to the whole `RemoteAddr`).
pub fn split_host_port(addr: &str) -> Option<(String, String)> {
    // IPv6 bracket form: [::1]:8080
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            if let Some(port) = after.strip_prefix(':') {
                return Some((host.to_string(), port.to_string()));
            }
            return None;
        }
        return None;
    }
    // host:port -- split at the last colon (Go requires exactly one colon).
    let colon = addr.rfind(':')?;
    let host = &addr[..colon];
    let port = &addr[colon + 1..];
    if host.is_empty() || port.is_empty() {
        return None;
    }
    // More than one colon means an unbracketed IPv6 address: Go rejects it.
    if host.contains(':') {
        return None;
    }
    Some((host.to_string(), port.to_string()))
}

/// Parse `Cookie` header values into name/value pairs, mirroring
/// `r.Cookies()` for the fields the engine reads. Malformed pairs are skipped.
fn parse_cookies(values: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in values {
        for pair in line.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            let (name, value) = match pair.find('=') {
                Some(idx) => (&pair[..idx], &pair[idx + 1..]),
                None => continue,
            };
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let value = value.trim().trim_matches('"');
            out.insert(name.to_string(), value.to_string());
        }
    }
    out
}

fn now_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Convenience: current time as an `Instant`, used by inspectors that time
/// windows. Wrapping keeps the import meaningful and centralised.
pub fn now() -> Instant {
    Instant::now()
}

/// A duration helper mirroring `time.Minute`, `time.Hour`, etc.
pub const fn seconds(n: u64) -> Duration {
    Duration::from_secs(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    #[test]
    fn query_values_tolerates_raw_semicolon() {
        // Go's url.Query would reject this entirely; query_values must keep it.
        let v = query_values("id=1;DROP TABLE users");
        assert_eq!(v.get("id").unwrap(), &["1;DROP TABLE users".to_string()]);
    }

    #[test]
    fn query_values_splits_on_ampersand_only() {
        let v = query_values("a=1&b=2&c");
        assert_eq!(v.get("a").unwrap(), &["1".to_string()]);
        assert_eq!(v.get("b").unwrap(), &["2".to_string()]);
        assert_eq!(v.get("c").unwrap(), &["".to_string()]);
    }

    #[test]
    fn query_values_decodes_plus_and_percent() {
        let v = query_values("q=hello+world&p=%2Fetc");
        assert_eq!(v.get("q").unwrap(), &["hello world".to_string()]);
        assert_eq!(v.get("p").unwrap(), &["/etc".to_string()]);
    }

    #[test]
    fn query_values_skips_malformed_escape() {
        let v = query_values("bad=%zz&good=1");
        assert!(!v.contains_key("bad"));
        assert_eq!(v.get("good").unwrap(), &["1".to_string()]);
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(
            split_host_port("1.2.3.4:5678"),
            Some(("1.2.3.4".to_string(), "5678".to_string()))
        );
        assert_eq!(
            split_host_port("[::1]:80"),
            Some(("::1".to_string(), "80".to_string()))
        );
        assert_eq!(split_host_port("1.2.3.4"), None);
        assert_eq!(split_host_port("::1"), None);
    }

    #[test]
    fn new_context_resolves_ip_and_headers() {
        let mut req = HttpRequest::new("GET", "/a");
        req.remote_addr = "10.0.0.1:1234".to_string();
        req.header.add("User-Agent", "curl/8.0");
        req.header.add("Content-Type", "text/plain");
        req.raw_query = "x=1".to_string();
        let ctx = RequestContext::new(req);
        assert_eq!(ctx.real_ip, "10.0.0.1");
        assert_eq!(ctx.user_agent, "curl/8.0");
        assert_eq!(ctx.content_type, "text/plain");
        assert_eq!(ctx.query_params.get("x").unwrap(), &["1".to_string()]);
        assert_eq!(ctx.path, "/a");
        assert_eq!(ctx.method, "GET");
    }
}
