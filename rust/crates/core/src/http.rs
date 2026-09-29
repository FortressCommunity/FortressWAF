//! A minimal, faithful HTTP request/response model.
//!
//! The Go engine reads a subset of `*http.Request` / `*http.Response`. This
//! module mirrors exactly that subset so the ported inspectors see the same
//! inputs. It is deliberately not a general-purpose HTTP library.

use std::collections::HashMap;
use std::sync::Arc;

/// A single parsed HTTP request as the engine sees it.
///
/// Field names and semantics mirror the Go `*http.Request` surface used by the
/// inspectors:
///
/// - `method`     -> `r.Method`
/// - `path`       -> `r.URL.Path`
/// - `raw_query`  -> `r.URL.RawQuery`
/// - `host`       -> `r.Host`
/// - `proto`      -> `r.Proto` (e.g. `"HTTP/1.0"`)
/// - `header`     -> `r.Header` (canonicalised keys, multi-value)
/// - `remote_addr`-> `r.RemoteAddr`
/// - `content_length` -> `r.ContentLength`
/// - `body`       -> the already-read request body
/// - `tls`        -> TLS connection state, if any
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub raw_query: String,
    pub host: String,
    pub proto: String,
    pub header: HeaderMap,
    pub remote_addr: String,
    /// `-1` means unknown length, matching Go's `ContentLength` semantics.
    pub content_length: i64,
    pub body: Vec<u8>,
    pub tls: Option<TlsState>,
    /// Raw (possibly non-UTF-8) bytes of the request path, as Go's
    /// `r.URL.Path` bytes would be. When empty, the parser uses
    /// `path.as_bytes()`. This exists so the parser hardener's invalid-UTF-8
    /// and overlong-UTF-8 checks (PARSER_010 / PARSER_012) see the same bytes
    /// Go would, which a `String` alone cannot represent.
    pub raw_path: Vec<u8>,
    /// Raw bytes of header key/value pairs. When empty, `header` is used.
    pub raw_header: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Default for HttpRequest {
    fn default() -> Self {
        HttpRequest {
            method: String::new(),
            path: String::new(),
            raw_query: String::new(),
            host: String::new(),
            proto: String::new(),
            header: HeaderMap::new(),
            remote_addr: String::new(),
            content_length: 0,
            body: Vec::new(),
            tls: None,
            raw_path: Vec::new(),
            raw_header: Vec::new(),
        }
    }
}

/// TLS connection state, mirroring the fields the engine reads from
/// `r.TLS` (version, cipher suite, and the negotiated parameters that feed
/// JA3/JA4 fingerprinting).
#[derive(Debug, Clone)]
pub struct TlsState {
    pub version: String,
    pub cipher_suite: String,
    /// Raw ClientHello-derived fingerprint inputs, when available.
    pub ja3_hash: String,
    /// The peer's leaf certificate in DER form, when mutual TLS presented one.
    /// Mirrors Go's `tls.Conn.ConnectionState().PeerCertificates[0].Raw`.
    pub peer_cert_der: Option<Vec<u8>>,
    /// Full DER chain, when available.
    pub peer_chain_der: Vec<Vec<u8>>,
    /// Whether the connection is TLS at all (Go: `r.TLS != nil`).
    pub present: bool,
}

impl HttpRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            ..Default::default()
        }
    }

    /// `r.Header.Get(name)` -- first value (case-insensitive key lookup).
    pub fn header_get(&self, name: &str) -> Option<&str> {
        self.header.get(name)
    }

    /// `r.Header.Values(name)` -- all values for a header.
    pub fn header_values(&self, name: &str) -> &[String] {
        self.header.values(name)
    }

    /// `r.UserAgent()` -- `Header.Get("User-Agent")`.
    pub fn user_agent(&self) -> &str {
        self.header.get("User-Agent").unwrap_or("")
    }

    /// `r.URL.Path` fallback: if the request was built from a raw target,
    /// callers should populate `path` directly. This helper returns it.
    pub fn url_path(&self) -> &str {
        &self.path
    }
}

/// A single parsed HTTP response as the engine sees it.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status_code: i32,
    pub header: HeaderMap,
    pub body: Vec<u8>,
}

/// Multi-value, case-insensitive header map, matching Go's `http.Header`
/// canonicalisation (first letter of each `-`-separated token uppercased,
/// rest lowercased).
#[derive(Debug, Clone, Default)]
pub struct HeaderMap {
    map: HashMap<String, Vec<String>>,
}

impl HeaderMap {
    pub fn new() -> Self {
        HeaderMap {
            map: HashMap::new(),
        }
    }

    /// Canonicalise a header key the way Go's `textproto.CanonicalMIMEHeaderKey`
    /// does for ASCII: uppercase the first letter and any letter following a
    /// `-`, lowercase everything else. Invalid keys (containing spaces or
    /// control characters) are returned unchanged, matching Go.
    pub fn canonical_key(key: &str) -> String {
        let bytes = key.as_bytes();
        // Go returns the key unchanged if it contains a space or any byte that
        // is not a valid token character.
        if bytes.iter().any(|&b| b == b' ' || !is_token_byte(b)) {
            return key.to_string();
        }
        let mut out = Vec::with_capacity(bytes.len());
        let mut upper = true;
        for &b in bytes {
            if upper && b.is_ascii_lowercase() {
                out.push(b.to_ascii_uppercase());
            } else if !upper && b.is_ascii_uppercase() {
                out.push(b.to_ascii_lowercase());
            } else {
                out.push(b);
            }
            upper = b == b'-';
        }
        String::from_utf8(out).unwrap_or_else(|_| key.to_string())
    }

    /// Append a value under the canonical key (`Header.Add`).
    pub fn add(&mut self, key: &str, value: impl Into<String>) {
        self.map
            .entry(Self::canonical_key(key))
            .or_default()
            .push(value.into());
    }

    /// Set a value, replacing any existing (`Header.Set`).
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.map
            .insert(Self::canonical_key(key), vec![value.into()]);
    }

    /// `Header.Get`: first value for the key, or `None`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.map
            .get(&Self::canonical_key(key))
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// `Header.Values`: all values for the key (empty slice if absent).
    pub fn values(&self, key: &str) -> &[String] {
        self.map
            .get(&Self::canonical_key(key))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// `Header.Get` returning an owned empty string when absent -- matching the
    /// Go idiom of comparing `Header.Get(x) == ""`.
    pub fn get_or_empty(&self, key: &str) -> &str {
        self.get(key).unwrap_or("")
    }

    /// Iterate over all (canonical key, first value) pairs. The Go engine
    /// iterates `for k, v := range r.Header { ctx.Headers[k] = v[0] }`; use the
    /// `first_values` accessor to reproduce that.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.map.iter()
    }

    /// Reproduce Go's `for k, v := range r.Header { ctx.Headers[k] = v[0] }`
    /// where only the first value per key is retained.
    pub fn first_values(&self) -> Vec<(String, String)> {
        self.map
            .iter()
            .filter_map(|(k, v)| v.first().map(|first| (k.clone(), first.clone())))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// RFC 7230 token byte check, used for header-key canonicalisation validity.
fn is_token_byte(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
        b'^' | b'_' | b'`' | b'|' | b'~' |
        b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// A shared handle to a request body, mirroring Go's `r.Body` being replaced
/// after read so downstream handlers can re-read it. In Rust we keep the bytes
/// and hand out a fresh cursor.
pub type BodyHandle = Arc<Vec<u8>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_key_matches_go() {
        assert_eq!(HeaderMap::canonical_key("content-type"), "Content-Type");
        assert_eq!(HeaderMap::canonical_key("CONTENT-TYPE"), "Content-Type");
        assert_eq!(
            HeaderMap::canonical_key("x-forwarded-for"),
            "X-Forwarded-For"
        );
        assert_eq!(HeaderMap::canonical_key("host"), "Host");
        // Invalid keys (with spaces) are returned unchanged, like Go.
        assert_eq!(HeaderMap::canonical_key("bad key"), "bad key");
    }

    #[test]
    fn header_get_and_values() {
        let mut h = HeaderMap::new();
        h.add("X-Test", "one");
        h.add("x-test", "two");
        assert_eq!(h.get("X-TEST"), Some("one"));
        assert_eq!(h.values("x-test"), &["one".to_string(), "two".to_string()]);
        assert_eq!(h.get("absent"), None);
        assert_eq!(h.get_or_empty("absent"), "");
    }

    #[test]
    fn first_values_keeps_only_first() {
        let mut h = HeaderMap::new();
        h.add("Transfer-Encoding", "chunked");
        h.add("Transfer-Encoding", "gzip");
        let fv = h.first_values();
        assert_eq!(fv.len(), 1);
        assert_eq!(fv[0].1, "chunked");
    }
}
