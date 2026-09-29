//! Middleware inspectors and the response-buffering writer.
//!
//! Port of `internal/engine/middleware.go` (`CAPTCHAVerifier`, `ResponseWriter`,
//! `SOAPValidator`, `GRPCInspector`, `NewResponseInspector`).
//!
//! ## Deviation (documented)
//!
//! `ResponseWriter` wraps an `http.ResponseWriter`. This port models the
//! buffering semantics over a [`Sink`] trait (the thing bytes are eventually
//! written to), so the buffer/commit/discard logic is testable and the proxy's
//! hyper adapter implements `Sink`. See `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

/// The destination for committed response bytes. The proxy supplies a hyper
/// response builder; tests supply an in-memory buffer.
pub trait Sink: Send {
    /// Write status + headers + body to the destination.
    fn write_all(
        &mut self,
        status: i32,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), String>;
    /// Whether the destination supports flush (streaming).
    fn flush(&mut self) -> Result<(), String>;
}

/// A `Sink` backed by an in-memory (`status`, `headers`, `body`) triple.
#[derive(Default)]
pub struct BufferSink {
    pub status: i32,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Sink for BufferSink {
    fn write_all(
        &mut self,
        status: i32,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(), String> {
        self.status = status;
        self.headers = headers.to_vec();
        self.body = body.to_vec();
        Ok(())
    }
    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Port of the Go `ResponseWriter`. Buffers up to `buf_cap` bytes so the
/// response can be inspected before any byte reaches the client.
pub struct ResponseWriter {
    pub status_code: i32,
    pub body: Vec<u8>,
    pub inspect_body: bool,
    pub headers: Vec<(String, String)>,

    buf_cap: usize,
    header_done: bool,
    flushed: bool,
    blocked: bool,
    pending: Vec<u8>,
    sink: Box<dyn Sink>,
}

impl ResponseWriter {
    /// Port of `NewResponseWriter`.
    pub fn new(sink: Box<dyn Sink>, inspect_body: bool, buf_cap: usize) -> Self {
        let buf_cap = if buf_cap == 0 { 1 << 20 } else { buf_cap };
        ResponseWriter {
            status_code: 200,
            body: Vec::new(),
            inspect_body,
            headers: Vec::new(),
            buf_cap,
            header_done: false,
            flushed: false,
            blocked: false,
            pending: Vec::new(),
            sink,
        }
    }

    /// Port of `WriteHeader` (headers are held back until commit).
    pub fn set_status(&mut self, code: i32) {
        self.status_code = code;
    }

    /// Set a response header (case-insensitive replace).
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        self.headers.push((name.to_string(), value.to_string()));
    }

    /// Remove a header.
    pub fn del_header(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    /// Get a header (first match).
    pub fn get_header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Port of `Write`.
    pub fn write(&mut self, b: &[u8]) -> Result<usize, String> {
        if self.blocked {
            return Ok(b.len());
        }
        if !self.inspect_body {
            self.commit_headers()?;
            let mut body = std::mem::take(&mut self.body);
            body.extend_from_slice(b);
            let hdrs = self.headers.clone();
            self.sink.write_all(self.status_code, &hdrs, &body)?;
            self.body = body;
            return Ok(b.len());
        }
        if self.body.len() < self.buf_cap {
            let room = self.buf_cap - self.body.len();
            if room >= b.len() {
                self.body.extend_from_slice(b);
                return Ok(b.len());
            }
            self.body.extend_from_slice(&b[..room]);
            self.pending.extend_from_slice(&b[room..]);
            self.commit_headers()?;
            let body = self.body.clone();
            let hdrs = self.headers.clone();
            self.sink.write_all(self.status_code, &hdrs, &body)?;
            self.flushed = true;
            if !self.pending.is_empty() {
                let pending = std::mem::take(&mut self.pending);
                let mut combined = body;
                combined.extend_from_slice(&pending);
                self.sink.write_all(self.status_code, &hdrs, &combined)?;
            }
            return Ok(b.len());
        }
        self.commit_headers()?;
        let mut body = self.body.clone();
        body.extend_from_slice(b);
        let hdrs = self.headers.clone();
        self.sink.write_all(self.status_code, &hdrs, &body)?;
        self.body = body;
        Ok(b.len())
    }

    fn commit_headers(&mut self) -> Result<(), String> {
        if self.header_done {
            return Ok(());
        }
        self.header_done = true;
        Ok(())
    }

    /// Port of `Flush`.
    pub fn flush(&mut self) -> Result<(), String> {
        if self.blocked {
            return Ok(());
        }
        self.commit_headers()?;
        if !self.body.is_empty() && !self.flushed {
            let body = self.body.clone();
            let hdrs = self.headers.clone();
            self.sink.write_all(self.status_code, &hdrs, &body)?;
            self.flushed = true;
        }
        self.sink.flush()
    }

    /// Port of `Commit`.
    pub fn commit(&mut self) -> Result<(), String> {
        if self.blocked {
            return Ok(());
        }
        self.commit_headers()?;
        if !self.flushed {
            let body = self.body.clone();
            let hdrs = self.headers.clone();
            self.sink.write_all(self.status_code, &hdrs, &body)?;
            self.flushed = true;
        }
        Ok(())
    }

    /// Port of `Discard`: drop the buffered response and clear origin entity
    /// headers so the replacement reply frames correctly.
    pub fn discard(&mut self) {
        self.blocked = true;
        self.body.clear();
        self.pending.clear();
        for k in [
            "Content-Length",
            "Content-Type",
            "Content-Encoding",
            "Content-Range",
            "Content-Disposition",
            "ETag",
            "Last-Modified",
            "Cache-Control",
            "Set-Cookie",
            "Transfer-Encoding",
        ] {
            self.del_header(k);
        }
    }

    /// Whether the writer was discarded in favour of a block page.
    pub fn is_blocked(&self) -> bool {
        self.blocked
    }
}

/// Port of `NewResponseInspector`.
pub fn new_response_inspector() -> crate::inspectors::response_leak::ResponseLeakInspector {
    crate::inspectors::response_leak::ResponseLeakInspector::new(true, false, 1 << 20)
}

// ---------------------------------------------------------------------------
// SOAP validator
// ---------------------------------------------------------------------------

/// Port of `SOAPValidator`.
pub struct SoapValidator {
    enabled: bool,
    strict_schema: bool,
    max_depth: i32,
}

impl SoapValidator {
    /// Port of `NewSOAPValidator`.
    pub fn new(strict_schema: bool, max_depth: i32) -> Self {
        SoapValidator {
            enabled: true,
            strict_schema,
            max_depth: if max_depth <= 0 { 10 } else { max_depth },
        }
    }
}

impl Inspector for SoapValidator {
    fn name(&self) -> &str {
        "soap"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if !self.enabled {
            return Ok(None);
        }
        if ctx.content_type != "text/xml" && ctx.content_type != "application/soap+xml" {
            return Ok(None);
        }
        let mut depth = 0;
        let mut open_tags = 0;
        for &b in &ctx.body {
            if b == b'<' {
                open_tags += 1;
                depth += 1;
                if depth > self.max_depth {
                    return Ok(Some(
                        Decision::new(Action::Block, 50.0)
                            .with_rule_id("SOAP001")
                            .with_rule_name("SOAP/XML Depth Exceeded")
                            .with_severity("medium")
                            .with_evidence(format!(
                                "XML nesting depth exceeded max of {}",
                                self.max_depth
                            )),
                    ));
                }
            }
            if b == b'>' {
                open_tags -= 1;
                if open_tags < 0 {
                    return Ok(Some(
                        Decision::new(Action::Block, 50.0)
                            .with_rule_id("SOAP002")
                            .with_rule_name("Malformed XML")
                            .with_severity("medium")
                            .with_evidence("unexpected closing tag"),
                    ));
                }
            }
        }
        let _ = self.strict_schema;
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// gRPC inspector
// ---------------------------------------------------------------------------

struct GrpcCounter {
    count: i32,
    reset_time: Instant,
}

/// Port of `GRPCInspector`.
pub struct GrpcInspector {
    enabled: bool,
    max_msg_size: i32,
    rate_limit: i32,
    counters: Mutex<HashMap<String, GrpcCounter>>,
}

impl GrpcInspector {
    /// Port of `NewGRPCInspector`.
    pub fn new(max_msg_size: i32, rate_limit: i32) -> Self {
        GrpcInspector {
            enabled: true,
            max_msg_size: if max_msg_size <= 0 {
                4 * 1024 * 1024
            } else {
                max_msg_size
            },
            rate_limit: if rate_limit <= 0 { 100 } else { rate_limit },
            counters: Mutex::new(HashMap::new()),
        }
    }
}

impl Inspector for GrpcInspector {
    fn name(&self) -> &str {
        "grpc"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if !self.enabled {
            return Ok(None);
        }
        if !ctx.content_type.starts_with("application/grpc") {
            return Ok(None);
        }

        let service = ctx.path.clone();
        let mut counters = self.counters.lock();
        let now = Instant::now();

        match counters.get_mut(&service) {
            None => {
                counters.insert(
                    service.clone(),
                    GrpcCounter {
                        count: 1,
                        reset_time: now,
                    },
                );
                return Ok(None);
            }
            Some(c) => {
                if now.duration_since(c.reset_time) > Duration::from_secs(60) {
                    c.count = 1;
                    c.reset_time = now;
                    return Ok(None);
                }
                c.count += 1;
                if c.count > self.rate_limit {
                    return Ok(Some(
                        Decision::new(Action::RateLimit, 60.0)
                            .with_rule_id("GRPC001")
                            .with_rule_name("gRPC Rate Limit")
                            .with_severity("medium")
                            .with_evidence(format!(
                                "gRPC {service} exceeded rate limit of {} req/min",
                                self.rate_limit
                            )),
                    ));
                }
            }
        }

        if ctx.request.content_length > self.max_msg_size as i64 {
            return Ok(Some(
                Decision::new(Action::Block, 40.0)
                    .with_rule_id("GRPC002")
                    .with_rule_name("gRPC Message Too Large")
                    .with_severity("medium")
                    .with_evidence(format!(
                        "gRPC message size {} exceeds max {}",
                        ctx.request.content_length, self.max_msg_size
                    )),
            ));
        }

        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// CAPTCHA verifier
// ---------------------------------------------------------------------------

/// The HTTP POST used by the CAPTCHA verifier.
pub trait CaptchaHttp: Send + Sync {
    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<String, String>;
}

/// Real CAPTCHA HTTP client.
pub struct UreqCaptchaHttp;

impl CaptchaHttp for UreqCaptchaHttp {
    fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Result<String, String> {
        let encoded: String = form
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let resp = ureq::post(url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&encoded)
            .map_err(|e| e.to_string())?;
        resp.into_string().map_err(|e| e.to_string())
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Port of `CAPTCHAVerifier`.
pub struct CaptchaVerifier {
    enabled: bool,
    provider: String,
    secret: String,
    #[allow(dead_code)]
    site_key: String,
    score: f64,
    http: Arc<dyn CaptchaHttp>,
}

impl CaptchaVerifier {
    /// Port of `NewCAPTCHAVerifier`.
    pub fn new(provider: &str, secret: &str, site_key: &str, score: f64) -> Self {
        Self::with_http(provider, secret, site_key, score, Arc::new(UreqCaptchaHttp))
    }

    pub fn with_http(
        provider: &str,
        secret: &str,
        site_key: &str,
        score: f64,
        http: Arc<dyn CaptchaHttp>,
    ) -> Self {
        CaptchaVerifier {
            enabled: true,
            provider: provider.to_string(),
            secret: secret.to_string(),
            site_key: site_key.to_string(),
            score,
            http,
        }
    }

    fn verify(&self, token: &str) -> Result<(bool, f64), String> {
        let (url, _) = match self.provider.as_str() {
            "recaptcha" => ("https://www.google.com/recaptcha/api/siteverify", ()),
            "hcaptcha" => ("https://hcaptcha.com/siteverify", ()),
            other => return Err(format!("unsupported captcha provider: {other}")),
        };
        let body = self
            .http
            .post_form(url, &[("secret", &self.secret), ("response", token)])?;
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let success = v.get("success").and_then(|x| x.as_bool()).unwrap_or(false);
        let score = v.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
        Ok((success && score >= self.score, score))
    }
}

impl Inspector for CaptchaVerifier {
    fn name(&self) -> &str {
        "captcha"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if !self.enabled {
            return Ok(None);
        }
        let token = ctx.request_header("X-CAPTCHA-Token").to_string();
        let token = if token.is_empty() {
            ctx.request_header("X-Recaptcha-Token").to_string()
        } else {
            token
        };
        if token.is_empty() {
            return Ok(None);
        }
        match self.verify(&token) {
            Err(e) => Err(EngineError::new(format!("captcha verify: {e}"))),
            Ok((ok, score)) => {
                if !ok {
                    Ok(Some(
                        Decision::new(Action::Block, 30.0)
                            .with_rule_id("CAPTCHA001")
                            .with_rule_name("CAPTCHA Verification Failed")
                            .with_severity("low")
                            .with_evidence(format!(
                                "CAPTCHA score {} below threshold {}",
                                score, self.score
                            )),
                    ))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

/// Silence unused-import warnings for Regex (kept for parity/extension).
static _RE: once_cell::sync::Lazy<Option<Regex>> = once_cell::sync::Lazy::new(|| None);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    #[test]
    fn response_writer_buffers_then_commits() {
        let w = ResponseWriter::new(Box::new(BufferSink::default()), true, 16);
        let mut w = w;
        w.write(b"short").unwrap();
        w.commit().unwrap();
        assert_eq!(w.body, b"short");
        assert!(!w.is_blocked());
    }

    #[test]
    fn response_writer_discard_clears() {
        let mut w = ResponseWriter::new(Box::new(BufferSink::default()), true, 16);
        w.set_header("Content-Type", "text/plain");
        w.set_header("Content-Length", "5");
        w.write(b"hello").unwrap();
        w.discard();
        assert!(w.is_blocked());
        assert!(w.body.is_empty());
        assert!(w.get_header("Content-Type").is_none());
        assert!(w.get_header("Content-Length").is_none());
    }

    #[test]
    fn soap_depth_exceeded() {
        let s = SoapValidator::new(false, 2);
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Content-Type", "text/xml");
        r.body = b"<a><b><c></c></b></a>".to_vec();
        let mut ctx = RequestContext::new(r);
        let dec = s.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "SOAP001");
    }

    #[test]
    fn soap_malformed_closing() {
        let s = SoapValidator::new(false, 10);
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("Content-Type", "application/soap+xml");
        r.body = b"></x>".to_vec();
        let mut ctx = RequestContext::new(r);
        let dec = s.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "SOAP002");
    }

    #[test]
    fn grpc_rate_limit() {
        let g = GrpcInspector::new(1024, 2);
        let mut r = HttpRequest::new("POST", "/svc");
        r.header.add("Content-Type", "application/grpc");
        let mut ctx = RequestContext::new(r);
        assert!(g.inspect(&mut ctx).unwrap().is_none());
        assert!(g.inspect(&mut ctx).unwrap().is_none());
        let dec = g.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "GRPC001");
    }

    #[test]
    fn captcha_low_score_blocked() {
        struct Fake;
        impl CaptchaHttp for Fake {
            fn post_form(&self, _url: &str, _form: &[(&str, &str)]) -> Result<String, String> {
                Ok(r#"{"success":true,"score":0.1}"#.to_string())
            }
        }
        let c = CaptchaVerifier::with_http("recaptcha", "s", "k", 0.5, Arc::new(Fake));
        let mut r = HttpRequest::new("POST", "/");
        r.header.add("X-CAPTCHA-Token", "tok");
        let mut ctx = RequestContext::new(r);
        let dec = c.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "CAPTCHA001");
    }
}
