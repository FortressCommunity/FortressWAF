//! ML engine client: inspect/classify/fingerprint/bot-score with a circuit
//! breaker and fallback.
//!
//! Port of `internal/ml/client.go`. The circuit breaker, retry/backoff, fallback
//! results and the request shapes are preserved.
//!
//! ## Deviation (documented)
//!
//! The Go client used `net/http`. The transport is behind the [`HttpTransport`]
//! trait so the retry/circuit-breaker logic is unit-testable without network;
//! [`UreqTransport`] is the real implementation. See `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// A single POST that returns the raw response body and status code.
pub trait HttpTransport: Send + Sync {
    fn post(&self, url: &str, body: &str, timeout: Duration) -> Result<(u16, String), String>;
    fn get(&self, url: &str, timeout: Duration) -> Result<u16, String>;
}

/// Real transport using `ureq`.
pub struct UreqTransport;

impl HttpTransport for UreqTransport {
    fn post(&self, url: &str, body: &str, timeout: Duration) -> Result<(u16, String), String> {
        let resp = ureq::post(url)
            .timeout(timeout)
            .set("Content-Type", "application/json")
            .send_string(body)
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        let body = resp.into_string().map_err(|e| e.to_string())?;
        Ok((status, body))
    }

    fn get(&self, url: &str, timeout: Duration) -> Result<u16, String> {
        let resp = ureq::get(url)
            .timeout(timeout)
            .call()
            .map_err(|e| e.to_string())?;
        Ok(resp.status())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InspectionResult {
    #[serde(default)]
    pub anomaly_score: f64,
    #[serde(default)]
    pub is_anomaly: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attack_type: String,
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub attack_confidence: f64,
    #[serde(default)]
    pub bot_score: f64,
    #[serde(default)]
    pub risk_score: i32,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub model_version: String,
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub attack_type: String,
    pub confidence: f64,
    pub model_version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub fingerprint: String,
    pub hash_algorithm: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BotScoreResult {
    pub bot_score: f64,
    pub is_bot: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bot_type: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InspectRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub body: String,
    pub query_params: HashMap<String, String>,
    pub source_ip: String,
    pub user_agent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
}

struct CircuitBreaker {
    failures: i32,
    last_error: Option<Instant>,
    threshold: i32,
    cooldown: Duration,
    open: bool,
}

pub struct Client {
    base_url: String,
    timeout: Duration,
    max_retries: i32,
    fallback: String,
    available: RwLock<bool>,
    cb_state: Mutex<CircuitBreaker>,
    transport: Arc<dyn HttpTransport>,
}

impl Client {
    /// Port of `NewClient`.
    pub fn new(endpoint: &str, timeout_sec: i32, max_retries: i32, fallback_mode: &str) -> Self {
        Self::with_transport(
            endpoint,
            timeout_sec,
            max_retries,
            fallback_mode,
            Arc::new(UreqTransport),
        )
    }

    pub fn with_transport(
        endpoint: &str,
        timeout_sec: i32,
        max_retries: i32,
        fallback_mode: &str,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Client {
            base_url: endpoint.to_string(),
            timeout: Duration::from_secs(timeout_sec.max(0) as u64),
            max_retries,
            fallback: fallback_mode.to_string(),
            available: RwLock::new(true),
            cb_state: Mutex::new(CircuitBreaker {
                failures: 0,
                last_error: None,
                threshold: 5,
                cooldown: Duration::from_secs(30),
                open: false,
            }),
            transport,
        }
    }

    /// Port of `Inspect`.
    pub fn inspect(&self, req: &InspectRequest) -> (InspectionResult, Option<String>) {
        if !self.is_available() {
            return (
                self.fallback_result(),
                Some("ml client unavailable".to_string()),
            );
        }

        let body = match serde_json::to_string(req) {
            Ok(b) => b,
            Err(e) => {
                return (
                    self.fallback_result(),
                    Some(format!("marshal request: {e}")),
                )
            }
        };

        let mut last_err = String::new();
        for i in 0..=self.max_retries {
            match self.call_inspect(&body) {
                Ok(result) => {
                    self.record_success();
                    return (result, None);
                }
                Err(e) => {
                    last_err = e;
                    self.record_failure();
                    if i < self.max_retries {
                        std::thread::sleep(Duration::from_millis((100 * (i + 1)) as u64));
                    }
                }
            }
        }

        (
            self.fallback_result(),
            Some(format!(
                "ml inspect failed after {} retries: {last_err}",
                self.max_retries
            )),
        )
    }

    fn call_inspect(&self, body: &str) -> Result<InspectionResult, String> {
        let url = format!("{}/v1/inspect", self.base_url);
        let (status, resp_body) = self.transport.post(&url, body, self.timeout)?;
        if status != 200 {
            return Err(format!("ml service returned {status}: {resp_body}"));
        }
        serde_json::from_str(&resp_body).map_err(|e| format!("decode response: {e}"))
    }

    /// Port of `Classify`.
    pub fn classify<T: Serialize>(&self, data: &T) -> Result<ClassificationResult, String> {
        let body = serde_json::to_string(data).map_err(|e| e.to_string())?;
        let url = format!("{}/v1/classify", self.base_url);
        let (_, resp_body) = self.transport.post(&url, &body, self.timeout)?;
        serde_json::from_str(&resp_body).map_err(|e| e.to_string())
    }

    /// Port of `Fingerprint`.
    pub fn fingerprint<T: Serialize>(&self, data: &T) -> Result<FingerprintResult, String> {
        let body = serde_json::to_string(data).map_err(|e| e.to_string())?;
        let url = format!("{}/v1/fingerprint", self.base_url);
        let (_, resp_body) = self.transport.post(&url, &body, self.timeout)?;
        serde_json::from_str(&resp_body).map_err(|e| e.to_string())
    }

    /// Port of `BotScore`.
    pub fn bot_score<T: Serialize>(&self, data: &T) -> Result<BotScoreResult, String> {
        let body = serde_json::to_string(data).map_err(|e| e.to_string())?;
        let url = format!("{}/v1/bot-score", self.base_url);
        let (_, resp_body) = self.transport.post(&url, &body, self.timeout)?;
        serde_json::from_str(&resp_body).map_err(|e| e.to_string())
    }

    fn is_available(&self) -> bool {
        if !*self.available.read() {
            return false;
        }

        let mut cb = self.cb_state.lock();
        if cb.open {
            if let Some(last) = cb.last_error {
                if last.elapsed() > cb.cooldown {
                    cb.open = false;
                    cb.failures = 0;
                    return true;
                }
            }
            return false;
        }
        true
    }

    fn record_success(&self) {
        self.cb_state.lock().failures = 0;
    }

    fn record_failure(&self) {
        let mut cb = self.cb_state.lock();
        cb.failures += 1;
        if cb.failures >= cb.threshold {
            cb.open = true;
            cb.last_error = Some(Instant::now());
            warn!(failures = cb.failures, "ml circuit breaker opened");
        }
    }

    /// Port of `fallbackResult`.
    pub fn fallback_result(&self) -> InspectionResult {
        match self.fallback.as_str() {
            "block" => InspectionResult {
                anomaly_score: 1.0,
                is_anomaly: true,
                bot_score: 100.0,
                risk_score: 100,
                ..Default::default()
            },
            "monitor" => InspectionResult {
                anomaly_score: 0.5,
                is_anomaly: false,
                bot_score: 50.0,
                risk_score: 50,
                ..Default::default()
            },
            _ => InspectionResult::default(),
        }
    }

    /// Port of `SetAvailable`.
    pub fn set_available(&self, avail: bool) {
        *self.available.write() = avail;
    }

    /// Port of `HealthCheck`.
    pub fn health_check(&self) -> Result<(), String> {
        let url = format!("{}/health", self.base_url);
        let status = self.transport.get(&url, self.timeout)?;
        if !(200..300).contains(&status) {
            return Err(format!("health check returned status {status}"));
        }
        Ok(())
    }
}

/// Port of `InspectRequestFromHTTP` for the fields the engine reads. Query
/// values are flattened to a comma-joined string (the ML schema wants
/// `map[string]string`).
pub fn inspect_request_from_parts(
    method: &str,
    path: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    query_params: &HashMap<String, Vec<String>>,
    remote_addr: &str,
) -> InspectRequest {
    let query: HashMap<String, String> = query_params
        .iter()
        .map(|(k, v)| (k.clone(), v.join(",")))
        .collect();

    let content_type = headers.get("Content-Type").cloned().unwrap_or_default();
    let user_agent = headers.get("User-Agent").cloned().unwrap_or_default();

    let mut req = InspectRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers: headers.clone(),
        query_params: query,
        user_agent,
        content_type,
        source_ip: String::new(),
        body: String::new(),
    };

    // Body limited to 1 MiB.
    let limited = &body[..body.len().min(1 << 20)];
    req.body = String::from_utf8_lossy(limited).into_owned();

    if let Some((ip, _)) = split_host_port(remote_addr) {
        if !ip.is_empty() {
            req.source_ip = ip;
        }
    }
    if let Some(xff) = headers.get("X-Forwarded-For") {
        if let Some(first) = xff.split(',').next() {
            req.source_ip = first.trim().to_string();
        }
    }

    req
}

fn split_host_port(addr: &str) -> Option<(String, String)> {
    let colon = addr.rfind(':')?;
    Some((addr[..colon].to_string(), addr[colon + 1..].to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct OkTransport;
    impl HttpTransport for OkTransport {
        fn post(&self, _url: &str, _body: &str, _t: Duration) -> Result<(u16, String), String> {
            Ok((
                200,
                r#"{"anomaly_score":0.9,"is_anomaly":true,"attack_type":"sqli","risk_score":80}"#
                    .to_string(),
            ))
        }
        fn get(&self, _url: &str, _t: Duration) -> Result<u16, String> {
            Ok(200)
        }
    }

    struct FailTransport;
    impl HttpTransport for FailTransport {
        fn post(&self, _url: &str, _body: &str, _t: Duration) -> Result<(u16, String), String> {
            Err("connection refused".to_string())
        }
        fn get(&self, _url: &str, _t: Duration) -> Result<u16, String> {
            Err("connection refused".to_string())
        }
    }

    fn req() -> InspectRequest {
        InspectRequest {
            method: "GET".into(),
            path: "/".into(),
            ..Default::default()
        }
    }

    #[test]
    fn successful_inspect_parses_result() {
        let c = Client::with_transport("http://ml", 5, 2, "allow", Arc::new(OkTransport));
        let (res, err) = c.inspect(&req());
        assert!(err.is_none());
        assert!(res.is_anomaly);
        assert_eq!(res.risk_score, 80);
    }

    #[test]
    fn failure_returns_fallback_allow() {
        let c = Client::with_transport("http://ml", 5, 0, "allow", Arc::new(FailTransport));
        let (res, err) = c.inspect(&req());
        assert!(err.is_some());
        assert!(!res.is_anomaly);
        assert_eq!(res.risk_score, 0);
    }

    #[test]
    fn failure_fallback_block_mode() {
        let c = Client::with_transport("http://ml", 5, 0, "block", Arc::new(FailTransport));
        let (res, _) = c.inspect(&req());
        assert!(res.is_anomaly);
        assert_eq!(res.risk_score, 100);
    }

    #[test]
    fn failure_fallback_monitor_mode() {
        let c = Client::with_transport("http://ml", 5, 0, "monitor", Arc::new(FailTransport));
        let (res, _) = c.inspect(&req());
        assert_eq!(res.risk_score, 50);
    }

    #[test]
    fn circuit_opens_after_threshold() {
        let c = Client::with_transport("http://ml", 5, 0, "allow", Arc::new(FailTransport));
        // Threshold is 5; after 5 failures the breaker opens.
        for _ in 0..5 {
            let _ = c.inspect(&req());
        }
        let (_, err) = c.inspect(&req());
        assert_eq!(err.as_deref(), Some("ml client unavailable"));
    }

    #[test]
    fn set_available_false_short_circuits() {
        let c = Client::with_transport("http://ml", 5, 0, "allow", Arc::new(OkTransport));
        c.set_available(false);
        let (_, err) = c.inspect(&req());
        assert_eq!(err.as_deref(), Some("ml client unavailable"));
    }

    #[test]
    fn health_check_ok() {
        let c = Client::with_transport("http://ml", 5, 0, "allow", Arc::new(OkTransport));
        assert!(c.health_check().is_ok());
    }

    #[test]
    fn inspect_request_flattens_query_and_limits_body() {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "curl".to_string());
        headers.insert(
            "X-Forwarded-For".to_string(),
            "9.9.9.9, 10.0.0.1".to_string(),
        );
        let mut q = HashMap::new();
        q.insert("a".to_string(), vec!["1".to_string(), "2".to_string()]);
        let req = inspect_request_from_parts("POST", "/x", &headers, b"hello", &q, "10.0.0.5:1234");
        assert_eq!(req.query_params.get("a"), Some(&"1,2".to_string()));
        assert_eq!(req.source_ip, "9.9.9.9");
        assert_eq!(req.body, "hello");
    }
}
