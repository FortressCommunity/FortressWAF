//! SIEM export: Splunk HEC and Elasticsearch bulk, plus CEF formatting.
//!
//! Port of `internal/siem/siem.go`. The buffer/flush model, batch threshold,
//! exporter payload shapes and the CEF formatter are preserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

#[derive(Debug, Clone, Default)]
pub struct SiemConfig {
    pub enabled: bool,
    pub export_interval: Duration,
    pub batch_size: usize,
    pub exporters: Vec<ExporterConfig>,
}

#[derive(Debug, Clone, Default)]
pub struct ExporterConfig {
    pub r#type: String,
    pub enabled: bool,
    pub url: String,
    pub token: String,
    pub index: String,
    pub username: String,
    pub password: String,
    pub verify_ssl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub timestamp: i64,
    pub event_type: String,
    pub host: String,
    pub source: String,
    pub event_id: i32,
    pub name: String,
    pub severity: i32,
    pub src_ip: String,
    pub dst_ip: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub http_uri: String,
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        rename = "http_user_agent"
    )]
    pub user_agent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub attack_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule_id: String,
    pub threat_score: f64,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub country: String,
    #[serde(default, skip_serializing_if = "is_zero_f64", rename = "latency_ms")]
    pub latency: f64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw_event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

/// An event exporter.
pub trait Exporter: Send + Sync {
    fn send(&self, events: &[SiemEvent]) -> Result<(), String>;
    fn close(&self) -> Result<(), String>;
}

pub struct Manager {
    config: SiemConfig,
    exporters: Arc<RwLock<HashMap<String, Arc<dyn Exporter>>>>,
    buffer: Arc<Mutex<Vec<SiemEvent>>>,
    should_flush: Arc<Mutex<bool>>,
}

impl Manager {
    /// Port of `NewManager`. Unknown exporter types are skipped with a warning.
    /// An empty exporter set is allowed (warning only).
    pub fn new(cfg: SiemConfig) -> Self {
        let mut exporters: HashMap<String, Arc<dyn Exporter>> = HashMap::new();
        for ec in &cfg.exporters {
            if !ec.enabled {
                continue;
            }
            match ec.r#type.as_str() {
                "splunk" => {
                    exporters.insert(
                        ec.r#type.clone(),
                        Arc::new(SplunkExporter::new(ec.clone())) as Arc<dyn Exporter>,
                    );
                }
                "elasticsearch" => {
                    exporters.insert(
                        ec.r#type.clone(),
                        Arc::new(ElasticsearchExporter::new(ec.clone())) as Arc<dyn Exporter>,
                    );
                }
                other => {
                    warn!(r#type = other, "unknown SIEM exporter type");
                }
            }
        }
        if exporters.is_empty() {
            warn!("no SIEM exporters configured");
        }
        Manager {
            config: cfg,
            exporters: Arc::new(RwLock::new(exporters)),
            buffer: Arc::new(Mutex::new(Vec::new())),
            should_flush: Arc::new(Mutex::new(false)),
        }
    }

    /// Port of `Send`. Appends to the buffer and signals a flush when the batch
    /// threshold is reached.
    pub fn send(&self, event: SiemEvent) {
        let should = {
            let mut buf = self.buffer.lock();
            buf.push(event);
            buf.len() >= self.config.batch_size
        };
        if should {
            *self.should_flush.lock() = true;
        }
    }

    /// Port of `SendBatch`.
    pub fn send_batch(&self, events: &[SiemEvent]) {
        for e in events {
            self.send(e.clone());
        }
    }

    /// Port of `flush`: drain the buffer and hand it to every exporter.
    pub fn flush(&self) {
        let events = {
            let mut buf = self.buffer.lock();
            if buf.is_empty() {
                return;
            }
            std::mem::take(&mut *buf)
        };

        let exporters = self.exporters.read();
        for ex in exporters.values() {
            if let Err(e) = ex.send(&events) {
                error!(error = e.as_str(), "SIEM export failed");
            }
        }
    }

    /// Whether a flush has been requested (the Go `flushCh` signal).
    pub fn take_flush_signal(&self) -> bool {
        let mut f = self.should_flush.lock();
        let v = *f;
        *f = false;
        v
    }

    /// Port of `Close`.
    pub fn close(&self) {
        self.flush();
        let exporters = self.exporters.read();
        let mut errs: Vec<String> = Vec::new();
        for (name, ex) in exporters.iter() {
            if let Err(e) = ex.close() {
                errs.push(format!("{name}: {e}"));
            }
        }
        if !errs.is_empty() {
            error!(errors = errs.join(", ").as_str(), "SIEM close errors");
        }
    }

    /// Port of `Stats`.
    pub fn stats(&self) -> HashMap<String, i64> {
        let mut m = HashMap::new();
        m.insert("buffer_size".to_string(), self.buffer.lock().len() as i64);
        m.insert("exporters".to_string(), self.exporters.read().len() as i64);
        m
    }
}

/// Splunk HEC exporter. Port of `SplunkExporter`.
pub struct SplunkExporter {
    url: String,
    token: String,
    index: String,
    /// Retained for parity with the Go struct (`VerifySSL`); the real HTTP
    /// client's TLS verification is configured at the transport layer.
    #[allow(dead_code)]
    verify_ssl: bool,
    timeout: Duration,
}

impl SplunkExporter {
    pub fn new(cfg: ExporterConfig) -> Self {
        SplunkExporter {
            url: cfg.url,
            token: cfg.token,
            index: cfg.index,
            verify_ssl: cfg.verify_ssl,
            timeout: Duration::from_secs(30),
        }
    }

    /// Build the HEC payload (newline-delimited JSON). Exposed for testing the
    /// payload shape without network.
    pub fn build_payload(&self, events: &[SiemEvent]) -> String {
        let mut out = String::new();
        for event in events {
            let data = match serde_json::to_string(event) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let hec = serde_json::json!({
                "event": data,
                "host": event.host,
                "index": self.index,
                "time": event.timestamp as f64,
            });
            if let Ok(line) = serde_json::to_string(&hec) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

impl Exporter for SplunkExporter {
    fn send(&self, events: &[SiemEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let payload = self.build_payload(events);
        let resp = ureq::post(&self.url)
            .timeout(self.timeout)
            .set("Authorization", &format!("Splunk {}", self.token))
            .set("Content-Type", "application/json")
            .send_string(&payload)
            .map_err(|e| e.to_string())?;
        if resp.status() != 200 {
            return Err(format!("splunk returned {}", resp.status()));
        }
        Ok(())
    }

    fn close(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Elasticsearch bulk exporter. Port of `ElasticsearchExporter`.
pub struct ElasticsearchExporter {
    urls: Vec<String>,
    index: String,
    username: String,
    password: String,
    timeout: Duration,
}

impl ElasticsearchExporter {
    pub fn new(cfg: ExporterConfig) -> Self {
        ElasticsearchExporter {
            urls: cfg.url.split(',').map(|s| s.to_string()).collect(),
            index: cfg.index,
            username: cfg.username,
            password: cfg.password,
            timeout: Duration::from_secs(30),
        }
    }

    /// Build the NDJSON bulk payload. Exposed for testing.
    pub fn build_payload(&self, events: &[SiemEvent], date: &str) -> String {
        let index_name = format!("{}-{}", self.index, date);
        let mut out = String::new();
        for event in events {
            let meta = serde_json::json!({ "index": index_name });
            if let Ok(line) = serde_json::to_string(&meta) {
                out.push_str(&line);
                out.push('\n');
            }
            if let Ok(line) = serde_json::to_string(event) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

impl Exporter for ElasticsearchExporter {
    fn send(&self, events: &[SiemEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let date = yyyymmdd_now();
        let payload = self.build_payload(events, &date);
        let url = format!("{}/_bulk", self.urls[0]);
        let mut req = ureq::post(&url)
            .timeout(self.timeout)
            .set("Content-Type", "application/x-ndjson");
        if !self.username.is_empty() {
            let auth = base64_encode(&format!("{}:{}", self.username, self.password));
            req = req.set("Authorization", &format!("Basic {auth}"));
        }
        let resp = req.send_string(&payload).map_err(|e| e.to_string())?;
        let status = resp.status();
        if status != 200 {
            let body = resp.into_string().unwrap_or_default();
            return Err(format!("elasticsearch returned {status}: {body}"));
        }
        Ok(())
    }

    fn close(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Port of `FormatCEF`.
pub fn format_cef(event: &SiemEvent) -> String {
    let mut sb = String::new();
    sb.push_str(&format!(
        "CEF:{}|{}|{}|{}|{}|{}|{}",
        0,
        event.host,
        "FortressWAF",
        event.name,
        event.severity,
        event.name,
        format_cef_severity(event.severity)
    ));
    sb.push_str(&format!(" src={}", event.src_ip));
    sb.push_str(&format!(" dst={}", event.dst_ip));
    sb.push_str(&format!(" dpt={}", event.host));
    if !event.http_method.is_empty() {
        sb.push_str(&format!(" requestMethod={}", event.http_method));
    }
    if !event.http_uri.is_empty() {
        sb.push_str(&format!(" request={}", event.http_uri));
    }
    if !event.attack_type.is_empty() {
        sb.push_str(&format!(" attackType={}", event.attack_type));
    }
    if !event.rule_id.is_empty() {
        sb.push_str(&format!(" ruleId={}", event.rule_id));
    }
    sb
}

/// Port of `formatCEFSeverity`.
pub fn format_cef_severity(level: i32) -> &'static str {
    if level >= 8 {
        "Very High"
    } else if level >= 6 {
        "High"
    } else if level >= 4 {
        "Medium"
    } else if level >= 2 {
        "Low"
    } else {
        "Unknown"
    }
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn yyyymmdd_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}.{m:02}.{d:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev() -> SiemEvent {
        SiemEvent {
            timestamp: 1_700_000_000,
            event_type: "attack".into(),
            host: "srv1".into(),
            source: "proxy".into(),
            event_id: 1000,
            name: "SQL Injection".into(),
            severity: 9,
            src_ip: "1.2.3.4".into(),
            dst_ip: "10.0.0.1".into(),
            http_method: "GET".into(),
            http_uri: "/x?id=1".into(),
            user_agent: "curl".into(),
            attack_type: "sqli".into(),
            rule_id: "SQLI001".into(),
            threat_score: 90.0,
            blocked: true,
            country: "ID".into(),
            latency: 12.0,
            raw_event: String::new(),
            metadata: None,
        }
    }

    #[test]
    fn cef_format_shape() {
        let cef = format_cef(&ev());
        assert!(cef.starts_with("CEF:0|srv1|FortressWAF|SQL Injection|9|SQL Injection|Very High"));
        assert!(cef.contains(" src=1.2.3.4"));
        assert!(cef.contains(" requestMethod=GET"));
        assert!(cef.contains(" ruleId=SQLI001"));
    }

    #[test]
    fn cef_severity_mapping() {
        assert_eq!(format_cef_severity(10), "Very High");
        assert_eq!(format_cef_severity(7), "High");
        assert_eq!(format_cef_severity(5), "Medium");
        assert_eq!(format_cef_severity(3), "Low");
        assert_eq!(format_cef_severity(1), "Unknown");
    }

    #[test]
    fn splunk_payload_is_ndjson() {
        let s = SplunkExporter::new(ExporterConfig {
            url: "http://x".into(),
            token: "t".into(),
            index: "main".into(),
            ..Default::default()
        });
        let payload = s.build_payload(&[ev()]);
        let lines: Vec<&str> = payload.trim().lines().collect();
        assert_eq!(lines.len(), 1);
        let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v["index"], "main");
        assert_eq!(v["host"], "srv1");
    }

    #[test]
    fn elasticsearch_payload_is_bulk_pairs() {
        let e = ElasticsearchExporter::new(ExporterConfig {
            url: "http://es1,http://es2".into(),
            index: "fwaf".into(),
            ..Default::default()
        });
        let payload = e.build_payload(&[ev()], "2024.01.02");
        let lines: Vec<&str> = payload.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        let meta: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(meta["index"], "fwaf-2024.01.02");
    }

    #[test]
    fn manager_buffer_flush_threshold() {
        let cfg = SiemConfig {
            batch_size: 2,
            export_interval: Duration::from_secs(10),
            ..Default::default()
        };
        let m = Manager::new(cfg);
        m.send(ev());
        assert!(!m.take_flush_signal());
        m.send(ev());
        assert!(m.take_flush_signal());
        assert_eq!(m.stats().get("buffer_size"), Some(&2));
    }

    #[test]
    fn flush_clears_buffer_no_exporters() {
        let cfg = SiemConfig {
            batch_size: 100,
            ..Default::default()
        };
        let m = Manager::new(cfg);
        m.send(ev());
        m.flush();
        assert_eq!(m.stats().get("buffer_size"), Some(&0));
    }
}
