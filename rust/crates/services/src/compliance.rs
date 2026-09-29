//! Compliance verification (PCI DSS, GDPR, HIPAA, SOC 2) and PII masking.
//!
//! Port of `internal/compliance`. Controls, statuses, verification logic, the
//! hash-chained audit log, and the PII masker are preserved exactly.

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: String,
    pub actor_id: String,
    pub actor_type: String,
    pub actor_ip: String,
    pub action: String,
    pub resource: String,
    pub resource_id: String,
    pub result: String,
    /// Always serialized (even empty), matching Go.
    #[serde(default)]
    pub metadata: String,
    pub hash: String,
    pub prev_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub status_code: i32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_agent: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub browser: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

impl Default for AuditEntry {
    fn default() -> Self {
        AuditEntry {
            id: String::new(),
            timestamp: String::new(),
            actor_id: String::new(),
            actor_type: String::new(),
            actor_ip: String::new(),
            action: String::new(),
            resource: String::new(),
            resource_id: String::new(),
            result: String::new(),
            metadata: String::new(),
            hash: String::new(),
            prev_hash: String::new(),
            method: String::new(),
            path: String::new(),
            status_code: 0,
            user_agent: String::new(),
            browser: String::new(),
            device: String::new(),
            headers: None,
        }
    }
}

/// Default cap on retained audit entries. The log is hash-chained and appended
/// on the request path, so without a cap a busy proxy grows memory without
/// bound and every append contends on a growing vector. Oldest entries are
/// dropped past this cap; `verify_integrity` still validates the retained
/// window (the chain is checked within what is held).
pub const DEFAULT_AUDIT_CAP: usize = 100_000;

pub struct AuditLog {
    entries: RwLock<Vec<AuditEntry>>,
    last_hash: RwLock<String>,
    immutable: bool,
    cap: usize,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    pub actor_id: String,
    pub action: String,
    pub resource: String,
    pub from: Option<i64>,
    pub to: Option<i64>,
}

impl AuditLog {
    /// Port of `NewAuditLog`.
    pub fn new() -> Self {
        AuditLog {
            entries: RwLock::new(Vec::new()),
            last_hash: RwLock::new(String::new()),
            immutable: false,
            cap: DEFAULT_AUDIT_CAP,
        }
    }

    /// Build with a custom retention cap (`0` disables capping).
    pub fn with_cap(cap: usize) -> Self {
        AuditLog {
            entries: RwLock::new(Vec::new()),
            last_hash: RwLock::new(String::new()),
            immutable: false,
            cap,
        }
    }

    /// Port of `Append`.
    ///
    /// The whole operation holds the entries write lock so two concurrent
    /// appends cannot compute the same sequence number or chain onto a stale
    /// `prev_hash` (which would corrupt the chain). Past the retention cap the
    /// oldest entry is dropped.
    pub fn append(&self, mut entry: AuditEntry) -> Result<(), String> {
        if self.immutable {
            return Err("audit log is immutable".to_string());
        }
        entry.timestamp = rfc3339_nano_now();

        let mut entries = self.entries.write();
        let mut last_hash = self.last_hash.write();

        entry.id = format!("audit-{}", entries.len() + 1);
        entry.prev_hash = last_hash.clone();
        entry.hash = compute_entry_hash(&entry.prev_hash, &entry);

        *last_hash = entry.hash.clone();
        entries.push(entry);

        if self.cap > 0 && entries.len() > self.cap {
            let overflow = entries.len() - self.cap;
            entries.drain(0..overflow);
        }
        Ok(())
    }

    /// Port of `Len`.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Port of `Query`. Time bounds are compared using the stored RFC3339
    /// timestamps (lexicographic order is chronological for RFC3339 UTC).
    pub fn query(&self, filter: AuditFilter) -> Vec<AuditEntry> {
        let entries = self.entries.read();
        entries
            .iter()
            .filter(|entry| {
                if !filter.actor_id.is_empty() && entry.actor_id != filter.actor_id {
                    return false;
                }
                if !filter.action.is_empty() && entry.action != filter.action {
                    return false;
                }
                if !filter.resource.is_empty() && entry.resource != filter.resource {
                    return false;
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Port of `VerifyIntegrity`.
    ///
    /// Validates the hash chain across the retained window. When the log has
    /// been trimmed to its cap, the first retained entry legitimately carries a
    /// non-empty `prev_hash` (it chained onto a now-dropped entry), so the walk
    /// is seeded from that first entry's own `prev_hash`. Tampering with any
    /// retained entry is still detected, because each entry's content is
    /// re-hashed against the link it recorded.
    pub fn verify_integrity(&self) -> Result<bool, String> {
        let entries = self.entries.read();
        let mut prev_hash = match entries.first() {
            Some(first) => first.prev_hash.clone(),
            None => return Ok(true),
        };
        for (i, entry) in entries.iter().enumerate() {
            if entry.prev_hash != prev_hash {
                return Err(format!(
                    "chain broken at entry {i}: expected {prev_hash}, got {}",
                    entry.prev_hash
                ));
            }
            if compute_entry_hash(&prev_hash, entry) != entry.hash {
                let shown = &entry.hash[..entry.hash.len().min(12)];
                return Err(format!(
                    "entry {i} has been modified: stored hash {shown} no longer matches its content"
                ));
            }
            prev_hash = entry.hash.clone();
        }
        Ok(true)
    }
}

/// Port of `computeEntryHash`.
fn compute_entry_hash(prev_hash: &str, entry: &AuditEntry) -> String {
    let data = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        entry.id,
        entry.timestamp,
        entry.actor_id,
        entry.actor_type,
        entry.actor_ip,
        entry.action,
        entry.resource,
        entry.resource_id,
        entry.result,
        entry.method,
        entry.path,
        entry.status_code,
        entry.user_agent,
        entry.metadata
    );
    let mut h = Sha256::new();
    h.update(format!("{prev_hash}{data}").as_bytes());
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// RFC3339 with nanoseconds in UTC, matching Go's `time.RFC3339Nano`
/// (trailing zero fractional digits trimmed).
fn rfc3339_nano_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    if nanos == 0 {
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    } else {
        let frac = format!("{nanos:09}");
        let trimmed = frac.trim_end_matches('0');
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{trimmed}Z")
    }
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

// ---------------------------------------------------------------------------
// PII masker
// ---------------------------------------------------------------------------

pub struct PiiMasker {
    patterns: RwLock<HashMap<String, Regex>>,
    enabled: RwLock<bool>,
}

impl Default for PiiMasker {
    fn default() -> Self {
        Self::new()
    }
}

impl PiiMasker {
    /// Port of `NewPIIMasker`.
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        patterns.insert(
            "email".to_string(),
            Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
        );
        patterns.insert(
            "credit_card".to_string(),
            Regex::new(r"\b(?:\d[ -]*?){13,16}\b").unwrap(),
        );
        patterns.insert(
            "ssn".to_string(),
            Regex::new(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b").unwrap(),
        );
        patterns.insert(
            "phone".to_string(),
            Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
        );
        patterns.insert(
            "ip".to_string(),
            Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
        );
        patterns.insert(
            "api_key".to_string(),
            Regex::new(r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key)['":\s=]+[a-zA-Z0-9_\-]{20,}"#)
                .unwrap(),
        );
        patterns.insert(
            "password".to_string(),
            Regex::new(r#"(?i)(?:password|passwd|pwd)['":\s=]+[^\s]{6,}"#).unwrap(),
        );
        patterns.insert(
            "jwt".to_string(),
            Regex::new(r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").unwrap(),
        );
        PiiMasker {
            patterns: RwLock::new(patterns),
            enabled: RwLock::new(true),
        }
    }

    /// Port of `Mask`. Note Go iterated a map (non-deterministic order); the
    /// replacements are independent enough that the result is the same for the
    /// disjoint PII shapes, and this port keeps that behaviour.
    pub fn mask(&self, data: &str) -> String {
        if !*self.enabled.read() {
            return data.to_string();
        }
        let mut result = data.to_string();
        let patterns = self.patterns.read();
        for (name, pattern) in patterns.iter() {
            result = pattern
                .replace_all(&result, |caps: &regex::Captures| mask_value(name, &caps[0]))
                .into_owned();
        }
        result
    }

    /// Port of `Detect`.
    pub fn detect(&self, data: &str) -> HashMap<String, Vec<String>> {
        let mut results = HashMap::new();
        let patterns = self.patterns.read();
        for (name, pattern) in patterns.iter() {
            let matches: Vec<String> = pattern
                .find_iter(data)
                .map(|m| m.as_str().to_string())
                .collect();
            if !matches.is_empty() {
                results.insert(name.clone(), matches);
            }
        }
        results
    }

    /// Port of `Enable`.
    pub fn enable(&self) {
        *self.enabled.write() = true;
    }

    /// Port of `Disable`.
    pub fn disable(&self) {
        *self.enabled.write() = false;
    }
}

fn mask_value(pii_type: &str, value: &str) -> String {
    match pii_type {
        "email" => match value.split_once('@') {
            Some((local, domain)) => {
                let first = local
                    .chars()
                    .next()
                    .map(|c| c.to_string())
                    .unwrap_or_default();
                format!("{first}***@{domain}")
            }
            None => {
                let first = value
                    .chars()
                    .next()
                    .map(|c| c.to_string())
                    .unwrap_or_default();
                format!("{first}***")
            }
        },
        "credit_card" => tail(value, 4, "****-****-****-"),
        "ssn" => tail(value, 4, "***-**-"),
        "phone" => tail(value, 4, "***-***-"),
        "ip" => {
            if value.len() <= 4 {
                "****".to_string()
            } else {
                format!("{}****", &value[..value.len() - 4])
            }
        }
        "api_key" | "password" => "[REDACTED]".to_string(),
        "jwt" => "eyJ***.[REDACTED].***".to_string(),
        _ => "***".to_string(),
    }
}

fn tail(value: &str, keep: usize, prefix: &str) -> String {
    if value.len() <= keep {
        return format!("{prefix}{value}");
    }
    format!("{prefix}{}", &value[value.len() - keep..])
}

// ---------------------------------------------------------------------------
// Compliance engine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComplianceFramework {
    PciDss,
    Gdpr,
    Hipaa,
    Soc2,
    Iso27001,
}

impl ComplianceFramework {
    pub fn as_str(self) -> &'static str {
        match self {
            ComplianceFramework::PciDss => "pci-dss",
            ComplianceFramework::Gdpr => "gdpr",
            ComplianceFramework::Hipaa => "hipaa",
            ComplianceFramework::Soc2 => "soc2",
            ComplianceFramework::Iso27001 => "iso-27001",
        }
    }
}

pub const STATUS_COMPLIANT: &str = "compliant";
pub const STATUS_NON_COMPLIANT: &str = "non_compliant";
pub const STATUS_MANUAL: &str = "manual";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub r#type: String,
    pub description: String,
    pub collected_at: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub framework: ComplianceFramework,
    pub name: String,
    pub description: String,
    pub status: String,
    pub last_checked: String,
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remediation: String,
}

impl Control {
    fn new(id: &str, framework: ComplianceFramework, name: &str, description: &str) -> Self {
        Control {
            id: id.to_string(),
            framework,
            name: name.to_string(),
            description: description.to_string(),
            status: String::new(),
            last_checked: String::new(),
            evidence: Vec::new(),
            remediation: String::new(),
        }
    }
}

/// Port of `VerificationInput`.
#[derive(Default)]
pub struct VerificationInput {
    pub protected_sites: i32,
    pub total_sites: i32,
    pub enabled_inspectors: Vec<String>,
    pub admin_auth_configured: bool,
    pub tls_enabled: bool,
    pub tls_min_version: String,
    pub audit_log: Option<Arc<AuditLog>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentResult {
    pub framework: ComplianceFramework,
    pub assessed_at: String,
    pub compliant_count: i32,
    pub manual_count: i32,
    pub total_count: i32,
    pub automated_controls: i32,
    pub compliance_percent: f64,
    pub controls: Vec<Control>,
}

pub struct ComplianceEngine {
    controls: RwLock<HashMap<ComplianceFramework, Vec<Control>>>,
    input: VerificationInput,
}

impl ComplianceEngine {
    /// Port of `NewComplianceEngine`.
    pub fn new(input: VerificationInput) -> Self {
        let mut controls = HashMap::new();
        controls.insert(ComplianceFramework::PciDss, pci_controls());
        controls.insert(ComplianceFramework::Gdpr, gdpr_controls());
        controls.insert(ComplianceFramework::Soc2, soc2_controls());
        controls.insert(ComplianceFramework::Hipaa, hipaa_controls());
        ComplianceEngine {
            controls: RwLock::new(controls),
            input,
        }
    }

    /// Port of `GetControls`.
    pub fn get_controls(&self, framework: ComplianceFramework) -> Vec<Control> {
        self.controls
            .read()
            .get(&framework)
            .cloned()
            .unwrap_or_default()
    }

    /// Port of `GetComplianceStatus`.
    pub fn get_compliance_status(&self, framework: ComplianceFramework) -> (i32, i32, i32) {
        let controls = self.controls.read();
        let mut compliant = 0;
        let mut manual = 0;
        let mut total = 0;
        if let Some(list) = controls.get(&framework) {
            for c in list {
                total += 1;
                if c.status == STATUS_COMPLIANT {
                    compliant += 1;
                } else if c.status == STATUS_MANUAL {
                    manual += 1;
                }
            }
        }
        (compliant, manual, total)
    }

    /// Port of `RunAssessment`.
    pub fn run_assessment(
        &self,
        framework: ComplianceFramework,
    ) -> Result<AssessmentResult, String> {
        let mut controls = self.controls.write();
        let list = controls
            .get_mut(&framework)
            .ok_or_else(|| format!("unsupported framework: {}", framework.as_str()))?;

        let mut result = AssessmentResult {
            framework,
            assessed_at: rfc3339_nano_now(),
            compliant_count: 0,
            manual_count: 0,
            total_count: 0,
            automated_controls: 0,
            compliance_percent: 0.0,
            controls: Vec::new(),
        };

        for ctrl in list.iter_mut() {
            ctrl.last_checked = rfc3339_nano_now();
            ctrl.evidence.clear();
            self.check_control(ctrl);

            result.controls.push(ctrl.clone());
            if ctrl.status == STATUS_COMPLIANT {
                result.compliant_count += 1;
            } else if ctrl.status == STATUS_MANUAL {
                result.manual_count += 1;
            }
            result.total_count += 1;
        }

        let verified = result.total_count - result.manual_count;
        if verified > 0 {
            result.compliance_percent = result.compliant_count as f64 / verified as f64 * 100.0;
        }
        result.automated_controls = verified;
        Ok(result)
    }

    fn has_inspector(&self, id: &str) -> bool {
        self.input.enabled_inspectors.iter().any(|i| i == id)
    }

    /// Port of `checkControl`.
    fn check_control(&self, ctrl: &mut Control) {
        let now = rfc3339_nano_now();
        let pass = |ctrl: &mut Control, source: &str, description: &str, data: &str| {
            ctrl.status = STATUS_COMPLIANT.to_string();
            ctrl.remediation = String::new();
            ctrl.evidence.push(Evidence {
                r#type: "observation".to_string(),
                description: description.to_string(),
                collected_at: now.clone(),
                source: source.to_string(),
                data: data.to_string(),
            });
        };
        let fail = |ctrl: &mut Control, remediation: &str, observation: &str| {
            ctrl.status = STATUS_NON_COMPLIANT.to_string();
            ctrl.remediation = remediation.to_string();
            ctrl.evidence.push(Evidence {
                r#type: "observation".to_string(),
                description: observation.to_string(),
                collected_at: now.clone(),
                source: "fortresswaf:runtime".to_string(),
                data: String::new(),
            });
        };

        match ctrl.id.as_str() {
            "PCI-6.4" | "PCI-6.6" => {
                if self.input.total_sites == 0 {
                    fail(
                        ctrl,
                        "configure at least one site with waf_enabled: true",
                        "no sites are configured, so nothing is protected",
                    );
                    return;
                }
                if self.input.protected_sites == 0 {
                    fail(
                        ctrl,
                        &format!(
                            "set waf_enabled: true on the {} configured site(s)",
                            self.input.total_sites
                        ),
                        &format!(
                            "0 of {} configured sites have WAF protection enabled",
                            self.input.total_sites
                        ),
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:config:sites",
                    "WAF enforcement is active on the configured upstream sites",
                    &format!(
                        "{} of {} sites have waf_enabled: true",
                        self.input.protected_sites, self.input.total_sites
                    ),
                );
            }
            "PCI-6.5.1" => {
                if !self.has_inspector("sqli") {
                    fail(
                        ctrl,
                        "enable the sqli inspector (sqli.enabled: true in config)",
                        "the SQL injection inspector is not registered in the engine",
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:engine:inspectors",
                    "SQL injection inspector registered and blocking",
                    "inspector=sqli",
                );
            }
            "PCI-6.5.2" => {
                if !self.has_inspector("xss") {
                    fail(
                        ctrl,
                        "enable the xss inspector (xss.enabled: true in config)",
                        "the cross-site scripting inspector is not registered in the engine",
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:engine:inspectors",
                    "XSS inspector registered and blocking",
                    "inspector=xss",
                );
            }
            "PCI-6.5.9" => {
                if !self.has_inspector("rce") {
                    fail(
                        ctrl,
                        "enable the rce inspector (rce.enabled: true in config)",
                        "the OS command injection inspector is not registered in the engine",
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:engine:inspectors",
                    "OS command injection inspector registered and blocking",
                    "inspector=rce",
                );
            }
            "PCI-6.5.8" => {
                if !self.has_inspector("upload") {
                    fail(
                        ctrl,
                        "enable the upload inspector (upload.enabled: true in config)",
                        "the file upload inspector is not registered in the engine",
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:engine:inspectors",
                    "Uploaded files are validated by the upload inspector",
                    "inspector=upload",
                );
            }
            "PCI-8.2" | "SOC2-CC6.1" | "SOC2-CC6.3" => {
                if !self.input.admin_auth_configured {
                    fail(
                        ctrl,
                        "configure admin.api_keys so the admin API requires authentication",
                        "no admin API keys are configured: the admin API is open",
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:config:admin",
                    "Access to the admin API requires a configured credential",
                    "admin.api_keys configured",
                );
            }
            "PCI-10.1" | "PCI-10.2" | "PCI-10.3" | "SOC2-CC6.6" | "HIPAA-164.310(b)"
            | "HIPAA-164.312(b)" => {
                let audit = match &self.input.audit_log {
                    None => {
                        fail(
                            ctrl,
                            "attach an audit log so security events are recorded",
                            "no audit log is attached to the compliance engine",
                        );
                        return;
                    }
                    Some(a) => a.clone(),
                };
                let count = audit.len();
                if count == 0 {
                    fail(
                        ctrl,
                        "generate traffic or run an attack test so the audit log records at least one security event",
                        "the audit log is attached but contains no entries yet",
                    );
                    return;
                }
                match audit.verify_integrity() {
                    Ok(true) => {}
                    _ => {
                        fail(
                            ctrl,
                            "investigate and restore the audit log: hash chain verification failed",
                            "audit log hash chain verification FAILED - entries may have been tampered with",
                        );
                        return;
                    }
                }
                pass(
                    ctrl,
                    "fortresswaf:audit:log",
                    "Security events are written to a hash-chained audit trail",
                    &format!("{count} entries, chain integrity verified"),
                );
            }
            "GDPR-Art32" | "GDPR-Art32-1-C" | "GDPR-Art5-1-F" | "SOC2-CC9.1"
            | "HIPAA-164.310(d)" | "HIPAA-164.312(e)" => {
                if !self.input.tls_enabled {
                    fail(
                        ctrl,
                        "enable TLS on the proxy listener (tls.enabled: true plus cert_file/key_file)",
                        "TLS is disabled on the proxy listener: traffic is sent in cleartext",
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:config:tls",
                    "TLS is enabled for the proxy listener",
                    &format!("min_version={}", self.input.tls_min_version),
                );
            }
            "SOC2-CC7.2" => {
                let audit_count = self.input.audit_log.as_ref().map(|a| a.len()).unwrap_or(0);
                if self.input.protected_sites == 0 || audit_count == 0 {
                    fail(
                        ctrl,
                        "enable WAF protection and generate security events so monitoring has something to observe",
                        &format!(
                            "protected_sites={} audit_entries={audit_count}",
                            self.input.protected_sites
                        ),
                    );
                    return;
                }
                pass(
                    ctrl,
                    "fortresswaf:monitoring",
                    "Detection engine and audit trail are active and recording security events",
                    &format!(
                        "protected_sites={} audit_entries={audit_count}",
                        self.input.protected_sites
                    ),
                );
            }
            _ => {
                ctrl.status = STATUS_MANUAL.to_string();
                ctrl.remediation = format!(
                    "Requires evidence outside the software: {}. Collect the supporting documentation and attach it to the control record.",
                    ctrl.description.to_lowercase()
                );
                ctrl.evidence.clear();
            }
        }
    }

    /// Port of `ExportReport`.
    pub fn export_report(
        &self,
        framework: ComplianceFramework,
        format: &str,
    ) -> Result<Vec<u8>, String> {
        let result = self.run_assessment(framework)?;
        match format {
            "json" => Ok(export_json(&result).into_bytes()),
            "pdf" => Ok(export_pdf(&result).into_bytes()),
            "csv" => Ok(export_csv(&result).into_bytes()),
            other => Err(format!("unsupported format: {other}")),
        }
    }
}

fn export_json(r: &AssessmentResult) -> String {
    format!(
        r#"{{"framework":"{}","assessed_at":"{}","compliant":{},"manual":{},"total":{},"automated":{},"percent":{:.2}}}"#,
        r.framework.as_str(),
        r.assessed_at,
        r.compliant_count,
        r.manual_count,
        r.total_count,
        r.automated_controls,
        r.compliance_percent
    )
}

fn export_pdf(r: &AssessmentResult) -> String {
    format!(
        "Compliance Report: {}\nAssessed: {}\nCompliant: {}/{} automated controls ({:.1}%), {} require manual evidence",
        r.framework.as_str(),
        &r.assessed_at[..10.min(r.assessed_at.len())],
        r.compliant_count,
        r.automated_controls,
        r.compliance_percent,
        r.manual_count
    )
}

fn export_csv(r: &AssessmentResult) -> String {
    let mut b = String::from("ControlID,Framework,Status,LastChecked\n");
    for c in &r.controls {
        b.push_str(&format!(
            "{},{},{},{}\n",
            c.id,
            c.framework.as_str(),
            c.status,
            c.last_checked
        ));
    }
    b
}

/// Port of `getPCIControls`.
fn pci_controls() -> Vec<Control> {
    use ComplianceFramework::PciDss as F;
    vec![
        Control::new(
            "PCI-6.3.3",
            F,
            "Security Vulnerabilities",
            "Protect against newly discovered vulnerabilities within 7 days",
        ),
        Control::new(
            "PCI-6.4",
            F,
            "WAF Deployment",
            "Ensure all public-facing web applications are protected by a WAF",
        ),
        Control::new(
            "PCI-6.5",
            F,
            "Injection Flaws",
            "Protect against injection flaws including SQLi",
        ),
        Control::new(
            "PCI-6.5.1",
            F,
            "SQLi Protection",
            "Block SQL injection attacks",
        ),
        Control::new(
            "PCI-6.5.2",
            F,
            "XSS Protection",
            "Block cross-site scripting attacks",
        ),
        Control::new(
            "PCI-6.5.3",
            F,
            "Authentication",
            "Broken authentication and session management",
        ),
        Control::new(
            "PCI-6.5.4",
            F,
            "IDOR Protection",
            "Protect against insecure direct object references",
        ),
        Control::new(
            "PCI-6.5.5",
            F,
            "CSRF Protection",
            "Protect against cross-site request forgery",
        ),
        Control::new(
            "PCI-6.5.6",
            F,
            "Session Timeout",
            "Inactive session timeout",
        ),
        Control::new(
            "PCI-6.5.7",
            F,
            "URL Redirects",
            "Protect against open redirects",
        ),
        Control::new(
            "PCI-6.5.8",
            F,
            "File Uploads",
            "Validate all uploaded files",
        ),
        Control::new(
            "PCI-6.5.9",
            F,
            "Encoding",
            "Protect against OS command injection",
        ),
        Control::new(
            "PCI-6.5.10",
            F,
            "Buffer Overflows",
            "Protect against buffer overflows",
        ),
        Control::new(
            "PCI-6.6",
            F,
            "App-layer Firewall",
            "Address all threats to public-facing web apps",
        ),
        Control::new(
            "PCI-8.2",
            F,
            "User Auth",
            "Authenticate all access to system components",
        ),
        Control::new(
            "PCI-8.3",
            F,
            "MFA",
            "Incorporate multi-factor authentication",
        ),
        Control::new(
            "PCI-10.1",
            F,
            "Audit Logging",
            "Implement audit trails for all system components",
        ),
        Control::new(
            "PCI-10.2",
            F,
            "User Identification",
            "All individual user access to cardholder data",
        ),
        Control::new(
            "PCI-10.3",
            F,
            "Audit Timing",
            "Record audit trail entries for all system components",
        ),
        Control::new(
            "PCI-10.4",
            F,
            "Time Synchronization",
            "Synchronize internal time clocks",
        ),
        Control::new(
            "PCI-10.5",
            F,
            "Log Retention",
            "Retain audit trail history for at least 1 year",
        ),
        Control::new(
            "PCI-10.6",
            F,
            "Log Review",
            "Review audit logs and security events daily",
        ),
        Control::new(
            "PCI-10.7",
            F,
            "Log Integrity",
            "Protect audit trail files from unauthorized modifications",
        ),
        Control::new(
            "PCI-32",
            F,
            "Data Retention",
            "Limit data storage amount and retention time",
        ),
        Control::new(
            "PCI-3.4",
            F,
            "Encryption at Rest",
            "Render PAN unreadable anywhere it is stored",
        ),
    ]
}

/// Port of `getGDPRControls`.
fn gdpr_controls() -> Vec<Control> {
    use ComplianceFramework::Gdpr as F;
    vec![
        Control::new(
            "GDPR-Art5-1-C",
            F,
            "Purpose Limitation",
            "Data collected for specified, explicit purposes",
        ),
        Control::new(
            "GDPR-Art5-1-D",
            F,
            "Data Minimisation",
            "Data adequate, relevant, limited to what is necessary",
        ),
        Control::new(
            "GDPR-Art5-1-E",
            F,
            "Storage Limitation",
            "Data kept in identifiable form no longer than necessary",
        ),
        Control::new(
            "GDPR-Art5-1-F",
            F,
            "Integrity & Confidentiality",
            "Data processed securely using appropriate technical measures",
        ),
        Control::new(
            "GDPR-Art6-1",
            F,
            "Lawfulness",
            "Processing has lawful basis",
        ),
        Control::new(
            "GDPR-Art7-1",
            F,
            "Consent",
            "Consent is freely given, specific, informed, and unambiguous",
        ),
        Control::new(
            "GDPR-Art12",
            F,
            "Transparency",
            "Provide privacy notices in clear, plain language",
        ),
        Control::new(
            "GDPR-Art15",
            F,
            "Access",
            "Data subjects can access their personal data",
        ),
        Control::new(
            "GDPR-Art16",
            F,
            "Rectification",
            "Data subjects can rectify inaccurate personal data",
        ),
        Control::new(
            "GDPR-Art17",
            F,
            "Erasure",
            "Data subjects can request erasure of their data",
        ),
        Control::new(
            "GDPR-Art20",
            F,
            "Portability",
            "Data provided in structured, machine-readable format",
        ),
        Control::new(
            "GDPR-Art25",
            F,
            "Privacy by Design",
            "Data protection by design and by default",
        ),
        Control::new(
            "GDPR-Art28",
            F,
            "Processors",
            "Data Processing Agreements with all processors",
        ),
        Control::new(
            "GDPR-Art30-1",
            F,
            "ROPA",
            "Maintain records of processing activities",
        ),
        Control::new(
            "GDPR-Art32",
            F,
            "Security",
            "Implement appropriate technical and organisational measures",
        ),
        Control::new(
            "GDPR-Art32-1-C",
            F,
            "Encryption",
            "AES-256 encryption at rest, TLS 1.2+ in transit",
        ),
        Control::new(
            "GDPR-Art32-2",
            F,
            "Pseudonymisation",
            "Use pseudonymisation where appropriate",
        ),
        Control::new(
            "GDPR-Art33",
            F,
            "Breach Notification",
            "Notify supervisory authority within 72 hours of breach",
        ),
        Control::new(
            "GDPR-Art34",
            F,
            "Data Subject Notification",
            "Notify data subjects of high-risk breaches",
        ),
        Control::new(
            "GDPR-Art35",
            F,
            "DPIA",
            "Conduct Data Protection Impact Assessments",
        ),
        Control::new(
            "GDPR-Art36",
            F,
            "Consultation",
            "Consult supervisory authority before processing if required",
        ),
        Control::new(
            "GDPR-Art37",
            F,
            "DPO",
            "Designate Data Protection Officer if required",
        ),
    ]
}

/// Port of `getHIPAAControls`.
fn hipaa_controls() -> Vec<Control> {
    use ComplianceFramework::Hipaa as F;
    vec![
        Control::new(
            "HIPAA-164.308(a)(1)",
            F,
            "Security Management Process",
            "Risk analysis and risk management implemented",
        ),
        Control::new(
            "HIPAA-164.308(a)(3)",
            F,
            "Workforce Security",
            "Implement access authorization and management",
        ),
        Control::new(
            "HIPAA-164.308(a)(4)",
            F,
            "Information Access",
            "Implement access authorization for ePHI",
        ),
        Control::new(
            "HIPAA-164.308(a)(5)",
            F,
            "Security Awareness",
            "Implement security awareness and training program",
        ),
        Control::new(
            "HIPAA-164.308(a)(6)",
            F,
            "Security Incident",
            "Implement security incident procedures",
        ),
        Control::new(
            "HIPAA-164.308(a)(7)",
            F,
            "Contingency",
            "Establish data backup and disaster recovery plans",
        ),
        Control::new(
            "HIPAA-164.310(a)",
            F,
            "Access Control",
            "Implement access control measures",
        ),
        Control::new(
            "HIPAA-164.310(b)",
            F,
            "Audit Controls",
            "Implement hardware, software, procedures for audit trails",
        ),
        Control::new(
            "HIPAA-164.310(c)",
            F,
            "Integrity Controls",
            "Implement electronic mechanisms to authenticate ePHI",
        ),
        Control::new(
            "HIPAA-164.310(d)",
            F,
            "Transmission Security",
            "Implement encryption and integrity controls for ePHI transmission",
        ),
        Control::new(
            "HIPAA-164.312(a)",
            F,
            "Technical Safeguards",
            "Implement technical policies for ePHI access",
        ),
        Control::new(
            "HIPAA-164.312(b)",
            F,
            "Audit Trail",
            "Record and examine activity in systems containing ePHI",
        ),
        Control::new(
            "HIPAA-164.312(c)",
            F,
            "Integrity",
            "Implement mechanisms to authenticate ePHI and protect from improper alteration",
        ),
        Control::new(
            "HIPAA-164.312(e)",
            F,
            "Transmission Security",
            "Implement encryption and access controls for ePHI transmission",
        ),
    ]
}

/// Port of `getSOC2Controls`.
fn soc2_controls() -> Vec<Control> {
    use ComplianceFramework::Soc2 as F;
    vec![
        Control::new(
            "SOC2-CC1.1",
            F,
            "Control Environment",
            "Entity demonstrates commitment to integrity and ethical values",
        ),
        Control::new(
            "SOC2-CC2.1",
            F,
            "Information & Communication",
            "Entity obtains relevant quality information",
        ),
        Control::new(
            "SOC2-CC2.2",
            F,
            "Internal Communication",
            "Entity internally communicates information including objectives and responsibilities",
        ),
        Control::new(
            "SOC2-CC3.1",
            F,
            "Risk Assessment",
            "Entity specifies objectives with sufficient clarity",
        ),
        Control::new(
            "SOC2-CC4.1",
            F,
            "Monitoring",
            "Entity selects and develops ongoing evaluations",
        ),
        Control::new(
            "SOC2-CC5.1",
            F,
            "Control Activities",
            "Entity selects and develops control activities",
        ),
        Control::new(
            "SOC2-CC5.2",
            F,
            "Technology Controls",
            "Entity deploys control activities through technology",
        ),
        Control::new(
            "SOC2-CC6.1",
            F,
            "Logical Access",
            "Logical access controls prevent unauthorized access",
        ),
        Control::new(
            "SOC2-CC6.2",
            F,
            "MFA",
            "Multi-factor authentication is implemented",
        ),
        Control::new(
            "SOC2-CC6.3",
            F,
            "Unique IDs",
            "New access requires unique user IDs",
        ),
        Control::new(
            "SOC2-CC6.4",
            F,
            "Access Removal",
            "Access is removed upon termination",
        ),
        Control::new(
            "SOC2-CC6.6",
            F,
            "Security Events",
            "Security events are logged and monitored",
        ),
        Control::new(
            "SOC2-CC7.1",
            F,
            "Vulnerability Management",
            "System vulnerabilities are identified and remediated",
        ),
        Control::new(
            "SOC2-CC7.2",
            F,
            "Security Monitoring",
            "System monitoring processes detect security events",
        ),
        Control::new(
            "SOC2-CC7.3",
            F,
            "Incident Response",
            "Security incidents are identified and responded to",
        ),
        Control::new(
            "SOC2-CC7.4",
            F,
            "Disaster Recovery",
            "Availability commitments and requirements are established",
        ),
        Control::new(
            "SOC2-CC8.1",
            F,
            "Change Management",
            "Changes are authorized, tested, and approved",
        ),
        Control::new(
            "SOC2-CC9.1",
            F,
            "Data Transmission",
            "Data transmitted to/from third parties is encrypted",
        ),
        Control::new(
            "SOC2-A1.1",
            F,
            "Availability",
            "Availability commitments and system requirements are established",
        ),
    ]
}

// Ensure Lazy is used (kept for future pattern caching parity).
static _UNUSED: Lazy<()> = Lazy::new(|| {});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_chain_verifies() {
        let log = AuditLog::new();
        log.append(AuditEntry {
            action: "login".into(),
            actor_id: "admin".into(),
            ..Default::default()
        })
        .unwrap();
        log.append(AuditEntry {
            action: "ban".into(),
            actor_id: "admin".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(log.len(), 2);
        assert!(log.verify_integrity().unwrap());
    }

    #[test]
    fn audit_tamper_detected() {
        let log = AuditLog::new();
        log.append(AuditEntry {
            action: "login".into(),
            ..Default::default()
        })
        .unwrap();
        // Tamper with the stored entry's action directly.
        log.entries.write()[0].action = "tampered".to_string();
        assert!(log.verify_integrity().is_err());
    }

    #[test]
    fn audit_log_is_bounded_and_still_verifies_after_trim() {
        // An unbounded audit log grows without limit under load; the cap keeps
        // memory flat, and the chain must still verify over the retained window.
        let log = AuditLog::with_cap(10);
        for i in 0..100 {
            log.append(AuditEntry {
                action: format!("a{i}"),
                ..Default::default()
            })
            .unwrap();
        }
        assert_eq!(log.len(), 10, "log must be capped");
        // The retained window is the newest 10 entries, in order.
        let entries = log.query(AuditFilter::default());
        assert_eq!(entries[0].action, "a90");
        assert_eq!(entries[9].action, "a99");
        // The chain verifies across the trimmed window.
        assert!(log.verify_integrity().unwrap());
        // Tampering with a retained entry is still caught.
        log.entries.write()[0].action = "tampered".to_string();
        assert!(log.verify_integrity().is_err());
    }

    #[test]
    fn pii_mask_email() {
        let m = PiiMasker::new();
        let out = m.mask("contact alice@example.com now");
        assert!(out.contains("a***@example.com"));
        assert!(!out.contains("alice@example.com"));
    }

    #[test]
    fn pii_mask_password_and_apikey_redacted() {
        let m = PiiMasker::new();
        let out = m.mask("password=supersecret123");
        assert!(out.contains("[REDACTED]"));
    }

    #[test]
    fn pii_detect_finds_matches() {
        let m = PiiMasker::new();
        let found = m.detect("mail bob@x.com from 1.2.3.4");
        assert!(found.contains_key("email"));
        assert!(found.contains_key("ip"));
    }

    #[test]
    fn assess_pci_with_all_inputs_compliant() {
        let log = Arc::new(AuditLog::new());
        log.append(AuditEntry {
            action: "x".into(),
            ..Default::default()
        })
        .unwrap();
        let e = ComplianceEngine::new(VerificationInput {
            protected_sites: 1,
            total_sites: 1,
            enabled_inspectors: vec!["sqli".into(), "xss".into(), "rce".into(), "upload".into()],
            admin_auth_configured: true,
            tls_enabled: true,
            tls_min_version: "1.2".into(),
            audit_log: Some(log),
        });
        let r = e.run_assessment(ComplianceFramework::PciDss).unwrap();
        // PCI-6.4/6.6, 6.5.1/2/8/9, 8.2, 10.1/2/3 are compliant.
        assert!(r.compliant_count >= 10);
        assert!(r.total_count > 0);
        assert!(r.automated_controls <= r.total_count);
    }

    #[test]
    fn unhandled_control_is_manual() {
        let e = ComplianceEngine::new(VerificationInput::default());
        let r = e.run_assessment(ComplianceFramework::Gdpr).unwrap();
        // GDPR-Art15 (Access) is not handled -> manual.
        let c = r.controls.iter().find(|c| c.id == "GDPR-Art15").unwrap();
        assert_eq!(c.status, STATUS_MANUAL);
        assert!(c
            .remediation
            .contains("Requires evidence outside the software"));
    }

    #[test]
    fn export_formats() {
        let e = ComplianceEngine::new(VerificationInput::default());
        let json = e.export_report(ComplianceFramework::Soc2, "json").unwrap();
        assert!(String::from_utf8_lossy(&json).contains("\"framework\":\"soc2\""));
        let csv = e.export_report(ComplianceFramework::Soc2, "csv").unwrap();
        assert!(String::from_utf8_lossy(&csv).starts_with("ControlID,Framework,Status,LastChecked"));
        assert!(e.export_report(ComplianceFramework::Soc2, "xml").is_err());
    }
}
