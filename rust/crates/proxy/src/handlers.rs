//! Admin API handlers.
//!
//! Port of the handlers in `cmd/proxy/main.go` and `cmd/proxy/admin_extra.go`:
//! health/metrics/ready/live, status, config, reload, sites/rules/inspectors,
//! auth login/me, and the CORS + auth middleware. The handler bodies return a
//! `(status, content_type, body)` triple so they are testable without a server.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use fwaf_config::types::Config;
use fwaf_core::engine::Engine;
use fwaf_services::compliance::AuditLog;

/// A minimal response the handlers produce.
pub struct Reply {
    pub status: i32,
    pub content_type: String,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(status: i32, v: serde_json::Value) -> Self {
        Reply {
            status,
            content_type: "application/json".to_string(),
            body: serde_json::to_vec(&v).unwrap_or_default(),
        }
    }
    pub fn text(status: i32, content_type: &str, body: String) -> Self {
        Reply {
            status,
            content_type: content_type.to_string(),
            body: body.into_bytes(),
        }
    }
}

/// Server identity + start time, mirroring the Go build vars.
#[derive(Clone)]
pub struct ServerInfo {
    pub version: String,
    pub commit: String,
    pub build_date: String,
    pub started_at: Instant,
}

impl Default for ServerInfo {
    fn default() -> Self {
        ServerInfo {
            version: "dev".to_string(),
            commit: "unknown".to_string(),
            build_date: "unknown".to_string(),
            started_at: Instant::now(),
        }
    }
}

/// Port of `handleHealth`.
pub fn handle_health(info: &ServerInfo) -> Reply {
    Reply::json(
        200,
        serde_json::json!({
            "status": "healthy",
            "version": info.version,
            "commit": info.commit,
            "uptime": format!("{:?}", info.started_at.elapsed()),
            "timestamp": rfc3339_now(),
        }),
    )
}

/// Port of `handleMetrics` (Prometheus text exposition).
pub fn handle_metrics(info: &ServerInfo, m: &crate::pipeline::Metrics) -> Reply {
    let uptime = info.started_at.elapsed().as_secs_f64();
    let total = m.get(&m.total_requests);
    let rps = if uptime > 0.0 {
        total as f64 / uptime
    } else {
        0.0
    };
    let body = format!(
        "# HELP fortresswaf_requests_total Total number of requests\n\
# TYPE fortresswaf_requests_total counter\n\
fortresswaf_requests_total {}\n\
# HELP fortresswaf_requests_allowed Total allowed requests\n\
# TYPE fortresswaf_requests_allowed counter\n\
fortresswaf_requests_allowed {}\n\
# HELP fortresswaf_requests_blocked Total blocked requests\n\
# TYPE fortresswaf_requests_blocked counter\n\
fortresswaf_requests_blocked {}\n\
# HELP fortresswaf_requests_excluded Requests forwarded by an exclude_paths rule\n\
# TYPE fortresswaf_requests_excluded counter\n\
fortresswaf_requests_excluded {}\n\
# HELP fortresswaf_requests_challenged Total challenged requests\n\
# TYPE fortresswaf_requests_challenged counter\n\
fortresswaf_requests_challenged {}\n\
# HELP fortresswaf_requests_rate_limited Total rate-limited requests\n\
# TYPE fortresswaf_requests_rate_limited counter\n\
fortresswaf_requests_rate_limited {}\n\
# HELP fortresswaf_requests_monitored Total monitored requests\n\
# TYPE fortresswaf_requests_monitored counter\n\
fortresswaf_requests_monitored {}\n\
# HELP fortresswaf_active_connections Current active connections\n\
# TYPE fortresswaf_active_connections gauge\n\
fortresswaf_active_connections {}\n\
# HELP fortresswaf_uptime_seconds Uptime in seconds\n\
# TYPE fortresswaf_uptime_seconds gauge\n\
fortresswaf_uptime_seconds {}\n\
# HELP fortresswaf_requests_per_second Current requests per second\n\
# TYPE fortresswaf_requests_per_second gauge\n\
fortresswaf_requests_per_second {}\n\
# HELP fortresswaf_version_info FortressWAF version info\n\
# TYPE fortresswaf_version_info gauge\n\
fortresswaf_version_info{{version=\"{}\",commit=\"{}\"}} 1\n",
        total,
        m.get(&m.allowed_requests),
        m.get(&m.blocked_requests),
        m.get(&m.excluded_requests),
        m.get(&m.challenged_reqs),
        m.get(&m.rate_limited_reqs),
        m.get(&m.monitored_reqs),
        m.get(&m.active_conns),
        uptime,
        rps,
        info.version,
        info.commit,
    );
    Reply::text(200, "text/plain; version=0.0.4; charset=utf-8", body)
}

/// Port of `handleReady`.
pub fn handle_ready(cfg: &Config) -> Reply {
    if cfg.sites.is_empty() {
        return Reply::json(
            503,
            serde_json::json!({"status":"not_ready","reason":"no sites configured"}),
        );
    }
    Reply::json(200, serde_json::json!({"status":"ready"}))
}

/// Port of `handleLive`.
pub fn handle_live() -> Reply {
    Reply::json(200, serde_json::json!({"status":"alive"}))
}

/// Port of `handleStatus`.
pub fn handle_status(info: &ServerInfo, m: &crate::pipeline::Metrics) -> Reply {
    let uptime = info.started_at.elapsed();
    let secs = uptime.as_secs_f64();
    let rps = if secs > 0.0 {
        m.get(&m.total_requests) as f64 / secs
    } else {
        0.0
    };
    Reply::json(
        200,
        serde_json::json!({
            "version": info.version,
            "commit": info.commit,
            "build_date": info.build_date,
            "uptime": format!("{uptime:?}"),
            "uptime_seconds": secs as i64,
            "requests_per_sec": rps,
            "total_requests": m.get(&m.total_requests),
            "blocked_requests": m.get(&m.blocked_requests),
            "allowed_requests": m.get(&m.allowed_requests),
            "active_connections": m.get(&m.active_conns),
            "challenged": m.get(&m.challenged_reqs),
            "rate_limited": m.get(&m.rate_limited_reqs),
            "monitored": m.get(&m.monitored_reqs),
        }),
    )
}

/// Port of `handleGetConfig`.
pub fn handle_get_config(cfg: &Config) -> Reply {
    let sites: Vec<serde_json::Value> = cfg
        .sites
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "domains": s.domains,
                "upstream": s.upstream,
                "waf_enabled": s.waf_enabled,
            })
        })
        .collect();
    Reply::json(
        200,
        serde_json::json!({
            "sites_count": cfg.sites.len(),
            "rules_count": cfg.rules.len(),
            "ml_enabled": cfg.ml.enabled,
            "redis_enabled": cfg.redis.enabled,
            "admin_port": cfg.admin.port,
            "sites": sites,
        }),
    )
}

/// Port of `handleListSites`.
pub fn handle_list_sites(cfg: &Config) -> Reply {
    let sites: Vec<serde_json::Value> = cfg
        .sites
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "domains": s.domains,
                "upstream": s.upstream,
                "port": s.port,
                "tls": s.tls,
                "waf_enabled": s.waf_enabled,
            })
        })
        .collect();
    Reply::json(
        200,
        serde_json::json!({"sites": sites, "count": cfg.sites.len()}),
    )
}

/// Port of `handleListRules`.
pub fn handle_list_rules(cfg: &Config) -> Reply {
    let rules: Vec<serde_json::Value> = cfg
        .rules
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "enabled": r.enabled,
                "severity": r.severity,
                "action": r.action,
                "tags": r.tags,
            })
        })
        .collect();
    Reply::json(
        200,
        serde_json::json!({"rules": rules, "count": cfg.rules.len()}),
    )
}

/// Port of `handleListInspectors`: reports the engine's inspectors and how many
/// audit entries each is responsible for (attributed by rule-id prefix).
pub fn handle_list_inspectors(engine: &Engine, audit: Option<&Arc<AuditLog>>) -> Reply {
    let prefixes: &[(&str, &str)] = &[
        ("sqli", "SQLI"),
        ("xss", "XSS"),
        ("rce", "RCE"),
        ("ddos_protection", "DDoS"),
        ("protocol_anomaly", "PROT"),
        ("bot_detector", "BOT"),
        ("api_protection", "API"),
        ("file_upload", "UPL"),
        ("ja3", "JA3"),
        ("desync", "DSYNC"),
        ("parser_hardener", "PARSER_"),
        ("credential_protection", "CRED"),
        ("response_inspect", "LEAK"),
    ];

    let entries = audit
        .map(|a| a.query(Default::default()))
        .unwrap_or_default();

    let inspectors = engine.inspectors();
    let mut hits: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for ent in &entries {
        let mut rule_id = ent.metadata.clone();
        if let Some(i) = rule_id.find(':') {
            if i > 0 {
                rule_id = rule_id[..i].to_string();
            }
        }
        for ins in &inspectors {
            if let Some((_, prefix)) = prefixes.iter().find(|(n, _)| *n == ins.name()) {
                if rule_id.starts_with(prefix) {
                    *hits.entry(ins.name().to_string()).or_insert(0) += 1;
                    break;
                }
            }
        }
    }

    let out: Vec<serde_json::Value> = inspectors
        .iter()
        .map(|ins| {
            serde_json::json!({
                "name": ins.name(),
                "enabled": true,
                "hits": hits.get(ins.name()).copied().unwrap_or(0),
            })
        })
        .collect();

    Reply::json(
        200,
        serde_json::json!({"inspectors": out, "count": out.len()}),
    )
}

/// Port of `originAllowed`: an empty list grants nothing.
pub fn origin_allowed(origin: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| origin.eq_ignore_ascii_case(a))
}

/// Port of `validAPIKey` (constant-time comparison over the key list).
pub fn valid_api_key(key: &str, keys: &[String]) -> bool {
    if keys.is_empty() {
        return false;
    }
    let kb = key.as_bytes();
    let mut ok = false;
    for configured in keys {
        if constant_time_eq(kb, configured.as_bytes()) {
            ok = true;
        }
    }
    ok
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Port of `adminAuthMiddleware`. Returns `Some(reply)` when the request must be
/// rejected, `None` when it may proceed.
pub fn admin_auth_guard(auth_header: Option<&str>, keys: &[String]) -> Option<Reply> {
    if keys.is_empty() {
        return Some(Reply::json(
            503,
            serde_json::json!({
                "error": "admin credentials not configured",
                "detail": "set admin.api_keys in the config file",
            }),
        ));
    }
    let auth = match auth_header {
        Some(a) if !a.is_empty() => a,
        _ => {
            return Some(Reply::json(
                401,
                serde_json::json!({"error":"unauthorized","detail":"missing Authorization header"}),
            ))
        }
    };
    let token = match auth.strip_prefix("Bearer ") {
        Some(t) => t,
        None => {
            return Some(Reply::json(
                401,
                serde_json::json!({"error":"unauthorized","detail":"Authorization must be Bearer token"}),
            ))
        }
    };
    if !valid_api_key(token, keys) {
        return Some(Reply::json(
            403,
            serde_json::json!({"error":"forbidden","detail":"invalid API key"}),
        ));
    }
    None
}

/// Port of `handleAuthLogin` (the post-parse credential check).
pub fn login_check(email: &str, password: &str, keys: &[String]) -> (i32, serde_json::Value) {
    if keys.is_empty() {
        return (
            503,
            serde_json::json!({
                "error": "admin credentials not configured",
                "detail": "set admin.api_keys in the config file",
            }),
        );
    }

    let (valid_user, valid_pass) = if keys.len() >= 2 {
        (
            constant_time_eq(email.as_bytes(), keys[0].as_bytes()),
            constant_time_eq(password.as_bytes(), keys[1].as_bytes()),
        )
    } else {
        (
            constant_time_eq(email.as_bytes(), keys[0].as_bytes()),
            constant_time_eq(password.as_bytes(), keys[0].as_bytes()),
        )
    };

    if !valid_user || !valid_pass {
        return (401, serde_json::json!({"error":"invalid credentials"}));
    }

    let token = keys[0].clone();
    (
        200,
        serde_json::json!({
            "token": token,
            "user": {
                "id": email,
                "email": email,
                "name": email,
                "role": "admin",
            }
        }),
    )
}

/// Port of `handleAuthMe`.
pub fn handle_auth_me(auth_header: Option<&str>, keys: &[String]) -> Reply {
    let auth = auth_header.unwrap_or("");
    let token = match auth.strip_prefix("Bearer ") {
        Some(t) => t,
        None => {
            return Reply::json(401, serde_json::json!({"error":"unauthorized"}));
        }
    };
    if !valid_api_key(token, keys) {
        return Reply::json(401, serde_json::json!({"error":"unauthorized"}));
    }
    Reply::json(
        200,
        serde_json::json!({
            "id": token,
            "email": token,
            "name": "Admin",
            "role": "admin",
        }),
    )
}

fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
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
    if m <= 2 {
        (y + 1, m, d)
    } else {
        (y, m, d)
    }
}

// Keep the Ordering import meaningful (metrics use SeqCst in pipeline).
#[allow(dead_code)]
fn _ordering_ref(c: &AtomicI64) -> i64 {
    c.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_reports_healthy() {
        let r = handle_health(&ServerInfo::default());
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["status"], "healthy");
    }

    #[test]
    fn ready_fails_with_no_sites() {
        let cfg = Config::default();
        let r = handle_ready(&cfg);
        assert_eq!(r.status, 503);
    }

    #[test]
    fn metrics_contains_expected_series() {
        let m = crate::pipeline::Metrics::new();
        m.inc(&m.total_requests);
        let r = handle_metrics(&ServerInfo::default(), &m);
        let body = String::from_utf8_lossy(&r.body);
        assert!(body.contains("fortresswaf_requests_total 1"));
        assert!(body.contains("fortresswaf_version_info"));
    }

    #[test]
    fn auth_guard_fails_closed_without_keys() {
        let r = admin_auth_guard(Some("Bearer x"), &[]).unwrap();
        assert_eq!(r.status, 503);
    }

    #[test]
    fn auth_guard_rejects_non_bearer() {
        let keys = vec!["secret".to_string()];
        let r = admin_auth_guard(Some("secret"), &keys).unwrap();
        assert_eq!(r.status, 401);
    }

    #[test]
    fn auth_guard_accepts_valid_bearer() {
        let keys = vec!["secret".to_string()];
        assert!(admin_auth_guard(Some("Bearer secret"), &keys).is_none());
    }

    #[test]
    fn login_requires_both_fields_when_two_keys() {
        let keys = vec!["user".to_string(), "pass".to_string()];
        let (s1, _) = login_check("user", "pass", &keys);
        assert_eq!(s1, 200);
        let (s2, _) = login_check("user", "wrong", &keys);
        assert_eq!(s2, 401);
    }

    #[test]
    fn single_key_accepted_in_either_field() {
        let keys = vec!["demo".to_string()];
        assert_eq!(login_check("demo", "demo", &keys).0, 200);
        assert_eq!(login_check("demo", "wrong", &keys).0, 401);
    }

    #[test]
    fn origin_allowed_empty_denies_all() {
        assert!(!origin_allowed("https://x.com", &[]));
        assert!(origin_allowed(
            "https://x.com",
            &["https://x.com".to_string()]
        ));
    }
}
