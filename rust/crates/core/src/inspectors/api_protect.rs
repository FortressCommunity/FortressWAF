//! API protection: sensitive paths, GraphQL/GRPC heuristics, XXE, shadow API.
//!
//! Port of `internal/engine/api_protect.go`. Rule IDs, scores and check order
//! are preserved exactly.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

struct Patterns {
    graphql: Vec<Regex>,
    sensitive_paths: Vec<Regex>,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let gq: Vec<Regex> = [
            r"(?i)query\s+\w+\s*\{",
            r"(?i)mutation\s+\w+\s*\{",
            r"(?i)subscription\s+\w+\s*\{",
            r"(?i)__schema\s*\{",
            r"(?i)__type\s*\{",
            r"(?i)introspection",
            r"(?i)__typename",
        ]
        .iter()
        .map(|r| Regex::new(r).unwrap())
        .collect();

        let sp: Vec<Regex> = [
            r"(?i)^/api/v?\d*/?$",
            r"(?i)(?:^|/)(?:swagger|openapi|api-docs)(?:/|$)",
            r"(?i)(?:^|/)docs(?:=.*)?(?:/|$)",
            r"(?i)(?:^|/)graphql(?:/|$)",
            r"(?i)(?:^|/)grpc(?:/|$)",
            r"(?i)(?:^|/)\.env(?:/|$)",
            r"(?i)(?:^|/)(?:config|debug|admin)(?:/|$)",
            r"(?i)(?:^|/)(?:actuator|info|metrics)(?:/|$)",
            r"(?i)(?:^|/)(?:wp-admin|wp-login|administrator|backup)(?:/|$)",
            r"(?i)(?:^|/)\.(?:git|svn|hg)(?:/|$)",
            r"(?:^|/)(?:\.)?\*(?:/|$)",
        ]
        .iter()
        .map(|r| Regex::new(r).unwrap())
        .collect();

        Patterns {
            graphql: gq,
            sensitive_paths: sp,
        }
    })
}

pub struct ApiProtection {
    pub dev_mode: bool,
    max_query_depth: usize,
    shadow_api_paths: Arc<Mutex<HashMap<String, i64>>>,
    open_api_specs: Arc<Mutex<HashMap<String, serde_json::Value>>>,
}

impl ApiProtection {
    pub fn new(dev_mode: bool) -> Self {
        let _ = patterns();
        ApiProtection {
            dev_mode,
            max_query_depth: 10,
            shadow_api_paths: Arc::new(Mutex::new(HashMap::new())),
            open_api_specs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn detect_owasp_top10(&self, ctx: &RequestContext) -> Option<Decision> {
        if ctx.method == "OPTIONS" && ctx.path == "/" {
            return Some(
                Decision::new(Action::Monitor, 30.0)
                    .with_rule_id("API001")
                    .with_rule_name("API Discovery Attempt")
                    .with_severity("medium")
                    .with_evidence(format!("OPTIONS / from {}", ctx.real_ip)),
            );
        }

        for pattern in &patterns().sensitive_paths {
            if pattern.is_match(&ctx.path) {
                return Some(
                    Decision::new(Action::Block, 70.0)
                        .with_rule_id("API002")
                        .with_rule_name("Sensitive API Path Access")
                        .with_severity("high")
                        .with_evidence(format!("sensitive path access: {}", ctx.path)),
                );
            }
        }

        let ct = ctx.headers.get("Content-Type").cloned().unwrap_or_default();
        if ct == "application/xml" || ct.contains("application/xml") {
            if !ctx.body.is_empty() && ctx.body.contains(&b'<') {
                let body_str = String::from_utf8_lossy(&ctx.body);
                if body_str.contains("<!ENTITY") || body_str.contains("<!DOCTYPE") {
                    return Some(
                        Decision::new(Action::Block, 90.0)
                            .with_rule_id("API003")
                            .with_rule_name("XXE Injection")
                            .with_severity("critical")
                            .with_evidence("XML external entity injection detected"),
                    );
                }
            }
        }

        if ctx
            .headers
            .get("Content-Length")
            .map(|v| v == "0")
            .unwrap_or(false)
            && ctx.method == "POST"
            && ctx.path.contains("/api/")
        {
            return Some(
                Decision::new(Action::Monitor, 10.0)
                    .with_rule_id("API004")
                    .with_rule_name("Empty POST to API")
                    .with_severity("low")
                    .with_evidence(format!("empty POST body to {}", ctx.path)),
            );
        }

        None
    }

    fn detect_graphql_abuse(&self, ctx: &RequestContext) -> Option<Decision> {
        // Go checked contains("graphql") || contains("gql") twice (a duplicate).
        if !ctx.path.contains("graphql") && !ctx.path.contains("gql") {
            return None;
        }

        let mut body_str = String::new();
        if !ctx.body.is_empty() {
            body_str = String::from_utf8_lossy(&ctx.body).into_owned();
        }

        for (k, v) in &ctx.query_params {
            body_str.push_str(k);
            body_str.push('=');
            body_str.push_str(&v.join(""));
            body_str.push(' ');
        }

        if body_str.contains("__schema")
            || body_str.contains("__type")
            || body_str.contains("introspection")
        {
            return Some(
                Decision::new(Action::Block, 70.0)
                    .with_rule_id("API005")
                    .with_rule_name("GraphQL Introspection Blocked")
                    .with_severity("high")
                    .with_evidence("graphql introspection query blocked"),
            );
        }

        if body_str.contains("__typename") {
            let has_depth = body_str.matches('{').count() > self.max_query_depth;
            if has_depth {
                return Some(
                    Decision::new(Action::Block, 65.0)
                        .with_rule_id("API006")
                        .with_rule_name("GraphQL Query Depth Exceeded")
                        .with_severity("high")
                        .with_evidence(format!(
                            "graphql query depth exceeds limit of {}",
                            self.max_query_depth
                        )),
                );
            }
        }

        for pattern in &patterns().graphql {
            if pattern.is_match(&body_str) {
                return Some(
                    Decision::new(Action::Monitor, 5.0)
                        .with_rule_id("API007")
                        .with_rule_name("GraphQL Query Detected")
                        .with_severity("low")
                        .with_evidence("graphql query detected"),
                );
            }
        }

        None
    }

    fn detect_grpc_attack(&self, ctx: &RequestContext) -> Option<Decision> {
        let ct = ctx.headers.get("Content-Type").cloned().unwrap_or_default();
        if ct == "application/grpc" || ct.starts_with("application/grpc") {
            if ct.contains("proto") {
                return Some(
                    Decision::new(Action::Monitor, 5.0)
                        .with_rule_id("API008")
                        .with_rule_name("gRPC Request")
                        .with_severity("low")
                        .with_evidence("gRPC request detected"),
                );
            }
        }
        None
    }

    fn detect_openapi_abuse(&self, ctx: &RequestContext) -> Option<Decision> {
        if ctx.path.ends_with('/') || ctx.path.ends_with('?') {
            return Some(
                Decision::new(Action::Monitor, 5.0)
                    .with_rule_id("API009")
                    .with_rule_name("OpenAPI Schema Violation")
                    .with_severity("low")
                    .with_evidence(format!("path format violation: {}", ctx.path)),
            );
        }
        None
    }

    fn detect_shadow_api(&self, ctx: &RequestContext) -> Option<Decision> {
        let path = &ctx.path;
        if path.starts_with("/api/") || path.starts_with("/v1/") || path.starts_with("/v2/") {
            let trimmed = path.trim_start_matches('/');
            let parts: Vec<&str> = trimmed.split('/').collect();
            if parts.len() >= 2 {
                let endpoint = format!("{}/{}", parts[0], parts[1]);

                let count = {
                    let mut map = self.shadow_api_paths.lock();
                    let c = map.entry(endpoint.clone()).or_insert(0);
                    *c += 1;
                    *c
                };

                if count < 2 {
                    // first_seen is always true here (count == 1), matching Go.
                    return Some(
                        Decision::new(Action::Monitor, 10.0)
                            .with_rule_id("API010")
                            .with_rule_name("Unknown API Endpoint")
                            .with_severity("low")
                            .with_evidence(format!("unknown API endpoint accessed: {endpoint}")),
                    );
                }
            }
        }
        None
    }

    /// Port of `LoadOpenAPISpec`.
    pub fn load_openapi_spec(&self, spec: HashMap<String, serde_json::Value>) {
        *self.open_api_specs.lock() = spec;
    }
}

impl Inspector for ApiProtection {
    fn name(&self) -> &str {
        "api_protection"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if let Some(dec) = self.detect_owasp_top10(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_graphql_abuse(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_grpc_attack(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_openapi_abuse(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_shadow_api(ctx) {
            return Ok(Some(dec));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn ap() -> ApiProtection {
        ApiProtection::new(false)
    }

    #[test]
    fn admin_path_blocked() {
        let p = ap();
        let r = HttpRequest::new("GET", "/admin/users");
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "API002");
    }

    #[test]
    fn administrator_tips_not_blocked() {
        // Regression: /blog/administrator-tips must not trip the admin rule.
        let p = ap();
        let r = HttpRequest::new("GET", "/blog/administrator-tips");
        let mut ctx = RequestContext::new(r);
        assert!(p.inspect(&mut ctx).unwrap().is_none());
    }

    #[test]
    fn environment_file_blocked() {
        let p = ap();
        let r = HttpRequest::new("GET", "/.env");
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "API002");
    }

    #[test]
    fn graphql_path_hits_sensitive_path_rule() {
        // NOTE (faithful): detectOWASPTop10 runs first and the sensitive-path
        // regex `(?:^|/)graphql(?:/|$)` matches /graphql, so API002 fires before
        // the introspection check (API005) can run. Go behaves identically.
        let p = ap();
        let mut r = HttpRequest::new("POST", "/graphql");
        r.body = b"query { __schema { types { name } } }".to_vec();
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "API002");
    }

    #[test]
    fn graphql_introspection_blocked_on_non_sensitive_path() {
        // On a path that is not itself a sensitive segment, the introspection
        // check runs and blocks with API005.
        let p = ap();
        let mut r = HttpRequest::new("POST", "/data/gqlq");
        r.body = b"query { __schema { types { name } } }".to_vec();
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "API005");
    }

    #[test]
    fn xxe_blocked() {
        let p = ap();
        let mut r = HttpRequest::new("POST", "/api/xml");
        r.header.add("Content-Type", "application/xml");
        r.body = b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><foo>&x;</foo>".to_vec();
        let mut ctx = RequestContext::new(r);
        let dec = p.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "API003");
    }
}
