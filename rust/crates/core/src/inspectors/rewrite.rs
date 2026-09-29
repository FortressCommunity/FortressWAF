//! Request/response rewriting: header, body and URL actions with conditions.
//!
//! Port of `internal/engine/rewrite.go`. Operations, condition operators, and
//! match semantics are preserved exactly.

use std::sync::Arc;

use regex::Regex;

use crate::context::{RequestContext, ResponseContext};

#[derive(Debug, Clone)]
pub struct RewriteCondition {
    pub field: String,
    pub name: String,
    pub operator: String,
    pub value: String,
}

/// A rewrite action. Port of the Go `RewriteAction` interface, split into
/// request/response application.
pub trait RewriteAction: Send + Sync {
    fn apply_request(&self, ctx: &mut RequestContext) -> Result<(), String>;
    fn apply_response(&self, ctx: &mut ResponseContext) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct HeaderAction {
    pub operation: String,
    pub name: String,
    pub value: String,
}

impl RewriteAction for HeaderAction {
    fn apply_request(&self, ctx: &mut RequestContext) -> Result<(), String> {
        match self.operation.as_str() {
            "add" | "set" => {
                ctx.headers.insert(self.name.clone(), self.value.clone());
            }
            "remove" => {
                ctx.headers.remove(&self.name);
            }
            "rename" => {
                if let Some(v) = ctx.headers.remove(&self.name) {
                    ctx.headers.insert(self.value.clone(), v);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_response(&self, ctx: &mut ResponseContext) -> Result<(), String> {
        match self.operation.as_str() {
            "add" | "set" => {
                ctx.headers.insert(self.name.clone(), self.value.clone());
            }
            "remove" => {
                ctx.headers.remove(&self.name);
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BodyAction {
    pub operation: String,
    pub pattern: String,
    pub value: String,
    pub regex: Option<Regex>,
}

impl BodyAction {
    /// Port of `NewBodyAction`.
    pub fn new(op: &str, pattern: &str, value: &str) -> Result<Self, String> {
        let regex = if op == "regex_replace" {
            Some(Regex::new(pattern).map_err(|e| format!("invalid regex: {e}"))?)
        } else {
            None
        };
        Ok(BodyAction {
            operation: op.to_string(),
            pattern: pattern.to_string(),
            value: value.to_string(),
            regex,
        })
    }
}

impl RewriteAction for BodyAction {
    fn apply_request(&self, ctx: &mut RequestContext) -> Result<(), String> {
        match self.operation.as_str() {
            "replace" => {
                ctx.body =
                    replace_all_bytes(&ctx.body, self.pattern.as_bytes(), self.value.as_bytes());
            }
            "regex_replace" => {
                if let Some(re) = &self.regex {
                    let text = String::from_utf8_lossy(&ctx.body);
                    ctx.body = re
                        .replace_all(&text, self.value.as_str())
                        .into_owned()
                        .into_bytes();
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_response(&self, ctx: &mut ResponseContext) -> Result<(), String> {
        match self.operation.as_str() {
            "replace" => {
                ctx.body =
                    replace_all_bytes(&ctx.body, self.pattern.as_bytes(), self.value.as_bytes());
            }
            "regex_replace" => {
                if let Some(re) = &self.regex {
                    let text = String::from_utf8_lossy(&ctx.body);
                    ctx.body = re
                        .replace_all(&text, self.value.as_str())
                        .into_owned()
                        .into_bytes();
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// `bytes.ReplaceAll`: replace every non-overlapping occurrence.
fn replace_all_bytes(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + from.len() <= haystack.len() && &haystack[i..i + from.len()] == from {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct UrlAction {
    pub operation: String,
    pub url: String,
    pub code: i32,
}

impl UrlAction {
    fn expand_url(&self, ctx: &RequestContext) -> String {
        self.url
            .replace("{{.path}}", &ctx.path)
            .replace("{{.ip}}", &ctx.real_ip)
            .replace("{{.host}}", &ctx.host)
            .replace("{{.method}}", &ctx.method)
    }
}

impl RewriteAction for UrlAction {
    fn apply_request(&self, ctx: &mut RequestContext) -> Result<(), String> {
        if self.operation == "redirect" {
            let url = self.expand_url(ctx);
            ctx.headers.insert("Location".to_string(), url);
        }
        Ok(())
    }

    fn apply_response(&self, _ctx: &mut ResponseContext) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct RewriteRule {
    pub name: String,
    pub conditions: Vec<RewriteCondition>,
    pub actions: Vec<Arc<dyn RewriteAction>>,
}

#[derive(Default)]
pub struct RewriteManager {
    rules: Vec<RewriteRule>,
}

impl RewriteManager {
    pub fn new() -> Self {
        RewriteManager { rules: Vec::new() }
    }

    /// Port of `AddRule` (Go took a pointer receiver and mutated in place).
    pub fn add_rule(&mut self, rule: RewriteRule) {
        self.rules.push(rule);
    }

    pub fn apply_request(&self, ctx: &mut RequestContext) -> Result<(), String> {
        for rule in &self.rules {
            if !match_conditions(&rule.conditions, ctx) {
                continue;
            }
            for action in &rule.actions {
                action.apply_request(ctx)?;
            }
        }
        Ok(())
    }

    pub fn apply_response(&self, ctx: &mut ResponseContext) -> Result<(), String> {
        for rule in &self.rules {
            for action in &rule.actions {
                action.apply_response(ctx)?;
            }
        }
        Ok(())
    }
}

fn match_conditions(conditions: &[RewriteCondition], ctx: &RequestContext) -> bool {
    conditions.iter().all(|c| match_condition(c, ctx))
}

fn match_condition(cond: &RewriteCondition, ctx: &RequestContext) -> bool {
    match cond.field.as_str() {
        "path" => match_value(&ctx.path, cond),
        "headers" => match ctx.headers.get(&cond.name) {
            Some(v) => match_value(v, cond),
            None => cond.operator == "not_exists" || cond.operator == "!exists",
        },
        "query" => match ctx.query_params.get(&cond.name) {
            Some(v) if !v.is_empty() => match_value(&v[0], cond),
            _ => cond.operator == "not_exists",
        },
        "method" => match_value(&ctx.method, cond),
        "ip" => match_value(&ctx.real_ip, cond),
        _ => false,
    }
}

/// Port of `matchValue`.
fn match_value(value: &str, cond: &RewriteCondition) -> bool {
    match cond.operator.as_str() {
        "equals" => value == cond.value,
        "contains" => value.contains(&cond.value),
        "prefix" => value.starts_with(&cond.value),
        "suffix" => value.ends_with(&cond.value),
        "regex" => match Regex::new(&cond.value) {
            Ok(re) => re.is_match(value),
            Err(_) => false,
        },
        "exists" => !value.is_empty(),
        "not_exists" | "!exists" => value.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, HttpResponse};

    #[test]
    fn header_action_set_and_remove() {
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        let a = HeaderAction {
            operation: "set".into(),
            name: "X-Test".into(),
            value: "1".into(),
        };
        a.apply_request(&mut ctx).unwrap();
        assert_eq!(ctx.headers.get("X-Test"), Some(&"1".to_string()));

        let r = HeaderAction {
            operation: "remove".into(),
            name: "X-Test".into(),
            value: String::new(),
        };
        r.apply_request(&mut ctx).unwrap();
        assert!(!ctx.headers.contains_key("X-Test"));
    }

    #[test]
    fn header_action_rename() {
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        ctx.headers.insert("Old".into(), "v".into());
        let a = HeaderAction {
            operation: "rename".into(),
            name: "Old".into(),
            value: "New".into(),
        };
        a.apply_request(&mut ctx).unwrap();
        assert!(!ctx.headers.contains_key("Old"));
        assert_eq!(ctx.headers.get("New"), Some(&"v".to_string()));
    }

    #[test]
    fn body_regex_replace() {
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        ctx.body = b"id=12345".to_vec();
        let a = BodyAction::new("regex_replace", r"id=\d+", "id=REDACTED").unwrap();
        a.apply_request(&mut ctx).unwrap();
        assert_eq!(ctx.body, b"id=REDACTED");
    }

    #[test]
    fn url_action_expands_placeholders() {
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/foo"));
        ctx.real_ip = "1.2.3.4".into();
        let a = UrlAction {
            operation: "redirect".into(),
            url: "https://x{{.path}}?ip={{.ip}}".into(),
            code: 302,
        };
        a.apply_request(&mut ctx).unwrap();
        assert_eq!(
            ctx.headers.get("Location"),
            Some(&"https://x/foo?ip=1.2.3.4".to_string())
        );
    }

    #[test]
    fn condition_prefix_matches() {
        let mut mgr = RewriteManager::new();
        let rule = RewriteRule {
            name: "test".into(),
            conditions: vec![RewriteCondition {
                field: "path".into(),
                name: String::new(),
                operator: "prefix".into(),
                value: "/api".into(),
            }],
            actions: vec![Arc::new(HeaderAction {
                operation: "set".into(),
                name: "X-Api".into(),
                value: "1".into(),
            })],
        };
        mgr.add_rule(rule);

        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/api/x"));
        mgr.apply_request(&mut ctx).unwrap();
        assert_eq!(ctx.headers.get("X-Api"), Some(&"1".to_string()));

        let mut ctx2 = RequestContext::new(HttpRequest::new("GET", "/web"));
        mgr.apply_request(&mut ctx2).unwrap();
        assert!(!ctx2.headers.contains_key("X-Api"));
    }

    #[test]
    fn response_body_replace() {
        let req = Arc::new(RequestContext::new(HttpRequest::new("GET", "/")));
        let mut resp = ResponseContext {
            status_code: 200,
            headers: Default::default(),
            body: b"secret=abc".to_vec(),
            request: req,
        };
        let a = BodyAction::new("replace", "abc", "***").unwrap();
        a.apply_response(&mut resp).unwrap();
        assert_eq!(resp.body, b"secret=***");
    }

    #[test]
    fn unused_http_response_type_is_referenced() {
        // Ensure the HttpResponse import is meaningful for the module.
        let _ = HttpResponse::default();
    }
}
