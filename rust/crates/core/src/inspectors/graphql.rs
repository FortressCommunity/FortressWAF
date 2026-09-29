//! GraphQL inspection: introspection/schema blocking, depth/cost/alias/batch
//! limits, operation allow-listing.
//!
//! Port of `internal/engine/graphql.go`. Rule IDs, scores, thresholds and the
//! query-analysis heuristics are preserved exactly.

use std::collections::HashMap;

use crate::action::{Action, Decision};
use crate::config_types::GraphQlConfig;
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

pub struct GraphQlInspector {
    max_depth: i32,
    max_cost: i32,
    max_aliases: i32,
    max_batch_size: i32,
    max_tokens: i32,
    block_introspection: bool,
    block_schema: bool,
    allowed_ops: HashMap<String, bool>,
    restricted_fields: HashMap<String, bool>,
    strict_validation: bool,
}

#[derive(Debug, Default)]
pub struct GraphQlQuery {
    pub operation: String,
    pub depth: i32,
    pub cost: i32,
    pub aliases: i32,
}

impl GraphQlInspector {
    pub fn new(cfg: GraphQlConfig) -> Self {
        let allowed = cfg
            .allowed_operations
            .into_iter()
            .map(|op| (op, true))
            .collect();
        let restricted = cfg
            .restricted_fields
            .into_iter()
            .map(|f| (f, true))
            .collect();
        GraphQlInspector {
            max_depth: cfg.max_depth,
            max_cost: cfg.max_cost,
            max_aliases: cfg.max_aliases,
            max_batch_size: cfg.max_batch_size,
            max_tokens: cfg.max_tokens,
            block_introspection: cfg.block_introspection,
            block_schema: cfg.block_schema,
            allowed_ops: allowed,
            restricted_fields: restricted,
            strict_validation: cfg.strict_validation,
        }
    }

    fn is_introspection_query(&self, body: &[u8]) -> bool {
        let body_str = String::from_utf8_lossy(body);
        ["__schema", "__type", "IntrospectionQuery", "Introspection"]
            .iter()
            .any(|p| body_str.contains(p))
    }

    fn is_schema_query(&self, body: &[u8]) -> bool {
        let body_str = String::from_utf8_lossy(body).to_lowercase();
        body_str.contains("{ __typename }") && body_str.contains("__type")
    }

    fn parse_query(&self, body: &[u8]) -> Result<GraphQlQuery, String> {
        let trimmed = body.strip_prefix(b" ").unwrap_or(body);
        let _ = trimmed;
        let trimmed_bytes: Vec<u8> = body
            .iter()
            .copied()
            .skip_while(|b| b.is_ascii_whitespace())
            .collect();

        if trimmed_bytes.first() == Some(&b'[') {
            let batch: Vec<serde_json::Value> =
                serde_json::from_slice(body).map_err(|e| format!("json batch unmarshal: {e}"))?;
            if batch.is_empty() {
                return Err("empty batch query".to_string());
            }
            let first = &batch[0];
            let mut query = GraphQlQuery::default();
            if let Some(q) = first.get("query").and_then(|v| v.as_str()) {
                self.analyze_query_string(q, &mut query);
            }
            if let Some(op) = first.get("operationName").and_then(|v| v.as_str()) {
                query.operation = op.to_string();
            }
            return Ok(query);
        }

        let parsed: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| format!("json unmarshal: {e}"))?;

        let mut query = GraphQlQuery::default();
        if let Some(q) = parsed.get("query").and_then(|v| v.as_str()) {
            self.analyze_query_string(q, &mut query);
        }
        if let Some(op) = parsed.get("operationName").and_then(|v| v.as_str()) {
            query.operation = op.to_string();
        }
        Ok(query)
    }

    fn analyze_query_string(&self, q: &str, query: &mut GraphQlQuery) {
        let trimmed = q.trim_start();
        if trimmed.starts_with("query") {
            query.operation = "query".to_string();
        } else if trimmed.starts_with("mutation") {
            query.operation = "mutation".to_string();
        } else if trimmed.starts_with("subscription") {
            query.operation = "subscription".to_string();
        } else {
            query.operation = "query".to_string();
        }

        let alias_re = regex::Regex::new(r"(\w+)\s*:").unwrap();
        query.aliases = alias_re.find_iter(q).count() as i32;

        query.depth = self.count_depth(q);
        query.cost = self.calculate_cost(q);
    }

    fn count_depth(&self, q: &str) -> i32 {
        let mut max_depth = 0;
        let mut current_depth = 0;
        for line in q.split('\n') {
            for r in line.chars() {
                if r == '{' {
                    current_depth += 1;
                    if current_depth > max_depth {
                        max_depth = current_depth;
                    }
                } else if r == '}' && current_depth > 0 {
                    current_depth -= 1;
                }
            }
        }
        max_depth
    }

    fn calculate_cost(&self, q: &str) -> i32 {
        let mut cost = 0;
        let patterns = [
            ("query", 1),
            ("mutation", 10),
            ("subscription", 100),
            ("fragment", 5),
            ("... on", 20),
            ("@include", 2),
            ("@skip", 2),
            ("@deprecated", 1),
        ];
        let lower = q.to_lowercase();
        for (pattern, c) in patterns {
            let cnt = lower.matches(pattern).count() as i32;
            cost += cnt * c;
        }
        let page_size = self.count_page_size(q);
        cost += page_size * page_size;
        cost
    }

    fn count_page_size(&self, q: &str) -> i32 {
        let mut page_size = 100;
        if let Some(first_pos) = q.to_lowercase().find("first:") {
            let mut end_pos = first_pos + 6;
            let bytes = q.as_bytes();
            while end_pos < bytes.len() && (bytes[end_pos] == b' ' || bytes[end_pos] == b'\t') {
                end_pos += 1;
            }
            let start = end_pos;
            while end_pos < bytes.len() && bytes[end_pos].is_ascii_digit() {
                end_pos += 1;
            }
            if end_pos > start {
                if let Ok(size) = q[start..end_pos].parse::<i32>() {
                    page_size = size;
                }
            }
        }
        page_size
    }

    fn count_operations(&self, body: &[u8]) -> i32 {
        if self.is_json_query(body) {
            if let Ok(req) = serde_json::from_slice::<serde_json::Value>(body) {
                if let Some(ops) = req.get("operations").and_then(|v| v.as_array()) {
                    return ops.len() as i32;
                }
            }
            if let Ok(batch) = serde_json::from_slice::<Vec<serde_json::Value>>(body) {
                return batch.len() as i32;
            }
        }
        let body_str = String::from_utf8_lossy(body);
        body_str.matches("{\"query\"").count() as i32
    }

    fn is_json_query(&self, body: &[u8]) -> bool {
        body.iter()
            .find(|b| !b.is_ascii_whitespace())
            .map(|b| *b == b'{')
            .unwrap_or(false)
    }

    /// Port of `ValidateQuery`.
    pub fn validate_query(&self, q: &str) -> (bool, String) {
        if self.max_tokens > 0 && q.len() as i32 > self.max_tokens {
            return (
                false,
                format!(
                    "query exceeds maximum tokens: {} > {}",
                    q.len(),
                    self.max_tokens
                ),
            );
        }
        let dangerous = [
            "${",
            "{{",
            "__dirname",
            "__filename",
            "process",
            "eval(",
            "require(",
            "import(",
        ];
        let lower = q.to_lowercase();
        for pattern in dangerous {
            if lower.contains(pattern) {
                return (false, format!("dangerous pattern detected: {pattern}"));
            }
        }
        (true, String::new())
    }
}

impl Inspector for GraphQlInspector {
    fn name(&self) -> &str {
        "graphql_protection"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if ctx.content_type.is_empty()
            || (!ctx.content_type.contains("graphql") && !ctx.content_type.contains("json"))
        {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        if ctx.body.is_empty() {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        if self.block_introspection && self.is_introspection_query(&ctx.body) {
            return Ok(Some(
                Decision::new(Action::Block, 85.0)
                    .with_rule_id("GRAPHQL-001")
                    .with_rule_name("GraphQL introspection blocked")
                    .with_severity("high")
                    .with_evidence("introspection query not allowed"),
            ));
        }

        if self.block_schema && self.is_schema_query(&ctx.body) {
            return Ok(Some(
                Decision::new(Action::Block, 85.0)
                    .with_rule_id("GRAPHQL-002")
                    .with_rule_name("GraphQL schema query blocked")
                    .with_severity("high")
                    .with_evidence("schema query not allowed"),
            ));
        }

        let query = match self.parse_query(&ctx.body) {
            Ok(q) => q,
            Err(e) => {
                if self.strict_validation {
                    return Ok(Some(
                        Decision::new(Action::Block, 60.0)
                            .with_rule_id("GRAPHQL-003")
                            .with_rule_name("GraphQL parse error")
                            .with_severity("medium")
                            .with_evidence(e),
                    ));
                }
                return Ok(Some(Decision::new(Action::Allow, 0.0)));
            }
        };

        if self.max_depth > 0 && query.depth > self.max_depth {
            return Ok(Some(
                Decision::new(Action::Block, 80.0)
                    .with_rule_id("GRAPHQL-004")
                    .with_rule_name("GraphQL depth limit exceeded")
                    .with_severity("high")
                    .with_evidence(format!("depth={}, limit={}", query.depth, self.max_depth)),
            ));
        }

        if self.max_cost > 0 && query.cost > self.max_cost {
            return Ok(Some(
                Decision::new(Action::Block, 80.0)
                    .with_rule_id("GRAPHQL-005")
                    .with_rule_name("GraphQL cost limit exceeded")
                    .with_severity("high")
                    .with_evidence(format!("cost={}, limit={}", query.cost, self.max_cost)),
            ));
        }

        if self.max_aliases > 0 && query.aliases > self.max_aliases {
            return Ok(Some(
                Decision::new(Action::Block, 65.0)
                    .with_rule_id("GRAPHQL-006")
                    .with_rule_name("GraphQL alias limit exceeded")
                    .with_severity("medium")
                    .with_evidence(format!(
                        "aliases={}, limit={}",
                        query.aliases, self.max_aliases
                    )),
            ));
        }

        if self.max_batch_size > 0 {
            let batch_size = self.count_operations(&ctx.body);
            if batch_size > self.max_batch_size {
                return Ok(Some(
                    Decision::new(Action::Block, 75.0)
                        .with_rule_id("GRAPHQL-007")
                        .with_rule_name("GraphQL batch size exceeded")
                        .with_severity("high")
                        .with_evidence(format!(
                            "batch_size={}, limit={}",
                            batch_size, self.max_batch_size
                        )),
                ));
            }
        }

        if !self.allowed_ops.is_empty() && !query.operation.is_empty() {
            if !self.allowed_ops.contains_key(&query.operation) {
                return Ok(Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("GRAPHQL-008")
                        .with_rule_name("GraphQL operation not allowed")
                        .with_severity("high")
                        .with_evidence(format!("operation={}", query.operation)),
                ));
            }
        }

        Ok(Some(Decision::new(Action::Allow, 0.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn inspector(cfg: GraphQlConfig) -> GraphQlInspector {
        GraphQlInspector::new(cfg)
    }

    fn ctx(body: &str) -> RequestContext {
        let mut r = HttpRequest::new("POST", "/graphql");
        r.header.add("Content-Type", "application/json");
        r.body = body.as_bytes().to_vec();
        RequestContext::new(r)
    }

    #[test]
    fn introspection_blocked() {
        let g = inspector(GraphQlConfig {
            block_introspection: true,
            ..Default::default()
        });
        let mut c = ctx(r#"{"query":"{ __schema { types { name } } }"}"#);
        let dec = g.inspect(&mut c).unwrap().unwrap();
        assert_eq!(dec.rule_id, "GRAPHQL-001");
    }

    #[test]
    fn depth_limit_enforced() {
        let g = inspector(GraphQlConfig {
            max_depth: 1,
            ..Default::default()
        });
        let mut c = ctx(r#"{"query":"{ a { b { c } } }"}"#);
        let dec = g.inspect(&mut c).unwrap().unwrap();
        assert_eq!(dec.rule_id, "GRAPHQL-004");
    }

    #[test]
    fn benign_query_allowed() {
        let g = inspector(GraphQlConfig {
            max_depth: 5,
            ..Default::default()
        });
        let mut c = ctx(r#"{"query":"{ user { id name } }"}"#);
        let dec = g.inspect(&mut c).unwrap().unwrap();
        assert_eq!(dec.action, Action::Allow);
    }

    #[test]
    fn count_depth_counts_braces() {
        let g = inspector(GraphQlConfig::default());
        assert_eq!(g.count_depth("{ a { b { c } } }"), 3);
    }

    #[test]
    fn count_page_size_parses_first() {
        let g = inspector(GraphQlConfig::default());
        assert_eq!(g.count_page_size("query { items(first: 42) { id } }"), 42);
        assert_eq!(g.count_page_size("query { items { id } }"), 100);
    }
}
