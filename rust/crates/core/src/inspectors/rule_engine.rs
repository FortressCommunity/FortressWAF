//! Disk-loaded rule engine.
//!
//! Closes README Known Limitation #4 ("Rules are not loaded from disk"). The
//! bundled `rules/` directory holds YAML rule files (`rules/owasp/*.yaml`,
//! `rules/virtual-patches/*.yaml`) that, until now, parsed into the config but
//! were never read or enforced. This module loads them and evaluates them as an
//! inspector in the normal pipeline.
//!
//! ## File format
//!
//! A file is a YAML list of rules:
//!
//! ```yaml
//! - id: "FORTRESS-SQLI-001"
//!   name: "SQL Injection - UNION SELECT"
//!   severity: critical
//!   tags: ["sqli"]
//!   condition:
//!     any:
//!       - field: request.body
//!         operator: regex
//!         pattern: '(?i)(union\s+(all\s+)?select)'
//!       - field: request.query
//!         operator: regex
//!         pattern: '(?i)(union\s+(all\s+)?select)'
//!   action: block
//! ```
//!
//! A condition combines `any` (OR) or `all` (AND) clauses. A clause names a
//! `field` (`request.query`, `request.body`, `request.headers`,
//! `request.cookies`, `request.path`, `request.method`), optionally narrowed by
//! `name` (a specific header/cookie/query key), an `operator` (`regex`,
//! `contains`, `equals`, `prefix`, `suffix`), and the `pattern`/`value`.
//!
//! ## Why an inspector, not config
//!
//! The existing `Config.rules` is a flat `{field, operator, value}` shape that
//! cannot express the `condition.any`/`condition.all` tree these files use. The
//! rule files are a separate, richer format, so they are loaded by their own
//! module and surfaced to the engine as one inspector. The operator is
//! unchanged: a rule with `action: block` produces a blocking decision, exactly
//! like any built-in inspector.
//!
//! ## Failure behaviour
//!
//! A rule file that fails to parse, or a regex that fails to compile, is
//! skipped with a warning; it is never a panic and never a startup failure.
//! That matches the port's approach elsewhere (a bad config value is logged, not
//! fatal) and means one malformed third-party rule cannot take the WAF down.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

/// One clause in a rule condition. A clause is either a leaf match (a `field`
/// with an `operator` and a `pattern`/`value`), or a nested `any`/`all` group.
///
/// The bundled rule files use both forms: a flat leaf, and `all: [ {field...},
/// {any: [...] } ]` where the second element is a sub-group. `pattern` may also
/// be a list of strings (any-of), which several files use.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleClause {
    #[serde(default)]
    pub field: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub operator: String,
    /// A single pattern string, or a list of alternatives (any-of).
    #[serde(default)]
    pub pattern: StringOrList,
    #[serde(default)]
    pub value: String,
    /// A nested condition group (`any`/`all`) inside a clause.
    #[serde(default)]
    pub any: Vec<RuleClause>,
    #[serde(default)]
    pub all: Vec<RuleClause>,
}

/// A field that is either one string or a list of strings.
#[derive(Debug, Clone, Default)]
pub struct StringOrList(pub Vec<String>);

impl StringOrList {
    fn first(&self) -> Option<&str> {
        self.0.first().map(|s| s.as_str())
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for StringOrList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
            Number(i64),
            Nothing,
        }
        match OneOrMany::deserialize(deserializer)? {
            OneOrMany::One(s) => Ok(StringOrList(vec![s])),
            OneOrMany::Many(v) => Ok(StringOrList(v)),
            OneOrMany::Number(n) => Ok(StringOrList(vec![n.to_string()])),
            OneOrMany::Nothing => Ok(StringOrList(vec![])),
        }
    }
}

impl RuleClause {
    /// A leaf clause has a field and no nested group.
    fn is_leaf(&self) -> bool {
        !self.field.is_empty() && self.any.is_empty() && self.all.is_empty()
    }
    fn is_group(&self) -> bool {
        !self.any.is_empty() || !self.all.is_empty()
    }
}

/// The `condition` object: `any` (OR) or `all` (AND).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RuleCondition {
    #[serde(default)]
    pub any: Vec<RuleClause>,
    #[serde(default)]
    pub all: Vec<RuleClause>,
}

/// A single rule as it appears on disk.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleSpec {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default)]
    pub condition: RuleCondition,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub cve: String,
}

fn default_action() -> String {
    "block".to_string()
}

/// A compiled leaf matcher.
#[derive(Debug, Clone)]
enum Matcher {
    /// Any of the alternatives matches (a single pattern is a one-element list).
    Regex(Vec<Regex>),
    Contains(String),
    Equals(String),
    Prefix(String),
    Suffix(String),
    /// The `in` / any-of operator over literal values.
    In(Vec<String>),
    /// An operator we do not recognise: never matches, so a typo cannot make a
    /// rule fire on everything.
    Never,
}

#[derive(Debug, Clone)]
enum CompiledClause {
    Leaf {
        field: String,
        name: String,
        matcher: Matcher,
    },
    Group {
        any: Vec<CompiledClause>,
        all: Vec<CompiledClause>,
    },
}

#[derive(Debug, Clone)]
struct CompiledRule {
    id: String,
    name: String,
    severity: String,
    action: Action,
    score: f64,
    any: Vec<CompiledClause>,
    all: Vec<CompiledClause>,
}

impl CompiledRule {
    fn matches(&self, ctx: &RequestContext) -> bool {
        group_matches(&self.any, &self.all, ctx)
    }
}

/// A rule matches when its `any` group (OR) and its `all` group (AND) both
/// match. An absent group is satisfied.
fn group_matches(any: &[CompiledClause], all: &[CompiledClause], ctx: &RequestContext) -> bool {
    if any.is_empty() && all.is_empty() {
        return false;
    }
    let any_ok = any.is_empty() || any.iter().any(|c| c.matches(ctx));
    let all_ok = all.is_empty() || all.iter().all(|c| c.matches(ctx));
    any_ok && all_ok
}

impl CompiledClause {
    fn matches(&self, ctx: &RequestContext) -> bool {
        match self {
            CompiledClause::Group { any, all } => group_matches(any, all, ctx),
            CompiledClause::Leaf {
                field,
                name,
                matcher,
            } => match_field(field, name, matcher, ctx),
        }
    }
}

fn match_field(field: &str, name: &str, matcher: &Matcher, ctx: &RequestContext) -> bool {
    let field = field.to_lowercase();
    match field.as_str() {
        "request.query" | "request.querystring" | "request.args" => values_match(
            ctx.query_params
                .iter()
                .flat_map(|(k, vs)| vs.iter().map(move |v| (k.clone(), v.clone()))),
            name,
            matcher,
        ),
        "request.body" | "request.data" => {
            let body = String::from_utf8_lossy(&ctx.body).into_owned();
            matcher.matches(&body)
        }
        "request.headers" | "request.header" => {
            if !name.is_empty() {
                match ctx.headers.get(&canonical(name)) {
                    Some(v) => matcher.matches(v),
                    None => false,
                }
            } else {
                values_match(
                    ctx.headers.iter().map(|(k, v)| (k.clone(), v.clone())),
                    "",
                    matcher,
                )
            }
        }
        "request.cookies" | "request.cookie" => {
            if !name.is_empty() {
                match ctx.cookies.get(name) {
                    Some(v) => matcher.matches(v),
                    None => false,
                }
            } else {
                values_match(
                    ctx.cookies.iter().map(|(k, v)| (k.clone(), v.clone())),
                    "",
                    matcher,
                )
            }
        }
        "request.path" | "request.uri" | "request.url" => {
            if field == "request.uri" || field == "request.url" {
                if ctx.request.raw_query.is_empty() {
                    matcher.matches(&ctx.path)
                } else {
                    matcher.matches(&format!("{}?{}", ctx.path, ctx.request.raw_query))
                }
            } else {
                matcher.matches(&ctx.path)
            }
        }
        "request.method" => matcher.matches(&ctx.method),
        "request.host" => matcher.matches(&ctx.host),
        "request.user_agent" | "request.useragent" => matcher.matches(&ctx.user_agent),
        _ => false,
    }
}

/// Match against a field with several values (query params, headers): when
/// `name` is set, only that key's values are considered.
fn values_match(
    iter: impl Iterator<Item = (String, String)>,
    name: &str,
    matcher: &Matcher,
) -> bool {
    for (k, v) in iter {
        if !name.is_empty() && !k.eq_ignore_ascii_case(name) {
            continue;
        }
        if matcher.matches(&v) {
            return true;
        }
    }
    false
}

impl Matcher {
    fn matches(&self, value: &str) -> bool {
        match self {
            Matcher::Regex(res) => res.iter().any(|re| re.is_match(value)),
            Matcher::Contains(s) => value.contains(s.as_str()),
            Matcher::Equals(s) => value == s,
            Matcher::Prefix(s) => value.starts_with(s.as_str()),
            Matcher::Suffix(s) => value.ends_with(s.as_str()),
            Matcher::In(values) => values.iter().any(|v| v == value),
            Matcher::Never => false,
        }
    }
}

fn canonical(key: &str) -> String {
    crate::http::HeaderMap::canonical_key(key)
}

/// The rule engine inspector: evaluates every loaded rule in file order and
/// returns the first rule whose condition matches.
pub struct RuleEngineInspector {
    pub dev_mode: bool,
    rules: Vec<CompiledRule>,
}

impl RuleEngineInspector {
    /// Build from a set of rule files and/or directories. Each path may be a
    /// `.yaml`/`.yml` file or a directory, which is scanned recursively for
    /// `*.yaml`/`*.yml`. Unparseable files and clauses are skipped with a
    /// warning.
    pub fn from_paths(paths: &[String]) -> Self {
        let mut files = Vec::new();
        for p in paths {
            let path = Path::new(p);
            if path.is_dir() {
                collect_yaml_recursive(path, &mut files);
            } else {
                files.push(path.to_path_buf());
            }
        }
        // Deterministic order: sort so rule evaluation does not depend on
        // readdir order.
        files.sort();
        files.dedup();

        let mut rules = Vec::new();
        for f in &files {
            rules.extend(load_rule_file(f));
        }

        RuleEngineInspector {
            dev_mode: false,
            rules,
        }
    }

    pub fn with_dev_mode(mut self, dev: bool) -> Self {
        self.dev_mode = dev;
        self
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Inspector for RuleEngineInspector {
    fn name(&self) -> &str {
        "rule_engine"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        for rule in &self.rules {
            if rule.matches(ctx) {
                if self.dev_mode {
                    tracing::debug!(rule_id = rule.id.as_str(), "disk rule matched");
                }
                return Ok(Some(
                    Decision::new(rule.action, rule.score)
                        .with_rule_id(rule.id.clone())
                        .with_rule_name(rule.name.clone())
                        .with_severity(rule.severity.clone())
                        .with_evidence(format!("disk rule {} matched", rule.id)),
                ));
            }
        }
        Ok(None)
    }
}

/// Parse and compile one rule file. Returns the compiled rules; a file that
/// cannot be read or parsed yields none (with a warning).
fn load_rule_file(path: &Path) -> Vec<CompiledRule> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(file = %path.display(), error = %e, "cannot read rule file");
            return Vec::new();
        }
    };

    let specs: Vec<RuleSpec> = match serde_yaml::from_str(&text) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(file = %path.display(), error = %e, "cannot parse rule file");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for spec in specs {
        if spec.enabled == Some(false) {
            continue;
        }
        match compile_rule(spec, path) {
            Some(r) => out.push(r),
            None => continue,
        }
    }
    out
}

fn compile_rule(spec: RuleSpec, path: &Path) -> Option<CompiledRule> {
    if spec.id.is_empty() {
        tracing::warn!(file = %path.display(), "rule without id skipped");
        return None;
    }

    let action = match spec.action.to_lowercase().as_str() {
        "block" | "deny" => Action::Block,
        "monitor" | "log" | "detect" => Action::Monitor,
        "challenge" => Action::Challenge,
        "allow" | "pass" => Action::Allow,
        // Any other action is unknown; treat it as a monitor so a rule never
        // silently blocks on a value the engine did not understand.
        other => {
            tracing::warn!(file = %path.display(), rule = spec.id.as_str(), action = other, "unknown rule action; using monitor");
            Action::Monitor
        }
    };

    let score = match action {
        Action::Block => 80.0,
        Action::Challenge => 60.0,
        Action::Monitor => 40.0,
        _ => 0.0,
    };

    let any = compile_clauses(&spec.condition.any, &spec.id, path);
    let all = compile_clauses(&spec.condition.all, &spec.id, path);
    if any.is_empty() && all.is_empty() {
        tracing::warn!(file = %path.display(), rule = spec.id.as_str(), "rule has no usable conditions; skipped");
        return None;
    }

    Some(CompiledRule {
        id: spec.id,
        name: if spec.name.is_empty() {
            spec.cve.clone()
        } else {
            spec.name
        },
        severity: if spec.severity.is_empty() {
            "high".to_string()
        } else {
            spec.severity
        },
        action,
        score,
        any,
        all,
    })
}

/// Compile a clause list to compiled clauses. A group clause (nested
/// `any`/`all`) compiles recursively; a leaf clause that fails to compile is
/// dropped.
fn compile_clauses(clauses: &[RuleClause], rule_id: &str, path: &Path) -> Vec<CompiledClause> {
    let mut out = Vec::new();
    for c in clauses {
        if c.is_group() {
            let any = compile_clauses(&c.any, rule_id, path);
            let all = compile_clauses(&c.all, rule_id, path);
            if !any.is_empty() || !all.is_empty() {
                out.push(CompiledClause::Group { any, all });
            }
            continue;
        }
        if !c.is_leaf() {
            // A clause with neither a field nor a group is meaningless; skip.
            continue;
        }
        let matcher = compile_matcher(c, rule_id, path);
        if matches!(matcher, Matcher::Never) {
            continue;
        }
        out.push(CompiledClause::Leaf {
            field: c.field.clone(),
            name: c.name.clone(),
            matcher,
        });
    }
    out
}

fn compile_matcher(c: &RuleClause, rule_id: &str, path: &Path) -> Matcher {
    let op = c.operator.to_lowercase();
    // The pattern alternatives: either the `pattern` list or the `value`.
    let alternatives: Vec<String> = if !c.pattern.is_empty() {
        c.pattern.0.clone()
    } else if !c.value.is_empty() {
        vec![c.value.clone()]
    } else {
        Vec::new()
    };

    match op.as_str() {
        "" | "regex" | "re" | "matches" => {
            if alternatives.is_empty() {
                return Matcher::Never;
            }
            let mut compiled = Vec::new();
            for pattern in &alternatives {
                match compile_regex(pattern) {
                    Some(re) => compiled.push(re),
                    None => {
                        tracing::warn!(file = %path.display(), rule = rule_id, pattern = pattern.as_str(), "invalid regex; alternative skipped");
                    }
                }
            }
            if compiled.is_empty() {
                Matcher::Never
            } else {
                Matcher::Regex(compiled)
            }
        }
        "in" | "oneof" | "one_of" => Matcher::In(alternatives),
        "contains" | "include" => first(&alternatives)
            .map(Matcher::Contains)
            .unwrap_or(Matcher::Never),
        "equals" | "eq" | "is" => first(&alternatives)
            .map(Matcher::Equals)
            .unwrap_or(Matcher::Never),
        "prefix" | "startswith" | "starts_with" => first(&alternatives)
            .map(Matcher::Prefix)
            .unwrap_or(Matcher::Never),
        "suffix" | "endswith" | "ends_with" => first(&alternatives)
            .map(Matcher::Suffix)
            .unwrap_or(Matcher::Never),
        other => {
            tracing::warn!(file = %path.display(), rule = rule_id, operator = other, "unknown operator; clause skipped");
            Matcher::Never
        }
    }
}

fn first(v: &[String]) -> Option<String> {
    v.first().cloned()
}

/// Compile a regex with a per-process cache so a rule set with repeated
/// patterns compiles each once.
fn compile_regex(pattern: &str) -> Option<Regex> {
    type Cache = std::sync::Mutex<std::collections::HashMap<String, Option<Regex>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    if let Ok(map) = cache.lock() {
        if let Some(hit) = map.get(pattern) {
            return hit.clone();
        }
    }
    let compiled = Regex::new(pattern).ok();
    if let Ok(mut map) = cache.lock() {
        map.insert(pattern.to_string(), compiled.clone());
    }
    compiled
}

fn collect_yaml_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_recursive(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml") | Some("yml")
        ) {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn parse_specs(yaml: &str) -> Vec<CompiledRule> {
        let specs: Vec<RuleSpec> = serde_yaml::from_str(yaml).unwrap();
        specs
            .into_iter()
            .filter_map(|s| compile_rule(s, Path::new("<test>")))
            .collect()
    }

    #[test]
    fn block_rule_matches_query_pattern() {
        let yaml = r#"
- id: "T-001"
  name: "Test SQLi"
  severity: critical
  condition:
    any:
      - field: request.query
        operator: regex
        pattern: '(?i)union\s+select'
  action: block
"#;
        let rules = parse_specs(yaml);
        assert_eq!(rules.len(), 1);
        let mut r = HttpRequest::new("GET", "/search");
        r.raw_query = "q=1%20UNION%20SELECT%20x".to_string();
        let ctx = RequestContext::new(r);
        assert!(rules[0].matches(&ctx));
    }

    #[test]
    fn benign_value_does_not_match() {
        let yaml = r#"
- id: "T-001"
  condition:
    any:
      - field: request.query
        operator: regex
        pattern: '(?i)union\s+select'
  action: block
"#;
        let rules = parse_specs(yaml);
        let mut r = HttpRequest::new("GET", "/search");
        r.raw_query = "q=finance".to_string();
        let ctx = RequestContext::new(r);
        assert!(!rules[0].matches(&ctx));
    }

    #[test]
    fn named_header_clause() {
        let yaml = r#"
- id: "T-002"
  condition:
    any:
      - field: request.headers
        name: "User-Agent"
        operator: regex
        pattern: 'sqlmap'
  action: block
"#;
        let rules = parse_specs(yaml);
        let mut ok = HttpRequest::new("GET", "/");
        ok.header.add("User-Agent", "sqlmap/1.7");
        assert!(rules[0].matches(&RequestContext::new(ok)));
        let mut browser = HttpRequest::new("GET", "/");
        browser.header.add("User-Agent", "Mozilla/5.0");
        assert!(!rules[0].matches(&RequestContext::new(browser)));
    }

    #[test]
    fn invalid_regex_is_skipped_not_panic() {
        let yaml = r#"
- id: "T-003"
  condition:
    any:
      - field: request.query
        operator: regex
        pattern: '([unclosed'
  action: block
"#;
        let rules = parse_specs(yaml);
        // The clause is dropped, so nothing matches.
        assert!(rules.is_empty() || rules[0].any.is_empty());
    }

    #[test]
    fn unknown_action_monitors_never_blocks() {
        let yaml = r#"
- id: "T-004"
  condition:
    any:
      - field: request.method
        operator: equals
        value: "GET"
  action: frobnicate
"#;
        let rules = parse_specs(yaml);
        assert_eq!(rules[0].action, Action::Monitor);
    }

    #[test]
    fn list_pattern_matches_any_alternative() {
        // `pattern` as a list is the `in`/any-of form several bundled files use.
        let yaml = r#"
- id: "T-IN"
  condition:
    any:
      - field: request.method
        operator: in
        pattern: ["CONNECT", "TRACE", "TRACK"]
  action: block
"#;
        let rules = parse_specs(yaml);
        let mut tr = HttpRequest::new("TRACE", "/");
        assert!(rules[0].matches(&RequestContext::new(std::mem::take(&mut tr))));
        let get = HttpRequest::new("GET", "/");
        assert!(!rules[0].matches(&RequestContext::new(get)));
    }

    #[test]
    fn nested_group_inside_all() {
        // A clause that is itself `{any: [...]}` inside an `all` group.
        let yaml = r#"
- id: "T-NEST"
  condition:
    all:
      - field: request.path
        operator: regex
        pattern: '/admin'
      - any:
          - field: request.query
            operator: regex
            pattern: 'debug'
          - field: request.headers
            name: "X-Debug"
            operator: equals
            value: "1"
  action: block
"#;
        let rules = parse_specs(yaml);
        // path matches + one sub-clause matches -> rule fires.
        let mut r = HttpRequest::new("GET", "/admin");
        r.raw_query = "q=debug".to_string();
        assert!(rules[0].matches(&RequestContext::new(r)));
        // path matches but no sub-clause -> no fire.
        let only = HttpRequest::new("GET", "/admin");
        assert!(!rules[0].matches(&RequestContext::new(only)));
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let dir = std::env::temp_dir().join(format!("fwaf-rules-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("r.yaml");
        std::fs::write(
            &file,
            "- id: X-1\n  enabled: false\n  condition:\n    any:\n      - field: request.method\n        operator: equals\n        value: GET\n  action: block\n",
        )
        .unwrap();
        let insp = RuleEngineInspector::from_paths(&[dir.to_string_lossy().to_string()]);
        assert_eq!(insp.rule_count(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loads_bundled_rules_directory() {
        // The repo ships rules/; loading it must compile a substantial number of
        // rules without panicking.
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // rust/crates/core -> repo root
        for _ in 0..4 {
            dir.pop();
        }
        let rules = dir.join("rules");
        if !rules.is_dir() {
            eprintln!("skipping: rules/ not found");
            return;
        }
        let insp = RuleEngineInspector::from_paths(&[rules.to_string_lossy().to_string()]);
        assert!(
            insp.rule_count() > 50,
            "expected the bundled rules to compile, got {}",
            insp.rule_count()
        );
    }
}
