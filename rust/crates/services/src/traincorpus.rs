//! Live attack-corpus collector for the ML training data.
//!
//! Port of `internal/traincorpus/collector.go`. Qualification rules, payload
//! sanitization, the noise filter and the corpus file format are preserved.

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct Sample {
    pub rule_id: String,
    pub category: String,
    pub payload: String,
    pub source: String,
    pub actor_ip: String,
    pub score: f64,
    pub observed_at: String,
}

/// Port of `ruleCategory`. Only these rule families produce training data.
pub fn rule_category() -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (prefix, cat) in [
        ("SQLI0", "sql-injection"),
        ("XSS0", "xss"),
        ("RCE0", "rce"),
        ("CMD", "command-injection"),
        ("SSTI", "ssti"),
        ("LDAP", "ldap-injection"),
        ("XXE", "xxe"),
        ("DESER", "deserialization"),
        ("WEBSHELL", "webshell"),
        ("PARSER_0", "path-traversal"),
    ] {
        m.insert(prefix.to_string(), cat.to_string());
    }
    m
}

static WHITESPACE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());
static STRUCTURAL_SIGNATURE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)<\s*/?\s*[a-z][^>]*>|\{\{|\$\{|\$\(|\(\)|\[\[|@@|\|\||&&|'\s*(?:or|and)\s|"\s*(?:or|and)\s|=\s*'|'\s*=|--\s*$|#\s*$|\bunion\b\s+\bselect\b|\bselect\b[^;]*\bfrom\b|\.\./|%2e%2e"#).unwrap()
});
static ATTACK_KEYWORD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(select|union|insert|update|delete|drop|exec|eval|system|script|alert|onerror|onload|jndi|ldap|xxe|entity|template|ssti|deserial|pickle|bash|cmd|powershell|passwd)\b").unwrap()
});

struct State {
    seen: HashMap<String, ()>,
    written: i64,
    dropped: i64,
}

pub struct Collector {
    dir: String,
    state: Arc<Mutex<State>>,
    trusted_rules: HashMap<String, String>,
}

impl Collector {
    /// Port of `NewCollector`. An empty dir disables collection.
    pub fn new(dir: &str) -> Self {
        Collector {
            dir: dir.to_string(),
            state: Arc::new(Mutex::new(State {
                seen: HashMap::new(),
                written: 0,
                dropped: 0,
            })),
            trusted_rules: rule_category(),
        }
    }

    /// Port of `Enabled`.
    pub fn enabled(&self) -> bool {
        !self.dir.is_empty()
    }

    /// Port of `Consider`.
    pub fn consider(&self, s: &Sample) -> (bool, String) {
        if !self.enabled() {
            return (false, "collector disabled".to_string());
        }

        let category = match self.category_for(&s.rule_id) {
            Some(c) => c,
            None => {
                return (
                    false,
                    "rule is not a high-confidence attack family".to_string(),
                )
            }
        };
        if s.score < 70.0 {
            return (false, "score below confidence floor".to_string());
        }
        let payload = sanitize_payload(&s.payload);
        if payload.is_empty() {
            return (false, "empty payload after cleaning".to_string());
        }
        if is_noise(&payload) {
            return (
                false,
                "payload is noise, not an attack signature".to_string(),
            );
        }

        let mut state = self.state.lock();

        let key = format!("{category}\u{0}{payload}");
        if state.seen.contains_key(&key) {
            return (false, "duplicate".to_string());
        }
        state.seen.insert(key, ());

        let dir = std::path::Path::new(&self.dir).join(&category);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            state.dropped += 1;
            return (false, format!("mkdir: {e}"));
        }
        let path = dir.join("payloads.txt");

        let line = format!(
            "{payload}\t# from {} at {} rule={}\n",
            s.actor_ip, s.observed_at, s.rule_id
        );

        use std::io::Write;
        let mut f = match std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                state.dropped += 1;
                return (false, format!("open: {e}"));
            }
        };
        if let Err(e) = f.write_all(line.as_bytes()) {
            state.dropped += 1;
            return (false, format!("write: {e}"));
        }
        state.written += 1;
        (true, "collected".to_string())
    }

    /// Port of `Stats`: (written, dropped, unique).
    pub fn stats(&self) -> (i64, i64, usize) {
        let state = self.state.lock();
        (state.written, state.dropped, state.seen.len())
    }

    fn category_for(&self, rule_id: &str) -> Option<String> {
        self.trusted_rules
            .iter()
            .find(|(prefix, _)| rule_id.starts_with(prefix.as_str()))
            .map(|(_, cat)| cat.clone())
    }
}

/// Port of `sanitizePayload`.
pub fn sanitize_payload(p: &str) -> String {
    let mut p = p.replace('\u{0}', "");
    p = p.replace('\r', " ");
    p = p.replace('\n', " ");
    p = p.replace('\t', " ");
    p = WHITESPACE_RE.replace_all(&p, " ").into_owned();
    let p = p.trim();
    if p.len() > 2048 {
        p[..2048].to_string()
    } else {
        p.to_string()
    }
}

/// Port of `isNoise`.
pub fn is_noise(p: &str) -> bool {
    if p.len() < 4 {
        return true;
    }
    let has_punct = p.contains([
        '\'', '"', '<', '>', '(', ')', '{', '}', ';', '=', '|', '&', '\\', '/', '`', '$', '%',
    ]);
    let has_keyword = has_attack_keyword(p);
    if STRUCTURAL_SIGNATURE_RE.is_match(p) {
        return false;
    }
    if has_punct && has_keyword {
        return false;
    }
    true
}

/// Port of `hasAttackKeyword`.
pub fn has_attack_keyword(p: &str) -> bool {
    ATTACK_KEYWORD_RE.is_match(p)
}

/// Port of `LoadCategory`.
pub fn load_category(dir: &str, category: &str) -> Result<Vec<String>, String> {
    let path = std::path::Path::new(dir)
        .join(category)
        .join("payloads.txt");
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };

    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = match line.find("\t#") {
            Some(i) => line[..i].trim(),
            None => line,
        };
        out.push(line.to_string());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rule: &str, payload: &str, score: f64) -> Sample {
        Sample {
            rule_id: rule.to_string(),
            category: String::new(),
            payload: payload.to_string(),
            source: "body".to_string(),
            actor_ip: "1.2.3.4".to_string(),
            score,
            observed_at: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn sanitize_collapses_whitespace_and_strips_nul() {
        // NUL is removed (not replaced), so "a\0b" becomes "ab"; CR/LF/TAB
        // become spaces and runs collapse.
        let s = sanitize_payload("a\u{0}b\r\nc\td");
        assert_eq!(s, "ab c d");
    }

    #[test]
    fn noise_filter_rejects_prose() {
        assert!(is_noise("please select the blue option"));
        assert!(!is_noise("1' OR '1'='1"));
        assert!(!is_noise("<script>alert(1)</script>"));
    }

    #[test]
    fn consider_writes_trusted_high_score_sample() {
        let dir = std::env::temp_dir().join(format!("fwaf-corpus-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = Collector::new(&dir.to_string_lossy());
        let (kept, reason) = c.consider(&sample("SQLI001", "1' OR '1'='1", 90.0));
        assert!(kept, "{reason}");
        let (w, _, unique) = c.stats();
        assert_eq!(w, 1);
        assert_eq!(unique, 1);

        // Duplicate rejected.
        let (kept2, reason2) = c.consider(&sample("SQLI001", "1' OR '1'='1", 90.0));
        assert!(!kept2);
        assert_eq!(reason2, "duplicate");

        // LoadCategory returns the payload.
        let loaded = load_category(&dir.to_string_lossy(), "sql-injection").unwrap();
        assert_eq!(loaded, vec!["1' OR '1'='1".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consider_rejects_low_score_and_untrusted_rule() {
        let c = Collector::new("/tmp/fwaf-corpus-x");
        let (k, r) = c.consider(&sample("SQLI001", "1' OR '1'='1", 50.0));
        assert!(!k);
        assert_eq!(r, "score below confidence floor");
        let (k2, r2) = c.consider(&sample("BOT004", "sqlmap", 90.0));
        assert!(!k2);
        assert!(r2.contains("not a high-confidence"));
    }

    #[test]
    fn disabled_collector_rejects_all() {
        let c = Collector::new("");
        let (k, r) = c.consider(&sample("SQLI001", "1' OR '1'='1", 90.0));
        assert!(!k);
        assert_eq!(r, "collector disabled");
    }
}
