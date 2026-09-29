//! SQL injection detection.
//!
//! Port of `internal/engine/sqli.go`. Rule IDs, scores, severities, the
//! tokenizer, the context-sensitive keyword check, and the double-encoding
//! logic are preserved exactly.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};
use crate::regex_util::percent_decode_once;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Keyword,
    Operator,
    String,
    Number,
    Identifier,
    Comment,
    Punctuation,
    Function,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub ty: TokenType,
    pub value: String,
    pub pos: usize,
}

struct Patterns {
    list: Vec<Regex>,
    encoding_re: Regex,
    comment_re: Regex,
    hex_re: Regex,
    unicode_re: Regex,
    null_byte_re: Regex,
    base64_re: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let raw: &[&str] = &[
            r"(?i)(?:\b(?:union|union\s+all)\s+select\b)",
            r"(?i)(?:select\s+.*?\bfrom\b.*?\bwhere\b)",
            r"(?i)(?:\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b|\b(?:drop|truncate)\s+(?:table|database|schema|index|view)\b|\balter\s+(?:table|database|schema)\b|\bcreate\s+(?:table|database|schema|index|view|user)\b|\breplace\s+into\b)",
            r"(?i)(?:\b(?:exec|execute|exec_sp|xp_cmdshell|sp_executesql)\b)",
            r#"(?i)(?:'.*\b(?:or|and)\b.*['"])"#,
            r"(?i)(?:'.*\s*=\s*'.*--|'.*=\s*'.*#)",
            r"(?i)(?:sleep|waitfor\s+delay|pg_sleep|benchmark)\s*\(",
            r"(?i)(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1)",
            r"(?i)(?:';.*--|';.*#|'\)\s*;?\s*--)",
            r"(?i)(?:pg_sleep|waitfor|delay|sleep|benchmark|if)\s*\(",
            r"(?i)(?:\b(?:information_schema|mysql\.|pg_catalog|sys\.|sqlite_master)\b)",
            r"(?i)(?:@@version|version\(\)|@@servername|db_name\(\))",
            r"(?i)(?:into\s+(?:outfile|dumpfile|load_file)\b)",
            r"(?i)(?:conv|char|nchar|hex|unhex|ord|ascii)\s*\(",
            r"(?i)(?:admin'|'admin|\bor\b.*\badmin\b|\badmin\b.*\bor\b)",
        ];
        let list = raw
            .iter()
            .map(|r| Regex::new(r).expect("valid sqli pattern"))
            .collect();
        Patterns {
            list,
            encoding_re: Regex::new(r"(?i)(?:\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}|&#x?[0-9a-f]+;)")
                .unwrap(),
            // Go: (?is)(?:/\*.*?\*|--.*?$|#.*?$|--\s). Rust `$` matches end of
            // text (Go RE2 `$` without (?m) also matches end of text, and before
            // a final \n). `(?s)` makes `.` match newlines in both. Preserved.
            comment_re: Regex::new(r"(?is)(?:/\*.*?\*|--.*?$|#.*?$|--\s)").unwrap(),
            hex_re: Regex::new(r"(?i)(?:0x[0-9a-f]+|x'[0-9a-f]+'|unhex\(|hex\(|char\()").unwrap(),
            unicode_re: Regex::new(r"(?i)(?:\\u[0-9a-f]{4}|%u[0-9a-f]{4}|nchar|n'|unicode\()")
                .unwrap(),
            null_byte_re: Regex::new("\u{0}").unwrap(),
            base64_re: Regex::new(r"(?i)(?:base64_decode|base64_encode|from_base64|to_base64)")
                .unwrap(),
        }
    })
}

/// SQLInjectionEngine. Port of the Go struct (patterns are process-global
/// because they are immutable and shared; the Go struct built them per
/// instance, but the result is identical).
pub struct SqlInjectionEngine {
    pub dev_mode: bool,
}

impl SqlInjectionEngine {
    pub fn new(dev_mode: bool) -> Self {
        // Force pattern compilation up front, like the Go constructor did.
        let _ = patterns();
        SqlInjectionEngine { dev_mode }
    }

    fn extract_targets(&self, ctx: &RequestContext) -> Vec<(String, String)> {
        let mut targets = Vec::new();
        for (k, vs) in &ctx.query_params {
            for val in vs {
                targets.push((val.clone(), format!("query:{k}")));
            }
        }
        for (k, vs) in &ctx.form_params {
            for val in vs {
                targets.push((val.clone(), format!("form:{k}")));
            }
        }
        if !ctx.body.is_empty() {
            targets.push((
                String::from_utf8_lossy(&ctx.body).into_owned(),
                "body".to_string(),
            ));
        }
        for (k, v) in &ctx.headers {
            targets.push((v.clone(), format!("header:{k}")));
        }
        for (k, v) in &ctx.cookies {
            targets.push((v.clone(), format!("cookie:{k}")));
        }
        targets
    }

    fn inspect_value(&self, value: &str, source: &str) -> Option<Decision> {
        if value.is_empty() {
            return None;
        }

        let original = value.to_string();

        if let Some(dec) = self.detect_encoding_bypass(value, source) {
            return Some(dec);
        }

        let normalized = self.normalize_input(value);

        let tokens = self.tokenize(&normalized);
        if let Some(dec) = self.analyze_tokens(&tokens, &normalized, source) {
            return Some(dec);
        }

        for pattern in &patterns().list {
            if pattern.is_match(&normalized) || pattern.is_match(&original) {
                return Some(
                    Decision::new(Action::Block, 75.0)
                        .with_rule_id("SQLI016")
                        .with_rule_name("SQL Pattern Match")
                        .with_severity("high")
                        .with_evidence(format!(
                            "SQL injection pattern matched in {source}: {:?}",
                            truncate_chars(&original, 200)
                        )),
                );
            }
        }

        None
    }

    fn detect_encoding_bypass(&self, value: &str, source: &str) -> Option<Decision> {
        if patterns().null_byte_re.is_match(value) {
            return Some(
                Decision::new(Action::Block, 70.0)
                    .with_rule_id("SQLI017")
                    .with_rule_name("Null Byte Injection")
                    .with_severity("high")
                    .with_evidence(format!("null byte detected in {source}")),
            );
        }

        if let Some(dec) = self.detect_double_encoding(value, source) {
            return Some(dec);
        }

        if patterns().hex_re.is_match(value) {
            return Some(
                Decision::new(Action::Monitor, 40.0)
                    .with_rule_id("SQLI019")
                    .with_rule_name("Hex Encoding")
                    .with_severity("medium")
                    .with_evidence(format!("hex encoding detected in {source}")),
            );
        }

        if patterns().base64_re.is_match(value) {
            return Some(
                Decision::new(Action::Monitor, 35.0)
                    .with_rule_id("SQLI020")
                    .with_rule_name("Base64 Encoding")
                    .with_severity("medium")
                    .with_evidence(format!("base64 function detected in {source}")),
            );
        }

        None
    }

    fn detect_double_encoding(&self, value: &str, source: &str) -> Option<Decision> {
        if !value.contains('%') {
            return None;
        }
        let (decoded, changed) = percent_decode_once(value);
        if !changed || decoded == value {
            return None;
        }
        if !introduces_meta_char(value, &decoded) {
            return None;
        }
        let normalized = self.normalize_input(&decoded);
        for pattern in &patterns().list {
            if pattern.is_match(&decoded) || pattern.is_match(&normalized) {
                return Some(
                    Decision::new(Action::Block, 75.0)
                        .with_rule_id("SQLI018")
                        .with_rule_name("Double Encoding")
                        .with_severity("high")
                        .with_evidence(format!("double encoding hides SQL in {source}")),
                );
            }
        }
        if let Some(mut dec) = self.analyze_tokens(&self.tokenize(&normalized), &decoded, source) {
            if dec.action == Action::Block {
                dec.rule_id = "SQLI018".to_string();
                dec.rule_name = "Double Encoding".to_string();
                return Some(dec);
            }
        }
        None
    }

    fn normalize_input(&self, input: &str) -> String {
        let result = patterns().comment_re.replace_all(input, " ");
        patterns()
            .encoding_re
            .replace_all(&result, "X")
            .into_owned()
    }

    fn tokenize(&self, input: &str) -> Vec<Token> {
        let mut tokens = Vec::new();
        let runes: Vec<char> = input.chars().collect();
        let mut i = 0usize;

        while i < runes.len() {
            let ch = runes[i];

            if ch.is_whitespace() {
                i += 1;
                continue;
            }

            if ch == '\'' || ch == '"' {
                let start = i;
                i += 1;
                while i < runes.len() && runes[i] != ch {
                    if runes[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i < runes.len() {
                    i += 1;
                }
                tokens.push(Token {
                    ty: TokenType::String,
                    value: runes[start..i].iter().collect(),
                    pos: start,
                });
                continue;
            }

            if ch == '/' && i + 1 < runes.len() && runes[i + 1] == '*' {
                let mut end = i + 2;
                while end + 1 < runes.len() && !(runes[end] == '*' && runes[end + 1] == '/') {
                    end += 1;
                }
                if end + 1 < runes.len() {
                    end += 2;
                }
                tokens.push(Token {
                    ty: TokenType::Comment,
                    value: runes[i..end].iter().collect(),
                    pos: i,
                });
                i = end;
                continue;
            }

            if ch == '-' && i + 1 < runes.len() && runes[i + 1] == '-' {
                let mut end = i + 2;
                while end < runes.len() && runes[end] != '\n' {
                    end += 1;
                }
                tokens.push(Token {
                    ty: TokenType::Comment,
                    value: runes[i..end].iter().collect(),
                    pos: i,
                });
                i = end;
                continue;
            }

            if ch == '#' && i + 1 < runes.len() {
                let mut end = i + 1;
                while end < runes.len() && runes[end] != '\n' {
                    end += 1;
                }
                tokens.push(Token {
                    ty: TokenType::Comment,
                    value: runes[i..end].iter().collect(),
                    pos: i,
                });
                i = end;
                continue;
            }

            if ch.is_ascii_digit()
                || (ch == '.' && i + 1 < runes.len() && runes[i + 1].is_ascii_digit())
            {
                let start = i;
                while i < runes.len() && (runes[i].is_ascii_digit() || runes[i] == '.') {
                    i += 1;
                }
                tokens.push(Token {
                    ty: TokenType::Number,
                    value: runes[start..i].iter().collect(),
                    pos: start,
                });
                continue;
            }

            if ch.is_alphabetic() || ch == '_' {
                let start = i;
                while i < runes.len()
                    && (runes[i].is_alphabetic() || runes[i].is_ascii_digit() || runes[i] == '_')
                {
                    i += 1;
                }
                let word: String = runes[start..i].iter().collect();
                let upper = word.to_uppercase();
                if is_sql_keyword(&upper) {
                    tokens.push(Token {
                        ty: TokenType::Keyword,
                        value: word,
                        pos: start,
                    });
                } else if i < runes.len() && runes[i] == '(' {
                    tokens.push(Token {
                        ty: TokenType::Function,
                        value: word,
                        pos: start,
                    });
                } else {
                    tokens.push(Token {
                        ty: TokenType::Identifier,
                        value: word,
                        pos: start,
                    });
                }
                continue;
            }

            if "=<>!+-*/%&|^~".contains(ch) {
                let start = i;
                if i + 1 < runes.len() && "=<>".contains(runes[i + 1]) {
                    i += 1;
                }
                i += 1;
                tokens.push(Token {
                    ty: TokenType::Operator,
                    value: runes[start..i].iter().collect(),
                    pos: start,
                });
                continue;
            }

            if "()[]{};,".contains(ch) {
                tokens.push(Token {
                    ty: TokenType::Punctuation,
                    value: ch.to_string(),
                    pos: i,
                });
                i += 1;
                continue;
            }

            tokens.push(Token {
                ty: TokenType::Unknown,
                value: ch.to_string(),
                pos: i,
            });
            i += 1;
        }

        tokens
    }

    fn analyze_tokens(&self, tokens: &[Token], _original: &str, source: &str) -> Option<Decision> {
        let mut keyword_count = 0usize;
        let mut string_count = 0usize;
        let mut has_semicolon = false;
        let mut keyword_pos: Vec<usize> = Vec::new();
        let mut semicolon_pos: Vec<usize> = Vec::new();

        for (idx, t) in tokens.iter().enumerate() {
            match t.ty {
                TokenType::Keyword => {
                    keyword_count += 1;
                    keyword_pos.push(idx);
                    let upper = t.value.to_uppercase();
                    if upper == "UNION"
                        || upper == "SELECT"
                        || upper == "DROP"
                        || upper == "EXEC"
                        || upper == "EXECUTE"
                    {
                        if !sql_keyword_in_context(tokens, idx) {
                            continue;
                        }
                        return Some(
                            Decision::new(Action::Block, 90.0)
                                .with_rule_id("SQLI021")
                                .with_rule_name("SQL Keyword Injection")
                                .with_severity("critical")
                                .with_evidence(format!(
                                    "dangerous SQL keyword {:?} in SQL context in {source}",
                                    t.value
                                )),
                        );
                    }
                }
                TokenType::String => string_count += 1,
                TokenType::Punctuation => {
                    if t.value == ";" {
                        has_semicolon = true;
                        semicolon_pos.push(idx);
                    }
                }
                _ => {}
            }
        }

        if has_semicolon
            && keyword_count > 0
            && keyword_next_to_semicolon(&keyword_pos, &semicolon_pos)
        {
            return Some(
                Decision::new(Action::Block, 85.0)
                    .with_rule_id("SQLI022")
                    .with_rule_name("SQL Statement Chaining")
                    .with_severity("critical")
                    .with_evidence(format!("SQL statement chaining detected in {source}")),
            );
        }

        if keyword_count >= 2 && string_count >= 1 {
            return Some(
                Decision::new(Action::Monitor, 60.0)
                    .with_rule_id("SQLI023")
                    .with_rule_name("SQL-like Injection Pattern")
                    .with_severity("high")
                    .with_evidence(format!(
                        "SQL-like token pattern in {source}: {keyword_count} keywords, {string_count} strings"
                    )),
            );
        }

        None
    }
}

impl Inspector for SqlInjectionEngine {
    fn name(&self) -> &str {
        "sqli"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        for (value, source) in self.extract_targets(ctx) {
            if let Some(dec) = self.inspect_value(&value, &source) {
                return Ok(Some(dec));
            }
        }
        Ok(None)
    }
}

fn is_sql_keyword(upper: &str) -> bool {
    matches!(
        upper,
        "SELECT"
            | "UNION"
            | "FROM"
            | "WHERE"
            | "INSERT"
            | "UPDATE"
            | "DELETE"
            | "DROP"
            | "CREATE"
            | "ALTER"
            | "TABLE"
            | "INTO"
            | "VALUES"
            | "SET"
            | "AND"
            | "OR"
            | "NOT"
            | "NULL"
            | "LIKE"
            | "BETWEEN"
            | "IN"
            | "EXISTS"
            | "HAVING"
            | "GROUP"
            | "ORDER"
            | "BY"
            | "LIMIT"
            | "OFFSET"
            | "JOIN"
            | "LEFT"
            | "RIGHT"
            | "INNER"
            | "OUTER"
            | "ON"
            | "AS"
            | "CASE"
            | "WHEN"
            | "THEN"
            | "ELSE"
            | "END"
            | "EXEC"
            | "EXECUTE"
            | "SLEEP"
            | "BENCHMARK"
            | "PG_SLEEP"
            | "WAITFOR"
            | "DELAY"
    )
}

/// Port of `sqlKeywordInContext`. The Go `next` closure returns on the first
/// non-comment token even when `offset` is still > 1, so it always inspects the
/// immediate next token; the loop structure is reproduced literally.
fn sql_keyword_in_context(tokens: &[Token], i: usize) -> bool {
    let next = |offset: i32| -> Option<String> {
        let mut offset = offset;
        let mut j = i + 1;
        while j < tokens.len() && offset > 0 {
            if tokens[j].ty == TokenType::Comment {
                j += 1;
                continue;
            }
            offset -= 1;
            return Some(tokens[j].value.to_uppercase());
        }
        None
    };

    match tokens[i].value.to_uppercase().as_str() {
        "SELECT" => {
            let mut j = i + 1;
            while j < tokens.len() && j <= i + 10 {
                if tokens[j].ty == TokenType::Comment {
                    j += 1;
                    continue;
                }
                if tokens[j].ty == TokenType::Keyword && tokens[j].value.to_uppercase() == "FROM" {
                    return true;
                }
                j += 1;
            }
            false
        }
        "UNION" => match next(1) {
            Some(v) => v == "SELECT" || v == "ALL",
            None => false,
        },
        "DROP" | "TRUNCATE" | "ALTER" | "CREATE" => match next(1) {
            Some(v) => {
                matches!(
                    v.as_str(),
                    "TABLE" | "DATABASE" | "SCHEMA" | "INDEX" | "VIEW" | "USER"
                )
            }
            None => false,
        },
        "EXEC" | "EXECUTE" => match next(1) {
            Some(v) => v == "(" || v != ";",
            None => false,
        },
        _ => true,
    }
}

/// Port of `introducesMetaChar`.
fn introduces_meta_char(original: &str, decoded: &str) -> bool {
    let orig = original.as_bytes();
    for &b in decoded.as_bytes() {
        if sql_meta_byte(b) && !orig.contains(&b) {
            return true;
        }
    }
    false
}

/// Port of `sqlMetaByte`.
fn sql_meta_byte(c: u8) -> bool {
    matches!(c, b'\'' | b'"' | b';' | b'#' | 0x00 | b'\n' | b'\r')
}

/// Port of `keywordNextToSemicolon`.
fn keyword_next_to_semicolon(keyword_pos: &[usize], semicolon_pos: &[usize]) -> bool {
    for &k in keyword_pos {
        for &s in semicolon_pos {
            let d = k as i64 - s as i64;
            if (-2..=2).contains(&d) {
                return true;
            }
        }
    }
    false
}

/// Go's `original[:min(len(original), 200)]` slices BYTES. Reproducing that on
/// a Rust `str` requires care: truncate at the byte length, then back off to a
/// char boundary so the slice is valid (Go tolerates a mid-rune cut because it
/// slices bytes; the only observable difference is the evidence string, which
/// is never compared byte-for-byte across implementations).
fn truncate_chars(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn ctx_with_query(q: &str) -> RequestContext {
        let mut r = HttpRequest::new("GET", "/");
        r.raw_query = q.to_string();
        RequestContext::new(r)
    }

    fn inspect(q: &str) -> Option<Decision> {
        let e = SqlInjectionEngine::new(false);
        let mut ctx = ctx_with_query(q);
        e.inspect(&mut ctx).unwrap()
    }

    #[test]
    fn union_select_is_blocked() {
        let d = inspect("id=1%20UNION%20SELECT%20user,pass%20FROM%20users").unwrap();
        assert_eq!(d.action, Action::Block);
        assert!(d.rule_id.starts_with("SQLI"));
    }

    #[test]
    fn sleep_is_blocked() {
        let d = inspect("q=1');%20SLEEP(5)--").unwrap();
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn ordinary_word_dropoff_is_not_blocked_as_keyword() {
        // "drop-off location" must not trip SQLI003/021.
        let d = inspect("q=drop-off%20location");
        // May be None or a monitor; must NOT be a block on a keyword rule.
        if let Some(d) = d {
            assert_ne!(d.action, Action::Block, "false positive: {d:?}");
        }
    }

    #[test]
    fn null_byte_flagged() {
        let d = inspect("q=abc%00def").unwrap();
        assert_eq!(d.rule_id, "SQLI017");
    }

    #[test]
    fn semicolon_in_prose_not_blocked() {
        // A browser UA-like string with "like" and ";" must not trip SQLI022.
        let mut ctx = ctx_with_query("");
        ctx.headers.insert(
            "User-Agent".into(),
            "Mozilla/5.0 (X11; Linux x86_64) like Gecko".into(),
        );
        let e = SqlInjectionEngine::new(false);
        let d = e.inspect(&mut ctx).unwrap();
        if let Some(d) = d {
            assert_ne!(d.action, Action::Block, "false positive on UA: {d:?}");
        }
    }
}
