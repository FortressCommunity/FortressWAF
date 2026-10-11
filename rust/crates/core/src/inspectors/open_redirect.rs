//! Open Redirect detection.
//!
//! Closes README Known Limitation #3 for the open-redirect category. An open
//! redirect is an application parameter that controls where the response sends
//! the client next (`?next=`, `?return=`, `?redirect=`). Attackers abuse it for
//! phishing and OAuth token theft. This inspector flags redirect parameters
//! whose value points off-site.
//!
//! Design notes, one reason per choice:
//!
//! - **Monitor by default, block on request** (`open_redirect.block`), matching
//!   the SSRF inspector and the response-leak precedent. Redirect parameters
//!   legitimately hold external URLs in many apps, so enforcement is opt-in.
//! - **Only redirect-shaped parameters are read.** A value is considered only
//!   when its parameter name is a known redirect target (`redirect`, `next`,
//!   `return`, `continue`, `dest`, `target`, `url`, ...). That is what keeps
//!   this from becoming a second copy of the SSRF inspector and tripping on
//!   every link in a page body.
//! - **Same-origin and relative values are never flagged.** `?next=/dashboard`
//!   and `?next=https://myown.example.com/x` pass; only a value that resolves
//!   to a *different* host does not. When `allowed_hosts` is set, a value whose
//!   host is in that list is treated as first-party.
//! - **Encoding and parser tricks are undone first.** `//evil.com`,
//!   `/\evil.com`, `https:/\evil.com`, and `%2f%2fevil.com` all reach the same
//!   place in a browser; the check normalizes them before deciding.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};
use crate::regex_util::percent_decode_once;

/// Options for [`OpenRedirectInspector`], wired from `open_redirect.*`.
#[derive(Debug, Clone, Default)]
pub struct OpenRedirectOptions {
    /// Promote a high-confidence match to a block. When false, matches are
    /// reported as [`Action::Monitor`] and forwarded.
    pub block: bool,
    /// Hosts that count as first-party, so a redirect to them is not a finding.
    pub allowed_hosts: Vec<String>,
}

struct Patterns {
    scheme_relative: Regex,
    absolute: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        // `//host`, `/\host`, `\/host`, `\\host` -- every spelling a browser
        // reads as scheme-relative authority.
        scheme_relative: Regex::new(r"^[/\\]{2,}").unwrap(),
        // An absolute URL with a scheme.
        absolute: Regex::new(r"(?i)^[a-z][a-z0-9+.\-]*://").unwrap(),
    })
}

/// The open-redirect inspector.
pub struct OpenRedirectInspector {
    pub dev_mode: bool,
    opts: OpenRedirectOptions,
}

impl OpenRedirectInspector {
    pub fn new(dev_mode: bool, opts: OpenRedirectOptions) -> Self {
        let _ = patterns();
        OpenRedirectInspector { dev_mode, opts }
    }

    fn inspect_value(&self, value: &str, source: &str, ctx: &RequestContext) -> Option<Decision> {
        let (decoded, _) = percent_decode_once(value);
        let v = decoded.trim();
        if v.is_empty() {
            return None;
        }

        // A same-origin or relative path (`/dashboard`, `dashboard`) is fine.
        // Only a value that escapes the current origin to another host is a
        // finding.
        let target_host = self.external_host(v)?;

        if self.is_first_party(&target_host, ctx) {
            return None;
        }

        let (action, score) = if self.opts.block {
            (Action::Block, 75.0)
        } else {
            // Monitor findings stay well below the cumulative thresholds, so
            // co-occurring monitor hits cannot add up to a challenge or block.
            (Action::Monitor, 15.0)
        };
        Some(
            Decision::new(action, score)
                .with_rule_id("REDIR001")
                .with_rule_name("Open Redirect")
                .with_severity("high")
                .with_evidence(format!(
                    "redirect in {source} targets another host: {target_host}"
                )),
        )
    }

    /// Return the external host a redirect value points at, or `None` when the
    /// value is relative (stays on the current origin).
    fn external_host(&self, value: &str) -> Option<String> {
        if patterns().scheme_relative.is_match(value) {
            // `//host/path`, `/\host`, `\/host`, `\\host`.
            let rest = value.trim_start_matches(['/', '\\']);
            return host_of(rest);
        }

        if patterns().absolute.is_match(value) {
            let after = &value[value.find("://").unwrap() + 3..];
            return host_of(after);
        }

        // `https:evil.com` (no `//`) and `javascript:`/`data:` pseudo-schemes
        // are not navigations a browser follows to another site in the redirect
        // sense; ignore them rather than guess.
        None
    }

    fn is_first_party(&self, host: &str, ctx: &RequestContext) -> bool {
        let host = host.trim_end_matches('.').to_lowercase();
        for allowed in &self.opts.allowed_hosts {
            if host == allowed.trim_end_matches('.').to_lowercase() {
                return true;
            }
        }
        // The request's own host is first-party.
        let own = ctx.host.trim_end_matches('.').to_lowercase();
        !own.is_empty() && host == own
    }
}

impl Inspector for OpenRedirectInspector {
    fn name(&self) -> &str {
        "open_redirect"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        for (k, vs) in &ctx.query_params {
            if !is_redirect_param(k) {
                continue;
            }
            for v in vs {
                if let Some(dec) = self.inspect_value(v, &format!("query:{k}"), ctx) {
                    return Ok(Some(dec));
                }
            }
        }
        for (k, vs) in &ctx.form_params {
            if !is_redirect_param(k) {
                continue;
            }
            for v in vs {
                if let Some(dec) = self.inspect_value(v, &format!("form:{k}"), ctx) {
                    return Ok(Some(dec));
                }
            }
        }
        Ok(None)
    }
}

/// Parameter names that conventionally control a post-action redirect.
fn is_redirect_param(name: &str) -> bool {
    let n = name.to_lowercase();
    matches!(
        n.as_str(),
        "redirect"
            | "redirect_uri"
            | "redirect_url"
            | "redirect_to"
            | "redirectto"
            | "return"
            | "returnurl"
            | "return_url"
            | "returnto"
            | "return_to"
            | "next"
            | "continue"
            | "dest"
            | "destination"
            | "target"
            | "url"
            | "goto"
            | "out"
            | "link"
            | "callback"
            | "callback_url"
    ) || n.starts_with("redirect_")
}

/// Extract the host from an authority string (everything after `//`).
fn host_of(authority: &str) -> Option<String> {
    let end = authority
        .find(['/', '?', '#', '\\'])
        .unwrap_or(authority.len());
    let authority = &authority[..end];
    if authority.is_empty() {
        return None;
    }
    let hostport = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let host = if hostport.starts_with('[') {
        match hostport.find(']') {
            Some(i) => &hostport[..=i],
            None => hostport,
        }
    } else {
        match hostport.rfind(':') {
            Some(i) if !hostport[i + 1..].is_empty() => &hostport[..i],
            _ => hostport,
        }
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn ctx_with(query: &str, host: &str) -> RequestContext {
        let mut r = HttpRequest::new("GET", "/login");
        r.raw_query = query.to_string();
        r.host = host.to_string();
        RequestContext::new(r)
    }

    fn inspect(query: &str, host: &str, opts: OpenRedirectOptions) -> Option<Decision> {
        let mut ctx = ctx_with(query, host);
        OpenRedirectInspector::new(false, opts)
            .inspect(&mut ctx)
            .unwrap()
    }

    fn blocking() -> OpenRedirectOptions {
        OpenRedirectOptions {
            block: true,
            allowed_hosts: vec![],
        }
    }

    #[test]
    fn external_redirect_blocked() {
        let d = inspect("next=https://evil.example/x", "myapp.example", blocking()).unwrap();
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.rule_id, "REDIR001");
    }

    #[test]
    fn scheme_relative_redirect_blocked() {
        let d = inspect("redirect=//evil.example/x", "myapp.example", blocking()).unwrap();
        assert_eq!(d.rule_id, "REDIR001");
    }

    #[test]
    fn backslash_trick_blocked() {
        let d = inspect(r"redirect=/\evil.example/x", "myapp.example", blocking()).unwrap();
        assert_eq!(d.rule_id, "REDIR001");
    }

    #[test]
    fn encoded_redirect_blocked() {
        let d = inspect(
            "next=https%3A%2F%2Fevil.example%2Fx",
            "myapp.example",
            blocking(),
        )
        .unwrap();
        assert_eq!(d.rule_id, "REDIR001");
    }

    #[test]
    fn relative_path_is_fine() {
        assert!(inspect("next=/dashboard", "myapp.example", blocking()).is_none());
    }

    #[test]
    fn same_origin_absolute_is_fine() {
        assert!(inspect(
            "next=https://myapp.example/dashboard",
            "myapp.example",
            blocking()
        )
        .is_none());
    }

    #[test]
    fn allowed_host_is_fine() {
        let opts = OpenRedirectOptions {
            block: true,
            allowed_hosts: vec!["accounts.example".to_string()],
        };
        assert!(inspect(
            "return_url=https://accounts.example/oauth",
            "myapp.example",
            opts
        )
        .is_none());
    }

    #[test]
    fn non_redirect_param_not_inspected() {
        assert!(inspect("q=https://evil.example/x", "myapp.example", blocking()).is_none());
    }

    #[test]
    fn monitor_by_default() {
        let d = inspect(
            "next=https://evil.example/x",
            "myapp.example",
            OpenRedirectOptions::default(),
        )
        .unwrap();
        assert_eq!(d.action, Action::Monitor);
    }

    #[test]
    fn host_extraction() {
        assert_eq!(
            host_of("evil.example:8443/x").as_deref(),
            Some("evil.example")
        );
        assert_eq!(
            host_of("user@evil.example/x").as_deref(),
            Some("evil.example")
        );
    }
}
