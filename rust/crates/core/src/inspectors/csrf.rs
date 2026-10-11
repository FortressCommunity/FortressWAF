//! CSRF (Cross-Site Request Forgery) detection.
//!
//! Closes README Known Limitation #3 for the CSRF category. A WAF cannot see
//! whether a session cookie is still valid, so it cannot prove a forgery. What
//! it *can* see is the exact combination a forged request has and a legitimate
//! one does not:
//!
//! 1. an unsafe method (POST / PUT / PATCH / DELETE), and
//! 2. an ambient credential (a session cookie or an `Authorization` header
//!    that the browser attaches automatically), and
//! 3. **no** valid CSRF token, and
//! 4. a cross-site `Origin` (or `Referer`, when `Origin` is absent) that names
//!    a site other than this one.
//!
//! All four together is the ship-it signal: a state-changing request that
//! carries the victim's cookie but originated from another site and presented
//! no token. Any one missing demotes it.
//!
//! Design notes, one reason per choice:
//!
//! - **Block by default for the full cross-site signal, monitor for the softer
//!   "unsafe method with no token" case.** A cross-site unsafe request with an
//!   ambient cookie and no token is unambiguous; a same-origin request that
//!   merely lacks a token is common and is only monitored, so a site that
//!   authenticates by cookie but does not use tokens is not bricked.
//! - **Token presence, not token validity.** The WAF does not know the site's
//!   token scheme, so it checks that *some* conventional CSRF header/field is
//!   present and non-empty (`X-CSRF-Token`, `X-XSRF-Token`, `X-CSRFToken`,
//!   `csrf_token`, `_csrf`, `authenticity_token`). An application validates the
//!   value; the WAF only ensures one exists on an ambient-credential request.
//! - **`same_site_cookie` option.** When the deployment sets `SameSite=Lax` or
//!   `Strict` cookies, the browser already blocks cross-site sends; set
//!   `csrf.same_site_cookie: true` to skip the cross-site rule entirely.

use std::sync::OnceLock;

use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

/// Options for [`CsrfInspector`], wired from `csrf.*`.
#[derive(Debug, Clone)]
pub struct CsrfOptions {
    /// Promote the soft case (unsafe method, ambient credential, no token) to a
    /// block. The full cross-site signal always blocks.
    pub block: bool,
    /// The deployment uses `SameSite=Lax`/`Strict` cookies, so the browser
    /// already stops cross-site sends; skip the cross-site rule.
    pub same_site_cookie: bool,
}

impl Default for CsrfOptions {
    fn default() -> Self {
        CsrfOptions {
            block: false,
            same_site_cookie: false,
        }
    }
}

struct Patterns {
    /// Header/field names that conventionally carry a CSRF token.
    token_field: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        token_field: Regex::new(
            r"(?i)^(?:x[-_]?csrf[-_]?token|x[-_]?xsrf[-_]?token|x[-_]?csrftoken|csrf[-_]?token|xsrf[-_]?token|_csrf(?:_token)?|authenticity[-_]?token|__requestverificationtoken)$",
        )
        .unwrap(),
    })
}

/// The CSRF inspector.
pub struct CsrfInspector {
    pub dev_mode: bool,
    opts: CsrfOptions,
}

impl CsrfInspector {
    pub fn new(dev_mode: bool, opts: CsrfOptions) -> Self {
        let _ = patterns();
        CsrfInspector { dev_mode, opts }
    }

    fn has_ambient_credential(&self, ctx: &RequestContext) -> bool {
        if !ctx.cookies.is_empty() {
            return true;
        }
        // An Authorization header is browser-ambient only if the browser set it
        // itself; a client that sets it explicitly is not a CSRF vector. The
        // WAF cannot tell the difference, so presence alone is the signal, which
        // is why this rule is conservative by default.
        !ctx.request_header("Authorization").is_empty()
    }

    fn has_token(&self, ctx: &RequestContext) -> bool {
        for (k, v) in &ctx.headers {
            if patterns().token_field.is_match(k) && !v.trim().is_empty() {
                return true;
            }
        }
        for (k, vs) in &ctx.form_params {
            if patterns().token_field.is_match(k) && vs.iter().any(|v| !v.trim().is_empty()) {
                return true;
            }
        }
        // A token may also ride in the decoded body when the form parser did not
        // populate form_params.
        if !ctx.body.is_empty() {
            let body = String::from_utf8_lossy(&ctx.body);
            for (k, _) in body.split('&').filter_map(|p| p.split_once('=')) {
                if patterns().token_field.is_match(k) {
                    return true;
                }
            }
        }
        false
    }

    fn inspect_unsafe(&self, ctx: &RequestContext) -> Option<Decision> {
        if !self.has_ambient_credential(ctx) {
            return None;
        }
        if self.has_token(ctx) {
            return None;
        }

        // No token. Is the request cross-site?
        if !self.opts.same_site_cookie {
            if let Some(origin) = self.cross_site_origin(ctx) {
                return Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("CSRF001")
                        .with_rule_name("Cross-Site Request Forgery")
                        .with_severity("high")
                        .with_evidence(format!(
                            "unsafe {} with a credential cookie from {origin}, no CSRF token",
                            ctx.method
                        )),
                );
            }
        }

        // Same-origin (or unverifiable) but still token-less: the soft case.
        let (action, score) = if self.opts.block {
            (Action::Block, 45.0)
        } else {
            // Monitor findings stay well below the cumulative thresholds.
            (Action::Monitor, 15.0)
        };
        Some(
            Decision::new(action, score)
                .with_rule_id("CSRF002")
                .with_rule_name("State-Changing Request Without CSRF Token")
                .with_severity("medium")
                .with_evidence(format!(
                    "unsafe {} carries a credential but no CSRF token",
                    ctx.method
                )),
        )
    }

    /// Return the cross-site origin when `Origin` (or `Referer`) names a host
    /// other than this request's own host.
    fn cross_site_origin(&self, ctx: &RequestContext) -> Option<String> {
        let own = ctx.host.trim_end_matches('.').to_lowercase();

        let origin = ctx.request_header("Origin");
        if !origin.is_empty() && origin != "null" {
            if let Some(host) = host_of_url(origin) {
                if !own.is_empty() && !same_site(&host, &own) {
                    return Some(origin.to_string());
                }
            }
            return None;
        }

        let referer = ctx.request_header("Referer");
        if !referer.is_empty() {
            if let Some(host) = host_of_url(referer) {
                if !own.is_empty() && !same_site(&host, &own) {
                    return Some(referer.to_string());
                }
            }
        }
        None
    }
}

impl Inspector for CsrfInspector {
    fn name(&self) -> &str {
        "csrf"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if !is_unsafe_method(&ctx.method) {
            return Ok(None);
        }
        Ok(self.inspect_unsafe(ctx))
    }
}

fn is_unsafe_method(method: &str) -> bool {
    matches!(
        method.to_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Extract the host from an absolute URL (`https://host/path`).
fn host_of_url(url: &str) -> Option<String> {
    let scheme = url.find("://")?;
    let after = &url[scheme + 3..];
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..end];
    let hostport = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let host = if hostport.starts_with('[') {
        hostport
            .find(']')
            .map(|i| &hostport[..=i])
            .unwrap_or(hostport)
    } else {
        match hostport.rfind(':') {
            Some(i) if !hostport[i + 1..].is_empty() => &hostport[..i],
            _ => hostport,
        }
    };
    if host.is_empty() {
        None
    } else {
        Some(host.trim_end_matches('.').to_lowercase())
    }
}

/// Same-site when the hosts are equal, or when one is a subdomain of the other.
fn same_site(a: &str, b: &str) -> bool {
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn ctx(method: &str, host: &str, headers: &[(&str, &str)], cookie: bool) -> RequestContext {
        let mut r = HttpRequest::new(method, "/account/settings");
        r.host = host.to_string();
        for (k, v) in headers {
            r.header.add(k, *v);
        }
        if cookie {
            r.header.add("Cookie", "session=abc123");
        }
        RequestContext::new(r)
    }

    fn inspect(mut c: RequestContext, opts: CsrfOptions) -> Option<Decision> {
        CsrfInspector::new(false, opts).inspect(&mut c).unwrap()
    }

    #[test]
    fn cross_site_post_with_cookie_and_no_token_blocked() {
        let c = ctx(
            "POST",
            "myapp.example",
            &[("Origin", "https://evil.example")],
            true,
        );
        let d = inspect(c, CsrfOptions::default()).unwrap();
        assert_eq!(d.action, Action::Block);
        assert_eq!(d.rule_id, "CSRF001");
    }

    #[test]
    fn cross_site_post_with_token_is_allowed() {
        let c = ctx(
            "POST",
            "myapp.example",
            &[("Origin", "https://evil.example"), ("X-CSRF-Token", "abc")],
            true,
        );
        assert!(inspect(c, CsrfOptions::default()).is_none());
    }

    #[test]
    fn same_origin_post_without_token_is_soft() {
        let c = ctx(
            "POST",
            "myapp.example",
            &[("Origin", "https://myapp.example")],
            true,
        );
        let d = inspect(c, CsrfOptions::default()).unwrap();
        assert_eq!(d.action, Action::Monitor);
        assert_eq!(d.rule_id, "CSRF002");
    }

    #[test]
    fn get_is_never_flagged() {
        let c = ctx(
            "GET",
            "myapp.example",
            &[("Origin", "https://evil.example")],
            true,
        );
        assert!(inspect(c, CsrfOptions::default()).is_none());
    }

    #[test]
    fn no_cookie_means_no_csrf() {
        let c = ctx(
            "POST",
            "myapp.example",
            &[("Origin", "https://evil.example")],
            false,
        );
        assert!(inspect(c, CsrfOptions::default()).is_none());
    }

    #[test]
    fn referer_used_when_origin_absent() {
        let c = ctx(
            "POST",
            "myapp.example",
            &[("Referer", "https://evil.example/page")],
            true,
        );
        let d = inspect(c, CsrfOptions::default()).unwrap();
        assert_eq!(d.rule_id, "CSRF001");
    }

    #[test]
    fn same_site_cookie_option_skips_cross_site_rule() {
        let c = ctx(
            "POST",
            "myapp.example",
            &[("Origin", "https://evil.example")],
            true,
        );
        let opts = CsrfOptions {
            block: false,
            same_site_cookie: true,
        };
        let d = inspect(c, opts).unwrap();
        // Falls through to the soft, monitored case instead of blocking.
        assert_eq!(d.action, Action::Monitor);
        assert_eq!(d.rule_id, "CSRF002");
    }

    #[test]
    fn subdomain_is_same_site() {
        let c = ctx(
            "POST",
            "myapp.example",
            &[("Origin", "https://api.myapp.example")],
            true,
        );
        let d = inspect(c, CsrfOptions::default()).unwrap();
        assert_eq!(d.rule_id, "CSRF002"); // soft, not cross-site
    }

    #[test]
    fn json_client_without_cookie_passes() {
        // A mobile/API client sets no cookie and sends no Origin; it must pass.
        let mut r = HttpRequest::new("POST", "/api/v1/items");
        r.host = "api.example".to_string();
        r.header.add("Content-Type", "application/json");
        let c = RequestContext::new(r);
        assert!(inspect(c, CsrfOptions::default()).is_none());
    }
}
