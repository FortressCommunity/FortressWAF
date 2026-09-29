//! The WAF request pipeline: the decision switch, block/challenge pages, and
//! the helpers the proxy handler uses.
//!
//! Port of the `wafHandler.ServeHTTP` decision logic and the pure helpers in
//! `cmd/proxy/main.go` (`writeBlockedResponse`, `blockPage`, `challengePage`,
//! `clientWantsJSON`, `isSensitiveHeader`, `bestPayload`, `recordRequest`,
//! `collectTraining`, `applyAutoBan`).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fwaf_core::action::{Action, Decision};
use fwaf_core::context::RequestContext;
use fwaf_core::engine::Engine;
use fwaf_services::blocklist::Store;
use fwaf_services::traincorpus::Collector;
use fwaf_services::uaparse;

/// Global request counters, mirroring the Go package-level atomics.
#[derive(Default)]
pub struct Metrics {
    pub total_requests: AtomicI64,
    pub blocked_requests: AtomicI64,
    pub allowed_requests: AtomicI64,
    pub excluded_requests: AtomicI64,
    pub challenged_reqs: AtomicI64,
    pub rate_limited_reqs: AtomicI64,
    pub monitored_reqs: AtomicI64,
    pub active_conns: AtomicI64,
    pub bytes_sent: AtomicI64,
    pub bytes_received: AtomicI64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn inc(&self, c: &AtomicI64) {
        c.fetch_add(1, Ordering::SeqCst);
    }
    pub fn get(&self, c: &AtomicI64) -> i64 {
        c.load(Ordering::SeqCst)
    }
}

/// What the pipeline decided to do with a request.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Forward to the upstream (with optional response headers already set).
    Forward { headers: Vec<(String, String)> },
    /// Reply with a block page/JSON (status 403).
    Blocked { decision: Decision },
    /// Reply with a challenge page (status 403).
    Challenge { html: String },
    /// Reply with a rate-limit JSON (status 429).
    RateLimited,
    /// No site configured (status 502).
    NoSite,
    /// The request was banned (status 403, BAN001).
    Banned,
}

/// The result of inspecting a request in the pipeline.
pub struct PipelineResult {
    pub outcome: Outcome,
    /// Headers to set on every reply (X-FortressWAF-*).
    pub response_headers: Vec<(String, String)>,
    /// If a ban was requested, the (ip, duration, rule_id, rule_name) to apply.
    pub ban: Option<BanRequest>,
}

#[derive(Debug, Clone)]
pub struct BanRequest {
    pub ip: String,
    pub duration: Duration,
    pub rule_id: String,
    pub rule_name: String,
}

/// Port of `isSensitiveHeader`.
pub fn is_sensitive_header(name: &str) -> bool {
    let n = name.to_lowercase();
    match n.as_str() {
        "authorization"
        | "proxy-authorization"
        | "cookie"
        | "set-cookie"
        | "x-api-key"
        | "x-auth-token"
        | "x-access-token"
        | "x-csrf-token"
        | "x-xsrf-token"
        | "x-session-token"
        | "x-forwarded-authorization" => return true,
        _ => {}
    }
    for marker in [
        "token",
        "secret",
        "password",
        "passwd",
        "api-key",
        "apikey",
        "auth",
        "credential",
        "session",
        "cookie",
    ] {
        if n.contains(marker) {
            return true;
        }
    }
    false
}

/// Port of `bestPayload`: the longest decoded query value, else a small POST
/// body, else the raw query, else the decision evidence.
pub fn best_payload(ctx: &RequestContext, decision: &Decision) -> String {
    let mut best = String::new();
    for vals in ctx.query_params.values() {
        for v in vals {
            if v.len() > best.len() {
                best = v.clone();
            }
        }
    }
    if !best.is_empty() {
        return best;
    }
    if ctx.method == "POST"
        && ctx.request.content_length > 0
        && ctx.request.content_length <= 4096
        && !ctx.body.is_empty()
    {
        return String::from_utf8_lossy(&ctx.body).into_owned();
    }
    if !ctx.request.raw_query.is_empty() {
        return ctx.request.raw_query.clone();
    }
    decision.evidence.clone()
}

/// Port of `clientWantsJSON`.
pub fn client_wants_json(ctx: &RequestContext) -> bool {
    let accept = ctx.request_header("Accept");
    if accept.contains("text/html") {
        return false;
    }
    if accept.contains("application/json") {
        return true;
    }
    if ctx
        .request_header("Content-Type")
        .contains("application/json")
    {
        return true;
    }
    if ctx.request_header("X-Requested-With") == "XMLHttpRequest" {
        return true;
    }
    false
}

/// The request id to show on a block page or in a block JSON body.
///
/// Prefer a client-supplied `X-Request-ID` for correlation when present;
/// otherwise fall back to the WAF-generated id (`ctx.request_id`), which is the
/// same id written to the audit log. Using only the header left this field
/// blank for every ordinary client, which is what a browser is.
pub fn block_request_id(ctx: &RequestContext) -> String {
    let header = ctx.request_header("X-Request-ID");
    if !header.is_empty() {
        header.to_string()
    } else {
        ctx.request_id.clone()
    }
}

/// Which kind of stop the client hit.
///
/// A ban, a flood, an attack match and a scanner are four different facts, and
/// the page has to say which one it is. Collapsing them into one generic
/// "blocked" page tells the client nothing and reads as a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    /// The address is on the operator ban list (a standing decision).
    Banned,
    /// A per-IP or per-endpoint rate limit was crossed (a flood).
    Flood,
    /// A request value matched an attack signature (SQLi, XSS, RCE, traversal).
    Attack,
    /// The client identified itself as known automation (scanner, bot tool).
    Automation,
    /// A challenge was issued; a real browser clears it, automation does not.
    Challenge,
}

impl StopKind {
    /// Classify a decision by its rule id. Rule-id prefixes are the stable
    /// contract here: they are what the audit log and the corpus test key on.
    pub fn from_decision(decision: &Decision) -> StopKind {
        let id = decision.rule_id.as_str();
        if id == "BAN001" || id.starts_with("BAN") {
            StopKind::Banned
        } else if id.starts_with("DDoS") || id.starts_with("GRPC") || id == "RATE" {
            StopKind::Flood
        } else if id.starts_with("BOT") || id.starts_with("JA3") {
            StopKind::Automation
        } else if decision.action == Action::Challenge {
            StopKind::Challenge
        } else {
            StopKind::Attack
        }
    }

    /// Plain words for the class of attempt, never the raw rule id. Rule ids
    /// are operator vocabulary; `SQLI016` means nothing to the client.
    fn attempt_label(self) -> &'static str {
        match self {
            StopKind::Banned => "address on the ban list",
            StopKind::Flood => "rate limit",
            StopKind::Attack => "attack signature",
            StopKind::Automation => "automation signature",
            StopKind::Challenge => "challenge",
        }
    }
}

/// The one-line, human name for a matched rule, used in the page's status line.
/// Falls back to the class name when the decision carries no rule name.
fn attempt_label(decision: &Decision) -> String {
    if !decision.rule_name.is_empty() {
        decision.rule_name.clone()
    } else {
        StopKind::from_decision(decision)
            .attempt_label()
            .to_string()
    }
}

/// Render the calm-sentinel copy for a stop, as (headline, lead, detail).
///
/// One reason per line: the headline states the fact, the lead says what the
/// WAF did with it, and the detail gives the client the one thing that is
/// genuinely useful to it. No threats the WAF cannot substantiate, no numbers
/// it does not hold.
pub fn stop_copy(kind: StopKind) -> (&'static str, &'static str, &'static str) {
    match kind {
        StopKind::Banned => (
            "This address is not being served",
            "Requests from this address are refused at the edge. This is a standing \
             decision, not a verdict on this one request, so retrying will not change it.",
            "If you believe the address was added in error, give the operator the request \
             id below. It is the same id written to the audit log.",
        ),
        StopKind::Flood => (
            "This address is sending too fast",
            "The request rate from this address crossed a configured limit. The WAF is \
             pacing it rather than blocking it outright.",
            "Wait for the interval shown, then resume at a lower rate. A steady client \
             never reaches this limit.",
        ),
        StopKind::Attack => (
            "This request carried an attack signature",
            "A value in this request matched a known attack pattern, so it was not \
             forwarded. The match is on the request, not on you as a client.",
            "If this was ordinary input, quote the request id below. The operator can see \
             exactly which value matched.",
        ),
        StopKind::Automation => (
            "This client identified itself as automation",
            "The User-Agent matches a known scanning or bot tool, so the request was held \
             at the edge before it reached the application.",
            "Automated clients that should be allowed need an allow-listed address on the \
             WAF, not a different User-Agent.",
        ),
        StopKind::Challenge => (
            "A quick check is required",
            "A real browser clears this on its own in a moment. Nothing needs to be typed \
             or clicked.",
            "Automated clients cannot complete this check; route them through an \
             allow-listed address instead.",
        ),
    }
}

/// The identity motif: a short status line every page carries, naming the WAF
/// and the request id. It is the one element shared by block and challenge
/// pages, so both surfaces speak in the same voice.
fn sentinel_status_line(ctx: &RequestContext) -> String {
    format!(
        r#"<p class="sentinel">FortressWAF recorded this as <code>{id}</code></p>"#,
        id = html_escape(&block_request_id(ctx))
    )
}

/// The rate-limit page. Like [`block_page`], but it can state the real limit
/// and the real wait, which are the only two numbers the client can act on.
/// Both come from the caller, never from a literal in the markup.
pub fn flood_page(ctx: &RequestContext, limit: i32, retry_after_secs: i64) -> String {
    let (headline, lead, detail) = stop_copy(StopKind::Flood);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{headline}</title>
<style>
{css}</style>
</head>
<body>
<main class="card" aria-labelledby="stop-title">
  <h1 id="stop-title">{headline}</h1>
  <p class="lead">{lead}</p>
  <p>{detail}</p>
  <p class="meta">Limit: {limit} requests per second from this address</p>
  <p class="meta">Retry after: {retry_after} seconds</p>
  {status}
</main>
</body>
</html>"#,
        css = crate::tokens::base_page_css(),
        headline = html_escape(headline),
        lead = html_escape(lead),
        detail = html_escape(detail),
        limit = limit,
        retry_after = retry_after_secs,
        status = sentinel_status_line(ctx),
    )
}

/// The FortressWAF block page, rendered per stop kind.
///
/// Rendered from the token spine ([`crate::tokens`]): semantic CSS custom
/// properties, both light and dark modes, WCAG AA contrast, a `<main>` landmark,
/// and HTML-escaped values so a crafted rule name or path cannot inject markup.
///
/// Anti-slop notes (one reason per decision):
/// - No eyebrow badge: the outcome is already the H1, so a pill restating it
///   would be decoration.
/// - The headline, lead and detail come from [`stop_copy`], so a ban, a flood
///   and an attack match each read differently instead of sharing one template.
/// - The one repeated element is the sentinel status line, which gives the
///   block and challenge pages a shared identity.
pub fn block_page(ctx: &RequestContext, decision: &Decision) -> String {
    let kind = StopKind::from_decision(decision);
    let (headline, lead, detail) = stop_copy(kind);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{headline}</title>
<style>
{css}</style>
</head>
<body>
<main class="card" aria-labelledby="stop-title">
  <h1 id="stop-title">{headline}</h1>
  <p class="lead">{lead}</p>
  <p>{detail}</p>
  <p class="meta">Matched: {attempt}</p>
  <p class="meta">Path: {path}</p>
  {status}
</main>
</body>
</html>"#,
        css = crate::tokens::base_page_css(),
        headline = html_escape(headline),
        lead = html_escape(lead),
        detail = html_escape(detail),
        attempt = html_escape(&attempt_label(decision)),
        path = html_escape(&ctx.path),
        status = sentinel_status_line(ctx),
    )
}

/// The FortressWAF challenge interstitial.
///
/// Shares the sentinel motif with the block page (same status line, same
/// vocabulary). The copy states why a browser passes on its own, which is the
/// only thing the client needs to know, and the `<noscript>` fallback keeps the
/// manual control usable when JavaScript is off.
pub fn challenge_page(ctx: &RequestContext) -> String {
    let mut token_bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut token_bytes);
    let challenge_token: String = token_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let now = unix_now();
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Quick check</title>
<style>
{css}.card{{text-align:center}}</style>
</head>
<body>
<main class="card" aria-labelledby="challenge-title" aria-busy="true">
  <h1 id="challenge-title">A quick check is required</h1>
  <p class="lead">A real browser clears this on its own in a moment. Nothing needs
     to be typed or clicked.</p>
  <form id="cf-form" action="/__challenge" method="POST">
    <input type="hidden" name="challenge_token" value="{token}">
    <input type="hidden" name="original_path" value="{path}">
  </form>
  <noscript>
    <p>JavaScript is off, so this check cannot run on its own.</p>
    <button type="submit" form="cf-form">Continue without JavaScript</button>
  </noscript>
  {status}
</main>
<script>
setTimeout(function(){{
  var elapsed = (Date.now() / 1000 | 0) - {now};
  if (elapsed > 2) {{
    document.getElementById("cf-form").submit();
  }}
}}, 2500);
</script>
</body>
</html>"#,
        css = crate::tokens::base_page_css(),
        token = challenge_token,
        path = html_escape(&ctx.path),
        now = now,
        status = sentinel_status_line(ctx),
    )
}

/// Minimal HTML escaping matching Go's `html.EscapeString` for the five
/// characters it replaces.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// The core decision switch. Mirrors the Go `ServeHTTP` after the engine has
/// inspected the request.
pub fn decide(outcome_headers: Vec<(String, String)>, decision: &Decision) -> PipelineResult {
    match decision.action {
        Action::Block => PipelineResult {
            outcome: Outcome::Blocked {
                decision: decision.clone(),
            },
            response_headers: vec![
                ("X-FortressWAF-Action".to_string(), "block".to_string()),
                ("X-FortressWAF-Rule".to_string(), decision.rule_id.clone()),
            ],
            ban: ban_from(decision),
        },
        Action::Challenge => PipelineResult {
            outcome: Outcome::Challenge {
                html: String::new(), // filled by caller with the request context
            },
            response_headers: vec![("X-FortressWAF-Action".to_string(), "challenge".to_string())],
            ban: ban_from(decision),
        },
        Action::Monitor => PipelineResult {
            outcome: Outcome::Forward {
                headers: outcome_headers,
            },
            response_headers: vec![
                ("X-FortressWAF-Monitored".to_string(), "true".to_string()),
                ("X-FortressWAF-Rule".to_string(), decision.rule_id.clone()),
            ],
            ban: ban_from(decision),
        },
        Action::RateLimit => PipelineResult {
            outcome: Outcome::RateLimited,
            response_headers: vec![("X-FortressWAF-Action".to_string(), "rate_limit".to_string())],
            ban: ban_from(decision),
        },
        Action::Allow => PipelineResult {
            outcome: Outcome::Forward {
                headers: outcome_headers,
            },
            response_headers: vec![],
            ban: ban_from(decision),
        },
    }
}

fn ban_from(decision: &Decision) -> Option<BanRequest> {
    if !decision.ban_request {
        return None;
    }
    Some(BanRequest {
        ip: String::new(),
        duration: decision.ban_duration,
        rule_id: decision.rule_id.clone(),
        rule_name: decision.rule_name.clone(),
    })
}

/// Port of `applyAutoBan`: skip loopback/trusted-proxy/invalid, default the
/// duration to 10m, and ban idempotently.
pub fn should_auto_ban(engine: &Engine, ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    let parsed: std::net::IpAddr = match ip.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if parsed.is_loopback() {
        return false;
    }
    if engine.is_trusted_proxy(ip) {
        return false;
    }
    true
}

/// Apply an auto-ban to the store. Returns whether a ban was recorded.
pub fn apply_auto_ban(store: &Store, engine: &Engine, ip: &str, ban: &BanRequest) -> bool {
    if !should_auto_ban(engine, ip) {
        return false;
    }
    let dur = if ban.duration.as_secs() == 0 {
        Duration::from_secs(600)
    } else {
        ban.duration
    };
    store
        .ban(
            ip,
            &format!("auto: {} {}", ban.rule_id, ban.rule_name),
            "waf",
            dur,
        )
        .is_ok()
}

/// Offer a high-confidence block to the corpus collector. Port of
/// `collectTraining`.
pub fn collect_training(
    trainer: &Collector,
    ctx: &RequestContext,
    decision: &Decision,
    client_ip: &str,
) -> bool {
    if !trainer.enabled() {
        return false;
    }
    let payload = best_payload(ctx, decision);
    if payload.is_empty() {
        return false;
    }
    let sample = fwaf_services::traincorpus::Sample {
        rule_id: decision.rule_id.clone(),
        category: String::new(),
        payload,
        source: decision.inspector_name.clone(),
        actor_ip: client_ip.to_string(),
        score: decision.score,
        observed_at: rfc3339_now(),
    };
    trainer.consider(&sample).0
}

/// Build the audit headers map for a request (redacting sensitive headers).
/// Port of the header-collection part of `recordRequest`.
pub fn audit_headers(ctx: &RequestContext) -> std::collections::BTreeMap<String, String> {
    let mut headers = std::collections::BTreeMap::new();
    for (k, v) in &ctx.headers {
        if is_sensitive_header(k) {
            headers.insert(k.clone(), "[redacted]".to_string());
            continue;
        }
        headers.insert(k.clone(), v.clone());
    }
    headers
}

/// Parse a UA for audit attribution. Port of the uaparse call in
/// `recordRequest`.
pub fn parse_ua_flags(ua: &str) -> (String, String) {
    let info = uaparse::parse(ua);
    (info.browser, info.device)
}

/// Minimal `net.SplitHostPort` for the `host:port` / `[v6]:port` forms.
pub fn split_host_port(addr: &str) -> Option<(String, String)> {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            if let Some(port) = after.strip_prefix(':') {
                return Some((host.to_string(), port.to_string()));
            }
            return None;
        }
        return None;
    }
    let colon = addr.rfind(':')?;
    let host = &addr[..colon];
    let port = &addr[colon + 1..];
    if host.is_empty() || port.is_empty() || host.contains(':') {
        return None;
    }
    Some((host.to_string(), port.to_string()))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn rfc3339_now() -> String {
    let secs = unix_now().max(0) as u64;
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
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwaf_core::http::HttpRequest;

    fn ctx() -> RequestContext {
        let mut r = HttpRequest::new("GET", "/x?id=1");
        r.raw_query = "id=1".to_string();
        r.header.add("Accept", "text/html");
        RequestContext::new(r)
    }

    #[test]
    fn sensitive_headers_redacted() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("X-API-Key"));
        assert!(is_sensitive_header("Set-Cookie"));
        assert!(is_sensitive_header("X-My-Token"));
        assert!(!is_sensitive_header("Accept"));
        assert!(!is_sensitive_header("User-Agent"));
    }

    #[test]
    fn client_wants_json_logic() {
        let mut c = ctx();
        assert!(!client_wants_json(&c)); // Accept: text/html
        c.request.header.set("Accept", "application/json");
        assert!(client_wants_json(&c));
        c.request.header.set("Accept", "*/*");
        c.request.header.set("X-Requested-With", "XMLHttpRequest");
        assert!(client_wants_json(&c));
    }

    #[test]
    fn block_page_escapes_rule_name() {
        let c = ctx();
        let d = Decision::new(Action::Block, 90.0)
            .with_rule_id("XSS001")
            .with_rule_name("<script>alert</script>")
            .with_severity("critical");
        let page = block_page(&c, &d);
        // The rule NAME is what the page shows (the raw rule id is operator
        // vocabulary and is deliberately not printed). It must be escaped.
        assert!(page.contains("&lt;script&gt;alert&lt;/script&gt;"));
        assert!(!page.contains("<script>alert</script>"));
    }

    #[test]
    fn block_page_shows_a_request_id_without_a_client_header() {
        // Regression: the page used to render only the client's X-Request-ID
        // header, which is absent for ordinary browsers, so the field was
        // blank. It must fall back to the WAF-generated id.
        let c = ctx();
        assert_eq!(c.request_header("X-Request-ID"), "");
        let d = Decision::new(Action::Block, 90.0)
            .with_rule_id("SQLI016")
            .with_severity("high");
        let page = block_page(&c, &d);
        // The generated id appears in the page, and the field is not empty.
        assert!(
            page.contains(&c.request_id) && !c.request_id.is_empty(),
            "block page must contain the generated request id"
        );
        assert!(
            page.contains("class=\"sentinel\""),
            "the sentinel status line is the shared identity motif"
        );
    }

    #[test]
    fn each_stop_kind_gets_its_own_copy() {
        let c = ctx();
        let kinds = [
            ("BAN001", "This address is not being served"),
            ("DDoS001", "This address is sending too fast"),
            ("SQLI016", "This request carried an attack signature"),
            ("BOT004", "This client identified itself as automation"),
        ];
        let mut headlines = std::collections::HashSet::new();
        for (rule_id, expected_headline) in kinds {
            let d = Decision::new(Action::Block, 90.0).with_rule_id(rule_id);
            let page = block_page(&c, &d);
            assert!(
                page.contains(expected_headline),
                "rule {rule_id} should render its own headline"
            );
            headlines.insert(expected_headline);
        }
        assert_eq!(headlines.len(), kinds.len(), "copy must differ per kind");
    }

    #[test]
    fn block_page_has_no_eyebrow_badge() {
        // The outcome is the H1; a pill above it restating the H1 is decoration.
        let c = ctx();
        let d = Decision::new(Action::Block, 90.0).with_rule_id("SQLI016");
        let page = block_page(&c, &d);
        assert!(!page.contains("class=\"badge\""), "no eyebrow badge");
        assert!(!page.contains("uppercase"), "no uppercase eyebrow");
    }

    #[test]
    fn block_page_does_not_leak_raw_severity() {
        let c = ctx();
        let d = Decision::new(Action::Block, 90.0)
            .with_rule_id("SQLI016")
            .with_severity("critical");
        let page = block_page(&c, &d);
        assert!(
            !page.contains("critical"),
            "the raw internal severity vocabulary must not reach the client"
        );
    }

    #[test]
    fn flood_page_states_the_real_limit() {
        let c = ctx();
        let page = flood_page(&c, 30, 60);
        assert!(page.contains("30 requests per second"));
        assert!(page.contains("Retry after: 60 seconds"));
        // It carries the shared sentinel motif too.
        assert!(page.contains("class=\"sentinel\""));
        assert!(page.contains(&c.request_id));
    }

    #[test]
    fn challenge_page_shares_the_sentinel_motif() {
        let c = ctx();
        let page = challenge_page(&c);
        assert!(page.contains("class=\"sentinel\""));
        assert!(page.contains("A real browser clears this on its own"));
    }

    #[test]
    fn stop_kind_classification() {
        let k =
            |id: &str| StopKind::from_decision(&Decision::new(Action::Block, 1.0).with_rule_id(id));
        assert_eq!(k("BAN001"), StopKind::Banned);
        assert_eq!(k("DDoS001"), StopKind::Flood);
        assert_eq!(k("GRPC001"), StopKind::Flood);
        assert_eq!(k("BOT004"), StopKind::Automation);
        assert_eq!(k("JA3_001"), StopKind::Automation);
        assert_eq!(k("SQLI016"), StopKind::Attack);
        assert_eq!(k("RCE005"), StopKind::Attack);
    }

    #[test]
    fn block_request_id_prefers_the_client_header() {
        let mut r = fwaf_core::http::HttpRequest::new("GET", "/x");
        r.raw_query = String::new();
        r.header.add("X-Request-ID", "caller-abc-123");
        let c = RequestContext::new(r);
        assert_eq!(block_request_id(&c), "caller-abc-123");
    }

    #[test]
    fn block_request_id_falls_back_to_generated() {
        let c = ctx();
        assert_eq!(block_request_id(&c), c.request_id);
        assert!(!block_request_id(&c).is_empty());
    }

    #[test]
    fn challenge_page_has_token() {
        let c = ctx();
        let page = challenge_page(&c);
        assert!(page.contains("challenge_token"));
        assert!(page.contains("/x?id=1"));
    }

    #[test]
    fn block_decision_sets_headers() {
        let d = Decision::new(Action::Block, 90.0).with_rule_id("SQLI001");
        let r = decide(vec![], &d);
        assert!(matches!(r.outcome, Outcome::Blocked { .. }));
        assert!(r
            .response_headers
            .iter()
            .any(|(k, v)| k == "X-FortressWAF-Action" && v == "block"));
        assert!(r
            .response_headers
            .iter()
            .any(|(k, v)| k == "X-FortressWAF-Rule" && v == "SQLI001"));
    }

    #[test]
    fn rate_limit_outcome() {
        let d = Decision::new(Action::RateLimit, 60.0);
        let r = decide(vec![], &d);
        assert_eq!(r.outcome, Outcome::RateLimited);
    }

    #[test]
    fn monitor_outcome_forwards_with_header() {
        let d = Decision::new(Action::Monitor, 20.0).with_rule_id("BOT006");
        let r = decide(vec![], &d);
        assert!(matches!(r.outcome, Outcome::Forward { .. }));
        assert!(r
            .response_headers
            .iter()
            .any(|(k, v)| k == "X-FortressWAF-Monitored" && v == "true"));
    }

    #[test]
    fn auto_ban_skips_loopback_and_invalid() {
        let cfg = fwaf_config::default_config();
        let e = fwaf_core::engine::Engine::new(fwaf_core::engine::EngineConfig::default());
        assert!(!should_auto_ban(&e, "127.0.0.1"));
        assert!(!should_auto_ban(&e, "not-an-ip"));
        assert!(!should_auto_ban(&e, ""));
        let _ = cfg;
        assert!(should_auto_ban(&e, "1.2.3.4"));
    }

    #[test]
    fn best_payload_prefers_longest_query_value() {
        let mut r = HttpRequest::new("GET", "/x");
        r.raw_query = "a=short&b=aVeryLongPayloadValue12345".to_string();
        let c = RequestContext::new(r);
        let d = Decision::new(Action::Block, 90.0);
        assert_eq!(best_payload(&c, &d), "aVeryLongPayloadValue12345");
    }
}
