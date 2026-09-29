//! Bot detection: good-bot verification, headless/bad-bot signatures, honeypot
//! fields, browser-feature heuristics, and repeat-offender auto-ban.
//!
//! Port of `internal/engine/bot.go`. Signatures, rule IDs, scores and the
//! auto-ban semantics are preserved exactly.
//!
//! ## Deviation (documented, not silently changed)
//!
//! `verifyGoodBot` in Go calls `net.LookupAddr` (a blocking reverse-DNS PTR
//! lookup) and matches the PTR name against the good-bot names. Rust's `std`
//! has no DNS resolver and this port does not add a DNS dependency, so the
//! resolver is injected via the [`ReverseDnsResolver`] trait. The default,
//! [`NoReverseDns`], returns no names -- which makes every good-bot UA
//! "unverified" and returns BOT002 (Challenge), exactly what Go does when the
//! lookup errors or returns no names. A production deployment wires in a real
//! resolver implementing the trait. See `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use tracing::debug;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::counter::SlidingWindowCounter;
use crate::engine::{EngineError, Inspector};

/// Reverse-DNS resolution, abstracted so the port does not depend on a C
/// resolver or a specific DNS crate.
pub trait ReverseDnsResolver: Send + Sync {
    /// Return PTR names for the address, or an empty vec on failure.
    fn lookup_addr(&self, ip: &str) -> Vec<String>;
}

/// Default resolver: no DNS. Good bots are treated as unverified (BOT002),
/// matching Go's behaviour when the lookup fails.
pub struct NoReverseDns;

impl ReverseDnsResolver for NoReverseDns {
    fn lookup_addr(&self, _ip: &str) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BotOptions {
    /// Bot-like requests per IP within the window before auto-ban. `0` uses the
    /// default (5); a negative value disables the counter and its ban.
    pub auto_ban_after: i32,
    pub auto_ban_window: Option<Duration>,
    pub auto_ban_duration: Option<Duration>,
}

impl Default for BotOptions {
    fn default() -> Self {
        BotOptions {
            auto_ban_after: 0,
            auto_ban_window: None,
            auto_ban_duration: None,
        }
    }
}

struct GoodBot {
    name: &'static str,
    re: Regex,
}

struct Patterns {
    good_bots: Vec<GoodBot>,
    bad_bots: Vec<Regex>,
    headless: Vec<Regex>,
}

fn compile(raw: &[&str]) -> Vec<Regex> {
    raw.iter()
        .map(|r| Regex::new(r).expect("valid bot pattern"))
        .collect()
}

fn patterns() -> &'static Patterns {
    static P: Lazy<Patterns> = Lazy::new(|| {
        let gb = |name: &'static str, re: &str| GoodBot {
            name,
            re: Regex::new(re).unwrap(),
        };
        Patterns {
            good_bots: vec![
                gb(
                    "googlebot",
                    r"(?i)googlebot|google(?:-mobile|bot|adsense|structured-data|cloud-platform)",
                ),
                gb("bingbot", r"(?i)bingbot|msnbot|bingpreview"),
                gb(
                    "yandexbot",
                    r"(?i)yandexbot|yandeximages|yandexmetrika|yandexwebmaster",
                ),
                gb("slurp", r"(?i)yahoo!\s+slurp|yahooseeker"),
                gb("baiduspider", r"(?i)baiduspider|baidugame"),
                gb("duckduckbot", r"(?i)duckduckbot"),
                gb(
                    "facebookbot",
                    r"(?i)facebookexternalhit|facebookcatalog|facebot",
                ),
                gb("twitterbot", r"(?i)twitterbot"),
                gb("linkedinbot", r"(?i)linkedinbot"),
                gb("slackbot", r"(?i)slackbot|slack-link-expand"),
                gb("discordbot", r"(?i)discordbot"),
                gb("telegrambot", r"(?i)telegrambot"),
                gb("applebot", r"(?i)applebot"),
                gb("semrushbot", r"(?i)semrushbot"),
                gb("ahrefsbot", r"(?i)ahrefsbot"),
                gb("majestic", r"(?i)majestic-seo"),
                gb("pinterest", r"(?i)pinterest"),
                gb("cloudflare", r"(?i)cloudflare"),
                gb("adidxbot", r"(?i)adidxbot"),
                gb("apple-pubsub", r"(?i)apple-pubsub"),
                gb("zgrab", r"(?i)zgrab"),
            ],
            bad_bots: compile(&[
                r"(?i)\bmasscan\b",
                r"(?i)\bnmap\b",
                r"(?i)\bnessus\b",
                r"(?i)\bopenvas\b",
                r"(?i)\bnikto\b",
                r"(?i)\bsqlmap\b",
                r"(?i)\bdirbuster\b",
                r"(?i)\bgobuster\b",
                r"(?i)\bwpscan\b",
                r"(?i)\bjoomscan\b",
                r"(?i)\bdroopescan\b",
                r"(?i)\bacunetix\b",
                r"(?i)\bnetsparker\b",
                r"(?i)\bappscan\b",
                r"(?i)\bw3af\b",
                r"(?i)\bburpsuite\b",
                r"(?i)\bzap\b",
                r"(?i)\bparos\b",
                r"(?i)\bwebinspect\b",
                r"(?i)\bzgrab\b",
                r"(?i)\bzmap\b",
                r"(?i)\bmassdns\b",
                r"(?i)\bhydra\b",
                r"(?i)\bwfuzz\b",
                r"(?i)\bferoxbuster\b",
                r"(?i)\bffuf\b",
                r"(?i)\bnuclei\b",
                r"(?i)\bcommix\b",
                r"(?i)\bxray\b",
                r"(?i)\bwhatweb\b",
            ]),
            headless: compile(&[
                r"(?i)headless",
                r"(?i)puppeteer",
                r"(?i)playwright",
                r"(?i)selenium",
                r"(?i)phantomjs",
                r"(?i)htmlunit",
                r"(?i)phantom",
                r"(?i)chromium-headless",
            ]),
        }
    });
    &P
}

const HONEYPOT_FIELDS: &[&str] = &[
    "hp_",
    "honeypot",
    "botfield",
    "bot_field",
    "nocomment",
    "leaveblank",
    "dontfill",
    "do_not_fill",
    "trapfield",
    "trap_field",
    "hidden_field_for_bots",
];

pub struct BotDetector {
    pub dev_mode: bool,
    auto_ban_after: i32,
    auto_ban_window: Duration,
    auto_ban_duration: Duration,
    bot_hits: Mutex<HashMap<String, Arc<SlidingWindowCounter>>>,
    last_cleanup: Mutex<Instant>,
    resolver: Arc<dyn ReverseDnsResolver>,
}

impl BotDetector {
    pub fn new(dev_mode: bool) -> Self {
        Self::with_options(dev_mode, BotOptions::default(), Arc::new(NoReverseDns))
    }

    pub fn new_with_resolver(dev_mode: bool, resolver: Arc<dyn ReverseDnsResolver>) -> Self {
        Self::with_options(dev_mode, BotOptions::default(), resolver)
    }

    pub fn with_options(
        dev_mode: bool,
        mut opts: BotOptions,
        resolver: Arc<dyn ReverseDnsResolver>,
    ) -> Self {
        if opts.auto_ban_after == 0 {
            opts.auto_ban_after = 5;
        }
        let auto_ban_window = match opts.auto_ban_window {
            Some(d) if !d.is_zero() => d,
            _ => Duration::from_secs(60),
        };
        let auto_ban_duration = match opts.auto_ban_duration {
            Some(d) if !d.is_zero() => d,
            _ => Duration::from_secs(600),
        };

        let _ = patterns();

        BotDetector {
            dev_mode,
            auto_ban_after: opts.auto_ban_after,
            auto_ban_window,
            auto_ban_duration,
            bot_hits: Mutex::new(HashMap::new()),
            last_cleanup: Mutex::new(Instant::now()),
            resolver,
        }
    }

    fn botlike(
        &self,
        ctx: &RequestContext,
        action: Action,
        rule_id: &str,
        name: &str,
        severity: &str,
        score: f64,
        evidence: String,
    ) -> Decision {
        self.botlike_decision(
            ctx,
            Decision::new(action, score)
                .with_rule_id(rule_id)
                .with_rule_name(name)
                .with_severity(severity)
                .with_evidence(evidence),
        )
    }

    fn botlike_decision(&self, ctx: &RequestContext, mut dec: Decision) -> Decision {
        if self.auto_ban_after < 0 || ctx.real_ip.is_empty() {
            return dec;
        }
        let count = self.record_bot_hit(&ctx.real_ip) as i32;
        if count >= self.auto_ban_after && !self.auto_ban_duration.is_zero() {
            dec.ban_request = true;
            dec.ban_duration = self.auto_ban_duration;
            dec.evidence = format!(
                "{} (bot-like request {}/{} in window)",
                dec.evidence, count, self.auto_ban_after
            );
        }
        dec
    }

    fn record_bot_hit(&self, ip: &str) -> usize {
        let now = Instant::now();
        {
            let mut last = self.last_cleanup.lock();
            if now.duration_since(*last) > Duration::from_secs(300) {
                let mut hits = self.bot_hits.lock();
                let cutoff = now.checked_sub(2 * self.auto_ban_window);
                hits.retain(|_, c| match (c.last_seen(), cutoff) {
                    (Some(t), Some(cut)) => t >= cut,
                    _ => true,
                });
                *last = now;
            }
        }

        let counter = {
            let mut hits = self.bot_hits.lock();
            hits.entry(ip.to_string())
                .or_insert_with(|| {
                    Arc::new(SlidingWindowCounter::new(
                        self.auto_ban_window,
                        (self.auto_ban_after + 1) as usize,
                    ))
                })
                .clone()
        };
        counter.record(now);
        counter.count()
    }

    fn detect_honeypot(&self, ctx: &RequestContext) -> Option<Decision> {
        for k in ctx.form_params.keys() {
            let lower = k.to_lowercase();
            for field in HONEYPOT_FIELDS {
                if lower.starts_with(field) || lower.contains(field) {
                    return Some(
                        Decision::new(Action::Block, 75.0)
                            .with_rule_id("BOT005")
                            .with_rule_name("Honeypot Field Triggered")
                            .with_severity("high")
                            .with_evidence(format!("honeypot field detected: {k}")),
                    );
                }
            }
        }
        None
    }

    fn detect_browser_features(&self, ctx: &RequestContext) -> Option<Decision> {
        let accept_lang = ctx
            .headers
            .get("Accept-Language")
            .cloned()
            .unwrap_or_default();
        if accept_lang.is_empty() {
            return Some(
                Decision::new(Action::Monitor, 15.0)
                    .with_rule_id("BOT006")
                    .with_rule_name("Missing Accept-Language")
                    .with_severity("low")
                    .with_evidence("no accept-language header from supposedly browser request"),
            );
        }

        let accept = ctx.headers.get("Accept").cloned().unwrap_or_default();
        if accept.is_empty() {
            return Some(
                Decision::new(Action::Monitor, 10.0)
                    .with_rule_id("BOT007")
                    .with_rule_name("Missing Accept Header")
                    .with_severity("low")
                    .with_evidence("no accept header from supposedly browser request"),
            );
        }

        None
    }

    fn verify_good_bot(&self, ctx: &RequestContext) -> bool {
        if !is_ip(&ctx.real_ip) {
            return false;
        }

        let names = self.resolver.lookup_addr(&ctx.real_ip);
        if names.is_empty() {
            return false;
        }

        let name = names[0].to_lowercase();
        for bot in &patterns().good_bots {
            if name.contains(bot.name) {
                return true;
            }
        }

        if self.dev_mode {
            debug!(
                ip = ctx.real_ip.as_str(),
                ptr = name.as_str(),
                ua = ctx.user_agent.as_str(),
                "good bot rDNS verification failed"
            );
        }

        false
    }

    /// Port of `GenerateJSChallenge`.
    pub fn generate_js_challenge(&self, ctx: &RequestContext) -> String {
        format!(
            r#"<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Challenge</title>
<script>
(function(){{
	var challenge = "{}";
	var result = "";
	var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
	for(var i=0;i<32;i++){{result+=chars.charAt(Math.floor(Math.random()*chars.length));}}
	document.cookie = "challenge="+result+":"+challenge+";path=/;max-age=300";
	window.location.reload();
}})();
</script>
<noscript><meta http-equiv="refresh" content="0;url=?noscript=1"></noscript>
</head><body>Checking your browser...</body></html>"#,
            ctx.request_id
        )
    }
}

impl Inspector for BotDetector {
    fn name(&self) -> &str {
        "bot_detector"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let ua = &ctx.user_agent;
        if ua.is_empty() {
            return Ok(Some(self.botlike(
                ctx,
                Action::Challenge,
                "BOT001",
                "Missing User-Agent",
                "medium",
                30.0,
                "request has no user-agent header".to_string(),
            )));
        }

        for bot in &patterns().good_bots {
            if bot.re.is_match(ua) {
                if !self.verify_good_bot(ctx) {
                    return Ok(Some(
                        Decision::new(Action::Challenge, 25.0)
                            .with_rule_id("BOT002")
                            .with_rule_name("Unverified Good Bot")
                            .with_severity("medium")
                            .with_evidence(format!("unverified good bot: {}", bot.name)),
                    ));
                }
                // Mirrors Go's `ctx.IsBot = true` for a verified good bot.
                ctx.is_bot = true;
                if self.dev_mode {
                    debug!(
                        bot = bot.name,
                        ip = ctx.real_ip.as_str(),
                        "verified good bot"
                    );
                }
                return Ok(None);
            }
        }

        for pattern in &patterns().headless {
            if pattern.is_match(ua) {
                return Ok(Some(self.botlike(
                    ctx,
                    Action::Block,
                    "BOT003",
                    "Headless Browser Detected",
                    "high",
                    70.0,
                    format!("headless browser pattern detected: {ua}"),
                )));
            }
        }

        for pattern in &patterns().bad_bots {
            if pattern.is_match(ua) {
                return Ok(Some(self.botlike(
                    ctx,
                    Action::Block,
                    "BOT004",
                    "Bad Bot Detected",
                    "high",
                    80.0,
                    format!("bad bot signature matched: {}", pattern.as_str()),
                )));
            }
        }

        if let Some(dec) = self.detect_honeypot(ctx) {
            return Ok(Some(self.botlike_decision(ctx, dec)));
        }

        if let Some(dec) = self.detect_browser_features(ctx) {
            return Ok(Some(dec));
        }

        Ok(None)
    }
}

/// Whether `ip` parses as a literal IP address (Go `net.ParseIP != nil`).
fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn req(ua: &str) -> RequestContext {
        let mut r = HttpRequest::new("GET", "/");
        r.remote_addr = "203.0.113.9:1234".to_string();
        r.header.add("User-Agent", ua);
        r.header.add("Accept-Language", "en");
        r.header.add("Accept", "*/*");
        RequestContext::new(r)
    }

    #[test]
    fn empty_ua_challenged() {
        let d = BotDetector::new(false);
        let r = HttpRequest::new("GET", "/");
        let mut ctx = RequestContext::new(r);
        let dec = d.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.action, Action::Challenge);
        assert_eq!(dec.rule_id, "BOT001");
    }

    #[test]
    fn sqlmap_blocked() {
        let d = BotDetector::new(false);
        let dec = {
            let mut c = req("sqlmap/1.7");
            d.inspect(&mut c).unwrap()
        }
        .unwrap();
        assert_eq!(dec.rule_id, "BOT004");
        assert_eq!(dec.action, Action::Block);
    }

    #[test]
    fn headless_blocked() {
        let d = BotDetector::new(false);
        let dec = {
            let mut c = req("Mozilla/5.0 HeadlessChrome/90");
            d.inspect(&mut c).unwrap()
        }
        .unwrap();
        assert_eq!(dec.rule_id, "BOT003");
    }

    #[test]
    fn curl_is_not_a_bad_bot() {
        let d = BotDetector::new(false);
        // curl is ordinary; only missing accept-language/accept will monitor.
        let dec = {
            let mut c = req("curl/8.0");
            d.inspect(&mut c).unwrap()
        };
        if let Some(dec) = dec {
            assert_ne!(dec.action, Action::Block);
        }
    }

    #[test]
    fn js_challenge_contains_request_id() {
        let d = BotDetector::new(false);
        let mut r = HttpRequest::new("GET", "/");
        r.remote_addr = "1.1.1.1:1".to_string();
        let ctx = RequestContext::new(r);
        let html = d.generate_js_challenge(&ctx);
        assert!(html.contains(&ctx.request_id));
    }

    #[test]
    fn repeat_offender_gets_auto_ban() {
        let d = BotDetector::with_options(
            false,
            BotOptions {
                auto_ban_after: 2,
                auto_ban_window: Some(Duration::from_secs(60)),
                auto_ban_duration: Some(Duration::from_secs(300)),
            },
            Arc::new(NoReverseDns),
        );
        let mut last = None;
        for _ in 0..3 {
            last = {
                let mut c = req("sqlmap/1.7");
                d.inspect(&mut c).unwrap()
            };
        }
        let dec = last.unwrap();
        assert!(dec.ban_request);
        assert_eq!(dec.ban_duration, Duration::from_secs(300));
    }
}
