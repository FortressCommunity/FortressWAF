//! DDoS / flood protection.
//!
//! Port of `internal/engine/ddos.go`. Thresholds, rule IDs, scores and the
//! check order are preserved exactly. The Go cleanup goroutine is replaced by
//! an explicit [`DdosProtection::cleanup`] call so callers control scheduling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::counter::SlidingWindowCounter;
use crate::engine::{EngineError, Inspector};

#[derive(Debug, Clone, Copy)]
pub struct DdosOptions {
    pub global_rate: i32,
    pub per_ip_rate: i32,
    pub per_endpoint_rate: i32,
    pub per_session_rate: i32,
    /// How long an address tripping the per-IP rate is banned. `None` means the
    /// default (10m); a negative duration means never auto-ban.
    pub per_ip_ban: Option<Duration>,
    /// Set to true when the caller explicitly passed a negative PerIPBan
    /// (disables auto-ban). Mirrors Go's `PerIPBan < 0` sentinel.
    pub per_ip_ban_disabled: bool,
}

impl Default for DdosOptions {
    fn default() -> Self {
        DdosOptions {
            global_rate: 0,
            per_ip_rate: 0,
            per_endpoint_rate: 0,
            per_session_rate: 0,
            per_ip_ban: None,
            per_ip_ban_disabled: false,
        }
    }
}

struct State {
    ip_counters: HashMap<String, Arc<SlidingWindowCounter>>,
    session_counters: HashMap<String, Arc<SlidingWindowCounter>>,
    endpoint_counters: HashMap<String, Arc<SlidingWindowCounter>>,
    slow_loris_timers: HashMap<String, Instant>,
    slow_post_timers: HashMap<String, Instant>,
    last_cleanup: Instant,
}

pub struct DdosProtection {
    pub dev_mode: bool,
    global_rate: i32,
    per_ip_rate: i32,
    per_endpoint_rate: i32,
    per_session_rate: i32,
    burst_allowance: i32,
    window_size: Duration,
    auto_ban_duration: Duration,
    state: Mutex<State>,
    global_counter: Mutex<Arc<SlidingWindowCounter>>,
}

impl DdosProtection {
    pub fn new(dev_mode: bool) -> Self {
        Self::with_options(dev_mode, DdosOptions::default())
    }

    pub fn with_options(dev_mode: bool, mut opts: DdosOptions) -> Self {
        if opts.global_rate <= 0 {
            opts.global_rate = 10000;
        }
        if opts.per_ip_rate <= 0 {
            opts.per_ip_rate = 30;
        }
        if opts.per_endpoint_rate <= 0 {
            opts.per_endpoint_rate = 200;
        }
        if opts.per_session_rate <= 0 {
            opts.per_session_rate = 200;
        }
        // Zero -> default 10m. A negative duration (signalled by
        // per_ip_ban_disabled) -> auto-ban disabled.
        let auto_ban_duration = match opts.per_ip_ban {
            Some(d) if d.is_zero() && !opts.per_ip_ban_disabled => Duration::from_secs(600),
            Some(_d) if opts.per_ip_ban_disabled => Duration::ZERO,
            None => Duration::from_secs(600),
            Some(d) => d,
        };

        let global_counter = Arc::new(SlidingWindowCounter::with_capacity(
            Duration::from_secs(1),
            (opts.global_rate + 20) as usize,
            (opts.global_rate + 20) as usize,
        ));

        DdosProtection {
            dev_mode,
            global_rate: opts.global_rate,
            per_ip_rate: opts.per_ip_rate,
            per_endpoint_rate: opts.per_endpoint_rate,
            per_session_rate: opts.per_session_rate,
            burst_allowance: 20,
            window_size: Duration::from_secs(1),
            auto_ban_duration,
            state: Mutex::new(State {
                ip_counters: HashMap::new(),
                session_counters: HashMap::new(),
                endpoint_counters: HashMap::new(),
                slow_loris_timers: HashMap::new(),
                slow_post_timers: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            global_counter: Mutex::new(global_counter),
        }
    }

    fn get_or_create_counter(
        counters: &mut HashMap<String, Arc<SlidingWindowCounter>>,
        key: &str,
        per_ip_rate: i32,
        burst_allowance: i32,
        window: Duration,
    ) -> Arc<SlidingWindowCounter> {
        if let Some(c) = counters.get(key) {
            return c.clone();
        }
        let c = Arc::new(SlidingWindowCounter::with_capacity(
            window,
            (per_ip_rate + burst_allowance) as usize,
            (per_ip_rate + burst_allowance) as usize,
        ));
        counters.insert(key.to_string(), c.clone());
        c
    }

    /// Port of `checkRate`. Returns true to allow, false to rate-limit.
    fn check_rate(&self, counter: &SlidingWindowCounter, limit: i32) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window_size);

        // Operate under the counter's own lock for the mutate-and-test.
        // parking_lot's Mutex does not expose the timestamps directly, so we
        // use a dedicated method on the counter through record semantics below.
        // To preserve the exact semantics (prune, test len>=limit, else append),
        // we expose a `check_and_record` helper.
        counter.check_and_record(now, cutoff, limit as usize)
    }

    fn detect_http_flood(&self, ctx: &RequestContext) -> Option<Decision> {
        let mut state = self.state.lock();

        if let Some(dec) = self.check_global_rate() {
            return Some(dec);
        }

        let ip_counter = Self::get_or_create_counter(
            &mut state.ip_counters,
            &ctx.real_ip,
            self.per_ip_rate,
            self.burst_allowance,
            self.window_size,
        );
        if !self.check_rate(&ip_counter, self.per_ip_rate) {
            let mut dec = Decision::new(Action::RateLimit, 65.0)
                .with_rule_id("DDoS001")
                .with_rule_name("HTTP Flood - IP")
                .with_severity("high")
                .with_evidence(format!(
                    "IP {} exceeded rate limit: {} req/s",
                    ctx.real_ip, self.per_ip_rate
                ));
            if !self.auto_ban_duration.is_zero() {
                dec.ban_request = true;
                dec.ban_duration = self.auto_ban_duration;
            }
            return Some(dec);
        }

        let ep_counter = Self::get_or_create_counter(
            &mut state.endpoint_counters,
            &ctx.path,
            self.per_ip_rate,
            self.burst_allowance,
            self.window_size,
        );
        if !self.check_rate(&ep_counter, self.per_endpoint_rate) {
            return Some(
                Decision::new(Action::RateLimit, 60.0)
                    .with_rule_id("DDoS002")
                    .with_rule_name("HTTP Flood - Endpoint")
                    .with_severity("high")
                    .with_evidence(format!(
                        "Endpoint {} exceeded rate: {} req/s",
                        ctx.path, self.per_endpoint_rate
                    )),
            );
        }

        if !ctx.session_id.is_empty() {
            let session_counter = Self::get_or_create_counter(
                &mut state.session_counters,
                &ctx.session_id,
                self.per_ip_rate,
                self.burst_allowance,
                self.window_size,
            );
            if !self.check_rate(&session_counter, self.per_session_rate) {
                return Some(
                    Decision::new(Action::RateLimit, 50.0)
                        .with_rule_id("DDoS003")
                        .with_rule_name("HTTP Flood - Session")
                        .with_severity("medium")
                        .with_evidence(format!(
                            "Session {} exceeded rate: {} req/s",
                            ctx.session_id, self.per_session_rate
                        )),
                );
            }
        }

        None
    }

    fn check_global_rate(&self) -> Option<Decision> {
        let global = self.global_counter.lock().clone();
        if !self.check_rate(&global, self.global_rate) {
            return Some(
                Decision::new(Action::RateLimit, 90.0)
                    .with_rule_id("DDoS000")
                    .with_rule_name("HTTP Flood - Global")
                    .with_severity("critical")
                    .with_evidence(format!(
                        "global rate limit exceeded: {} req/s",
                        self.global_rate
                    )),
            );
        }
        None
    }

    fn detect_slowloris(&self, ctx: &RequestContext) -> Option<Decision> {
        if ctx
            .headers
            .get("Expect")
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        {
            let mut state = self.state.lock();
            state
                .slow_loris_timers
                .insert(ctx.real_ip.clone(), Instant::now());
            return None;
        }

        let content_length = ctx.request_header("Content-Length");
        if content_length.is_empty() && ctx.method == "POST" {
            let mut state = self.state.lock();
            match state.slow_loris_timers.get(&ctx.real_ip).copied() {
                None => {
                    state
                        .slow_loris_timers
                        .insert(ctx.real_ip.clone(), Instant::now());
                    return None;
                }
                Some(start) => {
                    let elapsed = start.elapsed();
                    if elapsed > Duration::from_secs(30) {
                        return Some(
                            Decision::new(Action::Block, 85.0)
                                .with_rule_id("DDoS004")
                                .with_rule_name("Slowloris Attack")
                                .with_severity("high")
                                .with_evidence(format!(
                                    "slowloris detected from {}, elapsed: {:?}",
                                    ctx.real_ip, elapsed
                                )),
                        );
                    }
                }
            }
        }

        None
    }

    fn detect_slow_post(&self, ctx: &RequestContext) -> Option<Decision> {
        if ctx.method != "POST" || ctx.body.is_empty() {
            return None;
        }

        let content_length_str = ctx.request_header("Content-Length");
        if content_length_str.is_empty() {
            return None;
        }

        // Go: fmt.Sscanf("%d") parses a leading decimal integer and ignores
        // trailing characters. Reproduce that.
        let content_length = parse_leading_int(content_length_str);

        if content_length > 1024 * 1024 {
            let mut state = self.state.lock();
            match state.slow_post_timers.get(&ctx.real_ip).copied() {
                None => {
                    state
                        .slow_post_timers
                        .insert(ctx.real_ip.clone(), Instant::now());
                    return None;
                }
                Some(start) => {
                    let received = ctx.body.len();
                    let elapsed = start.elapsed();
                    let rate = received as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
                    if elapsed > Duration::from_secs(10) && rate < 1024.0 {
                        return Some(
                            Decision::new(Action::Block, 80.0)
                                .with_rule_id("DDoS005")
                                .with_rule_name("Slow POST Attack")
                                .with_severity("high")
                                .with_evidence(format!(
                                    "slow POST from {}, rate: {:.0} b/s, elapsed: {:?}",
                                    ctx.real_ip, rate, elapsed
                                )),
                        );
                    }
                }
            }
        }

        None
    }

    fn detect_cache_busting(&self, ctx: &RequestContext) -> Option<Decision> {
        let param_count = ctx.query_params.len();
        let mut random_patterns = 0;

        for (k, vs) in &ctx.query_params {
            let lower_k = k.to_lowercase();
            if lower_k.contains("cache")
                || lower_k.contains("rand")
                || lower_k.contains("t")
                || (lower_k.contains('_') && k.len() <= 3)
            {
                for val in vs {
                    let len = val.len();
                    if (8..=32).contains(&len) {
                        let is_hex = val.chars().all(|c| c.is_ascii_hexdigit());
                        if is_hex || len >= 16 {
                            random_patterns += 1;
                        }
                    }
                }
            }
        }

        if param_count >= 5 && random_patterns >= param_count / 2 {
            return Some(
                Decision::new(Action::Monitor, 40.0)
                    .with_rule_id("DDoS006")
                    .with_rule_name("Cache Busting Attack")
                    .with_severity("medium")
                    .with_evidence(format!(
                        "cache busting detected, params: {param_count}, random: {random_patterns}"
                    )),
            );
        }

        None
    }

    /// Port of `GetAdaptiveRate`.
    pub fn get_adaptive_rate(&self, ip: &str, current_rate: i32) -> i32 {
        let counter = {
            let state = self.state.lock();
            match state.ip_counters.get(ip) {
                Some(c) => c.clone(),
                None => return current_rate,
            }
        };

        let count = counter.raw_len() as i32;

        if count > current_rate * 2 {
            return (f64::max(current_rate as f64 * 0.5, 10.0)) as i32;
        }

        if count > current_rate {
            return (f64::max(current_rate as f64 * 0.8, 10.0)) as i32;
        }

        current_rate
    }

    /// Port of the `cleanup` body (prunes idle IP counters and old timers).
    pub fn cleanup(&self) {
        let mut state = self.state.lock();
        let now = Instant::now();
        state.ip_counters.retain(|_, counter| {
            let last = counter.last_seen();
            match last {
                None => false,
                Some(t) => now.duration_since(t) <= Duration::from_secs(600),
            }
        });
        state
            .slow_loris_timers
            .retain(|_, t| now.duration_since(*t) <= Duration::from_secs(300));
        state
            .slow_post_timers
            .retain(|_, t| now.duration_since(*t) <= Duration::from_secs(300));
    }
}

impl Inspector for DdosProtection {
    fn name(&self) -> &str {
        "ddos_protection"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if let Some(dec) = self.detect_http_flood(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_slowloris(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_slow_post(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_cache_busting(ctx) {
            return Ok(Some(dec));
        }
        Ok(None)
    }
}

/// Parse a leading decimal integer, ignoring trailing characters, matching
/// `fmt.Sscanf(s, "%d", &n)` (which returns 0 and no error on a non-numeric
/// prefix). Sign and leading whitespace are honoured.
fn parse_leading_int(s: &str) -> i64 {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let sign_start = i;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        i += 1;
    }
    let digits_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if digits_start == i {
        return 0;
    }
    s[sign_start..i].parse::<i64>().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn ctx(ip: &str) -> RequestContext {
        let mut r = HttpRequest::new("GET", "/x");
        r.remote_addr = format!("{ip}:1234");
        RequestContext::new(r)
    }

    #[test]
    fn per_ip_flood_is_rate_limited_and_bans() {
        let d = DdosProtection::with_options(
            false,
            DdosOptions {
                per_ip_rate: 3,
                global_rate: 100000,
                per_endpoint_rate: 100000,
                per_session_rate: 100000,
                ..Default::default()
            },
        );
        let mut last = None;
        let mut c = ctx("1.2.3.4");
        for _ in 0..6 {
            last = d.inspect(&mut c).unwrap();
        }
        let dec = last.expect("should rate limit");
        assert_eq!(dec.action, Action::RateLimit);
        assert_eq!(dec.rule_id, "DDoS001");
        assert!(dec.ban_request);
    }

    #[test]
    fn global_flood_is_rate_limited() {
        let d = DdosProtection::with_options(
            false,
            DdosOptions {
                global_rate: 2,
                per_ip_rate: 1000,
                per_endpoint_rate: 100000,
                per_session_rate: 100000,
                ..Default::default()
            },
        );
        let mut dec = None;
        for i in 0..5 {
            let mut c = ctx(&format!("10.0.0.{i}"));
            dec = d.inspect(&mut c).unwrap();
        }
        let dec = dec.unwrap();
        assert_eq!(dec.rule_id, "DDoS000");
    }

    #[test]
    fn parse_leading_int_matches_sscanf() {
        assert_eq!(parse_leading_int("1024abc"), 1024);
        assert_eq!(parse_leading_int("-5"), -5);
        assert_eq!(parse_leading_int("abc"), 0);
        assert_eq!(parse_leading_int(""), 0);
    }

    #[test]
    fn negative_ban_disables_autoban() {
        let d = DdosProtection::with_options(
            false,
            DdosOptions {
                per_ip_rate: 1,
                global_rate: 100000,
                per_endpoint_rate: 100000,
                per_session_rate: 100000,
                per_ip_ban: Some(Duration::from_secs(0)),
                per_ip_ban_disabled: true,
            },
        );
        let mut last = None;
        let mut c = ctx("9.9.9.9");
        for _ in 0..5 {
            last = d.inspect(&mut c).unwrap();
        }
        let dec = last.unwrap();
        assert_eq!(dec.rule_id, "DDoS001");
        assert!(!dec.ban_request);
    }
}
