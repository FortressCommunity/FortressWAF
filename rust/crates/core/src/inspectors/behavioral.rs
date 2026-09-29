//! Behavioural analysis: request velocity, IP reputation, path entropy.
//!
//! Port of `internal/engine/behavioral.go`. Rule IDs, scores, thresholds and
//! the entropy maths are preserved exactly, including the sliding-window
//! `add()` re-indexing behaviour.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use regex::Regex;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

static ENTROPY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[0-9a-f]{8,}|[a-z]{20,}|[A-Z]{20,}").unwrap());

struct SlidingWindow {
    times: Mutex<Vec<Instant>>,
    window: Duration,
    #[allow(dead_code)]
    max: usize,
}

impl SlidingWindow {
    fn new(window: Duration, max: usize) -> Self {
        SlidingWindow {
            times: Mutex::new(Vec::with_capacity(max)),
            window,
            max,
        }
    }

    /// Port of `slidingWindow.add`. Reproduces the exact compaction and
    /// re-index: prune to timestamps after cutoff, then set `times[j] = now`
    /// and return `len` (== j+1 after the write-through).
    fn add(&self) -> usize {
        let mut times = self.times.lock();
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window);

        let mut j = 0;
        for i in 0..times.len() {
            let t = times[i];
            let keep = match cutoff {
                Some(c) => t > c,
                None => true,
            };
            if keep {
                times[j] = t;
                j += 1;
            }
        }
        // Go: sw.times = sw.times[:j+1]; sw.times[j] = now
        if times.len() < j + 1 {
            times.resize(j + 1, now);
        } else {
            times.truncate(j + 1);
        }
        times[j] = now;
        times.len()
    }
}

struct State {
    ip_requests: HashMap<String, Arc<SlidingWindow>>,
    ip_reputation: HashMap<String, i64>,
    path_counts: HashMap<String, i64>,
    bad_ips: HashMap<String, bool>,
    blocked_ips: HashMap<String, Instant>,
}

pub struct BehavioralEngine {
    pub dev_mode: bool,
    reputation: bool,
    velocity: bool,
    path_entropy: bool,
    threshold: f64,
    window_sec: i64,
    max_requests: i64,
    state: Arc<RwLock<State>>,
}

impl BehavioralEngine {
    pub fn new(
        dev_mode: bool,
        reputation: bool,
        velocity: bool,
        path_entropy: bool,
        threshold: f64,
        window_sec: i32,
        max_requests: i32,
    ) -> Self {
        BehavioralEngine {
            dev_mode,
            reputation,
            velocity,
            path_entropy,
            threshold,
            window_sec: window_sec as i64,
            max_requests: max_requests as i64,
            state: Arc::new(RwLock::new(State {
                ip_requests: HashMap::new(),
                ip_reputation: HashMap::new(),
                path_counts: HashMap::new(),
                bad_ips: HashMap::new(),
                blocked_ips: HashMap::new(),
            })),
        }
    }

    fn get_window(&self, ip: &str) -> Arc<SlidingWindow> {
        let mut state = self.state.write();
        if let Some(sw) = state.ip_requests.get(ip) {
            return sw.clone();
        }
        let sw = Arc::new(SlidingWindow::new(
            Duration::from_secs(self.window_sec.max(0) as u64),
            (self.max_requests * 10).max(0) as usize,
        ));
        state.ip_requests.insert(ip.to_string(), sw.clone());
        sw
    }

    fn check_path_entropy(&self, path: &str) -> f64 {
        if path.is_empty() || path == "/" {
            return 0.0;
        }

        let trimmed = path.trim_end_matches('/');
        let parts: Vec<&str> = trimmed.trim_start_matches('/').split('/').collect();

        let mut entropy = 0.0f64;
        for part in parts {
            if part.len() < 4 {
                continue;
            }

            if ENTROPY_RE.is_match(part) {
                entropy += 15.0;
            }

            let mut freq: HashMap<char, f64> = HashMap::new();
            for c in part.chars() {
                *freq.entry(c).or_insert(0.0) += 1.0;
            }

            let mut part_entropy = 0.0;
            let l = part.chars().count() as f64;
            if l < 2.0 {
                continue;
            }
            for count in freq.values() {
                let p = count / l;
                if p > 0.0 {
                    part_entropy -= p * p.log2();
                }
            }

            let max_entropy = l.log2();
            if max_entropy > 0.0 {
                let normalized = part_entropy / max_entropy;
                if normalized > 0.85 && l > 8.0 {
                    entropy += 20.0;
                }
            }

            if part.chars().count() > 16 {
                entropy += 10.0;
            }
        }

        entropy.min(50.0)
    }

    /// Port of `ReportBadIP`.
    pub fn report_bad_ip(&self, ip: &str) {
        self.state.write().bad_ips.insert(ip.to_string(), true);
    }

    /// Port of `IncrementReputation`.
    pub fn increment_reputation(&self, ip: &str, delta: i64) {
        let mut state = self.state.write();
        let r = state.ip_reputation.entry(ip.to_string()).or_insert(0);
        *r += delta;
        if *r > 100 {
            state.bad_ips.insert(ip.to_string(), true);
        }
    }

    /// Port of `BlockIP`.
    pub fn block_ip(&self, ip: &str, duration: Duration) {
        let mut state = self.state.write();
        state
            .blocked_ips
            .insert(ip.to_string(), Instant::now() + duration);
        state.bad_ips.insert(ip.to_string(), true);
    }

    /// Port of the `cleanupLoop` body.
    pub fn cleanup(&self) {
        let mut state = self.state.write();
        let now = Instant::now();
        let expired: Vec<String> = state
            .blocked_ips
            .iter()
            .filter(|(_, until)| now > **until)
            .map(|(ip, _)| ip.clone())
            .collect();
        for ip in expired {
            state.blocked_ips.remove(&ip);
            state.bad_ips.remove(&ip);
            state.ip_reputation.remove(&ip);
        }

        if state.ip_requests.len() > 10000 {
            let mut removed = 0;
            let keys: Vec<String> = state.ip_requests.keys().cloned().collect();
            for ip in keys {
                if removed > 1000 {
                    break;
                }
                state.ip_requests.remove(&ip);
                removed += 1;
            }
        }
    }
}

impl Inspector for BehavioralEngine {
    fn name(&self) -> &str {
        "behavioral"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let ip = ctx.real_ip.clone();
        if ip.is_empty() {
            return Ok(None);
        }

        let mut score = 0.0f64;

        if self.velocity {
            let sw = self.get_window(&ip);
            let count = sw.add() as i64;
            if count > self.max_requests {
                score += 35.0;
                if self.dev_mode {
                    return Ok(Some(
                        Decision::new(Action::RateLimit, 35.0)
                            .with_rule_id("BEH_001")
                            .with_rule_name("Request Velocity Exceeded")
                            .with_severity("high")
                            .with_evidence(format!(
                                "IP {ip} exceeded {} requests per {}s window (got {count})",
                                self.max_requests, self.window_sec
                            )),
                    ));
                }
            }
            if count > self.max_requests * 2 {
                score += 30.0;
                return Ok(Some(
                    Decision::new(Action::Block, 65.0)
                        .with_rule_id("BEH_002")
                        .with_rule_name("High Request Velocity")
                        .with_severity("critical")
                        .with_evidence(format!(
                            "IP {ip} high velocity: {count} requests in {}s",
                            self.window_sec
                        )),
                ));
            }
        }

        if self.reputation {
            let (is_bad, rep) = {
                let state = self.state.read();
                (
                    state.bad_ips.get(&ip).copied().unwrap_or(false),
                    state.ip_reputation.get(&ip).copied().unwrap_or(0),
                )
            };

            if is_bad {
                return Ok(Some(
                    Decision::new(Action::Block, 90.0)
                        .with_rule_id("BEH_010")
                        .with_rule_name("Known Bad IP")
                        .with_severity("critical")
                        .with_evidence(format!("IP {ip} has negative reputation")),
                ));
            }

            if rep > 10 {
                score += 20.0;
            }
            if rep > 50 {
                score += 25.0;
                return Ok(Some(
                    Decision::new(Action::Block, 45.0)
                        .with_rule_id("BEH_011")
                        .with_rule_name("Poor IP Reputation")
                        .with_severity("high")
                        .with_evidence(format!("IP {ip} poor reputation score: {rep}")),
                ));
            }
        }

        if self.path_entropy {
            let path_score = self.check_path_entropy(&ctx.path);
            score += path_score;
            if path_score > 20.0 {
                return Ok(Some(
                    Decision::new(Action::Monitor, path_score)
                        .with_rule_id("BEH_020")
                        .with_rule_name("High Path Entropy")
                        .with_severity("medium")
                        .with_evidence(format!(
                            "path {:?} has high entropy ({:.2})",
                            ctx.path, path_score
                        )),
                ));
            }
        }

        if score >= self.threshold {
            return Ok(Some(
                Decision::new(Action::Monitor, score)
                    .with_rule_id("BEH_099")
                    .with_rule_name("Behavioral Threat Detected")
                    .with_severity("medium")
                    .with_evidence(format!(
                        "cumulative behavioral score {:.0} for IP {ip}",
                        score
                    )),
            ));
        }

        Ok(None)
    }
}

/// Port of `shannonEntropy` (exposed for completeness/tests).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, f64> = HashMap::new();
    for c in s.chars() {
        *freq.entry(c).or_insert(0.0) += 1.0;
    }
    let mut entropy = 0.0;
    let l = s.chars().count() as f64;
    for count in freq.values() {
        let p = count / l;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn ctx(ip: &str, path: &str) -> RequestContext {
        let mut r = HttpRequest::new("GET", path);
        r.remote_addr = format!("{ip}:1234");
        RequestContext::new(r)
    }

    #[test]
    fn velocity_blocks_high_rate() {
        let e = BehavioralEngine::new(false, false, true, false, 100.0, 60, 3);
        let mut c = ctx("1.2.3.4", "/");
        let mut last = None;
        for _ in 0..8 {
            last = e.inspect(&mut c).unwrap();
        }
        let dec = last.unwrap();
        // count > maxRequests*2 (6) -> BEH_002
        assert_eq!(dec.rule_id, "BEH_002");
        assert_eq!(dec.action, Action::Block);
    }

    #[test]
    fn low_entropy_path_scores_zero() {
        let e = BehavioralEngine::new(false, false, false, true, 100.0, 60, 1000);
        assert_eq!(e.check_path_entropy("/users/1"), 0.0);
    }

    #[test]
    fn high_entropy_path_scores_positive() {
        let e = BehavioralEngine::new(false, false, false, true, 100.0, 60, 1000);
        let score = e.check_path_entropy("/aB3xY9zQ1wE7rT2uI8oP4aS6dF0gH2jK5l");
        assert!(score > 20.0, "got {score}");
    }

    #[test]
    fn bad_ip_blocked() {
        let e = BehavioralEngine::new(false, true, false, false, 100.0, 60, 1000);
        e.report_bad_ip("9.9.9.9");
        let mut c = ctx("9.9.9.9", "/");
        let dec = e.inspect(&mut c).unwrap().unwrap();
        assert_eq!(dec.rule_id, "BEH_010");
    }

    #[test]
    fn shannon_entropy_known_value() {
        // "abcd" uniform -> 2 bits
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }
}
