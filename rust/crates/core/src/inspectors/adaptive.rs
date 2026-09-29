//! Adaptive challenge escalation: JS / CAPTCHA / tarpit / block.
//!
//! Port of `internal/engine/adaptive.go`. Challenge levels, thresholds, token
//! issuance and the JS challenge page are preserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChallengeLevel {
    None = 0,
    Js = 1,
    Captcha = 2,
    Tarpit = 3,
    Block = 4,
}

struct ChallengeState {
    score: f64,
    last_seen: Option<Instant>,
    level: ChallengeLevel,
    request_cnt: i64,
}

struct IssuedChallenge {
    token: String,
    ip: String,
    level: ChallengeLevel,
    expires_at: Instant,
    solved: bool,
}

struct State {
    ip_scores: HashMap<String, ChallengeState>,
    challenges: HashMap<String, IssuedChallenge>,
}

pub struct AdaptiveChallenge {
    pub dev_mode: bool,
    js_script_path: String,
    tarpit_delay: Duration,
    captcha_score: f64,
    challenge_ttl: Duration,
    state: Arc<Mutex<State>>,
}

impl AdaptiveChallenge {
    pub fn new(
        dev_mode: bool,
        js_script_path: String,
        tarpit_delay_ms: i64,
        captcha_score: f64,
        challenge_ttl: i64,
    ) -> Self {
        AdaptiveChallenge {
            dev_mode,
            js_script_path,
            tarpit_delay: Duration::from_millis(tarpit_delay_ms.max(0) as u64),
            captcha_score,
            challenge_ttl: Duration::from_secs(challenge_ttl.max(0) as u64),
            state: Arc::new(Mutex::new(State {
                ip_scores: HashMap::new(),
                challenges: HashMap::new(),
            })),
        }
    }

    fn get_or_create_state<'a>(state: &'a mut State, ip: &str) -> &'a mut ChallengeState {
        state
            .ip_scores
            .entry(ip.to_string())
            .or_insert_with(|| ChallengeState {
                score: 0.0,
                last_seen: None,
                level: ChallengeLevel::None,
                request_cnt: 0,
            })
    }

    fn determine_level(&self, state: &ChallengeState) -> ChallengeLevel {
        let score = state.score;
        if score >= 90.0 {
            ChallengeLevel::Block
        } else if score >= 70.0 {
            ChallengeLevel::Tarpit
        } else if score >= 50.0 {
            ChallengeLevel::Captcha
        } else if score >= 20.0 {
            ChallengeLevel::Js
        } else {
            ChallengeLevel::None
        }
    }

    fn issue_challenge(&self, ip: &str, _level: ChallengeLevel) -> String {
        let mut buf = [0u8; 32];
        let ok = getrandom::getrandom(&mut buf).is_ok();
        if !ok {
            // Go fell back to `%x` of UnixNano on rand failure.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            return format!("{nanos:x}");
        }
        let mut hasher = Sha256::new();
        hasher.update(buf);
        hasher.update(ip.as_bytes());
        let h = hasher.finalize();
        hex_encode(&h[..16])
    }

    /// Port of `RecordEvent`.
    pub fn record_event(&self, ip: &str, score: f64) {
        let mut state = self.state.lock();
        match state.ip_scores.get_mut(ip) {
            None => {
                state.ip_scores.insert(
                    ip.to_string(),
                    ChallengeState {
                        score,
                        last_seen: Some(Instant::now()),
                        level: ChallengeLevel::None,
                        request_cnt: 0,
                    },
                );
            }
            Some(s) => {
                s.score = score;
                s.last_seen = Some(Instant::now());
            }
        }
    }

    /// Port of the `cleanupLoop` body.
    pub fn cleanup(&self) {
        let mut state = self.state.lock();
        let now = Instant::now();
        state.challenges.retain(|_, c| now <= c.expires_at);
        state.ip_scores.retain(|_, s| match s.last_seen {
            Some(t) => now <= t + self.challenge_ttl * 2,
            None => true,
        });
    }

    /// Accessor for the configured captcha score threshold.
    pub fn captcha_score(&self) -> f64 {
        self.captcha_score
    }
}

impl Inspector for AdaptiveChallenge {
    fn name(&self) -> &str {
        "adaptive"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let ip = ctx.real_ip.clone();
        if ip.is_empty() {
            return Ok(None);
        }

        let token = ctx.request_header("X-Challenge-Token").to_string();
        if !token.is_empty() {
            let mut state = self.state.lock();
            if let Some(c) = state.challenges.get(&token) {
                if !c.solved {
                    state.challenges.remove(&token);
                    drop(state);
                    return Ok(Some(
                        Decision::new(Action::Allow, 0.0)
                            .with_rule_id("ADAPT_000")
                            .with_rule_name("Challenge Solved")
                            .with_severity("info")
                            .with_evidence(format!(
                                "challenge solved for IP {ip} via token {token}"
                            )),
                    ));
                }
            }
        }

        let (existing_score, state_level, state_score) = {
            let mut state = self.state.lock();
            let s = Self::get_or_create_state(&mut state, &ip);
            s.request_cnt += 1;

            if s.level >= ChallengeLevel::Block {
                return Ok(Some(
                    Decision::new(Action::Block, 95.0)
                        .with_rule_id("ADAPT_004")
                        .with_rule_name("Adaptive Block")
                        .with_severity("critical")
                        .with_evidence(format!(
                            "IP {ip} blocked after adaptive escalation (score={:.1})",
                            s.score
                        )),
                ));
            }

            let existing = if ctx.threat_score <= 0.0 {
                s.score
            } else {
                ctx.threat_score
            };
            s.score = existing;
            s.last_seen = Some(Instant::now());

            let level = self.determine_level(s);
            if level > s.level {
                s.level = level;
            }
            (existing, s.level, s.score)
        };
        let _ = existing_score;

        match state_level {
            ChallengeLevel::Js => {
                let ct = self.issue_challenge(&ip, ChallengeLevel::Js);
                let mut state = self.state.lock();
                state.challenges.insert(
                    ct.clone(),
                    IssuedChallenge {
                        token: ct.clone(),
                        ip: ip.clone(),
                        level: ChallengeLevel::Js,
                        expires_at: Instant::now() + self.challenge_ttl,
                        solved: false,
                    },
                );
                drop(state);

                ctx.response = None;
                Ok(Some(
                    Decision::new(Action::Challenge, 30.0)
                        .with_rule_id("ADAPT_001")
                        .with_rule_name("JS Challenge")
                        .with_severity("medium")
                        .with_evidence(format!(
                            "JS challenge issued for IP {ip} (score={:.1})",
                            state_score
                        )),
                ))
            }
            ChallengeLevel::Captcha => {
                let ct = self.issue_challenge(&ip, ChallengeLevel::Captcha);
                let mut state = self.state.lock();
                state.challenges.insert(
                    ct.clone(),
                    IssuedChallenge {
                        token: ct.clone(),
                        ip: ip.clone(),
                        level: ChallengeLevel::Captcha,
                        expires_at: Instant::now() + self.challenge_ttl,
                        solved: false,
                    },
                );
                drop(state);

                Ok(Some(
                    Decision::new(Action::Challenge, 60.0)
                        .with_rule_id("ADAPT_002")
                        .with_rule_name("CAPTCHA Challenge")
                        .with_severity("high")
                        .with_evidence(format!(
                            "CAPTCHA challenge issued for IP {ip} (score={:.1})",
                            state_score
                        )),
                ))
            }
            ChallengeLevel::Tarpit => {
                let delay = self.tarpit_delay;
                std::thread::sleep(delay);
                Ok(Some(
                    Decision::new(Action::Monitor, 80.0)
                        .with_rule_id("ADAPT_003")
                        .with_rule_name("Tarpit Applied")
                        .with_severity("high")
                        .with_evidence(format!(
                            "tarpit delay of {delay:?} applied to IP {ip} (score={state_score:.1})"
                        )),
                ))
            }
            ChallengeLevel::Block => Ok(Some(
                Decision::new(Action::Block, 95.0)
                    .with_rule_id("ADAPT_004")
                    .with_rule_name("Adaptive Block")
                    .with_severity("critical")
                    .with_evidence(format!(
                        "IP {ip} blocked after adaptive escalation (score={state_score:.1})"
                    )),
            )),
            ChallengeLevel::None => Ok(None),
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Port of `JSChallengePage`. Generates the interstitial with a fresh token.
pub fn js_challenge_page(path: &str) -> Vec<u8> {
    let mut token_bytes = [0u8; 16];
    let _ = getrandom::getrandom(&mut token_bytes);
    let challenge_token = hex_encode(&token_bytes);

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Security Check</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{display:flex;justify-content:center;align-items:center;min-height:100vh;background:#1a1a2e;font-family:system-ui,monospace;color:#e0e0e0}}
.card{{text-align:center;padding:3rem;border:3px solid #e94560;background:#16213e;max-width:480px;width:90%}}
.card h2{{color:#e94560;margin-bottom:1rem;font-size:1.5rem}}
.spinner{{width:40px;height:40px;border:4px solid #333;border-top:4px solid #e94560;border-radius:50%;animation:spin 1s linear infinite;margin:1.5rem auto}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.card p{{color:#aaa;font-size:0.9rem;line-height:1.5}}
.card .footer{{margin-top:1.5rem;font-size:0.8rem;color:#666}}
</style>
</head>
<body>
<div class="card">
<h2>Security Verification</h2>
<div class="spinner"></div>
<p>Please wait while we verify your browser environment.</p>
<p id="status">Initializing...</p>
<div class="footer">FortressWAF &bull; Adaptive Challenge</div>
</div>
<form id="cf" action="/__challenge" method="POST" style="display:none">
<input type="hidden" name="challenge_token" value="{token}">
<input type="hidden" name="original_path" value="{path}">
</form>
<script>
(function(){{
var results = [];
var checks = 0;
var required = 4;
var elapsed = Date.now() - (new Date()).getTimezoneOffset()*60000;
var start = Date.now();
var ua = navigator.userAgent.toLowerCase();
var pf = navigator.platform.toLowerCase();

results.push(ua.length > 10 ? 1 : 0);
results.push(pf.length > 0 ? 1 : 0);

var img = new Image();
var imgChecked = false;
img.onload = img.onerror = function(){{ if(!imgChecked){{ imgChecked=true; results.push(1); checks++; }} }};
setTimeout(function(){{ if(!imgChecked){{ imgChecked=true; results.push(0); checks++; }} }}, 500);

var canvas = document.createElement('canvas');
canvas.width = 200; canvas.height = 50;
var ctx = canvas.getContext('2d');
ctx.fillText('fortress', 10, 30);
var imgData = canvas.toDataURL();
results.push(imgData.length > 100 ? 1 : 0);

var cpuCores = (navigator.hardwareConcurrency || 1) > 1 ? 1 : 0;
results.push(cpuCores);

var webdriver = navigator.webdriver ? 0 : 1;
results.push(webdriver);

var pluginsLen = navigator.plugins.length > 0 ? 1 : 0;
results.push(pluginsLen);

checks += required;
var score = results.reduce(function(a,b){{return a+b}},0);
var maxScore = results.length;

function submitForm(){{
document.getElementById('status').textContent = 'Verification complete. Redirecting...';
setTimeout(function(){{
document.getElementById('cf').submit();
}}, 500);
}}

var waitTime = Math.max(1500, (Date.now() - start));
if(score >= maxScore * 0.6 && waitTime >= 1500){{
document.getElementById('status').textContent = 'Browser verification passed.';
submitForm();
}} else {{
document.getElementById('status').textContent = 'Additional checks required...';
setTimeout(function(){{ document.getElementById('status').textContent = 'Verifying...'; }}, 2000);
setTimeout(submitForm, 3000);
}}
}})();
</script>
<noscript>
<div style="text-align:center;padding:2rem">
<p>JavaScript is required to pass the security check.</p>
<p><a href="/">Reload page</a></p>
</div>
</noscript>
</body>
</html>"#,
        token = challenge_token,
        path = path
    );

    html.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    #[test]
    fn escalation_levels() {
        let a = AdaptiveChallenge::new(false, String::new(), 0, 0.5, 300);
        let mk = |score| ChallengeState {
            score,
            last_seen: None,
            level: ChallengeLevel::None,
            request_cnt: 0,
        };
        assert_eq!(a.determine_level(&mk(0.0)), ChallengeLevel::None);
        assert_eq!(a.determine_level(&mk(25.0)), ChallengeLevel::Js);
        assert_eq!(a.determine_level(&mk(55.0)), ChallengeLevel::Captcha);
        assert_eq!(a.determine_level(&mk(75.0)), ChallengeLevel::Tarpit);
        assert_eq!(a.determine_level(&mk(95.0)), ChallengeLevel::Block);
    }

    #[test]
    fn js_challenge_page_has_token_and_path() {
        let page = String::from_utf8(js_challenge_page("/account")).unwrap();
        assert!(page.contains("original_path\" value=\"/account\""));
        assert!(page.contains("challenge_token"));
    }

    #[test]
    fn missing_ip_returns_none() {
        let a = AdaptiveChallenge::new(false, String::new(), 0, 0.5, 300);
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        ctx.real_ip = String::new();
        assert!(a.inspect(&mut ctx).unwrap().is_none());
    }

    #[test]
    fn low_score_no_challenge() {
        let a = AdaptiveChallenge::new(false, String::new(), 0, 0.5, 300);
        let mut r = HttpRequest::new("GET", "/");
        r.remote_addr = "1.2.3.4:1".to_string();
        let mut ctx = RequestContext::new(r);
        // threat_score 0 -> existing score 0 -> level None
        assert!(a.inspect(&mut ctx).unwrap().is_none());
    }
}
