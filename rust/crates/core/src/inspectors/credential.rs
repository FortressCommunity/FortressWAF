//! Credential protection: stuffing, spray, brute force, leaked creds, JWT.
//!
//! Port of `internal/engine/credential.go`. Rule IDs, scores, thresholds and
//! the check order are preserved exactly.
//!
//! ## Faithful bugs preserved
//!
//! - `detectPasswordSpray` never populates `sprayTracker.usernames`, so
//!   `uniqueUsernames` is always 0 and CRED004/CRED005 can never fire. Go has
//!   the same dead behaviour; the port reproduces it deliberately.
//! - `detectBruteForce` only counts authentication attempts (POST to a login
//!   path or a POST carrying a `password`), matching the Go fix that stopped
//!   ordinary asset requests from tripping CRED006.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

struct LoginTracker {
    attempts: i64,
    first_seen: Instant,
    last_seen: Instant,
    locked: bool,
    lockout_at: Instant,
}

struct SprayTracker {
    usernames: HashMap<String, i64>,
    count: i64,
    last_seen: Instant,
}

struct BruteForceTracker {
    attempts: i64,
    backoff: Duration,
    next_try: Instant,
    first_seen: Instant,
}

struct State {
    login_attempts: HashMap<String, LoginTracker>,
    password_spray: HashMap<String, SprayTracker>,
    brute_force: HashMap<String, BruteForceTracker>,
    leaked_creds: HashMap<String, bool>,
}

pub struct CredentialProtection {
    pub dev_mode: bool,
    state: Arc<Mutex<State>>,
    hibp_enabled: bool,
    lockout_duration: Duration,
    window: Duration,
    login_paths: Vec<String>,
    max_attempts: i64,
}

impl CredentialProtection {
    pub fn new(
        dev_mode: bool,
        max_attempts: i32,
        window_sec: i32,
        block_duration_sec: i32,
        login_paths: Vec<String>,
    ) -> Self {
        let paths = if login_paths.is_empty() {
            vec![
                "/login".to_string(),
                "/signin".to_string(),
                "/auth".to_string(),
                "/api/login".to_string(),
            ]
        } else {
            login_paths
        };
        let normalized: Vec<String> = paths.iter().map(|p| normalize_login_path(p)).collect();
        let max_attempts = if max_attempts <= 0 { 5 } else { max_attempts };
        let block_duration_sec = if block_duration_sec <= 0 {
            3600
        } else {
            block_duration_sec
        };
        let window_sec = if window_sec <= 0 { 300 } else { window_sec };

        CredentialProtection {
            dev_mode,
            state: Arc::new(Mutex::new(State {
                login_attempts: HashMap::new(),
                password_spray: HashMap::new(),
                brute_force: HashMap::new(),
                leaked_creds: HashMap::new(),
            })),
            hibp_enabled: false,
            lockout_duration: Duration::from_secs(block_duration_sec as u64),
            window: Duration::from_secs(window_sec as u64),
            login_paths: normalized,
            max_attempts: max_attempts as i64,
        }
    }

    fn is_auth_attempt(&self, ctx: &RequestContext) -> bool {
        if ctx.method != "POST" {
            return false;
        }
        if ctx.form_params.contains_key("password") {
            return true;
        }
        if ctx.query_params.contains_key("password") {
            return true;
        }
        let path = normalize_login_path(&ctx.path);
        self.login_paths.iter().any(|p| path == *p)
    }

    fn detect_credential_stuffing(&self, ctx: &RequestContext) -> Option<Decision> {
        if ctx.method != "POST" {
            return None;
        }

        let username = ctx
            .form_params
            .get("username")
            .or_else(|| ctx.query_params.get("username"));
        let password = ctx
            .form_params
            .get("password")
            .or_else(|| ctx.query_params.get("password"));

        // Go: if either form value is empty, fall back to query for BOTH.
        let (username, password) = match (username, password) {
            (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => (u, p),
            _ => (
                ctx.query_params.get("username").unwrap_or(&EMPTY),
                ctx.query_params.get("password").unwrap_or(&EMPTY),
            ),
        };

        if username.is_empty() || password.is_empty() {
            return None;
        }

        let user_hash = sha256_hex_lower(username[0].as_bytes());

        let mut state = self.state.lock();

        let now = Instant::now();

        let tracker = match state.login_attempts.get_mut(&user_hash) {
            None => {
                state.login_attempts.insert(
                    user_hash.clone(),
                    LoginTracker {
                        attempts: 1,
                        first_seen: now,
                        last_seen: now,
                        locked: false,
                        lockout_at: now,
                    },
                );
                return None;
            }
            Some(t) => t,
        };

        tracker.attempts += 1;
        tracker.last_seen = now;

        if tracker.locked {
            if now.duration_since(tracker.lockout_at) < self.lockout_duration {
                let remaining = self.lockout_duration - now.duration_since(tracker.lockout_at);
                return Some(
                    Decision::new(Action::Block, 80.0)
                        .with_rule_id("CRED001")
                        .with_rule_name("Account Locked")
                        .with_severity("high")
                        .with_evidence(format!(
                            "account locked for a further {:?} ({}s)",
                            remaining,
                            remaining.as_secs()
                        )),
                );
            }
            tracker.locked = false;
            tracker.attempts = 0;
            return None;
        }

        if tracker.attempts > self.max_attempts * 3 {
            tracker.locked = true;
            tracker.lockout_at = now;
            return Some(
                Decision::new(Action::Block, 90.0)
                    .with_rule_id("CRED002")
                    .with_rule_name("Credential Stuffing Detected")
                    .with_severity("critical")
                    .with_evidence(format!(
                        "credential stuffing: {} attempts for user hash {}",
                        tracker.attempts,
                        &user_hash[..8.min(user_hash.len())]
                    )),
            );
        }

        if tracker.attempts > self.max_attempts {
            return Some(
                Decision::new(Action::RateLimit, 50.0)
                    .with_rule_id("CRED003")
                    .with_rule_name("Excessive Login Attempts")
                    .with_severity("medium")
                    .with_evidence(format!("{} login attempts for user", tracker.attempts)),
            );
        }

        None
    }

    fn detect_password_spray(&self, ctx: &RequestContext) -> Option<Decision> {
        let password = ctx
            .form_params
            .get("password")
            .or_else(|| ctx.query_params.get("password"));
        let password = match password {
            Some(p) if !p.is_empty() => p,
            _ => return None,
        };

        let full = sha256_hex_lower(password[0].as_bytes());
        let pass_hash = full[..16].to_string();

        let mut state = self.state.lock();
        let now = Instant::now();

        let tracker = match state.password_spray.get_mut(&pass_hash) {
            None => {
                state.password_spray.insert(
                    pass_hash.clone(),
                    SprayTracker {
                        usernames: HashMap::new(),
                        count: 1,
                        last_seen: now,
                    },
                );
                return None;
            }
            Some(t) => t,
        };

        tracker.count += 1;
        tracker.last_seen = now;

        // Faithful: `usernames` is never populated, so unique_usernames is
        // always 0 and neither CRED004 nor CRED005 can fire (Go behaves the
        // same way).
        let unique_usernames = tracker.usernames.len() as i64;
        if unique_usernames >= 10 && tracker.count >= 50 {
            return Some(
                Decision::new(Action::Block, 90.0)
                    .with_rule_id("CRED004")
                    .with_rule_name("Password Spray Attack")
                    .with_severity("critical")
                    .with_evidence(format!(
                        "password spray detected: {} attempts across {} users",
                        tracker.count, unique_usernames
                    )),
            );
        }

        if tracker.count >= 20 && unique_usernames >= 5 {
            return Some(
                Decision::new(Action::RateLimit, 65.0)
                    .with_rule_id("CRED005")
                    .with_rule_name("Potential Password Spray")
                    .with_severity("high")
                    .with_evidence(format!(
                        "potential password spray: {} attempts",
                        tracker.count
                    )),
            );
        }

        None
    }

    fn detect_brute_force(&self, ctx: &RequestContext) -> Option<Decision> {
        if !self.is_auth_attempt(ctx) {
            return None;
        }

        let ip = ctx.real_ip.clone();
        let now = Instant::now();

        let mut state = self.state.lock();

        let tracker = match state.brute_force.get_mut(&ip) {
            None => {
                state.brute_force.insert(
                    ip.clone(),
                    BruteForceTracker {
                        attempts: 1,
                        backoff: Duration::from_secs(1),
                        next_try: now,
                        first_seen: now,
                    },
                );
                return None;
            }
            Some(t) => t,
        };

        if now.duration_since(tracker.first_seen) > self.window {
            tracker.attempts = 1;
            tracker.backoff = Duration::from_secs(1);
            tracker.next_try = now;
            tracker.first_seen = now;
            return None;
        }

        tracker.attempts += 1;

        if now < tracker.next_try {
            return Some(
                Decision::new(Action::Block, 80.0)
                    .with_rule_id("CRED006")
                    .with_rule_name("Brute Force Blocked")
                    .with_severity("high")
                    .with_evidence(format!(
                        "brute force blocked for {ip}, backoff: {:?}",
                        tracker.backoff
                    )),
            );
        }

        tracker.backoff = match tracker.attempts {
            a if a > 20 => Duration::from_secs(30 * 60),
            a if a > 10 => Duration::from_secs(5 * 60),
            a if a > 5 => Duration::from_secs(30),
            _ => Duration::from_secs(1),
        };

        tracker.next_try = now + tracker.backoff;

        None
    }

    fn detect_leaked_credential(&self, ctx: &RequestContext) -> Option<Decision> {
        let password = ctx
            .form_params
            .get("password")
            .or_else(|| ctx.query_params.get("password"));
        let password = match password {
            Some(p) if !p.is_empty() => p,
            _ => return None,
        };

        let pass_hash = sha256_hex_upper(password[0].as_bytes());

        if self.hibp_enabled {
            if self
                .state
                .lock()
                .leaked_creds
                .get(&pass_hash)
                .copied()
                .unwrap_or(false)
            {
                return Some(
                    Decision::new(Action::Block, 95.0)
                        .with_rule_id("CRED007")
                        .with_rule_name("Leaked Credential")
                        .with_severity("critical")
                        .with_evidence("password matches known leaked credential database"),
                );
            }
        }

        None
    }

    fn validate_jwt(&self, ctx: &RequestContext) -> Option<Decision> {
        let auth_header = ctx
            .headers
            .get("Authorization")
            .cloned()
            .unwrap_or_default();
        if auth_header.is_empty() {
            return None;
        }

        if !auth_header.to_uppercase().starts_with("BEARER ") {
            return None;
        }

        let token = &auth_header[7..];
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Some(
                Decision::new(Action::Block, 70.0)
                    .with_rule_id("CRED008")
                    .with_rule_name("Malformed JWT")
                    .with_severity("high")
                    .with_evidence("jwt token does not have 3 parts"),
            );
        }

        let header_json = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(v) => v,
            Err(_) => {
                return Some(
                    Decision::new(Action::Block, 65.0)
                        .with_rule_id("CRED009")
                        .with_rule_name("Invalid JWT Header Encoding")
                        .with_severity("high")
                        .with_evidence("invalid base64 encoding in jwt header"),
                );
            }
        };

        let header: serde_json::Value = match serde_json::from_slice(&header_json) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if alg.eq_ignore_ascii_case("none") {
            return Some(
                Decision::new(Action::Block, 95.0)
                    .with_rule_id("CRED010")
                    .with_rule_name("JWT alg:none Attack")
                    .with_severity("critical")
                    .with_evidence("jwt with alg:none detected"),
            );
        }

        let payload_json = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let payload: serde_json::Value = match serde_json::from_slice(&payload_json) {
            Ok(v) => v,
            Err(_) => return None,
        };

        let now = now_unix_secs();
        if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
            if exp > 0 && now > exp {
                return Some(
                    Decision::new(Action::Block, 40.0)
                        .with_rule_id("CRED013")
                        .with_rule_name("Expired JWT")
                        .with_severity("medium")
                        .with_evidence("jwt token has expired"),
                );
            }
        }

        None
    }

    fn detect_oauth_abuse(&self, ctx: &RequestContext) -> Option<Decision> {
        let auth_header = ctx
            .headers
            .get("Authorization")
            .cloned()
            .unwrap_or_default();
        if auth_header.to_lowercase().starts_with("bearer ") {
            let token = &auth_header[7..];
            if token.matches('.').count() == 2 {
                return None;
            }
        }

        if let Some(state_param) = ctx.query_params.get("state") {
            if !state_param.is_empty() && state_param[0].len() > 2048 {
                return Some(
                    Decision::new(Action::Block, 40.0)
                        .with_rule_id("CRED013")
                        .with_rule_name("OAuth State Overflow")
                        .with_severity("medium")
                        .with_evidence("oauth state parameter exceeds maximum size"),
                );
            }
        }

        None
    }
}

static EMPTY: Vec<String> = Vec::new();

impl Inspector for CredentialProtection {
    fn name(&self) -> &str {
        "credential_protection"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if let Some(dec) = self.detect_credential_stuffing(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_password_spray(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_brute_force(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_leaked_credential(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.validate_jwt(ctx) {
            return Ok(Some(dec));
        }
        if let Some(dec) = self.detect_oauth_abuse(ctx) {
            return Ok(Some(dec));
        }
        Ok(None)
    }
}

/// `normalizeLoginPath`.
pub fn normalize_login_path(path: &str) -> String {
    path.to_lowercase().trim_end_matches('/').to_string()
}

fn sha256_hex_lower(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

fn sha256_hex_upper(data: &[u8]) -> String {
    sha256_hex_lower(data).to_uppercase()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn cred() -> CredentialProtection {
        CredentialProtection::new(false, 5, 300, 3600, vec![])
    }

    fn post_login(ip: &str, user: &str, pass: &str) -> RequestContext {
        let mut r = HttpRequest::new("POST", "/login");
        r.remote_addr = format!("{ip}:1234");
        r.body = format!("username={user}&password={pass}").into_bytes();
        let mut ctx = RequestContext::new(r);
        // Simulate a parsed form body (the proxy fills form_params; here we set
        // them directly to exercise the inspector).
        ctx.form_params.insert("username".into(), vec![user.into()]);
        ctx.form_params.insert("password".into(), vec![pass.into()]);
        ctx
    }

    #[test]
    fn credential_stuffing_locks_account() {
        let c = cred();
        let mut ctx = post_login("1.2.3.4", "admin", "pw");
        let mut saw_stuffing = false;
        let mut saw_locked = false;
        for _ in 0..25 {
            if let Some(dec) = c.inspect(&mut ctx).unwrap() {
                if dec.rule_id == "CRED002" {
                    assert_eq!(dec.action, Action::Block);
                    saw_stuffing = true;
                }
                if dec.rule_id == "CRED001" {
                    saw_locked = true;
                }
            }
        }
        // maxAttempts=5 -> *3=15, so CRED002 fires, then the account stays
        // locked and later attempts report CRED001.
        assert!(saw_stuffing, "expected CRED002 credential stuffing block");
        assert!(
            saw_locked,
            "expected CRED001 account-locked block afterwards"
        );
    }

    #[test]
    fn excessive_login_attempts_rate_limited() {
        let c = cred();
        // 6th attempt (attempts=6 > 5) triggers CRED003 before stuffing.
        let mut ctx = post_login("1.2.3.4", "alice", "pw");
        let mut dec = None;
        for _ in 0..6 {
            dec = c.inspect(&mut ctx).unwrap();
        }
        assert_eq!(dec.unwrap().rule_id, "CRED003");
    }

    #[test]
    fn jwt_alg_none_blocked() {
        let c = cred();
        // header {"alg":"none"} base64url no pad = eyJhbGciOiJub25lIn0
        let token = "eyJhbGciOiJub25lIn0.eyJleHAiOjF9.sig";
        let mut r = HttpRequest::new("GET", "/");
        r.header.add("Authorization", format!("Bearer {token}"));
        let mut ctx = RequestContext::new(r);
        // Skip brute-force by using a non-POST method.
        let dec = c.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "CRED010");
    }

    #[test]
    fn jar_with_two_dots_ok() {
        let c = cred();
        let mut r = HttpRequest::new("GET", "/");
        r.header.add("Authorization", "Bearer a.b.c");
        let mut ctx = RequestContext::new(r);
        let dec = c.inspect(&mut ctx).unwrap();
        // Not a malformed-jwt finding; oauth abuse sees 2 dots -> returns None.
        if let Some(dec) = dec {
            assert_ne!(dec.rule_id, "CRED008");
        }
    }

    #[test]
    fn malformed_jwt_blocked() {
        let c = cred();
        let mut r = HttpRequest::new("GET", "/");
        r.header.add("Authorization", "Bearer notajwt");
        let mut ctx = RequestContext::new(r);
        let dec = c.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "CRED008");
    }
}
