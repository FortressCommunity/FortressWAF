//! Admin login rate limiter (per source address).
//!
//! Port of `cmd/proxy/loginlimit.go`. The windowed failure count, lockout, and
//! the deliberate refusal to read X-Forwarded-For are preserved.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub struct LoginLimiter {
    max_failures: usize,
    lock_for: Duration,
    window: Duration,
    failures: Mutex<HashMap<String, Vec<Instant>>>,
    locked_at: Mutex<HashMap<String, Instant>>,
}

impl LoginLimiter {
    /// Port of `newLoginLimiter`.
    pub fn new(max_failures: usize, lock_for: Duration, window: Duration) -> Self {
        LoginLimiter {
            max_failures,
            lock_for,
            window,
            failures: Mutex::new(HashMap::new()),
            locked_at: Mutex::new(HashMap::new()),
        }
    }

    /// Port of `key`: the caller's address, with X-Forwarded-For deliberately
    /// ignored.
    pub fn key(remote_addr: &str) -> String {
        crate::pipeline::split_host_port(remote_addr)
            .map(|(h, _)| h)
            .unwrap_or_else(|| remote_addr.to_string())
    }

    /// Port of `isLocked`: returns (locked, retry_after).
    pub fn is_locked(&self, remote_addr: &str) -> (bool, Duration) {
        let key = Self::key(remote_addr);
        let mut locked = self.locked_at.lock();
        match locked.get(&key).copied() {
            Some(until) if Instant::now() <= until => {
                (true, until.saturating_duration_since(Instant::now()))
            }
            Some(_) => {
                locked.remove(&key);
                (false, Duration::ZERO)
            }
            None => (false, Duration::ZERO),
        }
    }

    /// Port of `recordFailure`: returns whether the allowance is now exhausted.
    pub fn record_failure(&self, remote_addr: &str) -> bool {
        let key = Self::key(remote_addr);
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window);

        let mut failures = self.failures.lock();
        let entry = failures.entry(key.clone()).or_default();
        entry.retain(|t| match cutoff {
            Some(c) => *t > c,
            None => true,
        });
        entry.push(now);

        if entry.len() >= self.max_failures {
            self.locked_at.lock().insert(key, now + self.lock_for);
            return true;
        }
        false
    }

    /// Port of `recordSuccess`.
    pub fn record_success(&self, remote_addr: &str) {
        let key = Self::key(remote_addr);
        self.failures.lock().remove(&key);
        self.locked_at.lock().remove(&key);
    }

    /// Port of `gc`.
    pub fn gc(&self) {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window);
        let mut failures = self.failures.lock();
        failures.retain(|_, ts| {
            ts.retain(|t| match cutoff {
                Some(c) => *t > c,
                None => true,
            });
            !ts.is_empty()
        });
        self.locked_at.lock().retain(|_, until| now <= *until);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_max_failures() {
        let l = LoginLimiter::new(3, Duration::from_secs(900), Duration::from_secs(60));
        assert!(!l.is_locked("1.2.3.4:1234").0);
        l.record_failure("1.2.3.4:1234");
        l.record_failure("1.2.3.4:1234");
        assert!(l.record_failure("1.2.3.4:1234"));
        let (locked, retry) = l.is_locked("1.2.3.4:1234");
        assert!(locked);
        assert!(retry.as_secs() > 0);
    }

    #[test]
    fn success_clears_history() {
        let l = LoginLimiter::new(3, Duration::from_secs(900), Duration::from_secs(60));
        l.record_failure("1.2.3.4:1");
        l.record_failure("1.2.3.4:1");
        l.record_success("1.2.3.4:1");
        assert!(!l.is_locked("1.2.3.4:1").0);
        // Counter reset: one more failure must not lock.
        assert!(!l.record_failure("1.2.3.4:1"));
    }

    #[test]
    fn different_ports_same_ip_share_key() {
        let l = LoginLimiter::new(2, Duration::from_secs(900), Duration::from_secs(60));
        l.record_failure("1.2.3.4:1000");
        assert!(l.record_failure("1.2.3.4:2000"));
    }
}
