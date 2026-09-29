//! Rate limiting: fixed window, sliding window, token bucket, leaky bucket.
//!
//! Port of `internal/ratelimit/ratelimit.go`. Algorithms, decisions
//! (`RetryAfter`, `Remaining`, `Limit`, `ResetAt`) and granularity resolution
//! are preserved exactly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    FixedWindow,
    SlidingWindow,
    TokenBucket,
    LeakyBucket,
}

impl Algorithm {
    pub fn from_str(s: &str) -> Algorithm {
        match s {
            "sliding_window" => Algorithm::SlidingWindow,
            "token_bucket" => Algorithm::TokenBucket,
            "leaky_bucket" => Algorithm::LeakyBucket,
            _ => Algorithm::FixedWindow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    PerIp,
    PerUser,
    PerSession,
    PerApiKey,
    PerEndpoint,
    PerGeo,
}

impl Granularity {
    pub fn from_str(s: &str) -> Granularity {
        match s {
            "user" => Granularity::PerUser,
            "session" => Granularity::PerSession,
            "api_key" => Granularity::PerApiKey,
            "endpoint" => Granularity::PerEndpoint,
            "geo" => Granularity::PerGeo,
            _ => Granularity::PerIp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub allowed: bool,
    pub retry_after: i64,
    pub remaining: i64,
    pub limit: i64,
    pub reset_at: Instant,
}

struct WindowEntry {
    timestamp: Instant,
    count: i64,
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

struct LeakyBucket {
    queue: Vec<Instant>,
    capacity: i64,
    leak_rate: Duration,
    last_leak: Instant,
}

struct State {
    fixed_windows: HashMap<String, WindowEntry>,
    sliding_windows: HashMap<String, Vec<Instant>>,
    token_buckets: HashMap<String, TokenBucket>,
    leaky_buckets: HashMap<String, LeakyBucket>,
    per_ip_limits: HashMap<String, i64>,
    per_user_limits: HashMap<String, i64>,
    per_endpoint_limits: HashMap<String, i64>,
    per_geo_limits: HashMap<String, i64>,
    per_api_key_limits: HashMap<String, i64>,
    priority_queues: HashMap<String, bool>,
}

pub struct RateLimiter {
    algorithm: Algorithm,
    default_rate: i64,
    default_burst: i64,
    window_size: Duration,
    cleanup_tick: Duration,
    state: Arc<RwLock<State>>,
}

impl RateLimiter {
    /// Port of `NewRateLimiter`. Cleanup is exposed via [`RateLimiter::cleanup`]
    /// rather than an owned goroutine.
    pub fn new(algorithm: Algorithm, default_rate: i32, default_burst: i32) -> Self {
        RateLimiter {
            algorithm,
            default_rate: default_rate as i64,
            default_burst: default_burst as i64,
            window_size: Duration::from_secs(1),
            cleanup_tick: Duration::from_secs(5 * 60),
            state: Arc::new(RwLock::new(State {
                fixed_windows: HashMap::new(),
                sliding_windows: HashMap::new(),
                token_buckets: HashMap::new(),
                leaky_buckets: HashMap::new(),
                per_ip_limits: HashMap::new(),
                per_user_limits: HashMap::new(),
                per_endpoint_limits: HashMap::new(),
                per_geo_limits: HashMap::new(),
                per_api_key_limits: HashMap::new(),
                priority_queues: HashMap::new(),
            })),
        }
    }

    /// Port of `Inspect` / `Allowed`.
    pub fn inspect(&self, key: &str, granularity: Granularity) -> (bool, Decision) {
        let rate = self.get_rate(key, granularity);
        let burst = self.get_burst(key);

        match self.algorithm {
            Algorithm::SlidingWindow => self.check_sliding_window(key, rate, burst),
            Algorithm::TokenBucket => self.check_token_bucket(key, rate, burst),
            Algorithm::LeakyBucket => self.check_leaky_bucket(key, rate, burst),
            Algorithm::FixedWindow => self.check_fixed_window(key, rate, burst),
        }
    }

    fn check_fixed_window(&self, key: &str, rate: i64, burst: i64) -> (bool, Decision) {
        let mut state = self.state.write();
        let now = Instant::now();
        let window_key = format!("{key}:{}", unix_now());

        let limit = rate + burst;

        match state.fixed_windows.get_mut(&window_key) {
            None => {
                state.fixed_windows.insert(
                    window_key.clone(),
                    WindowEntry {
                        timestamp: now,
                        count: 1,
                    },
                );
                (
                    true,
                    Decision {
                        allowed: true,
                        retry_after: 0,
                        remaining: limit - 1,
                        limit,
                        reset_at: now + Duration::from_secs(1),
                    },
                )
            }
            Some(entry) => {
                if now.duration_since(entry.timestamp) > Duration::from_secs(1) {
                    entry.timestamp = now;
                    entry.count = 1;
                    return (
                        true,
                        Decision {
                            allowed: true,
                            retry_after: 0,
                            remaining: limit - 1,
                            limit,
                            reset_at: now + Duration::from_secs(1),
                        },
                    );
                }
                entry.count += 1;
                if entry.count > limit {
                    return (
                        false,
                        Decision {
                            allowed: false,
                            retry_after: 1,
                            remaining: 0,
                            limit,
                            reset_at: now + Duration::from_secs(1),
                        },
                    );
                }
                (
                    true,
                    Decision {
                        allowed: true,
                        retry_after: 0,
                        remaining: limit - entry.count,
                        limit,
                        reset_at: now + Duration::from_secs(1),
                    },
                )
            }
        }
    }

    fn check_sliding_window(&self, key: &str, rate: i64, burst: i64) -> (bool, Decision) {
        let mut state = self.state.write();
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window_size);

        let entries = state.sliding_windows.get(key).cloned().unwrap_or_default();
        let mut valid: Vec<Instant> = Vec::new();
        for t in entries {
            let keep = match cutoff {
                Some(c) => t > c,
                None => true,
            };
            if keep {
                valid.push(t);
            }
        }

        let count = valid.len() as i64;
        let limit = rate + burst;

        if count >= limit {
            let oldest = valid[0];
            let elapsed = now.duration_since(oldest).as_secs_f64();
            let retry_after = (self.window_size.as_secs_f64() - elapsed).max(0.0) as i64;
            state.sliding_windows.insert(key.to_string(), valid);
            return (
                false,
                Decision {
                    allowed: false,
                    retry_after,
                    remaining: 0,
                    limit,
                    reset_at: oldest + self.window_size,
                },
            );
        }

        valid.push(now);
        state.sliding_windows.insert(key.to_string(), valid);

        (
            true,
            Decision {
                allowed: true,
                retry_after: 0,
                remaining: limit - count - 1,
                limit,
                reset_at: now + self.window_size,
            },
        )
    }

    fn check_token_bucket(&self, key: &str, rate: i64, burst: i64) -> (bool, Decision) {
        let rate = if rate <= 0 { 1 } else { rate };
        let mut state = self.state.write();

        let bucket = state
            .token_buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: burst as f64,
                capacity: burst as f64,
                refill_rate: rate as f64,
                last_refill: Instant::now(),
            });

        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = f64::min(
            bucket.capacity,
            bucket.tokens + elapsed * bucket.refill_rate,
        );
        bucket.last_refill = now;

        if bucket.tokens < 1.0 {
            let refill_ms = (1.0 / bucket.refill_rate * 1000.0) as i64;
            let refill_time = Duration::from_millis(refill_ms.max(0) as u64);
            return (
                false,
                Decision {
                    allowed: false,
                    retry_after: refill_ms,
                    remaining: 0,
                    limit: rate + burst,
                    reset_at: now + refill_time,
                },
            );
        }

        bucket.tokens -= 1.0;
        (
            true,
            Decision {
                allowed: true,
                retry_after: 0,
                remaining: bucket.tokens as i64,
                limit: rate + burst,
                reset_at: now + Duration::from_secs(1),
            },
        )
    }

    fn check_leaky_bucket(&self, key: &str, rate: i64, burst: i64) -> (bool, Decision) {
        let rate = if rate <= 0 { 1 } else { rate };
        let mut state = self.state.write();

        let leak_rate = Duration::from_secs(1) / (rate as u32);
        let bucket = state
            .leaky_buckets
            .entry(key.to_string())
            .or_insert_with(|| LeakyBucket {
                queue: Vec::with_capacity(burst.max(0) as usize),
                capacity: burst,
                leak_rate,
                last_leak: Instant::now(),
            });

        let now = Instant::now();
        let leak_count = (now.duration_since(bucket.last_leak).as_nanos()
            / bucket.leak_rate.as_nanos().max(1)) as i64;
        if leak_count > 0 {
            if leak_count >= bucket.queue.len() as i64 {
                bucket.queue.clear();
            } else {
                bucket.queue.drain(0..leak_count as usize);
            }
            bucket.last_leak = now;
        }

        if bucket.queue.len() as i64 >= bucket.capacity {
            let oldest = bucket.queue[0];
            let retry_after = (bucket.leak_rate.as_millis() as i64
                * (bucket.queue.len() as i64 - bucket.capacity + 1))
                / 1_000_000;
            return (
                false,
                Decision {
                    allowed: false,
                    retry_after,
                    remaining: 0,
                    limit: burst,
                    reset_at: oldest + bucket.leak_rate * burst as u32,
                },
            );
        }

        bucket.queue.push(now);
        let remaining = bucket.capacity - bucket.queue.len() as i64;
        (
            true,
            Decision {
                allowed: true,
                retry_after: 0,
                remaining,
                limit: burst,
                reset_at: now + bucket.leak_rate * remaining.max(0) as u32,
            },
        )
    }

    fn get_rate(&self, key: &str, granularity: Granularity) -> i64 {
        let state = self.state.read();
        let map = match granularity {
            Granularity::PerIp => &state.per_ip_limits,
            Granularity::PerUser => &state.per_user_limits,
            Granularity::PerEndpoint => &state.per_endpoint_limits,
            Granularity::PerGeo => &state.per_geo_limits,
            Granularity::PerApiKey => &state.per_api_key_limits,
            Granularity::PerSession => &state.per_ip_limits,
        };
        // PerSession has no dedicated map in Go (it fell through to default).
        if granularity == Granularity::PerSession {
            return self.default_rate;
        }
        map.get(key).copied().unwrap_or(self.default_rate)
    }

    fn get_burst(&self, key: &str) -> i64 {
        if self
            .state
            .read()
            .priority_queues
            .get(key)
            .copied()
            .unwrap_or(false)
        {
            self.default_burst * 2
        } else {
            self.default_burst
        }
    }

    /// Port of `SetRateLimit`.
    pub fn set_rate_limit(&self, granularity: Granularity, key: &str, rate: i64) {
        let mut state = self.state.write();
        let map = match granularity {
            Granularity::PerIp => &mut state.per_ip_limits,
            Granularity::PerUser => &mut state.per_user_limits,
            Granularity::PerEndpoint => &mut state.per_endpoint_limits,
            Granularity::PerGeo => &mut state.per_geo_limits,
            Granularity::PerApiKey => &mut state.per_api_key_limits,
            Granularity::PerSession => &mut state.per_ip_limits,
        };
        map.insert(key.to_string(), rate);
    }

    /// Port of `SetPriority`.
    pub fn set_priority(&self, key: &str, premium: bool) {
        self.state
            .write()
            .priority_queues
            .insert(key.to_string(), premium);
    }

    /// Port of the `cleanupLoop` body.
    pub fn cleanup(&self) {
        let mut state = self.state.write();
        let now = Instant::now();
        let window = self.window_size;
        state
            .fixed_windows
            .retain(|_, e| now.duration_since(e.timestamp) <= window * 2);
        state.sliding_windows.retain(|_, entries| {
            let cutoff = now.checked_sub(window * 2);
            match cutoff {
                Some(c) => entries.retain(|t| *t > c),
                None => {}
            }
            !entries.is_empty()
        });
        let tick2 = self.cleanup_tick * 2;
        state
            .token_buckets
            .retain(|_, b| now.duration_since(b.last_refill) <= tick2);
        state
            .leaky_buckets
            .retain(|_, b| !(now.duration_since(b.last_leak) > tick2 && b.queue.is_empty()));
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window_allows_up_to_limit() {
        let rl = RateLimiter::new(Algorithm::FixedWindow, 2, 1); // limit 3
        let (a1, d1) = rl.inspect("k", Granularity::PerIp);
        assert!(a1);
        assert_eq!(d1.limit, 3);
        let _ = rl.inspect("k", Granularity::PerIp);
        let (a3, _) = rl.inspect("k", Granularity::PerIp);
        assert!(a3);
        let (a4, d4) = rl.inspect("k", Granularity::PerIp);
        assert!(!a4);
        assert_eq!(d4.retry_after, 1);
    }

    #[test]
    fn sliding_window_blocks_when_full() {
        let rl = RateLimiter::new(Algorithm::SlidingWindow, 1, 1); // limit 2
        assert!(rl.inspect("k", Granularity::PerIp).0);
        assert!(rl.inspect("k", Granularity::PerIp).0);
        assert!(!rl.inspect("k", Granularity::PerIp).0);
    }

    #[test]
    fn token_bucket_allows_burst_then_blocks() {
        let rl = RateLimiter::new(Algorithm::TokenBucket, 1, 2);
        assert!(rl.inspect("k", Granularity::PerIp).0);
        assert!(rl.inspect("k", Granularity::PerIp).0);
        // Bucket now empty (capacity 2).
        assert!(!rl.inspect("k", Granularity::PerIp).0);
    }

    #[test]
    fn priority_doubles_burst() {
        let rl = RateLimiter::new(Algorithm::TokenBucket, 1, 2);
        rl.set_priority("vip", true);
        let (_, d) = rl.inspect("vip", Granularity::PerIp);
        assert_eq!(d.limit, 1 + 4); // rate + burst*2
    }

    #[test]
    fn set_rate_limit_overrides_default() {
        let rl = RateLimiter::new(Algorithm::FixedWindow, 1, 0);
        rl.set_rate_limit(Granularity::PerIp, "k", 10);
        let (_, d) = rl.inspect("k", Granularity::PerIp);
        assert_eq!(d.limit, 10);
    }

    #[test]
    fn cleanup_does_not_panic() {
        let rl = RateLimiter::new(Algorithm::SlidingWindow, 1, 1);
        rl.inspect("k", Granularity::PerIp);
        rl.cleanup();
    }
}
