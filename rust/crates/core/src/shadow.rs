//! Learning / shadow mode: per-path baselines and auto-whitelisting.
//!
//! Port of `internal/engine/shadow.go`.
//!
//! The Go `LearningEngine` ran a cleanup goroutine every 15 minutes; here
//! [`LearningEngine::cleanup`] performs the same prune and callers schedule it.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::action::{Action, Decision};
use crate::context::RequestContext;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(15 * 60);
const WHITELIST_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const BASELINE_TTL: Duration = Duration::from_secs(72 * 3600);

#[derive(Debug, Clone)]
pub struct PathBaseline {
    pub path: String,
    pub total_count: i64,
    pub allowed_count: i64,
    pub mean_rate: f64,
    pub std_dev: f64,
    pub sum_squares: f64,
    pub last_seen: Instant,
    pub status_codes: HashMap<i32, i64>,
    pub methods: HashMap<String, i64>,
}

#[derive(Debug, Clone)]
struct WhitelistEntry {
    pattern: String,
    reason: String,
    expires_at: Instant,
    hits: i64,
    created_at: Instant,
}

pub struct LearningEngine {
    baselines: Arc<RwLock<HashMap<String, PathBaseline>>>,
    whitelist: Arc<RwLock<HashMap<String, WhitelistEntry>>>,
    evaluation: bool,
    pub cleanup_interval: Duration,
}

impl Default for LearningEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl LearningEngine {
    pub fn new() -> Self {
        LearningEngine {
            baselines: Arc::new(RwLock::new(HashMap::new())),
            whitelist: Arc::new(RwLock::new(HashMap::new())),
            evaluation: true,
            cleanup_interval: CLEANUP_INTERVAL,
        }
    }

    /// Port of `Record`.
    pub fn record(&self, _inspector: &str, ctx: &RequestContext, dec: Option<&Decision>) {
        let path = ctx.path.clone();
        let status = ctx.response.as_ref().map(|r| r.status_code).unwrap_or(0);

        let mut baselines = self.baselines.write();

        let bl = baselines
            .entry(path.clone())
            .or_insert_with(|| PathBaseline {
                path: path.clone(),
                total_count: 0,
                allowed_count: 0,
                mean_rate: 0.0,
                std_dev: 0.0,
                sum_squares: 0.0,
                last_seen: Instant::now(),
                status_codes: HashMap::new(),
                methods: HashMap::new(),
            });

        bl.total_count += 1;
        bl.last_seen = Instant::now();
        *bl.methods.entry(ctx.method.clone()).or_insert(0) += 1;
        if status > 0 {
            *bl.status_codes.entry(status).or_insert(0) += 1;
        }

        if let Some(dec) = dec {
            if dec.action == Action::Allow {
                bl.allowed_count += 1;

                if !self.evaluation {
                    return;
                }

                // NOTE: Go computed `time.Since(bl.lastSeen)` AFTER assigning
                // lastSeen = time.Now() just above, so the elapsed time is
                // effectively ~0 and `math.Max(1, ...)` clamps the divisor to 1;
                // rate therefore equals allowedCount. This port reproduces that
                // arithmetic exactly (elapsed since the lastSeen we just set).
                let elapsed = bl.last_seen.elapsed().as_secs_f64();
                let rate = bl.allowed_count as f64 / f64::max(1.0, elapsed);
                if bl.mean_rate > 0.0 {
                    let old_mean = bl.mean_rate;
                    bl.mean_rate = old_mean + (rate - old_mean) / bl.total_count as f64;
                    bl.sum_squares += (rate - old_mean) * (rate - bl.mean_rate);
                    bl.std_dev = (bl.sum_squares / bl.total_count as f64).sqrt();
                } else {
                    bl.mean_rate = rate;
                }
            }
        }

        let should_whitelist =
            self.evaluation && bl.total_count > 100 && bl.allowed_count > bl.total_count * 90 / 100;
        let reason = if should_whitelist {
            Some(format!(
                "automatic: {} allowed / {} total for path {} with methods {:?} and statuses {:?}",
                bl.allowed_count,
                bl.total_count,
                path,
                map_keys(&bl.methods),
                map_keys_int(&bl.status_codes)
            ))
        } else {
            None
        };

        drop(baselines);

        if let Some(reason) = reason {
            self.auto_whitelist(&path, &reason);
        }
    }

    /// Port of `Baseline` (returns a copy).
    pub fn baseline(&self, path: &str) -> Option<PathBaseline> {
        self.baselines.read().get(path).cloned()
    }

    /// Port of `IsWhitelisted`.
    pub fn is_whitelisted(&self, path: &str) -> bool {
        let whitelist = self.whitelist.read();
        match whitelist.get(path) {
            Some(entry) => Instant::now() < entry.expires_at,
            None => false,
        }
    }

    fn auto_whitelist(&self, path: &str, reason: &str) {
        let mut whitelist = self.whitelist.write();
        if whitelist.contains_key(path) {
            return;
        }
        whitelist.insert(
            path.to_string(),
            WhitelistEntry {
                pattern: path.to_string(),
                reason: reason.to_string(),
                expires_at: Instant::now() + WHITELIST_TTL,
                hits: 0,
                created_at: Instant::now(),
            },
        );
        info!(
            path = path,
            reason = reason,
            "learning: auto-whitelisted path"
        );
    }

    /// Port of the `cleanupLoop` body.
    pub fn cleanup(&self) {
        let now = Instant::now();
        {
            let mut whitelist = self.whitelist.write();
            whitelist.retain(|path, entry| {
                if now >= entry.expires_at {
                    debug!(path = path.as_str(), "learning: whitelist entry expired");
                    false
                } else {
                    true
                }
            });
        }
        {
            let mut baselines = self.baselines.write();
            baselines.retain(|_, bl| now.duration_since(bl.last_seen) <= BASELINE_TTL);
        }
    }

    /// Port of `Stats`.
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "baselines": self.baselines.read().len(),
            "whitelist": self.whitelist.read().len(),
            "evaluation": self.evaluation,
        })
    }
}

fn map_keys(m: &HashMap<String, i64>) -> Vec<String> {
    let mut keys: Vec<String> = m.keys().cloned().collect();
    keys.sort();
    keys
}

fn map_keys_int(m: &HashMap<i32, i64>) -> Vec<i32> {
    let mut keys: Vec<i32> = m.keys().copied().collect();
    keys.sort_unstable();
    keys
}
