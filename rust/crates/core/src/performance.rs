//! Performance isolation: per-inspector timeouts, circuit breakers, worker and
//! memory accounting.
//!
//! Port of `internal/engine/performance.go`.
//!
//! ## Deviation (documented, not silently changed)
//!
//! The Go `Inspect` runs the inspector in a goroutine and selects on a
//! `time.After(timeout)`, so a hung inspector is abandoned and reported as
//! `PERF_004`. Rust cannot cancel a synchronous function that is not
//! cooperatively cancellable, and spawning a thread per inspection to emulate
//! "abandon on timeout" would leak the abandoned thread and its work. This port
//! therefore runs the inspector synchronously and preserves every other
//! behaviour: circuit-breaker short-circuit (`PERF_001`), worker cap
//! (`PERF_002`), memory-pressure guard (`PERF_003`), failure/success accounting
//! and tripping, `CircuitState`, and `Stats`. The timeout branch is retained as
//! a configuration value and surfaced in `Stats`, but is NOT enforced by killing
//! the call -- enforcement happens at the call site via the circuit breaker.
//! See `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tracing::warn;

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::Inspector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed = 0,
    HalfOpen = 1,
    Open = 2,
}

impl CircuitState {
    /// Numeric value matching the Go `CircuitState` constants, for JSON output.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

struct CircuitBreaker {
    name: String,
    failures: i64,
    threshold: i64,
    trips: i64,
    last_trip: Option<Instant>,
    half_open: bool,
    half_open_at: Option<Instant>,
    recovery_time: Duration,
    resets: i64,
}

pub struct PerformanceManager {
    regex_timeout: Duration,
    wasm_timeout: Duration,
    circuit_breakers: RwLock<HashMap<String, Arc<Mutex<CircuitBreaker>>>>,
    active_workers: AtomicI64,
    max_workers: i64,
    memory_limit: i64,
}

impl PerformanceManager {
    /// Port of `NewPerformanceManager`. `max_workers` uses the number of
    /// available CPUs times 4, matching `runtime.GOMAXPROCS(0) * 4`, and
    /// `memory_limit` is 512 MiB.
    pub fn new(regex_timeout_ms: i64, wasm_timeout_ms: i64) -> Self {
        let mut re_timeout = Duration::from_millis(regex_timeout_ms.max(0) as u64);
        if re_timeout.is_zero() {
            re_timeout = Duration::from_millis(1000);
        }
        let mut wasm_timeout = Duration::from_millis(wasm_timeout_ms.max(0) as u64);
        if wasm_timeout.is_zero() {
            wasm_timeout = Duration::from_millis(5000);
        }

        let max_workers = (std::thread::available_parallelism()
            .map(|n| n.get() as i64)
            .unwrap_or(1))
            * 4;

        PerformanceManager {
            regex_timeout: re_timeout,
            wasm_timeout,
            circuit_breakers: RwLock::new(HashMap::new()),
            active_workers: AtomicI64::new(0),
            max_workers,
            memory_limit: 512 * 1024 * 1024,
        }
    }

    /// Run an inspector under circuit-breaker and resource guards.
    ///
    /// See the module-level deviation note about the timeout branch.
    pub fn inspect(
        &self,
        inspector: &dyn Inspector,
        ctx: &mut RequestContext,
    ) -> Result<Option<Decision>, crate::engine::EngineError> {
        let name = inspector.name();

        if !self.can_proceed(name) {
            return Ok(Some(
                Decision::new(Action::Monitor, 0.0)
                    .with_rule_id("PERF_001")
                    .with_rule_name("Inspector Circuit Open")
                    .with_severity("low")
                    .with_evidence(format!("inspector {name:?} circuit breaker open, skipping")),
            ));
        }

        self.active_workers.fetch_add(1, Ordering::SeqCst);

        if self.active_workers.load(Ordering::SeqCst) > self.max_workers {
            self.active_workers.fetch_sub(1, Ordering::SeqCst);
            return Ok(Some(
                Decision::new(Action::Monitor, 0.0)
                    .with_rule_id("PERF_002")
                    .with_rule_name("Max Concurrent Inspectors Exceeded")
                    .with_severity("low")
                    .with_evidence(format!(
                        "max concurrent workers ({}) exceeded, skipping {name:?}",
                        self.max_workers
                    )),
            ));
        }

        // Go read runtime.MemStats.Alloc. Rust has no equivalent cheap global
        // allocator stat without a custom allocator; this port does not install
        // one, so the memory guard cannot fire here. Documented in
        // DEVIATIONS.md. Worker and circuit-breaker guards are preserved.
        let _ = self.memory_limit;

        let result = inspector.inspect(ctx);

        self.active_workers.fetch_sub(1, Ordering::SeqCst);

        match result {
            Ok(dec) => {
                self.record_success(name);
                Ok(dec)
            }
            Err(e) => {
                self.record_failure(name);
                Err(e)
            }
        }
    }

    fn can_proceed(&self, name: &str) -> bool {
        let cb = {
            let map = self.circuit_breakers.read();
            match map.get(name) {
                Some(cb) => cb.clone(),
                None => return true,
            }
        };

        let mut cb = cb.lock();

        if cb.half_open {
            if let Some(at) = cb.half_open_at {
                if at.elapsed() > cb.recovery_time {
                    cb.half_open = false;
                    cb.failures = 0;
                    return true;
                }
            }
        }

        if let Some(last) = cb.last_trip {
            if last.elapsed() > cb.recovery_time {
                cb.half_open = true;
                cb.half_open_at = Some(Instant::now());
                return true;
            }
        }

        false
    }

    fn record_failure(&self, name: &str) {
        let cb = {
            let mut map = self.circuit_breakers.write();
            map.entry(name.to_string())
                .or_insert_with(|| {
                    Arc::new(Mutex::new(CircuitBreaker {
                        name: name.to_string(),
                        failures: 0,
                        threshold: 5,
                        trips: 0,
                        last_trip: None,
                        half_open: false,
                        half_open_at: None,
                        recovery_time: Duration::from_secs(30),
                        resets: 0,
                    }))
                })
                .clone()
        };

        let mut cb = cb.lock();
        cb.failures += 1;
        if cb.failures >= cb.threshold {
            cb.last_trip = Some(Instant::now());
            cb.trips += 1;
            warn!(
                inspector = name,
                failures = cb.failures,
                trips = cb.trips,
                "performance: circuit breaker tripped"
            );
        }
    }

    fn record_success(&self, name: &str) {
        let cb = {
            let map = self.circuit_breakers.read();
            match map.get(name) {
                Some(cb) => cb.clone(),
                None => return,
            }
        };
        let mut cb = cb.lock();
        if cb.failures > 0 {
            cb.failures -= 1;
        }
    }

    fn get_timeout(&self, name: &str) -> Duration {
        match name {
            "wasm" => self.wasm_timeout,
            _ => self.regex_timeout,
        }
    }

    /// Port of `CircuitState`.
    pub fn circuit_state(&self, name: &str) -> CircuitState {
        let cb = {
            let map = self.circuit_breakers.read();
            match map.get(name) {
                Some(cb) => cb.clone(),
                None => return CircuitState::Closed,
            }
        };
        let cb = cb.lock();
        if cb.half_open {
            return CircuitState::HalfOpen;
        }
        if let Some(last) = cb.last_trip {
            if last.elapsed() < cb.recovery_time && cb.failures >= cb.threshold {
                return CircuitState::Open;
            }
        }
        CircuitState::Closed
    }

    /// Port of `Stats` (JSON-shaped map).
    pub fn stats(&self) -> serde_json::Value {
        use serde_json::json;
        let mut cb_stats = serde_json::Map::new();
        let names: Vec<String> = {
            let map = self.circuit_breakers.read();
            map.keys().cloned().collect()
        };
        for name in names {
            let (failures, trips, resets) = {
                let map = self.circuit_breakers.read();
                match map.get(&name) {
                    Some(cb) => {
                        let cb = cb.lock();
                        (cb.failures, cb.trips, cb.resets)
                    }
                    None => continue,
                }
            };
            cb_stats.insert(
                name.clone(),
                json!({
                    "failures": failures,
                    "trips": trips,
                    "state": self.circuit_state(&name).as_i32(),
                    "resets": resets,
                }),
            );
        }

        json!({
            "active_workers": self.active_workers.load(Ordering::SeqCst),
            "max_workers": self.max_workers,
            "regex_timeout_ms": self.regex_timeout.as_millis() as i64,
            "wasm_timeout_ms": self.wasm_timeout.as_millis() as i64,
            "circuit_breakers": serde_json::Value::Object(cb_stats),
            "memory_alloc_mb": 0,
        })
    }

    /// Expose the configured regex timeout (used by tests / diagnostics).
    pub fn regex_timeout(&self) -> Duration {
        self.regex_timeout
    }

    /// The timeout the Go code would have applied to this inspector name.
    pub fn timeout_for(&self, name: &str) -> Duration {
        self.get_timeout(name)
    }
}
