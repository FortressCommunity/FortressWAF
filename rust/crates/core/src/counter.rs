//! Sliding-window request counter shared by the DDoS and bot inspectors.
//!
//! Port of `SlidingWindowCounter` from `internal/engine/ddos.go`.

use std::time::{Duration, Instant};

use parking_lot::Mutex;

pub struct SlidingWindowCounter {
    timestamps: Mutex<Vec<Instant>>,
    window: Duration,
    /// Retained for parity with the Go struct field; not used by record/count.
    #[allow(dead_code)]
    max_count: usize,
}

impl SlidingWindowCounter {
    pub fn new(window: Duration, max_count: usize) -> Self {
        SlidingWindowCounter {
            timestamps: Mutex::new(Vec::new()),
            window,
            max_count,
        }
    }

    /// With a pre-sized capacity, matching the Go constructors.
    pub fn with_capacity(window: Duration, max_count: usize, capacity: usize) -> Self {
        SlidingWindowCounter {
            timestamps: Mutex::new(Vec::with_capacity(capacity)),
            window,
            max_count,
        }
    }

    /// Add a timestamp now and prune anything older than the window.
    /// Port of `record`.
    pub fn record(&self, now: Instant) {
        let mut ts = self.timestamps.lock();
        let cutoff = now.checked_sub(self.window);
        let mut valid: Vec<Instant> = Vec::with_capacity(ts.len());
        for &t in ts.iter() {
            match cutoff {
                Some(c) => {
                    if t > c {
                        valid.push(t);
                    }
                }
                None => valid.push(t),
            }
        }
        valid.push(now);
        *ts = valid;
    }

    /// Number of timestamps still inside the window. Port of `count`.
    pub fn count(&self) -> usize {
        let ts = self.timestamps.lock();
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window);
        let mut n = 0;
        for &t in ts.iter() {
            match cutoff {
                Some(c) => {
                    if t > c {
                        n += 1;
                    }
                }
                None => n += 1,
            }
        }
        n
    }

    /// Newest timestamp, or `None` when empty (Go returns the zero time).
    /// Port of `lastSeen`.
    pub fn last_seen(&self) -> Option<Instant> {
        let ts = self.timestamps.lock();
        ts.last().copied()
    }

    /// Raw timestamp count (used by `GetAdaptiveRate`, which the Go code did
    /// with `len(counter.timestamps)`).
    pub fn raw_len(&self) -> usize {
        self.timestamps.lock().len()
    }

    /// Port of the DDoS `checkRate` body: prune entries older than `cutoff`,
    /// and if the surviving count is >= `limit` return false (rate limited)
    /// WITHOUT recording; otherwise append `now` and return true.
    pub fn check_and_record(&self, now: Instant, cutoff: Option<Instant>, limit: usize) -> bool {
        let mut ts = self.timestamps.lock();
        let mut valid: Vec<Instant> = Vec::with_capacity(ts.len());
        for &t in ts.iter() {
            match cutoff {
                Some(c) => {
                    if t > c {
                        valid.push(t);
                    }
                }
                None => valid.push(t),
            }
        }
        *ts = valid;

        if ts.len() >= limit {
            return false;
        }
        ts.push(now);
        true
    }

    /// The window duration (parity accessor).
    pub fn window(&self) -> Duration {
        self.window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_count() {
        let c = SlidingWindowCounter::new(Duration::from_secs(60), 10);
        let now = Instant::now();
        c.record(now);
        c.record(now);
        c.record(now);
        assert_eq!(c.count(), 3);
    }

    #[test]
    fn old_entries_pruned() {
        let c = SlidingWindowCounter::new(Duration::from_millis(50), 10);
        let old = Instant::now() - Duration::from_secs(1);
        c.record(old);
        // The next record prunes the stale entry.
        c.record(Instant::now());
        assert_eq!(c.count(), 1);
    }
}
