//! eBPF telemetry counters.
//!
//! Port of `internal/engine/ebpf.go` (the linux variant, which is pure
//! in-memory counters -- no real eBPF syscalls) and `ebpf_stub.go` (the
//! non-linux variant, which is a no-op). The port keeps the counter logic and
//! the `EBPF_001` decision, and provides the stub behaviour when telemetry is
//! disabled.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

struct Counters {
    packet_count: u64,
    byte_count: u64,
    syn_count: u64,
    rst_count: u64,
}

pub struct EbpfTelemetry {
    pub dev_mode: bool,
    iface: String,
    port: i32,
    sample_rate: i32,
    counters: Arc<RwLock<Counters>>,
    active: Arc<AtomicBool>,
    stop: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

impl EbpfTelemetry {
    pub fn new(dev_mode: bool, iface: String, port: i32, sample_rate: i32) -> Self {
        EbpfTelemetry {
            dev_mode,
            iface,
            port,
            sample_rate,
            counters: Arc::new(RwLock::new(Counters {
                packet_count: 0,
                byte_count: 0,
                syn_count: 0,
                rst_count: 0,
            })),
            active: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(Mutex::new(None)),
        }
    }

    /// Port of `Start`. Spawns a background thread that increments counters
    /// every second, mirroring `collectLoop`.
    pub fn start(&self) {
        if self.active.swap(true, Ordering::SeqCst) {
            return;
        }
        let stop_flag = Arc::new(AtomicBool::new(false));
        *self.stop.lock() = Some(stop_flag.clone());

        let counters = self.counters.clone();
        let sample_rate = self.sample_rate;
        std::thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(1));
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                let mut c = counters.write();
                c.packet_count += (sample_rate * 100).max(0) as u64;
                c.byte_count += (sample_rate * 10240).max(0) as u64;
                let step = (sample_rate * 100).max(0) as u64;
                if step > 0 && c.packet_count % step < step {
                    c.syn_count += (sample_rate * 5).max(0) as u64;
                }
            }
        });
    }

    /// Port of `Stop`.
    pub fn stop(&self) {
        if !self.active.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Some(flag) = self.stop.lock().take() {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// Port of `Stats`.
    pub fn stats(&self) -> std::collections::HashMap<String, u64> {
        let c = self.counters.read();
        let mut m = std::collections::HashMap::new();
        m.insert("packets".to_string(), c.packet_count);
        m.insert("bytes".to_string(), c.byte_count);
        m.insert("syn".to_string(), c.syn_count);
        m.insert("rst".to_string(), c.rst_count);
        m
    }

    /// Accessor: the configured interface.
    pub fn iface(&self) -> &str {
        &self.iface
    }
}

/// The stub behaviour for non-linux/disabled telemetry, matching `ebpf_stub.go`.
pub fn stub_inspect() -> Option<Decision> {
    None
}

impl Inspector for EbpfTelemetry {
    fn name(&self) -> &str {
        "ebpf"
    }

    fn inspect(&self, _ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let count = self.counters.read().packet_count;
        if count > 1_000_000 {
            return Ok(Some(
                Decision::new(Action::Monitor, 10.0)
                    .with_rule_id("EBPF_001")
                    .with_rule_name("Elevated Packet Activity")
                    .with_severity("low")
                    .with_evidence(format!(
                        "eBPF detected {count} total packets on {}",
                        self.iface
                    )),
            ));
        }
        // Parity with the stub: no decision.
        Ok(stub_inspect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    #[test]
    fn below_threshold_no_decision() {
        let e = EbpfTelemetry::new(false, "eth0".into(), 80, 100);
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        assert!(e.inspect(&mut ctx).unwrap().is_none());
    }

    #[test]
    fn elevated_packets_monitored() {
        let e = EbpfTelemetry::new(false, "eth0".into(), 80, 100);
        e.counters.write().packet_count = 2_000_000;
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        let dec = e.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "EBPF_001");
    }

    #[test]
    fn stats_shape() {
        let e = EbpfTelemetry::new(false, "eth0".into(), 80, 100);
        let s = e.stats();
        assert!(s.contains_key("packets"));
        assert!(s.contains_key("bytes"));
    }
}
