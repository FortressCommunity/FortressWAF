//! IP block list with expiry.
//!
//! Port of `internal/blocklist/store.go`. Ban/unban semantics, lazy eviction,
//! newest-first listing and permanent bans are preserved.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub ip: String,
    pub reason: String,
    /// RFC3339 timestamp, matching Go's `time.Time` JSON rendering.
    pub created_at: String,
    /// RFC3339 expiry; empty for permanent bans.
    #[serde(default)]
    pub expires_at: String,
    pub created_by: String,
    pub permanent: bool,

    /// Internal ordering key (not serialized), giving the sub-second precision
    /// Go's `time.Time` comparison provided.
    #[serde(skip, default = "Instant::now")]
    created_instant: Instant,
    /// Internal expiry instant (not serialized).
    #[serde(skip)]
    expires_instant: Option<Instant>,
}

/// The ban store. Safe for concurrent use.
pub struct Store {
    bans: RwLock<HashMap<String, Entry>>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// Port of `New`.
    pub fn new() -> Self {
        Store {
            bans: RwLock::new(HashMap::new()),
        }
    }

    /// Port of `Ban`. A zero ttl means permanent.
    pub fn ban(&self, ip: &str, reason: &str, by: &str, ttl: Duration) -> Result<Entry, String> {
        let parsed = IpAddr::from_str(ip.trim()).map_err(|_| format!("invalid IP: {ip}"))?;
        let key = canonical_ip(parsed);

        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let permanent = ttl.as_secs() == 0;
        let expires_instant = if permanent { None } else { Some(now + ttl) };
        let e = Entry {
            ip: key.clone(),
            reason: reason.to_string(),
            created_at: rfc3339(now_unix),
            expires_at: if permanent {
                String::new()
            } else {
                rfc3339(now_unix + ttl.as_secs())
            },
            created_by: by.to_string(),
            permanent,
            created_instant: now,
            expires_instant,
        };
        self.bans.write().insert(key, e.clone());
        Ok(e)
    }

    /// Port of `Unban`. Returns whether the address was banned.
    pub fn unban(&self, ip: &str) -> bool {
        let key = match IpAddr::from_str(ip.trim()) {
            Ok(parsed) => canonical_ip(parsed),
            Err(_) => ip.to_string(),
        };
        let mut bans = self.bans.write();
        bans.remove(&key).is_some()
    }

    /// Port of `IsBanned`, with lazy eviction of expired entries.
    pub fn is_banned(&self, ip: &str) -> bool {
        let parsed = match IpAddr::from_str(ip.trim()) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let key = canonical_ip(parsed);

        let entry = {
            let bans = self.bans.read();
            bans.get(&key).cloned()
        };
        let entry = match entry {
            Some(e) => e,
            None => return false,
        };
        let expired = match entry.expires_instant {
            Some(exp) => Instant::now() > exp,
            None => false,
        };
        if !entry.permanent && expired {
            let mut bans = self.bans.write();
            if let Some(cur) = bans.get(&key) {
                let still_expired = match cur.expires_instant {
                    Some(exp) => Instant::now() > exp,
                    None => false,
                };
                if !cur.permanent && still_expired {
                    bans.remove(&key);
                }
            }
            return false;
        }
        true
    }

    /// Port of `List`: active bans, newest first, pruning expired.
    pub fn list(&self) -> Vec<Entry> {
        let mut bans = self.bans.write();
        let now = Instant::now();
        let mut out: Vec<Entry> = Vec::with_capacity(bans.len());
        bans.retain(|_, e| {
            let expired = match e.expires_instant {
                Some(exp) => now > exp,
                None => false,
            };
            if !e.permanent && expired {
                false
            } else {
                out.push(e.clone());
                true
            }
        });
        out.sort_by(|a, b| b.created_instant.cmp(&a.created_instant));
        out
    }

    /// Port of `Count`.
    pub fn count(&self) -> usize {
        self.list().len()
    }
}

/// Go's `net.ParseIP(ip).String()` canonical form.
fn canonical_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
    }
}

/// Format a Unix seconds value as an RFC3339 UTC timestamp
/// (`2006-01-02T15:04:05Z`), matching Go's `time.Time` JSON rendering.
fn rfc3339(unix_secs: u64) -> String {
    let days = unix_secs / 86400;
    let rem = unix_secs % 86400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days as i64);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Convert days-since-Unix-epoch to (year, month, day). Standard civil-from-days
/// algorithm (Howard Hinnant), valid for the full proleptic Gregorian range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_and_is_banned() {
        let s = Store::new();
        s.ban("1.2.3.4", "flood", "admin", Duration::from_secs(300))
            .unwrap();
        assert!(s.is_banned("1.2.3.4"));
        assert!(!s.is_banned("5.6.7.8"));
    }

    #[test]
    fn invalid_ip_rejected() {
        let s = Store::new();
        assert!(s.ban("not-an-ip", "x", "admin", Duration::ZERO).is_err());
        assert!(!s.is_banned("not-an-ip"));
    }

    #[test]
    fn permanent_ban_has_no_expiry() {
        let s = Store::new();
        let e = s
            .ban("9.9.9.9", "forever", "admin", Duration::ZERO)
            .unwrap();
        assert!(e.permanent);
        assert!(s.is_banned("9.9.9.9"));
    }

    #[test]
    fn unban_removes() {
        let s = Store::new();
        s.ban("1.1.1.1", "x", "a", Duration::from_secs(60)).unwrap();
        assert!(s.unban("1.1.1.1"));
        assert!(!s.is_banned("1.1.1.1"));
        assert!(!s.unban("1.1.1.1"));
    }

    #[test]
    fn list_newest_first() {
        let s = Store::new();
        s.ban("1.0.0.1", "a", "x", Duration::from_secs(300))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.ban("1.0.0.2", "b", "x", Duration::from_secs(300))
            .unwrap();
        let list = s.list();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].ip, "1.0.0.2");
    }
}
