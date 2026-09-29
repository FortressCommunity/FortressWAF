//! IP reputation engine: allow/block CIDRs, Tor/VPN/proxy/datacenter scoring.
//!
//! Port of `internal/reputation/reputation.go`. Scoring, the datacenter CIDR
//! list, and the cache TTL are preserved exactly.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Cidr (network + prefix) with a `contains` test.
#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse a CIDR like `net.ParseCIDR`, masking the network.
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip_part, prefix_part) = s.trim().split_once('/')?;
        let ip = IpAddr::from_str(ip_part).ok()?;
        let prefix: u8 = prefix_part.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return None;
        }
        Some(Cidr {
            network: mask_ip(ip, prefix),
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask_ip(ip, self.prefix) == self.network
            }
            (IpAddr::V4(net), IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                Some(v4) => mask_ip(IpAddr::V4(v4), self.prefix) == IpAddr::V4(net),
                None => false,
            },
            (IpAddr::V6(_), IpAddr::V4(v4)) => {
                mask_ip(IpAddr::V6(v4.to_ipv6_mapped()), self.prefix) == self.network
            }
        }
    }
}

fn mask_ip(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            IpAddr::V4(std::net::Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(std::net::Ipv6Addr::from(bits & mask))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedSource {
    AbuseIpdb,
    Spamhaus,
    EmergingThreats,
    AlienVaultOtx,
    TorExitNodes,
    VpnRanges,
    ProxyRanges,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpRecord {
    pub ip: String,
    pub score: f64,
    pub last_seen: i64,
    pub abuse_reports: i32,
    pub source: FeedSource,
    pub categories: Vec<String>,
    pub is_tor: bool,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub is_datacenter: bool,

    #[serde(skip, default = "Instant::now")]
    last_seen_instant: Instant,
}

struct State {
    cache: HashMap<String, IpRecord>,
    allowlist: Vec<Cidr>,
    blocklist: Vec<Cidr>,
    allowlist_asns: HashMap<u32, bool>,
    blocklist_asns: HashMap<u32, bool>,
    allowlist_countries: HashMap<String, bool>,
    blocklist_countries: HashMap<String, bool>,
    tor_nodes: HashMap<String, bool>,
    vpn_ranges: Vec<Cidr>,
    proxy_ranges: Vec<Cidr>,
}

pub struct Engine {
    state: Arc<RwLock<State>>,
    cache_ttl: Duration,
}

/// The datacenter CIDR list, reproduced verbatim from `isDatacenterIP`.
const DATACENTER_RANGES: &[&str] = &[
    "13.32.0.0/15",
    "13.104.0.0/14",
    "15.0.0.0/8",
    "35.0.0.0/8",
    "52.0.0.0/8",
    "54.0.0.0/8",
    "63.0.0.0/8",
    "64.0.0.0/8",
    "65.0.0.0/8",
    "66.0.0.0/8",
    "67.0.0.0/8",
    "68.0.0.0/8",
    "69.0.0.0/8",
    "70.0.0.0/8",
    "71.0.0.0/8",
    "72.0.0.0/8",
    "73.0.0.0/8",
    "74.0.0.0/8",
    "75.0.0.0/8",
    "76.0.0.0/8",
    "77.0.0.0/8",
    "78.0.0.0/8",
    "79.0.0.0/8",
    "80.0.0.0/5",
    "96.0.0.0/6",
    "100.0.0.0/8",
    "104.0.0.0/8",
    "108.0.0.0/8",
    "128.0.0.0/16",
];

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// Port of `NewEngine`.
    pub fn new() -> Self {
        Engine {
            state: Arc::new(RwLock::new(State {
                cache: HashMap::new(),
                allowlist: vec![],
                blocklist: vec![],
                allowlist_asns: HashMap::new(),
                blocklist_asns: HashMap::new(),
                allowlist_countries: HashMap::new(),
                blocklist_countries: HashMap::new(),
                tor_nodes: HashMap::new(),
                vpn_ranges: vec![],
                proxy_ranges: vec![],
            })),
            cache_ttl: Duration::from_secs(30 * 60),
        }
    }

    /// Port of `Inspect`. Returns the record and its score.
    pub fn inspect(&self, ip_str: &str) -> (Option<IpRecord>, f64) {
        if ip_str.is_empty() {
            return (None, 0.0);
        }

        {
            let state = self.state.read();
            if let Some(record) = state.cache.get(ip_str) {
                if record.last_seen_instant.elapsed() < self.cache_ttl {
                    return (Some(record.clone()), record.score);
                }
            }
        }

        let ip = match IpAddr::from_str(ip_str) {
            Ok(ip) => ip,
            Err(_) => return (None, 0.0),
        };

        let mut record = IpRecord {
            ip: ip_str.to_string(),
            score: 0.0,
            last_seen: now_unix(),
            abuse_reports: 0,
            source: FeedSource::AbuseIpdb,
            categories: vec![],
            is_tor: false,
            is_vpn: false,
            is_proxy: false,
            is_datacenter: false,
            last_seen_instant: Instant::now(),
        };

        let state = self.state.read();

        if state.allowlist.iter().any(|c| c.contains(ip)) {
            record.score = 0.0;
            drop(state);
            self.set_cache(ip_str, record.clone());
            return (Some(record), 0.0);
        }

        if state.blocklist.iter().any(|c| c.contains(ip)) {
            record.score = 100.0;
            drop(state);
            self.set_cache(ip_str, record.clone());
            return (Some(record), 100.0);
        }

        let mut score = 0.0;

        if state.tor_nodes.get(ip_str).copied().unwrap_or(false) {
            score += 60.0;
            record.is_tor = true;
            record.categories.push("tor".to_string());
        }
        if state.vpn_ranges.iter().any(|c| c.contains(ip)) {
            score += 40.0;
            record.is_vpn = true;
            record.categories.push("vpn".to_string());
        }
        if state.proxy_ranges.iter().any(|c| c.contains(ip)) {
            score += 50.0;
            record.is_proxy = true;
            record.categories.push("proxy".to_string());
        }
        if self.is_datacenter_ip(ip) {
            score += 20.0;
            record.is_datacenter = true;
            record.categories.push("datacenter".to_string());
        }

        drop(state);

        record.score = score;
        self.set_cache(ip_str, record.clone());
        (Some(record), score)
    }

    fn is_datacenter_ip(&self, ip: IpAddr) -> bool {
        DATACENTER_RANGES
            .iter()
            .any(|cidr| Cidr::parse(cidr).map(|c| c.contains(ip)).unwrap_or(false))
    }

    fn set_cache(&self, ip: &str, record: IpRecord) {
        self.state.write().cache.insert(ip.to_string(), record);
    }

    /// Port of `AddAllowlist`.
    pub fn add_allowlist(&self, cidr: &str) -> Result<(), String> {
        let network = Cidr::parse(cidr).ok_or_else(|| format!("invalid cidr: {cidr}"))?;
        self.state.write().allowlist.push(network);
        Ok(())
    }

    /// Port of `AddBlocklist`.
    pub fn add_blocklist(&self, cidr: &str) -> Result<(), String> {
        let network = Cidr::parse(cidr).ok_or_else(|| format!("invalid cidr: {cidr}"))?;
        self.state.write().blocklist.push(network);
        Ok(())
    }

    pub fn allowlist_asn(&self, asn: u32) {
        self.state.write().allowlist_asns.insert(asn, true);
    }

    pub fn blocklist_asn(&self, asn: u32) {
        self.state.write().blocklist_asns.insert(asn, true);
    }

    pub fn allowlist_country(&self, code: &str) {
        self.state
            .write()
            .allowlist_countries
            .insert(code.to_string(), true);
    }

    pub fn blocklist_country(&self, code: &str) {
        self.state
            .write()
            .blocklist_countries
            .insert(code.to_string(), true);
    }

    /// Port of `LoadTorNodes`.
    pub fn load_tor_nodes(&self, nodes: &[String]) {
        let mut state = self.state.write();
        for node in nodes {
            state.tor_nodes.insert(node.clone(), true);
        }
    }

    /// Port of `LoadVPNRanges`.
    pub fn load_vpn_ranges(&self, cidrs: &[String]) -> Result<(), String> {
        let mut state = self.state.write();
        for cidr in cidrs {
            let network = Cidr::parse(cidr).ok_or_else(|| format!("invalid vpn cidr: {cidr}"))?;
            state.vpn_ranges.push(network);
        }
        Ok(())
    }

    /// Port of `LoadProxyRanges`.
    pub fn load_proxy_ranges(&self, cidrs: &[String]) -> Result<(), String> {
        let mut state = self.state.write();
        for cidr in cidrs {
            let network = Cidr::parse(cidr).ok_or_else(|| format!("invalid proxy cidr: {cidr}"))?;
            state.proxy_ranges.push(network);
        }
        Ok(())
    }

    /// Port of `GetScore`.
    pub fn get_score(&self, ip_str: &str) -> f64 {
        self.inspect(ip_str).1
    }

    /// Port of the `Cleanup` loop body: prune cache entries older than 2× TTL.
    pub fn cleanup(&self) {
        let mut state = self.state.write();
        let ttl2 = self.cache_ttl * 2;
        state
            .cache
            .retain(|_, record| record.last_seen_instant.elapsed() <= ttl2);
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_scores_zero() {
        let e = Engine::new();
        e.add_allowlist("10.0.0.0/8").unwrap();
        assert_eq!(e.get_score("10.1.2.3"), 0.0);
    }

    #[test]
    fn blocklist_scores_hundred() {
        let e = Engine::new();
        e.add_blocklist("203.0.113.0/24").unwrap();
        assert_eq!(e.get_score("203.0.113.5"), 100.0);
    }

    #[test]
    fn tor_scores_sixty() {
        let e = Engine::new();
        e.load_tor_nodes(&["1.2.3.4".to_string()]);
        let (_, score) = e.inspect("1.2.3.4");
        assert_eq!(score, 60.0);
    }

    #[test]
    fn datacenter_range_scores_twenty() {
        let e = Engine::new();
        // 52.0.0.0/8 is a datacenter range.
        let (_, score) = e.inspect("52.10.10.10");
        assert_eq!(score, 20.0);
    }

    #[test]
    fn combined_tor_vpn_proxy_datacenter() {
        let e = Engine::new();
        e.load_tor_nodes(&["52.1.1.1".to_string()]);
        e.load_vpn_ranges(&["52.0.0.0/8".to_string()]).unwrap();
        e.load_proxy_ranges(&["52.0.0.0/8".to_string()]).unwrap();
        let (_, score) = e.inspect("52.1.1.1");
        // tor 60 + vpn 40 + proxy 50 + datacenter 20 = 170
        assert_eq!(score, 170.0);
    }

    #[test]
    fn invalid_ip_returns_none() {
        let e = Engine::new();
        let (rec, score) = e.inspect("not-an-ip");
        assert!(rec.is_none());
        assert_eq!(score, 0.0);
    }

    #[test]
    fn invalid_cidr_rejected() {
        let e = Engine::new();
        assert!(e.add_allowlist("bogus").is_err());
    }
}
