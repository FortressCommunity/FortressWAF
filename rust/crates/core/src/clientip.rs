//! Trusted-proxy handling and client IP resolution.
//!
//! Port of `internal/engine/clientip.go`. The security-critical property is
//! preserved: the peer address is authoritative unless it belongs to a
//! configured trusted-proxy CIDR; only then are forwarded headers honoured, and
//! only the left-most `X-Forwarded-For` entry is used.

use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::http::HttpRequest;

/// trustedProxy holds parsed CIDRs whose forwarded headers are believed.
/// The zero value trusts nothing (correct for an edge deployment).
#[derive(Default)]
pub struct TrustedProxies {
    nets: RwLock<Vec<Cidr>>,
}

#[derive(Debug, Clone, Copy)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parse a CIDR string, mirroring `net.ParseCIDR` returning `(nil, err)` on
    /// failure. The masked network and prefix length are stored.
    fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (ip_part, prefix_part) = s.split_once('/')?;
        let ip: IpAddr = IpAddr::from_str(ip_part).ok()?;
        let prefix: u8 = prefix_part.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return None;
        }
        // Mask the address to the network, like net.ParseCIDR.
        let network = mask_ip(ip, prefix);
        Some(Cidr { network, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask_ip(ip, self.prefix) == self.network
            }
            // IPv4-mapped IPv6 handling: Go's IPNet.Contains unmaps v4-in-v6.
            (IpAddr::V4(net), IpAddr::V6(v6)) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    mask_ip(IpAddr::V4(v4), self.prefix) == IpAddr::V4(net)
                } else {
                    false
                }
            }
            (IpAddr::V6(_), IpAddr::V4(v4)) => {
                // Compare as IPv4-mapped.
                let mapped = IpAddr::V6(v4.to_ipv6_mapped());
                mask_ip(mapped, self.prefix) == self.network
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
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

impl TrustedProxies {
    pub fn new() -> Self {
        TrustedProxies {
            nets: RwLock::new(Vec::new()),
        }
    }

    /// Replace the allow list. Invalid entries are skipped (reported by the
    /// caller via [`parse_trusted_proxies`]). Port of `SetTrustedProxies`.
    pub fn set_trusted_proxies(&self, cidrs: &[String]) {
        let mut nets = Vec::with_capacity(cidrs.len());
        for c in cidrs {
            if let Some(cidr) = Cidr::parse(c) {
                nets.push(cidr);
            }
        }
        let mut guard = self.nets.write();
        *guard = nets;
    }

    /// Whether the immediate peer is a configured proxy. Port of `trusts`.
    pub fn trusts(&self, peer: &str) -> bool {
        let guard = self.nets.read();
        if guard.is_empty() {
            return false;
        }
        let ip = match IpAddr::from_str(peer.trim()) {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        guard.iter().any(|n| n.contains(ip))
    }

    /// Resolve the client IP for a request. Port of `Engine.ClientIP`.
    ///
    /// The peer is authoritative unless it is a trusted proxy, in which case
    /// `CF-Connecting-IP`, then the left-most `X-Forwarded-For`, then
    /// `X-Real-IP` are honoured -- each validated by `net.ParseIP`.
    pub fn client_ip(&self, r: &HttpRequest) -> String {
        let peer = split_host_port(&r.remote_addr)
            .map(|(host, _)| host)
            .unwrap_or_else(|| r.remote_addr.clone());

        if !self.trusts(&peer) {
            return peer;
        }

        if let Some(cf) = r.header.get("CF-Connecting-IP") {
            if let Ok(ip) = IpAddr::from_str(cf.trim()) {
                return canonical_ip_string(ip);
            }
        }

        if let Some(xff) = r.header.get("X-Forwarded-For") {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = IpAddr::from_str(first.trim()) {
                    return canonical_ip_string(ip);
                }
            }
        }

        if let Some(xri) = r.header.get("X-Real-IP") {
            if let Ok(ip) = IpAddr::from_str(xri.trim()) {
                return canonical_ip_string(ip);
            }
        }

        peer
    }
}

/// Go's `net.ParseIP(...).String()`: canonical textual form. IPv4 stays dotted;
/// IPv4-mapped IPv6 is rendered as dotted-quad (Go renders it as `::ffff:a.b.c.d`
/// actually -- see note). We match Go: `net.ParseIP("::ffff:1.2.3.4").String()`
/// == `"1.2.3.4"` because Go's `IP.String()` collapses a 16-byte v4-mapped
/// address to its 4-byte form.
fn canonical_ip_string(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                v6.to_string()
            }
        }
    }
}

/// Validate each CIDR and return the entries that could not be parsed.
/// Port of `ParseTrustedProxies`.
pub fn parse_trusted_proxies(cidrs: &[String]) -> Vec<String> {
    let mut invalid = Vec::new();
    for c in cidrs {
        if Cidr::parse(c).is_none() {
            invalid.push(c.clone());
        }
    }
    invalid
}

fn split_host_port(addr: &str) -> Option<(String, String)> {
    crate::context::split_host_port(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    fn req(remote: &str) -> HttpRequest {
        let mut r = HttpRequest::new("GET", "/");
        r.remote_addr = remote.to_string();
        r
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_headers() {
        let tp = TrustedProxies::new();
        let mut r = req("203.0.113.5:1234");
        r.header.add("X-Forwarded-For", "1.2.3.4");
        assert_eq!(tp.client_ip(&r), "203.0.113.5");
    }

    #[test]
    fn trusted_peer_honours_xff_first_entry() {
        let tp = TrustedProxies::new();
        tp.set_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let mut r = req("10.0.0.9:443");
        r.header.add("X-Forwarded-For", "1.2.3.4, 10.0.0.1");
        assert_eq!(tp.client_ip(&r), "1.2.3.4");
    }

    #[test]
    fn cf_connecting_ip_preferred_from_trusted_peer() {
        let tp = TrustedProxies::new();
        tp.set_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let mut r = req("10.0.0.9:443");
        r.header.add("CF-Connecting-IP", "8.8.8.8");
        r.header.add("X-Forwarded-For", "1.2.3.4");
        assert_eq!(tp.client_ip(&r), "8.8.8.8");
    }

    #[test]
    fn x_real_ip_used_last() {
        let tp = TrustedProxies::new();
        tp.set_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let mut r = req("10.0.0.9:443");
        r.header.add("X-Real-IP", "9.9.9.9");
        assert_eq!(tp.client_ip(&r), "9.9.9.9");
    }

    #[test]
    fn invalid_forwarded_value_falls_back_to_peer() {
        let tp = TrustedProxies::new();
        tp.set_trusted_proxies(&["10.0.0.0/8".to_string()]);
        let mut r = req("10.0.0.9:443");
        r.header.add("X-Forwarded-For", "not-an-ip");
        assert_eq!(tp.client_ip(&r), "10.0.0.9");
    }

    #[test]
    fn parse_trusted_proxies_reports_invalid() {
        let invalid = parse_trusted_proxies(&[
            "10.0.0.0/8".to_string(),
            "bogus".to_string(),
            "1.2.3.4/33".to_string(),
        ]);
        assert_eq!(invalid, vec!["bogus".to_string(), "1.2.3.4/33".to_string()]);
    }

    #[test]
    fn cidr_contains_ipv4_and_ipv6() {
        let tp = TrustedProxies::new();
        tp.set_trusted_proxies(&["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()]);
        assert!(tp.trusts("10.1.2.3"));
        assert!(!tp.trusts("11.0.0.1"));
        assert!(tp.trusts("2001:db8::1"));
        assert!(!tp.trusts("2001:db9::1"));
    }
}
