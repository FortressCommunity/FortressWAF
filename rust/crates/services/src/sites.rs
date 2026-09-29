//! Protected-domain management and DNS verification.
//!
//! Port of `internal/sites/verify.go` and `internal/sites/manager.go`.
//! Domain validation, the "resolves to this server" check, and config-bound
//! add/remove are preserved.
//!
//! ## Deviation (documented)
//!
//! Go used `net.Resolver` for A/AAAA lookups. The resolver is behind the
//! [`DnsResolver`] trait so verification is testable without network;
//! [`SystemResolver`] performs real lookups via the `dns_lookup`-style path
//! through `std` where possible, and a caller may inject a test resolver. When
//! no resolver is available the lookup returns an error (the same outcome as a
//! failed DNS lookup). See `rust/DEVIATIONS.md`.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;

use fwaf_config::types::{Config, SiteConfig};

static DOMAIN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$").unwrap());

/// Resolve A/AAAA records for a domain.
pub trait DnsResolver: Send + Sync {
    /// Return the resolved IP strings, or an error.
    fn resolve_all(&self, domain: &str, timeout: Duration) -> Result<Vec<String>, String>;
}

/// Real resolver. Uses the `std` to-address path when possible; since `std` has
/// no DNS API, this returns an error unless a specific resolver is injected.
/// Deployments wire a real resolver (e.g. a DNS crate) behind this trait.
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve_all(&self, domain: &str, _timeout: Duration) -> Result<Vec<String>, String> {
        // `std::net::ToSocketAddrs` performs resolution via the system resolver.
        use std::net::ToSocketAddrs;
        match (domain, 0u16).to_socket_addrs() {
            Ok(addrs) => {
                let mut seen = std::collections::BTreeSet::new();
                let mut out = Vec::new();
                for a in addrs {
                    let s = canonical_ip(a.ip());
                    if seen.insert(s.clone()) {
                        out.push(s);
                    }
                }
                Ok(out)
            }
            Err(e) => Err(format!("DNS lookup failed: {e}")),
        }
    }
}

fn canonical_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => v6.to_string(),
        },
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VerifyResult {
    pub domain: String,
    pub verified: bool,
    pub resolved_ips: Vec<String>,
    pub expected_ips: Vec<String>,
    pub reason: String,
}

/// Port of `Verifier`.
pub struct Verifier {
    expected_ips: Vec<String>,
    timeout: Duration,
    resolver: Arc<dyn DnsResolver>,
}

impl Verifier {
    /// Port of `NewVerifier`.
    pub fn new(expected_ips: Vec<String>) -> Self {
        let cleaned: Vec<String> = expected_ips
            .into_iter()
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect();
        Verifier {
            expected_ips: cleaned,
            timeout: Duration::from_secs(8),
            resolver: Arc::new(SystemResolver),
        }
    }

    /// Inject a resolver (for tests or a real DNS backend).
    pub fn with_resolver(expected_ips: Vec<String>, resolver: Arc<dyn DnsResolver>) -> Self {
        let mut v = Self::new(expected_ips);
        v.resolver = resolver;
        v
    }

    /// Port of `ExpectedIPs`.
    pub fn expected_ips(&self) -> Vec<String> {
        self.expected_ips.clone()
    }

    /// Port of `Verify`.
    pub fn verify(&self, domain: &str) -> VerifyResult {
        let domain = normalize_domain(domain);
        let mut res = VerifyResult {
            domain: domain.clone(),
            expected_ips: self.expected_ips.clone(),
            ..Default::default()
        };

        if let Err(e) = validate_domain(&domain) {
            res.reason = e;
            return res;
        }

        let ips = match self.resolver.resolve_all(&domain, self.timeout) {
            Ok(mut ips) => {
                ips.sort();
                ips
            }
            Err(e) => {
                res.reason = e;
                return res;
            }
        };
        res.resolved_ips = ips.clone();
        if ips.is_empty() {
            res.reason = "no A or AAAA record found for this domain".to_string();
            return res;
        }

        if self.expected_ips.is_empty() {
            res.verified = true;
            res.reason =
                "domain resolves (configure server.expected_ips to require a specific address)"
                    .to_string();
            return res;
        }

        for got in &ips {
            for want in &self.expected_ips {
                if ip_equal(got, want) {
                    res.verified = true;
                    res.reason = format!("{domain} resolves to {got}, which is this server");
                    return res;
                }
            }
        }

        res.reason = format!(
            "{domain} resolves to {}, none of which match this server ({})",
            ips.join(", "),
            self.expected_ips.join(", ")
        );
        res
    }
}

/// Port of `ValidateDomain`.
pub fn validate_domain(domain: &str) -> Result<(), String> {
    let domain = normalize_domain(domain);
    if domain.is_empty() {
        return Err("domain is required".to_string());
    }
    if domain.len() > 253 {
        return Err("domain is too long".to_string());
    }
    if domain.contains('/') || domain.contains('@') || domain.contains(':') || domain.contains(' ')
    {
        return Err("domain must be a bare hostname (no scheme, port, or path)".to_string());
    }
    if IpAddr::from_str(&domain).is_ok() {
        return Err("enter a domain name, not an IP address".to_string());
    }
    if !DOMAIN_RE.is_match(&domain) {
        return Err("not a valid domain name".to_string());
    }
    Ok(())
}

/// Port of `normalizeDomain`.
pub fn normalize_domain(d: &str) -> String {
    let mut d = d.trim().to_lowercase();
    d = d.strip_prefix("https://").unwrap_or(&d).to_string();
    d = d.strip_prefix("http://").unwrap_or(&d).to_string();
    if let Some(i) = d.find('/') {
        d = d[..i].to_string();
    }
    if let Some(i) = d.rfind(':') {
        if !d[i..].contains(']') {
            d = d[..i].to_string();
        }
    }
    d = d.trim_end_matches('.').to_string();
    d
}

/// Port of `ipEqual`.
fn ip_equal(a: &str, b: &str) -> bool {
    match (IpAddr::from_str(a.trim()), IpAddr::from_str(b.trim())) {
        (Ok(ia), Ok(ib)) => canonical_ip(ia) == canonical_ip(ib),
        _ => a == b,
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ManagedDomain {
    pub domain: String,
    pub site: String,
    pub upstream: String,
    pub verified: bool,
    pub resolved_ips: Vec<String>,
    pub reason: String,
    pub added_at: String,
}

/// The input to `Manager::add`.
pub struct DomainAdd {
    pub domain: String,
    pub site_name: String,
    pub upstream: String,
    pub verifier: Arc<Verifier>,
}

/// Port of `Manager`. Bound to a config `Manager` supplied by the caller. To
/// keep this crate independent of a specific config-manager instance, the
/// config mutation is expressed through a closure that receives the live
/// `Config`; the caller wires it to `fwaf_config::Manager::update_config`.
pub struct Manager {
    records: Mutex<std::collections::HashMap<String, ManagedDomain>>,
    cfg: Arc<Mutex<Config>>,
    /// Persist hook: called after a config mutation so the caller can save.
    persist: Option<Box<dyn Fn(&Config) + Send + Sync>>,
    audit: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
}

impl Manager {
    /// Build a manager over an initial config snapshot and a persist hook.
    pub fn new(
        cfg: Config,
        persist: Option<Box<dyn Fn(&Config) + Send + Sync>>,
        audit: Option<Box<dyn Fn(&str, &str) + Send + Sync>>,
    ) -> Self {
        let m = Manager {
            records: Mutex::new(std::collections::HashMap::new()),
            cfg: Arc::new(Mutex::new(cfg)),
            persist,
            audit,
        };
        m.load_from_config();
        m
    }

    fn load_from_config(&self) {
        let cfg = self.cfg.lock().clone();
        let mut records = self.records.lock();
        for s in &cfg.sites {
            for d in &s.domains {
                let key = normalize_domain(d);
                records.insert(
                    key.clone(),
                    ManagedDomain {
                        domain: key,
                        site: s.name.clone(),
                        upstream: s.upstream.clone(),
                        verified: true,
                        reason: "defined in the config file".to_string(),
                        ..Default::default()
                    },
                );
            }
        }
    }

    /// Port of `List`.
    pub fn list(&self) -> Vec<ManagedDomain> {
        let records = self.records.lock();
        let mut out: Vec<ManagedDomain> = records.values().cloned().collect();
        out.sort_by(|a, b| a.domain.cmp(&b.domain));
        out
    }

    /// Port of `Add`.
    pub fn add(&self, d: DomainAdd) -> Result<ManagedDomain, String> {
        let domain = normalize_domain(&d.domain);
        validate_domain(&domain)?;

        let mut records = self.records.lock();
        if records.contains_key(&domain) {
            return Err(format!("domain {domain:?} is already protected"));
        }

        validate_upstream(&d.upstream)?;

        let result = d.verifier.verify(&domain);
        let mut rec = ManagedDomain {
            domain: domain.clone(),
            site: d.site_name.clone(),
            upstream: d.upstream.clone(),
            verified: result.verified,
            resolved_ips: result.resolved_ips.clone(),
            reason: result.reason.clone(),
            added_at: now_string(),
        };
        if !result.verified {
            return Err(format!("DNS verification failed: {}", result.reason));
        }

        // Attach the domain to an existing site (by name) or a new one.
        {
            let mut cfg = self.cfg.lock();
            let mut attached = false;
            if !d.site_name.is_empty() {
                for s in cfg.sites.iter_mut() {
                    if s.name == d.site_name {
                        if !contains_string(&s.domains, &domain) {
                            s.domains.push(domain.clone());
                        }
                        rec.site = s.name.clone();
                        rec.upstream = s.upstream.clone();
                        attached = true;
                        break;
                    }
                }
            }
            if !attached {
                let mut site_name = d.site_name.clone();
                if site_name.is_empty() {
                    site_name = site_name_for(&domain);
                }
                if cfg.sites.iter().any(|s| s.name == site_name) {
                    // Existing name collision: do not create a duplicate.
                    drop(cfg);
                    return Err(format!("site {site_name:?} already exists"));
                }
                let mut upstream = d.upstream.clone();
                if upstream.is_empty() && !cfg.sites.is_empty() {
                    upstream = cfg.sites[0].upstream.clone();
                }
                cfg.sites.push(SiteConfig {
                    name: site_name.clone(),
                    domains: vec![domain.clone()],
                    upstream: upstream.clone(),
                    waf_enabled: true,
                    ..Default::default()
                });
                rec.site = site_name;
                rec.upstream = upstream;
            }

            // Validate the resulting config before committing.
            fwaf_config::validate(&cfg)?;
            if let Some(p) = &self.persist {
                p(&cfg);
            }
        }

        records.insert(domain.clone(), rec.clone());
        if let Some(a) = &self.audit {
            a(
                "domain_added",
                &format!(
                    "{} -> site {} (resolved {})",
                    domain,
                    rec.site,
                    result.resolved_ips.join(",")
                ),
            );
        }
        Ok(rec)
    }

    /// Port of `Remove`.
    pub fn remove(&self, domain: &str) -> Result<(), String> {
        let domain = normalize_domain(domain);
        let mut records = self.records.lock();
        if !records.contains_key(&domain) {
            return Err(format!("domain {domain:?} is not managed"));
        }

        {
            let mut cfg = self.cfg.lock();
            for s in cfg.sites.iter_mut() {
                s.domains.retain(|d| *d != domain);
            }
            cfg.sites.retain(|s| !s.domains.is_empty());
            if let Some(p) = &self.persist {
                p(&cfg);
            }
        }

        records.remove(&domain);
        if let Some(a) = &self.audit {
            a("domain_removed", &domain);
        }
        Ok(())
    }

    /// Snapshot the live config (for tests).
    pub fn config_snapshot(&self) -> Config {
        self.cfg.lock().clone()
    }
}

/// Port of `validateUpstream`.
pub fn validate_upstream(raw: &str) -> Result<(), String> {
    if raw.trim().is_empty() {
        return Ok(());
    }
    // Manual scheme/host parse (no url crate).
    let (scheme, rest) = match raw.split_once("://") {
        Some((s, r)) => (s, r),
        None => return Err("upstream is not a valid URL: missing scheme".to_string()),
    };
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "upstream must be an http or https URL (got scheme {scheme:?})"
        ));
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        return Err("upstream URL has no host".to_string());
    }
    Ok(())
}

fn contains_string(list: &[String], s: &str) -> bool {
    list.iter().any(|v| v == s)
}

/// Port of `siteNameFor`.
fn site_name_for(domain: &str) -> String {
    let label = domain.split('.').next().unwrap_or("");
    let mapped: String = label
        .chars()
        .map(|r| {
            if r.is_ascii_lowercase() || r.is_ascii_digit() || r == '-' {
                r
            } else {
                '-'
            }
        })
        .collect();
    if mapped.is_empty() {
        "site".to_string()
    } else {
        mapped
    }
}

fn now_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

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

    struct FixedResolver(Vec<String>);
    impl DnsResolver for FixedResolver {
        fn resolve_all(&self, _domain: &str, _t: Duration) -> Result<Vec<String>, String> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn validate_domain_accepts_public_hostname() {
        assert!(validate_domain("example.com").is_ok());
        assert!(validate_domain("sub.example.co.id").is_ok());
    }

    #[test]
    fn validate_domain_rules() {
        assert!(validate_domain("1.2.3.4").is_err());
        // A pasted URL is normalized (scheme/port stripped) by ValidateDomain,
        // exactly as in Go, so these become "example.com" and pass.
        assert!(validate_domain("http://example.com").is_ok());
        assert!(validate_domain("example.com:8080").is_ok());
        // These remain invalid after normalization.
        assert!(validate_domain("").is_err());
        assert!(validate_domain("localhost").is_err()); // no dot
        assert!(validate_domain("bad_domain.com").is_err()); // underscore
    }

    #[test]
    fn normalize_strips_scheme_and_port() {
        assert_eq!(
            normalize_domain("HTTPS://Example.COM:443/path"),
            "example.com"
        );
    }

    #[test]
    fn verify_matches_expected_ip() {
        let v = Verifier::with_resolver(
            vec!["1.2.3.4".to_string()],
            Arc::new(FixedResolver(vec!["1.2.3.4".to_string()])),
        );
        let r = v.verify("example.com");
        assert!(r.verified);
        assert_eq!(r.resolved_ips, vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn verify_rejects_mismatch() {
        let v = Verifier::with_resolver(
            vec!["1.2.3.4".to_string()],
            Arc::new(FixedResolver(vec!["9.9.9.9".to_string()])),
        );
        let r = v.verify("example.com");
        assert!(!r.verified);
        assert!(r.reason.contains("none of which match"));
    }

    #[test]
    fn validate_upstream_rules() {
        assert!(validate_upstream("http://127.0.0.1:8080").is_ok());
        assert!(validate_upstream("https://backend.internal").is_ok());
        assert!(validate_upstream("").is_ok());
        assert!(validate_upstream("file:///etc/passwd").is_err());
        assert!(validate_upstream("gopher://x").is_err());
    }

    #[test]
    fn add_and_remove_domain() {
        let cfg = Config {
            sites: vec![SiteConfig {
                name: "main".into(),
                domains: vec!["localhost".into()],
                upstream: "http://127.0.0.1:8080".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let audit: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let a2 = audit.clone();
        let m = Manager::new(
            cfg,
            None,
            Some(Box::new(move |action, detail| {
                a2.lock().push((action.to_string(), detail.to_string()));
            })),
        );
        let verifier = Arc::new(Verifier::with_resolver(
            vec!["1.2.3.4".to_string()],
            Arc::new(FixedResolver(vec!["1.2.3.4".to_string()])),
        ));
        let rec = m
            .add(DomainAdd {
                domain: "new.example.com".into(),
                site_name: "main".into(),
                upstream: String::new(),
                verifier,
            })
            .unwrap();
        assert!(rec.verified);
        assert_eq!(m.config_snapshot().sites[0].domains.len(), 2);
        assert!(m.remove("new.example.com").is_ok());
        assert_eq!(m.config_snapshot().sites[0].domains.len(), 1);
        assert_eq!(audit.lock().len(), 2);
    }

    #[test]
    fn add_rejects_unverified() {
        let cfg = Config {
            sites: vec![SiteConfig {
                name: "main".into(),
                domains: vec!["localhost".into()],
                upstream: "http://127.0.0.1:8080".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let m = Manager::new(cfg, None, None);
        let verifier = Arc::new(Verifier::with_resolver(
            vec!["1.2.3.4".to_string()],
            Arc::new(FixedResolver(vec!["9.9.9.9".to_string()])),
        ));
        let err = m
            .add(DomainAdd {
                domain: "bad.example.com".into(),
                site_name: "main".into(),
                upstream: String::new(),
                verifier,
            })
            .unwrap_err();
        assert!(err.contains("DNS verification failed"));
        // Not stored.
        assert!(m.list().iter().all(|r| r.domain != "bad.example.com"));
    }
}
