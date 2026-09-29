//! GeoIP lookup (country/city/ASN).
//!
//! Port of `internal/geo/geo.go`.
//!
//! ## Deviation (documented)
//!
//! Go used `oschwald/geoip2-golang` to read MaxMind `.mmdb` files. This port
//! defines the [`GeoBackend`] trait so the crate does not hard-depend on a
//! MaxMind reader. [`StubBackend`] is the default and returns the same "not
//! available" record Go returned when the database could not be opened
//! (`CountryCode: "XX"`, `CountryName: "Unknown"`). A production deployment
//! wires in a `maxminddb`-backed implementation. See `rust/DEVIATIONS.md`.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Record {
    pub country_code: String,
    pub country_name: String,
    pub city: String,
    pub isp: String,
    pub asn: u32,
    pub as_org: String,
    pub timezone: String,
    pub latitude: f64,
    pub longitude: f64,
    pub is_anonymous_proxy: bool,
    pub is_satellite_provider: bool,
}

/// A GeoIP database backend.
pub trait GeoBackend: Send + Sync {
    /// Whether a database is available at all.
    fn available(&self) -> bool;
    /// Look up an IP.
    fn lookup(&self, ip: IpAddr) -> Record;
}

/// Default backend: no database (returns the "not available" record).
pub struct StubBackend;

impl GeoBackend for StubBackend {
    fn available(&self) -> bool {
        false
    }
    fn lookup(&self, _ip: IpAddr) -> Record {
        Record {
            country_code: "XX".to_string(),
            country_name: "Unknown".to_string(),
            ..Default::default()
        }
    }
}

pub struct Lookup {
    backend: Arc<dyn GeoBackend>,
    city_db_path: String,
    asn_db_path: String,
}

impl Lookup {
    /// Port of `NewLookup`. Uses the stub backend by default; call
    /// [`Lookup::with_backend`] to supply a real database reader.
    pub fn new(city_db_path: &str, asn_db_path: &str) -> Self {
        Lookup {
            backend: Arc::new(StubBackend),
            city_db_path: city_db_path.to_string(),
            asn_db_path: asn_db_path.to_string(),
        }
    }

    pub fn with_backend(
        city_db_path: &str,
        asn_db_path: &str,
        backend: Arc<dyn GeoBackend>,
    ) -> Self {
        if !backend.available() {
            tracing::warn!("geoip database not available, using stub");
        }
        Lookup {
            backend,
            city_db_path: city_db_path.to_string(),
            asn_db_path: asn_db_path.to_string(),
        }
    }

    /// Port of `LookupIP`.
    pub fn lookup_ip(&self, ip_str: &str) -> Record {
        if !self.backend.available() {
            return Record {
                country_code: "XX".to_string(),
                country_name: "Unknown".to_string(),
                ..Default::default()
            };
        }

        let ip = match IpAddr::from_str(ip_str) {
            Ok(ip) => ip,
            Err(_) => {
                return Record {
                    country_code: "XX".to_string(),
                    country_name: "Invalid IP".to_string(),
                    ..Default::default()
                }
            }
        };

        self.backend.lookup(ip)
    }

    /// Port of `CountryCode`.
    pub fn country_code(&self, ip_str: &str) -> String {
        self.lookup_ip(ip_str).country_code
    }

    pub fn city_db_path(&self) -> &str {
        &self.city_db_path
    }

    pub fn asn_db_path(&self) -> &str {
        &self.asn_db_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_returns_unknown() {
        let l = Lookup::new("/nonexistent", "/nonexistent");
        let r = l.lookup_ip("8.8.8.8");
        assert_eq!(r.country_code, "XX");
        assert_eq!(r.country_name, "Unknown");
    }

    #[test]
    fn country_code_shortcut() {
        let l = Lookup::new("", "");
        assert_eq!(l.country_code("1.2.3.4"), "XX");
    }

    struct FixedBackend;
    impl GeoBackend for FixedBackend {
        fn available(&self) -> bool {
            true
        }
        fn lookup(&self, _ip: IpAddr) -> Record {
            Record {
                country_code: "ID".to_string(),
                country_name: "Indonesia".to_string(),
                asn: 7713,
                ..Default::default()
            }
        }
    }

    #[test]
    fn real_backend_used_when_available() {
        let l = Lookup::with_backend("", "", Arc::new(FixedBackend));
        let r = l.lookup_ip("1.1.1.1");
        assert_eq!(r.country_code, "ID");
        assert_eq!(r.asn, 7713);
    }

    #[test]
    fn invalid_ip_reported() {
        let l = Lookup::with_backend("", "", Arc::new(FixedBackend));
        let r = l.lookup_ip("not-an-ip");
        assert_eq!(r.country_name, "Invalid IP");
    }
}
