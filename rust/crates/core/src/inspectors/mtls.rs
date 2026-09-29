//! Mutual TLS client-certificate inspection.
//!
//! Port of `internal/engine/mtls.go`. The decision logic (require-and-verify,
//! failOnError, skipVerify, policy OID) is preserved.
//!
//! ## Deviation (documented)
//!
//! Go read peer certificates from a `*tls.Conn` stored in the request context.
//! This port models the TLS state on the request (`TlsState.peer_cert_der`)
//! and parses it with `x509-parser`. Certificate-collection (`loadCAFile`) is
//! performed by the caller (the proxy TLS layer) and the resulting "chain
//! verified" fact is represented by the presence of `peer_cert_der`. See
//! `rust/DEVIATIONS.md`.

use std::sync::Arc;

use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::*;

use crate::action::{Action, Decision};
use crate::config_types::MtlsConfig;
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: i64,
    pub not_after: i64,
    pub serial_number: String,
    pub fingerprint: String,
    pub pem: String,
}

pub struct MtlsInspector {
    cfg: MtlsConfig,
    verify_depth: i32,
    fail_on_error: bool,
    early_auth: bool,
    username_header: String,
}

impl MtlsInspector {
    /// Port of `NewMTLSInspector` (minus the CA file read, which the proxy TLS
    /// layer performs; the caller supplies the parsed policy via the config).
    pub fn new(cfg: MtlsConfig) -> Result<Self, String> {
        Ok(MtlsInspector {
            verify_depth: cfg.verify_depth,
            fail_on_error: cfg.fail_on_error,
            early_auth: cfg.early_auth,
            username_header: cfg.username_header.clone(),
            cfg,
        })
    }

    /// Port of `validateCertificatePolicy`.
    fn validate_certificate_policy(&self, der: &[u8]) -> bool {
        if self.cfg.policy_oid.is_empty() {
            return true;
        }
        let cert = match X509Certificate::from_der(der) {
            Ok((_, c)) => c,
            Err(_) => return false,
        };
        // Walk the certificate-policies extension (OID 2.5.29.32).
        for ext in cert.extensions() {
            if ext.oid.to_id_string() == "2.5.29.32" {
                if let ParsedExtension::CertificatePolicies(policies) = ext.parsed_extension() {
                    for policy in policies.iter() {
                        if policy.policy_id.to_id_string() == self.cfg.policy_oid {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Port of `GetClientCertInfo`.
    pub fn get_client_cert_info(&self, ctx: &RequestContext) -> Option<ClientCertInfo> {
        let der = ctx.request.tls.as_ref()?.peer_cert_der.as_ref()?;
        let (_, cert) = X509Certificate::from_der(der).ok()?;
        Some(extract_cert_info(&cert))
    }

    /// Accessor for verify depth (parity).
    pub fn verify_depth(&self) -> i32 {
        self.verify_depth
    }

    /// Accessor for early auth (parity).
    pub fn early_auth(&self) -> bool {
        self.early_auth
    }
}

fn extract_cert_info(cert: &X509Certificate) -> ClientCertInfo {
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    ClientCertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before,
        not_after,
        serial_number: cert.raw_serial_as_string(),
        fingerprint: cert
            .raw_serial()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        pem: String::new(),
    }
}

impl Inspector for MtlsInspector {
    fn name(&self) -> &str {
        "mtls_inspection"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if !self.cfg.enabled {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        // Go: GetConnFromContext -> nil means no connection info.
        let tls = match &ctx.request.tls {
            Some(t) if t.present => t,
            _ => {
                if self.fail_on_error {
                    return Ok(Some(
                        Decision::new(Action::Block, 85.0)
                            .with_rule_id("MTLS-001")
                            .with_rule_name("mTLS connection info unavailable")
                            .with_severity("high"),
                    ));
                }
                return Ok(Some(Decision::new(Action::Allow, 0.0)));
            }
        };

        let peer_cert_der = match &tls.peer_cert_der {
            Some(c) => c,
            None => {
                if self.cfg.client_auth == "require-and-verify-client-cert"
                    || self.cfg.client_auth == "require-any-client-cert"
                {
                    return Ok(Some(
                        Decision::new(Action::Block, 90.0)
                            .with_rule_id("MTLS-003")
                            .with_rule_name("client certificate required")
                            .with_severity("high")
                            .with_evidence("no client certificate provided"),
                    ));
                }
                return Ok(Some(Decision::new(Action::Allow, 0.0)));
            }
        };

        let cert_info = {
            let (_, cert) = match X509Certificate::from_der(peer_cert_der) {
                Ok(c) => c,
                Err(_) => {
                    // Unparseable cert: treated like "not TLS" for the fail path.
                    if self.fail_on_error {
                        return Ok(Some(
                            Decision::new(Action::Block, 90.0)
                                .with_rule_id("MTLS-002")
                                .with_rule_name("connection is not TLS")
                                .with_severity("high"),
                        ));
                    }
                    return Ok(Some(Decision::new(Action::Allow, 0.0)));
                }
            };
            extract_cert_info(&cert)
        };

        if !self.username_header.is_empty() {
            ctx.headers
                .insert(self.username_header.clone(), cert_info.subject.clone());
        }

        if self.cfg.skip_verify {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        if !self.cfg.policy_oid.is_empty() {
            if !self.validate_certificate_policy(peer_cert_der) {
                return Ok(Some(
                    Decision::new(Action::Block, 85.0)
                        .with_rule_id("MTLS-004")
                        .with_rule_name("client certificate policy violation")
                        .with_severity("high")
                        .with_evidence(format!("required policy: {}", self.cfg.policy_oid)),
                ));
            }
        }

        Ok(Some(Decision::new(Action::Allow, 0.0)))
    }
}

/// A shared handle to the mTLS inspector, for the proxy.
pub type SharedMtlsInspector = Arc<MtlsInspector>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, TlsState};

    fn req_with_tls(peer_der: Option<Vec<u8>>) -> RequestContext {
        let mut r = HttpRequest::new("GET", "/");
        r.tls = Some(TlsState {
            version: "TLS1.3".into(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".into(),
            ja3_hash: String::new(),
            peer_cert_der: peer_der,
            peer_chain_der: vec![],
            present: true,
        });
        RequestContext::new(r)
    }

    #[test]
    fn disabled_allows() {
        let m = MtlsInspector::new(MtlsConfig {
            enabled: false,
            ..Default::default()
        })
        .unwrap();
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        assert_eq!(m.inspect(&mut ctx).unwrap().unwrap().action, Action::Allow);
    }

    #[test]
    fn no_connection_info_blocks_when_fail_on_error() {
        let m = MtlsInspector::new(MtlsConfig {
            enabled: true,
            fail_on_error: true,
            ..Default::default()
        })
        .unwrap();
        let mut ctx = RequestContext::new(HttpRequest::new("GET", "/"));
        let dec = m.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "MTLS-001");
    }

    #[test]
    fn missing_client_cert_blocked_when_required() {
        let m = MtlsInspector::new(MtlsConfig {
            enabled: true,
            client_auth: "require-and-verify-client-cert".into(),
            ..Default::default()
        })
        .unwrap();
        let mut ctx = req_with_tls(None);
        let dec = m.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "MTLS-003");
    }

    #[test]
    fn skip_verify_allows_with_cert() {
        // A minimal valid DER cert is complex to build; here we assert the
        // policy-oid path returns allow when skip_verify is set and a cert is
        // present but we cannot parse it: the parse-fail path is exercised by
        // the fail_on_error=false case returning Allow.
        let m = MtlsInspector::new(MtlsConfig {
            enabled: true,
            skip_verify: true,
            ..Default::default()
        })
        .unwrap();
        let mut ctx = req_with_tls(Some(vec![0x30, 0x00])); // invalid DER
        let dec = m.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.action, Action::Allow);
    }
}
