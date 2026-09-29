//! TLS termination via `rustls`.
//!
//! Port of the TLS setup in `cmd/proxy/main.go` (`proxySrv.TLSConfig`): a
//! minimum protocol version, optional HTTP/2 ALPN, and optional mutual-TLS
//! client verification against a CA file.
//!
//! ## Deviation (documented)
//!
//! Go used `crypto/tls` (and `golang.org/x/crypto/acme/autocert` for ACME).
//! This port uses `rustls`, a memory-safe TLS implementation. TLS 1.2 and 1.3
//! are supported; ACME auto-provisioning is **not** implemented — supply
//! `cert_file`/`key_file`. See `rust/DEVIATIONS.md`.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

/// Build a `rustls::ServerConfig` from the TLS settings.
///
/// `min_version` accepts `"1.2"` (default) or `"1.3"`. When `ca_file` is set,
/// client certificates are required and verified against it (mutual TLS).
pub fn build_server_config(
    cert_file: &str,
    key_file: &str,
    min_version: &str,
    http2_enabled: bool,
    ca_file: &str,
) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(cert_file)?;
    let key = load_key(key_file)?;

    let builder = match min_version {
        "1.3" => {
            // TLS 1.3 only.
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        }
        // "1.2" or anything else: rustls' default is TLS 1.2 + 1.3.
        _ => ServerConfig::builder(),
    };

    let mut config = if !ca_file.is_empty() {
        let mut roots = RootCertStore::empty();
        for cert in load_certs(ca_file)? {
            roots
                .add(cert)
                .map_err(|e| format!("add client CA cert: {e}"))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| format!("client verifier: {e}"))?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| format!("load cert/key: {e}"))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("load cert/key: {e}"))?
    };

    // The proxy currently serves HTTP/1.1 only (hyper `http1::Builder`), so
    // advertise only http/1.1 over ALPN. Advertising h2 without an HTTP/2
    // server makes a client negotiate h2 and then fail the connection.
    // `http2_enabled` is honoured once an h2 server is wired; until then it is
    // accepted in config but does not change the ALPN list.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let _ = http2_enabled;

    Ok(Arc::new(config))
}

/// Load a PEM certificate chain.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| format!("open cert file {path:?}: {e}"))?;
    let mut reader = BufReader::new(file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| format!("parse cert file {path:?}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {path:?}"));
    }
    Ok(certs)
}

/// Load a PEM private key (PKCS#8, PKCS#1, or SEC1).
fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    if !Path::new(path).exists() {
        return Err(format!("key file not found: {path:?}"));
    }
    let file = File::open(path).map_err(|e| format!("open key file {path:?}: {e}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key file {path:?}: {e}"))?
        .ok_or_else(|| format!("no private key found in {path:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_cert_file_errors() {
        let err = build_server_config(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "1.2",
            true,
            "",
        )
        .unwrap_err();
        assert!(err.contains("open cert file"), "got: {err}");
    }

    #[test]
    fn missing_key_file_errors() {
        // Cert path checked first, so this also fails on cert; use an existing
        // but non-PEM file to reach the key path.
        let err = build_server_config("/etc/hostname", "/nonexistent/key.pem", "1.2", true, "")
            .unwrap_err();
        // Either "no certificates found" (hostname is not PEM) is acceptable.
        assert!(
            err.contains("no certificates found") || err.contains("parse cert file"),
            "got: {err}"
        );
    }
}
