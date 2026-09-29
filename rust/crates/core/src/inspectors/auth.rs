//! JWT validation (HS/RS/ES) and OAuth 2.0 token introspection.
//!
//! Port of `internal/engine/auth.go`. Algorithm allow-listing, claim checks,
//! the signing-key selection logic, and the exact signatures verified are
//! preserved.
//!
//! ## Deviation (documented, not silently changed)
//!
//! The Go code fetched JWKS and performed OAuth introspection with `net/http`.
//! Those outbound calls are behind the [`JwksFetcher`] and [`IntrospectClient`]
//! traits so the crate compiles and unit-tests without network access;
//! [`UreqFetcher`] is the real HTTP implementation used in production. The
//! crypto (HMAC/RSA/ECDSA) is real RustCrypto, not stubbed. See
//! `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::action::{Action, Decision};
use crate::config_types::{JwtConfig, OAuthConfig};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

/// Fetch a JWKS document by URL. `Err` mirrors a failed HTTP fetch.
pub trait JwksFetcher: Send + Sync {
    fn fetch(&self, url: &str) -> Result<String, String>;
}

/// Perform an OAuth token introspection. Returns the raw JSON body.
pub trait IntrospectClient: Send + Sync {
    fn introspect(
        &self,
        url: &str,
        client_id: &str,
        client_secret: &str,
        token: &str,
        token_type_hint: &str,
    ) -> Result<String, String>;
}

/// Real HTTP-backed fetcher using `ureq`.
pub struct UreqFetcher;

impl JwksFetcher for UreqFetcher {
    fn fetch(&self, url: &str) -> Result<String, String> {
        let resp = ureq::get(url)
            .timeout(Duration::from_secs(10))
            .call()
            .map_err(|e| format!("fetch jwks: {e}"))?;
        if resp.status() != 200 {
            return Err(format!("jwks endpoint returned {}", resp.status()));
        }
        resp.into_string().map_err(|e| format!("decode jwks: {e}"))
    }
}

impl IntrospectClient for UreqFetcher {
    fn introspect(
        &self,
        url: &str,
        client_id: &str,
        client_secret: &str,
        token: &str,
        token_type_hint: &str,
    ) -> Result<String, String> {
        let body = format!("token={}", urlencode(token));
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:{client_secret}"));
        let mut req = ureq::post(url)
            .timeout(Duration::from_secs(10))
            .set("Content-Type", "application/x-www-form-urlencoded")
            .set("Authorization", &format!("Basic {auth}"));
        if !token_type_hint.is_empty() {
            req = req.set("Token-Type-Hint", token_type_hint);
        }
        let resp = req.send_string(&body).map_err(|e| e.to_string())?;
        if resp.status() != 200 {
            return Err(format!("introspection returned {}", resp.status()));
        }
        resp.into_string().map_err(|e| e.to_string())
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub kty: String,
    #[serde(default)]
    pub kid: String,
    #[serde(default)]
    pub r#use: String,
    #[serde(default)]
    pub alg: String,
    #[serde(default)]
    pub n: String,
    #[serde(default)]
    pub e: String,
    #[serde(default)]
    pub crv: String,
    #[serde(default)]
    pub x: String,
    #[serde(default)]
    pub y: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Jwks {
    #[serde(default)]
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub aud: serde_json::Value,
    #[serde(default)]
    pub exp: i64,
    #[serde(default)]
    pub iat: i64,
    #[serde(default)]
    pub nbf: i64,
    #[serde(default)]
    pub jti: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

impl JwtClaims {
    /// `aud` may be a string or an array of strings (`JWTClaims.Audience
    /// []string` with Go accepting both). Returns the normalised list.
    pub fn audience(&self) -> Vec<String> {
        match &self.aud {
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            serde_json::Value::String(s) => vec![s.clone()],
            _ => Vec::new(),
        }
    }
}

struct JwksCache {
    keys: HashMap<String, Jwk>,
    expires_at: Option<Instant>,
    ttl: Duration,
}

pub struct JwtValidator {
    jwks_url: String,
    jwks_cache: RwLock<JwksCache>,
    issuers: Vec<String>,
    audiences: Vec<String>,
    algorithms: Vec<String>,
    secret: String,
    fetcher: Arc<dyn JwksFetcher>,
}

impl JwtValidator {
    pub fn new(cfg: JwtConfig) -> Self {
        Self::with_fetcher(cfg, Arc::new(UreqFetcher))
    }

    pub fn with_fetcher(cfg: JwtConfig, fetcher: Arc<dyn JwksFetcher>) -> Self {
        JwtValidator {
            jwks_url: cfg.jwks_url,
            jwks_cache: RwLock::new(JwksCache {
                keys: HashMap::new(),
                expires_at: None,
                ttl: Duration::from_secs(3600),
            }),
            issuers: cfg.issuers,
            audiences: cfg.audiences,
            algorithms: cfg.algorithms,
            secret: cfg.secret,
            fetcher,
        }
    }

    /// Port of `Validate`.
    pub fn validate(&self, token_string: &str) -> Result<JwtClaims, String> {
        let parts: Vec<&str> = token_string.split('.').collect();
        if parts.len() != 3 {
            return Err("invalid token format".to_string());
        }

        let header = decode_segment(parts[0]).map_err(|e| format!("decode header: {e}"))?;
        let header_obj: serde_json::Value =
            serde_json::from_slice(&header).map_err(|e| format!("parse header: {e}"))?;
        let alg = header_obj.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        let kid = header_obj.get("kid").and_then(|v| v.as_str()).unwrap_or("");

        if !self.is_allowed_algorithm(alg) {
            return Err(format!("algorithm not allowed: {alg}"));
        }
        if alg == "none" {
            return Err("algorithm 'none' not allowed".to_string());
        }

        let payload = decode_segment(parts[1]).map_err(|e| format!("decode payload: {e}"))?;
        let claims: JwtClaims =
            serde_json::from_slice(&payload).map_err(|e| format!("parse claims: {e}"))?;

        self.validate_claims(&claims)?;

        let has_key_source = !self.jwks_url.is_empty() || !self.secret.is_empty();

        if !kid.is_empty() {
            if self.jwks_url.is_empty() {
                return Err("kid present but JWKS URL not configured".to_string());
            }
            let key = self
                .get_key(kid)
                .map_err(|e| format!("get signing key: {e}"))?;
            self.verify_signature(&parts, alg, &key)
                .map_err(|e| format!("verify signature: {e}"))?;
        } else if !self.secret.is_empty() {
            if !alg.eq_ignore_ascii_case("HS256")
                && !alg.eq_ignore_ascii_case("HS384")
                && !alg.eq_ignore_ascii_case("HS512")
            {
                return Err(format!("algorithm {alg} not compatible with secret key"));
            }
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let expected_sig = compute_hmac(self.secret.as_bytes(), signing_input.as_bytes(), alg);
            let provided_sig =
                decode_segment(parts[2]).map_err(|e| format!("decode signature: {e}"))?;
            if !constant_time_eq(&expected_sig, &provided_sig) {
                return Err("invalid signature".to_string());
            }
        } else if has_key_source {
            return Err(format!(
                "unable to determine signing key for token (kid={kid:?})"
            ));
        } else {
            return Err(
                "JWT validation enabled but no signing key configured (jwks_url or secret)"
                    .to_string(),
            );
        }

        Ok(claims)
    }

    fn is_allowed_algorithm(&self, alg: &str) -> bool {
        if self.algorithms.is_empty() {
            return true;
        }
        self.algorithms.iter().any(|a| a == alg)
    }

    fn validate_claims(&self, claims: &JwtClaims) -> Result<(), String> {
        let now = now_unix();

        if claims.exp > 0 && claims.exp < now {
            return Err("token expired".to_string());
        }
        if claims.nbf > 0 && claims.nbf > now {
            return Err("token not yet valid".to_string());
        }
        if !self.issuers.is_empty() && !self.issuers.iter().any(|i| *i == claims.iss) {
            return Err(format!("issuer not allowed: {}", claims.iss));
        }
        if !self.audiences.is_empty() {
            let aud = claims.audience();
            let found = self.audiences.iter().any(|a| aud.iter().any(|c| c == a));
            if !found {
                return Err("audience not allowed".to_string());
            }
        }
        Ok(())
    }

    fn get_key(&self, kid: &str) -> Result<Jwk, String> {
        {
            let cache = self.jwks_cache.read();
            if let Some(exp) = cache.expires_at {
                if Instant::now() < exp {
                    if let Some(key) = cache.keys.get(kid) {
                        return Ok(key.clone());
                    }
                }
            }
        }

        if self.jwks_url.is_empty() {
            return Err("jwks url not configured".to_string());
        }

        self.refresh_jwks()?;

        let cache = self.jwks_cache.read();
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| format!("key not found: {kid}"))
    }

    fn refresh_jwks(&self) -> Result<(), String> {
        let body = self.fetcher.fetch(&self.jwks_url)?;
        let jwks: Jwks = serde_json::from_str(&body).map_err(|e| format!("decode jwks: {e}"))?;

        let mut cache = self.jwks_cache.write();
        cache.keys = jwks.keys.into_iter().map(|k| (k.kid.clone(), k)).collect();
        cache.expires_at = Some(Instant::now() + cache.ttl);
        Ok(())
    }

    fn verify_signature(&self, parts: &[&str], alg: &str, key: &Jwk) -> Result<(), String> {
        let sig = decode_segment(parts[2])?;
        let data = format!("{}.{}", parts[0], parts[1]);

        match alg {
            "RS256" | "RS384" | "RS512" => verify_rsa(data.as_bytes(), &sig, key),
            "ES256" | "ES384" | "ES512" => verify_ec(data.as_bytes(), &sig, key),
            other => Err(format!("unsupported signature algorithm: {other}")),
        }
    }

    /// Port of `HasScope`.
    pub fn has_scope(&self, claims: &JwtClaims, scope: &str) -> bool {
        if claims.scope.is_empty() {
            return false;
        }
        claims.scope.split(' ').any(|s| s == scope)
    }

    /// Port of `HasRole`.
    pub fn has_role(&self, claims: &JwtClaims, role: &str) -> bool {
        claims.roles.iter().any(|r| r == role)
    }
}

impl Inspector for JwtValidator {
    fn name(&self) -> &str {
        "jwt_validation"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        // Go looked up "Authorization" then "authorization"; our header map is
        // case-insensitive so a single lookup covers both.
        let auth = ctx
            .headers
            .get("Authorization")
            .cloned()
            .unwrap_or_default();
        if auth.is_empty() || !auth.starts_with("Bearer ") {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        let token = &auth["Bearer ".len()..];
        if token.is_empty() {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        match self.validate(token) {
            Ok(claims) => {
                ctx.user_id = claims.sub.clone();
                Ok(Some(Decision::new(Action::Allow, 0.0)))
            }
            Err(e) => Ok(Some(
                Decision::new(Action::Block, 85.0)
                    .with_rule_id("JWT-001")
                    .with_rule_name("JWT validation failed")
                    .with_severity("high")
                    .with_evidence(e),
            )),
        }
    }
}

fn verify_rsa(data: &[u8], sig: &[u8], key: &Jwk) -> Result<(), String> {
    if key.n.is_empty() || key.e.is_empty() {
        return Err("incomplete RSA key: missing n or e".to_string());
    }

    let n_bytes = decode_segment(&key.n).map_err(|e| format!("decode RSA modulus: {e}"))?;
    let e_bytes = decode_segment(&key.e).map_err(|e| format!("decode RSA exponent: {e}"))?;

    let exp = if e_bytes.len() >= 8 {
        u64::from_be_bytes(e_bytes[e_bytes.len() - 8..].try_into().unwrap()) as u32
    } else {
        let mut exp: u32 = 0;
        for b in &e_bytes {
            exp = (exp << 8) | (*b as u32);
        }
        exp
    };

    let n = rsa::BigUint::from_bytes_be(&n_bytes);
    let pub_key = RsaPublicKey::new(n, rsa::BigUint::from(exp))
        .map_err(|e| format!("invalid rsa key: {e}"))?;

    // Go hard-coded crypto.SHA256 regardless of RS256/384/512 (see auth.go
    // `hash := crypto.SHA256`). Reproduce that exactly.
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hashed = hasher.finalize();

    // Mirror Go's rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, sig).
    pub_key
        .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, sig)
        .map_err(|_| "RSA signature verification failed".to_string())
}

fn verify_ec(data: &[u8], sig: &[u8], key: &Jwk) -> Result<(), String> {
    if key.crv.is_empty() || key.x.is_empty() || key.y.is_empty() {
        return Err("incomplete EC key: missing crv, x, or y".to_string());
    }
    let x = decode_segment(&key.x).map_err(|e| format!("decode EC x: {e}"))?;
    let y = decode_segment(&key.y).map_err(|e| format!("decode EC y: {e}"))?;
    let sec1 = encode_sec1_point(&x, &y);

    match key.crv.as_str() {
        "P-256" => verify_ec_p256(data, sig, &sec1),
        "P-384" => verify_ec_p384(data, sig, &sec1),
        "P-521" => verify_ec_p521(data, sig, &sec1),
        other => Err(format!("unsupported EC curve: {other}")),
    }
}

/// Build an uncompressed SEC1 point `0x04 || X || Y`.
fn encode_sec1_point(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + x.len() + y.len());
    v.push(0x04);
    v.extend_from_slice(x);
    v.extend_from_slice(y);
    v
}

fn verify_ec_p256(data: &[u8], sig: &[u8], sec1: &[u8]) -> Result<(), String> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::EncodedPoint;
    let point = EncodedPoint::from_bytes(sec1).map_err(|e| format!("bad P-256 point: {e}"))?;
    let vk = VerifyingKey::from_encoded_point(&point).map_err(|e| format!("bad P-256 key: {e}"))?;
    let signature = Signature::from_slice(sig).map_err(|e| format!("bad P-256 sig: {e}"))?;
    vk.verify(data, &signature)
        .map_err(|_| "ECDSA signature verification failed".to_string())
}

fn verify_ec_p384(data: &[u8], sig: &[u8], sec1: &[u8]) -> Result<(), String> {
    use p384::ecdsa::signature::Verifier;
    use p384::ecdsa::{Signature, VerifyingKey};
    use p384::EncodedPoint;
    let point = EncodedPoint::from_bytes(sec1).map_err(|e| format!("bad P-384 point: {e}"))?;
    let vk = VerifyingKey::from_encoded_point(&point).map_err(|e| format!("bad P-384 key: {e}"))?;
    let signature = Signature::from_slice(sig).map_err(|e| format!("bad P-384 sig: {e}"))?;
    vk.verify(data, &signature)
        .map_err(|_| "ECDSA signature verification failed".to_string())
}

fn verify_ec_p521(data: &[u8], sig: &[u8], sec1: &[u8]) -> Result<(), String> {
    use p521::ecdsa::signature::Verifier;
    use p521::ecdsa::{Signature, VerifyingKey};
    use p521::EncodedPoint;
    let point = EncodedPoint::from_bytes(sec1).map_err(|e| format!("bad P-521 point: {e}"))?;
    let vk = VerifyingKey::from_encoded_point(&point).map_err(|e| format!("bad P-521 key: {e}"))?;
    let signature = Signature::from_slice(sig).map_err(|e| format!("bad P-521 sig: {e}"))?;
    vk.verify(data, &signature)
        .map_err(|_| "ECDSA signature verification failed".to_string())
}

/// Port of `decodeSegment`: try base64url-no-pad, then standard base64.
fn decode_segment(seg: &str) -> Result<Vec<u8>, String> {
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(seg) {
        return Ok(v);
    }
    base64::engine::general_purpose::STANDARD
        .decode(seg)
        .map_err(|e| e.to_string())
}

/// Port of `computeHMAC`.
fn compute_hmac(secret: &[u8], data: &[u8], alg: &str) -> Vec<u8> {
    match alg {
        "HS384" => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac key");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Constant-time byte comparison (`hmac.Equal`).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// OAuth introspection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenInfo {
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub exp: i64,
    #[serde(default)]
    pub iat: i64,
    #[serde(default)]
    pub nbf: i64,
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub aud: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

struct CachedToken {
    info: TokenInfo,
    expires_at: Instant,
}

struct TokenCache {
    tokens: HashMap<String, CachedToken>,
    ttl: Duration,
}

pub struct OAuthIntrospector {
    introspection_url: String,
    client_id: String,
    client_secret: String,
    token_type_hint: String,
    cache: RwLock<TokenCache>,
    client: Arc<dyn IntrospectClient>,
}

impl OAuthIntrospector {
    pub fn new(cfg: OAuthConfig) -> Self {
        Self::with_client(cfg, Arc::new(UreqFetcher))
    }

    pub fn with_client(cfg: OAuthConfig, client: Arc<dyn IntrospectClient>) -> Self {
        OAuthIntrospector {
            introspection_url: cfg.introspection_url,
            client_id: cfg.client_id,
            client_secret: cfg.client_secret,
            token_type_hint: cfg.token_type_hint,
            cache: RwLock::new(TokenCache {
                tokens: HashMap::new(),
                ttl: Duration::from_secs(5 * 60),
            }),
            client,
        }
    }

    /// Port of `Introspect`.
    pub fn introspect(&self, token: &str) -> Result<TokenInfo, String> {
        if let Some(info) = self.get_cached(token) {
            return Ok(info);
        }

        if self.introspection_url.is_empty() {
            return Err("introspection URL not configured".to_string());
        }

        let body = self.client.introspect(
            &self.introspection_url,
            &self.client_id,
            &self.client_secret,
            token,
            &self.token_type_hint,
        )?;

        let info: TokenInfo = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        self.cache_token(token, &info);
        Ok(info)
    }

    fn get_cached(&self, token: &str) -> Option<TokenInfo> {
        let cache = self.cache.read();
        let cached = cache.tokens.get(token)?;
        if Instant::now() > cached.expires_at {
            return None;
        }
        Some(cached.info.clone())
    }

    fn cache_token(&self, token: &str, info: &TokenInfo) {
        let mut cache = self.cache.write();
        let expires_at = if info.exp > 0 {
            let now = now_unix();
            let remaining = (info.exp - now).max(0) as u64;
            Instant::now() + Duration::from_secs(remaining)
        } else {
            Instant::now() + cache.ttl
        };
        cache.tokens.insert(
            token.to_string(),
            CachedToken {
                info: info.clone(),
                expires_at,
            },
        );
    }

    /// Port of `HasScope`.
    pub fn has_scope(&self, info: &TokenInfo, scope: &str) -> bool {
        if info.scope.is_empty() {
            return false;
        }
        info.scope.split(' ').any(|s| s == scope)
    }

    /// Port of `HasRole`.
    pub fn has_role(&self, info: &TokenInfo, role: &str) -> bool {
        info.roles.iter().any(|r| r == role)
    }
}

impl Inspector for OAuthIntrospector {
    fn name(&self) -> &str {
        "oauth_introspection"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let auth = ctx
            .headers
            .get("Authorization")
            .cloned()
            .unwrap_or_default();
        if auth.is_empty() || !auth.starts_with("Bearer ") {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        let token = &auth["Bearer ".len()..];
        if token.is_empty() {
            return Ok(Some(Decision::new(Action::Allow, 0.0)));
        }

        match self.introspect(token) {
            Ok(info) => {
                if !info.active {
                    return Ok(Some(
                        Decision::new(Action::Block, 90.0)
                            .with_rule_id("OAUTH-002")
                            .with_rule_name("OAuth token inactive")
                            .with_severity("high")
                            .with_evidence("token is not active"),
                    ));
                }
                ctx.user_id = info.sub.clone();
                Ok(Some(Decision::new(Action::Allow, 0.0)))
            }
            Err(e) => Ok(Some(
                Decision::new(Action::Block, 80.0)
                    .with_rule_id("OAUTH-001")
                    .with_rule_name("OAuth token introspection failed")
                    .with_severity("high")
                    .with_evidence(e),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs256_token(secret: &str, payload: &str) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signing_input = format!("{header}.{p}");
        let sig = compute_hmac(secret.as_bytes(), signing_input.as_bytes(), "HS256");
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
        format!("{signing_input}.{sig_b64}")
    }

    #[test]
    fn valid_hs256_passes() {
        let secret = "topsecret";
        let token = hs256_token(secret, r#"{"sub":"user1","exp":9999999999}"#);
        let v = JwtValidator::with_fetcher(
            JwtConfig {
                secret: secret.to_string(),
                ..Default::default()
            },
            Arc::new(UselessFetcher),
        );
        let claims = v.validate(&token).unwrap();
        assert_eq!(claims.sub, "user1");
    }

    #[test]
    fn wrong_secret_fails() {
        let token = hs256_token("right", r#"{"sub":"u"}"#);
        let v = JwtValidator::new(JwtConfig {
            secret: "wrong".to_string(),
            ..Default::default()
        });
        assert!(v.validate(&token).is_err());
    }

    #[test]
    fn alg_none_rejected() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"u"}"#);
        let token = format!("{header}.{p}.");
        let v = JwtValidator::new(JwtConfig {
            secret: "s".to_string(),
            ..Default::default()
        });
        let err = v.validate(&token).unwrap_err();
        assert!(err.contains("none"));
    }

    #[test]
    fn expired_token_rejected() {
        let secret = "s";
        let token = hs256_token(secret, r#"{"sub":"u","exp":1}"#);
        let v = JwtValidator::new(JwtConfig {
            secret: secret.to_string(),
            ..Default::default()
        });
        assert_eq!(v.validate(&token).unwrap_err(), "token expired");
    }

    #[test]
    fn algorithm_allowlist_enforced() {
        let token = hs256_token("s", r#"{"sub":"u"}"#);
        let v = JwtValidator::new(JwtConfig {
            secret: "s".to_string(),
            algorithms: vec!["RS256".to_string()],
            ..Default::default()
        });
        assert!(v.validate(&token).unwrap_err().contains("not allowed"));
    }

    #[test]
    fn oauth_inactive_token_blocked() {
        struct Inactive;
        impl IntrospectClient for Inactive {
            fn introspect(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<String, String> {
                Ok(r#"{"active":false}"#.to_string())
            }
        }
        let o = OAuthIntrospector::with_client(
            OAuthConfig {
                introspection_url: "http://x".to_string(),
                ..Default::default()
            },
            Arc::new(Inactive),
        );
        let mut r = crate::http::HttpRequest::new("GET", "/");
        r.header.add("Authorization", "Bearer tok");
        let mut ctx = RequestContext::new(r);
        let dec = o.inspect(&mut ctx).unwrap().unwrap();
        assert_eq!(dec.rule_id, "OAUTH-002");
    }

    struct UselessFetcher;
    impl JwksFetcher for UselessFetcher {
        fn fetch(&self, _: &str) -> Result<String, String> {
            Err("no network".to_string())
        }
    }
}
