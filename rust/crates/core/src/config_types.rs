//! Engine-facing configuration types.
//!
//! This is a focused subset of `internal/config` that the engine inspectors
//! depend on (`JWTConfig`, `OAuthConfig`, and the MFA/adaptive knobs used by
//! `adaptive.go`). The full configuration loader is ported separately in the
//! `fwaf-config` crate; these types are duplicated here as plain data so the
//! engine crate has no dependency on the loader.

use serde::{Deserialize, Serialize};

/// Port of `config.JWTConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwtConfig {
    #[serde(default)]
    pub jwks_url: String,
    #[serde(default)]
    pub issuers: Vec<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    #[serde(default)]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub secret: String,
}

/// Port of `config.OAuthConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OAuthConfig {
    #[serde(default)]
    pub introspection_url: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub token_type_hint: String,
}

/// Port of `config.GraphQLConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GraphQlConfig {
    #[serde(default)]
    pub max_depth: i32,
    #[serde(default)]
    pub max_cost: i32,
    #[serde(default)]
    pub max_aliases: i32,
    #[serde(default)]
    pub max_batch_size: i32,
    #[serde(default)]
    pub max_tokens: i32,
    #[serde(default)]
    pub block_introspection: bool,
    #[serde(default)]
    pub block_schema: bool,
    #[serde(default)]
    pub allowed_operations: Vec<String>,
    #[serde(default)]
    pub restricted_fields: Vec<String>,
    #[serde(default)]
    pub strict_validation: bool,
}

/// Port of `config.WebSocketConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default)]
    pub max_frame_size: i32,
    #[serde(default)]
    pub max_message_size: i32,
    #[serde(default)]
    pub max_depth: i32,
    #[serde(default)]
    pub max_frames_per_min: i32,
    #[serde(default)]
    pub max_bytes_per_min: i32,
    #[serde(default)]
    pub block_on_limit: bool,
    #[serde(default)]
    pub allowed_types: Vec<i32>,
    #[serde(default)]
    pub strict_mode: bool,
    #[serde(default)]
    pub enable_ping: bool,
    #[serde(default)]
    pub enable_pong: bool,
    #[serde(default)]
    pub enable_close: bool,
    #[serde(default)]
    pub connection_timeout_sec: i64,
}

/// Port of `config.MTLSConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ca_file: String,
    #[serde(default)]
    pub client_auth: String,
    #[serde(default)]
    pub verify_depth: i32,
    #[serde(default)]
    pub fail_on_error: bool,
    #[serde(default)]
    pub early_auth: bool,
    #[serde(default)]
    pub username_header: String,
    #[serde(default)]
    pub skip_verify: bool,
    #[serde(default)]
    pub policy_oid: String,
}
