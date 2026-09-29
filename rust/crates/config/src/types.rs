//! Configuration data types.
//!
//! Faithful port of the structs in `internal/config/config.go`. Field names use
//! serde's default snake_case, matching the Go `yaml:"..."` tags exactly.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output: String,
    pub verbose: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_file: String,
    pub key_file: String,
    pub min_version: String,
    pub http2_enabled: bool,
    pub ocsp_enabled: bool,
    pub acme_enabled: bool,
    pub acme_email: String,
    pub acme_domains: Vec<String>,
    pub acme_cache_dir: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    pub port: i32,
    pub enabled: bool,
    pub mtls: bool,
    pub ca_cert: String,
    pub cert_file: String,
    pub key_file: String,
    pub api_keys: Vec<String>,
    pub cors_origins: Vec<String>,
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    pub enabled: bool,
    pub addr: String,
    pub password: String,
    pub db: i32,
    pub pool_size: i32,
    pub ttl: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    pub driver: String,
    pub dsn: String,
    pub max_open: i32,
    pub max_idle: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MlConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub timeout_sec: i32,
    pub max_retries: i32,
    pub fallback_mode: String,
    pub min_score: f64,
    pub model_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteRuleOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteConfig {
    pub name: String,
    pub domains: Vec<String>,
    pub upstream: String,
    pub port: i32,
    pub tls: bool,
    pub cert_file: String,
    pub key_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitSiteConfig>,
    pub waf_enabled: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_paths: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rule_overrides: BTreeMap<String, SiteRuleOverride>,
}

impl SiteConfig {
    /// Port of `ExcludesPath`. An entry matches the path itself or anything
    /// below it (`/administrator` covers `/administrator/index.php` but not
    /// `/administratorX`); matching is case-sensitive and a path containing a
    /// `..` segment is never excluded.
    pub fn excludes_path(&self, path: &str) -> bool {
        if has_dot_dot_segment(path) {
            return false;
        }
        let cleaned = clean_path(path);

        for entry in &self.exclude_paths {
            if entry == "/" {
                return true;
            }
            let entry = entry.trim_end_matches('/');
            if !entry.is_empty() && (cleaned == entry || cleaned.starts_with(&format!("{entry}/")))
            {
                return true;
            }
        }
        false
    }
}

/// Port of `hasDotDotSegment`.
pub fn has_dot_dot_segment(path: &str) -> bool {
    path.split('/').any(|seg| seg == "..")
}

/// Port of Go `path.Clean`. Collapses duplicate slashes, resolves `.` and `..`
/// segments, and removes a trailing slash (except for the root).
pub fn clean_path(path: &str) -> String {
    if path.is_empty() {
        return ".".to_string();
    }

    let rooted = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                if let Some(last) = out.last() {
                    if *last != ".." {
                        out.pop();
                        continue;
                    }
                }
                if !rooted {
                    out.push("..");
                }
            }
            s => out.push(s),
        }
    }

    let mut result = String::new();
    if rooted {
        result.push('/');
    }
    result.push_str(&out.join("/"));

    if result.is_empty() {
        return ".".to_string();
    }
    result
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitSiteConfig {
    pub requests_per_second: i32,
    pub burst: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleConfig {
    #[serde(rename = "id")]
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity: String,
    pub action: String,
    pub phase: String,
    pub priority: i32,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub transform: Vec<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<BTreeMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtConfig {
    pub enabled: bool,
    pub jwks_url: String,
    pub issuers: Vec<String>,
    pub audiences: Vec<String>,
    pub algorithms: Vec<String>,
    pub secret: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub introspection_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_type_hint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphQlConfig {
    pub enabled: bool,
    pub max_depth: i32,
    pub max_cost: i32,
    pub max_aliases: i32,
    pub max_batch_size: i32,
    pub max_tokens: i32,
    pub block_introspection: bool,
    pub block_schema: bool,
    pub allowed_operations: Vec<String>,
    pub restricted_fields: Vec<String>,
    pub strict_validation: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MtlsConfig {
    pub enabled: bool,
    pub ca_file: String,
    pub client_auth: String,
    pub skip_verify: bool,
    pub policy_oid: String,
    pub verify_depth: i32,
    pub fail_on_error: bool,
    pub early_auth: bool,
    pub username_header: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WebSocketConfig {
    pub enabled: bool,
    pub max_frame_size: i32,
    pub max_message_size: i32,
    pub max_depth: i32,
    pub max_frames_per_min: i32,
    pub max_bytes_per_min: i32,
    pub block_on_limit: bool,
    pub allowed_types: Vec<i32>,
    pub strict_mode: bool,
    pub enable_ping: bool,
    pub enable_pong: bool,
    pub enable_close: bool,
    #[serde(with = "crate::duration")]
    pub connection_timeout: Duration,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SiemConfig {
    pub enabled: bool,
    #[serde(with = "crate::duration")]
    pub export_interval: Duration,
    pub batch_size: i32,
    pub exporters: Vec<SiemExporterConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SiemExporterConfig {
    pub r#type: String,
    pub enabled: bool,
    pub url: String,
    pub token: String,
    pub index: String,
    pub username: String,
    pub password: String,
    pub verify_ssl: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RewriteRuleConfig {
    pub enabled: bool,
    pub name: String,
    pub conditions: Vec<RewriteConditionConfig>,
    pub actions: Vec<RewriteActionConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RewriteConditionConfig {
    pub field: String,
    pub name: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RewriteActionConfig {
    pub r#type: String,
    pub name: String,
    pub value: String,
    pub op: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DDoSConfig {
    pub enabled: bool,
    pub per_ip_rate: i32,
    pub per_endpoint_rate: i32,
    pub global_rate: i32,
    pub ban_seconds: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BotConfig {
    pub enabled: bool,
    pub auto_ban_after: i32,
    pub auto_ban_window_sec: i32,
    pub auto_ban_seconds: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CredentialConfig {
    pub enabled: bool,
    pub max_attempts: i32,
    pub window_sec: i32,
    pub block_duration_sec: i32,
    pub login_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoConfig {
    pub enabled: bool,
    pub city_db_path: String,
    pub asn_db_path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub default_rate: i32,
    pub default_burst: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    pub enabled: bool,
    #[serde(with = "crate::duration")]
    pub ttl: Duration,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptchaConfig {
    pub enabled: bool,
    pub provider: String,
    pub site_key: String,
    pub secret: String,
    pub score: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseInspectConfig {
    pub enabled: bool,
    pub inspect_body: bool,
    pub block: bool,
    pub sensitive_patterns: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SoapConfig {
    pub enabled: bool,
    pub strict_schema: bool,
    pub max_depth: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GrpcConfig {
    pub enabled: bool,
    pub max_msg_size: i32,
    pub rate_limit: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub path: String,
    pub port: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BehavioralConfig {
    pub enabled: bool,
    pub reputation: bool,
    pub velocity: bool,
    pub path_entropy: bool,
    pub threshold: f64,
    pub window_sec: i32,
    pub max_requests: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WasmConfig {
    pub enabled: bool,
    pub module_dir: String,
    pub max_memory_pages: i32,
    pub modules: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DesyncConfig {
    pub enabled: bool,
    pub max_body_size: i64,
    pub strict_cl: bool,
    pub detect_obs_fold: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AdaptiveConfig {
    pub enabled: bool,
    pub js_script_path: String,
    pub tarpit_delay_ms: i32,
    pub captcha_score: f64,
    pub challenge_ttl: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EbpfConfig {
    pub enabled: bool,
    pub interface: String,
    pub port: i32,
    pub sample_rate: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceConfig {
    pub enabled: bool,
    pub max_regex_ms: i32,
    pub max_wasm_ms: i32,
    pub max_memory_mb: i32,
    pub max_concurrency: i32,
    pub circuit_threshold: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FeatureConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub expected_ips: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrainingConfig {
    pub corpus_dir: String,
    pub enabled: bool,
}

/// The full configuration. Field order mirrors the Go struct for readability;
/// serialisation is by name, not order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub sites: Vec<SiteConfig>,
    pub rules: Vec<RuleConfig>,
    pub ml: MlConfig,
    pub redis: RedisConfig,
    pub db: DbConfig,
    pub logging: LoggingConfig,
    pub tls: TlsConfig,
    pub admin: AdminConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
    pub graphql: GraphQlConfig,
    pub mtls: MtlsConfig,
    pub websocket: WebSocketConfig,
    pub siem: SiemConfig,
    pub rewrite_rules: Vec<RewriteRuleConfig>,
    pub sqli: FeatureConfig,
    pub xss: FeatureConfig,
    pub rce: FeatureConfig,
    pub ddos: DDoSConfig,
    pub protocol: FeatureConfig,
    pub bot: BotConfig,
    pub api_protect: FeatureConfig,
    pub upload: FeatureConfig,
    pub credential: CredentialConfig,
    pub geo: GeoConfig,
    pub rate_limit: RateLimitConfig,
    pub session: SessionConfig,
    pub reputation: FeatureConfig,
    pub rules_cfg: FeatureConfig,
    pub captcha: CaptchaConfig,
    pub response_inspect: ResponseInspectConfig,
    pub soap: SoapConfig,
    pub grpc: GrpcConfig,
    pub prometheus: PrometheusConfig,
    pub ja3: FeatureConfig,
    pub behavioral: BehavioralConfig,
    pub wasm: WasmConfig,
    pub desync: DesyncConfig,
    pub adaptive: AdaptiveConfig,
    pub ebpf: EbpfConfig,
    pub parser_hardening: FeatureConfig,
    pub shadow_mode: FeatureConfig,
    pub learning_mode: FeatureConfig,
    pub performance: PerformanceConfig,
    pub server: ServerConfig,
    pub training: TrainingConfig,

    /// The path this config was loaded from. Not serialised (Go: unexported
    /// `filePath`).
    #[serde(skip)]
    pub file_path: String,
}
