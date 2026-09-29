//! Config loading, validation, atomic save, and hot reload.
//!
//! Port of the `Manager`, `Load`, `Validate`, `SaveToFile`, `ExpandEnvRefs`
//! and accessor helpers in `internal/config/config.go`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use regex::Regex;

use crate::defaults::default_config;
use crate::types::*;

/// Load the configuration from `path`: read, expand `${ENV}` references, parse
/// YAML over the defaults, then validate. Port of `Load`.
pub fn load(path: &str) -> Result<Config, String> {
    let data = std::fs::read(path).map_err(|e| format!("read config: {e}"))?;

    let expanded = expand_env_refs(&data)?;

    // Parse the user YAML and deep-merge it over the defaults, matching Go's
    // unmarshal-into-a-populated-struct semantics.
    let mut cfg = merge_yaml_over_defaults(&expanded)?;

    cfg.file_path = path.to_string();

    validate(&cfg).map_err(|e| format!("invalid config: {e}"))?;

    Ok(cfg)
}

/// Merge a user YAML document over the defaults, reproducing Go's
/// `yaml.Unmarshal(data, cfg)` which unmarshals *into* a pre-populated struct
/// so any omitted field keeps its Go default (which is often non-zero). serde's
/// `#[serde(default)]` would instead use `Default::default()` for the type, so
/// a deep-merge over the serialised default config is required for fidelity.
fn merge_yaml_over_defaults(expanded: &[u8]) -> Result<Config, String> {
    let user: serde_yaml::Value =
        serde_yaml::from_slice(expanded).map_err(|e| format!("parse config: {e}"))?;
    let defaults_value =
        serde_yaml::to_value(default_config()).map_err(|e| format!("serialize defaults: {e}"))?;
    let merged = deep_merge(defaults_value, user);
    let cfg: Config = serde_yaml::from_value(merged).map_err(|e| format!("parse config: {e}"))?;
    Ok(cfg)
}

/// Deep-merge `overlay` onto `base`: mappings are merged key-by-key, and any
/// other value (including sequences) is replaced wholesale by the overlay --
/// matching Go's YAML behaviour where a present key wins.
fn deep_merge(base: serde_yaml::Value, overlay: serde_yaml::Value) -> serde_yaml::Value {
    use serde_yaml::Value::*;
    match (base, overlay) {
        (Mapping(mut b), Mapping(o)) => {
            for (k, v) in o {
                let merged = match b.remove(&k) {
                    Some(existing) => deep_merge(existing, v),
                    None => v,
                };
                b.insert(k, merged);
            }
            Mapping(b)
        }
        (_, o) => o,
    }
}

/// Validate the config. Port of `Validate`, including the duplicate site-name
/// and duplicate-domain checks.
pub fn validate(c: &Config) -> Result<(), String> {
    if c.sites.is_empty() {
        return Err("at least one site must be configured".to_string());
    }

    let mut seen_site_name: HashMap<String, usize> = HashMap::new();
    let mut seen_domain: HashMap<String, String> = HashMap::new();
    for (i, site) in c.sites.iter().enumerate() {
        if site.name.is_empty() {
            return Err(format!("site[{i}]: name is required"));
        }
        if let Some(prev) = seen_site_name.get(&site.name) {
            return Err(format!(
                "site[{i}] {:?}: duplicate site name (also site[{prev}])",
                site.name
            ));
        }
        seen_site_name.insert(site.name.clone(), i);
        if site.domains.is_empty() {
            return Err(format!(
                "site[{i}] {:?}: at least one domain is required",
                site.name
            ));
        }
        if site.upstream.is_empty() {
            return Err(format!("site[{i}] {:?}: upstream is required", site.name));
        }
        for domain in &site.domains {
            if let Some(owner) = seen_domain.get(domain) {
                return Err(format!(
                    "site[{i}] {:?}: domain {domain:?} is already used by site {owner:?}",
                    site.name
                ));
            }
            seen_domain.insert(domain.clone(), site.name.clone());
        }
        for (j, p) in site.exclude_paths.iter().enumerate() {
            if !p.starts_with('/') {
                return Err(format!(
                    "site[{i}] {:?}: exclude_paths[{j}] {p:?} must start with \"/\"",
                    site.name
                ));
            }
        }
    }

    for (i, rule) in c.rules.iter().enumerate() {
        if rule.id.is_empty() {
            return Err(format!("rule[{i}]: ID is required"));
        }
        if rule.field.is_empty() {
            return Err(format!("rule[{i}] {:?}: field is required", rule.id));
        }
        if rule.operator.is_empty() {
            return Err(format!("rule[{i}] {:?}: operator is required", rule.id));
        }
    }

    if c.ml.enabled && c.ml.endpoint.is_empty() {
        return Err("ml.endpoint is required when ml is enabled".to_string());
    }

    if c.redis.enabled && c.redis.addr.is_empty() {
        return Err("redis.addr is required when redis is enabled".to_string());
    }

    Ok(())
}

static ENV_REF_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\$\{([^}]+)\}").unwrap());

/// Port of `ExpandEnvRefs`. Only replaces a reference when the env var is set
/// and non-empty (matching Go's `os.Getenv(envVar) != ""`).
pub fn expand_env_refs(data: &[u8]) -> Result<Vec<u8>, String> {
    let s = String::from_utf8_lossy(data).into_owned();
    let mut out = s.clone();
    for cap in ENV_REF_RE.captures_iter(&s) {
        let whole = &cap[0];
        let var = &cap[1];
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                out = out.replace(whole, &val);
            }
        }
    }
    Ok(out.into_bytes())
}

/// Atomically write `cfg` to `path` (marshal -> temp -> fsync -> chmod ->
/// rename). Port of `SaveToFile`.
pub fn save_to_file(path: &str, cfg: &Config) -> Result<(), String> {
    let data = serde_yaml::to_string(cfg).map_err(|e| format!("marshal config: {e}"))?;

    let dir = Path::new(path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // Create a unique temp file in the same directory.
    let tmp_name = dir.join(format!(
        ".config-{}-{}.yaml.tmp",
        std::process::id(),
        now_nanos()
    ));

    let mode = std::fs::metadata(path)
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o777
        })
        .unwrap_or(0o644);

    {
        use std::io::Write;
        let mut f =
            std::fs::File::create(&tmp_name).map_err(|e| format!("create temp config: {e}"))?;
        f.write_all(data.as_bytes())
            .map_err(|e| format!("write temp config: {e}"))?;
        f.sync_all().map_err(|e| format!("sync temp config: {e}"))?;
    }

    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&tmp_name, perms)
            .map_err(|e| format!("chmod temp config: {e}"))?;
    }

    if let Err(e) = std::fs::rename(&tmp_name, path) {
        let _ = std::fs::remove_file(&tmp_name);
        return Err(format!("replace config: {e}"));
    }

    Ok(())
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Config accessors. Port of the `Config` methods on the merged config.
impl Config {
    pub fn get_site(&self, name: &str) -> Option<&SiteConfig> {
        self.sites.iter().find(|s| s.name == name)
    }

    pub fn find_site_by_domain(&self, domain: &str) -> Option<&SiteConfig> {
        self.sites
            .iter()
            .find(|s| s.domains.iter().any(|d| d == domain))
    }

    pub fn get_rule(&self, id: &str) -> Option<&RuleConfig> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn get_enabled_rules(&self) -> Vec<RuleConfig> {
        self.rules.iter().filter(|r| r.enabled).cloned().collect()
    }
}

/// The manager: holds the current config and hot-reloads on file change.
///
/// Port of `Manager`. Go ran a `fsnotify` goroutine; this port uses the
/// `notify` crate's recommended-watcher in a background thread.
pub struct Manager {
    config: Arc<RwLock<Config>>,
    on_change: Arc<Mutex<Vec<Box<dyn Fn(&Config) + Send + Sync>>>>,
    watcher: Option<notify::RecommendedWatcher>,
    abs_path: Option<PathBuf>,
}

impl Manager {
    /// Port of `NewManager`. A watcher failure is non-fatal (logged, manager
    /// still usable), matching Go.
    pub fn new(path: &str) -> Result<Self, String> {
        let cfg = load(path)?;
        let config = Arc::new(RwLock::new(cfg));
        let on_change: Arc<Mutex<Vec<Box<dyn Fn(&Config) + Send + Sync>>>> =
            Arc::new(Mutex::new(Vec::new()));

        let abs_path = std::fs::canonicalize(path).ok();
        let mut watcher_opt = None;

        if let Some(abs) = &abs_path {
            use notify::{RecursiveMode, Watcher};
            match notify::recommended_watcher({
                let config = config.clone();
                let on_change = on_change.clone();
                let abs = abs.clone();
                move |res: Result<notify::Event, notify::Error>| {
                    if let Ok(event) = res {
                        use notify::EventKind;
                        let is_write =
                            matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_));
                        if is_write && event.paths.iter().any(|p| p == &abs) {
                            if let Err(e) = Self::reload_inner(&config, &on_change, &abs) {
                                tracing::error!(error = e.as_str(), "config reload failed");
                            }
                        }
                    }
                }
            }) {
                Ok(mut w) => {
                    let dir = abs.parent().map(|p| p.to_path_buf());
                    if let Some(dir) = dir {
                        if let Err(e) = w.watch(&dir, RecursiveMode::NonRecursive) {
                            tracing::warn!(
                                dir = dir.to_string_lossy().as_ref(),
                                error = e.to_string().as_str(),
                                "cannot watch config directory"
                            );
                        } else {
                            watcher_opt = Some(w);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = e.to_string().as_str(),
                        "hot-reload watcher not available"
                    );
                }
            }
        }

        Ok(Manager {
            config,
            on_change,
            watcher: watcher_opt,
            abs_path,
        })
    }

    /// Build a manager over an already-parsed config with no file watcher.
    /// Used by tests and by callers that manage persistence themselves.
    pub fn new_detached(cfg: Config) -> Self {
        Manager {
            config: Arc::new(RwLock::new(cfg)),
            on_change: Arc::new(Mutex::new(Vec::new())),
            watcher: None,
            abs_path: None,
        }
    }

    fn reload_inner(
        config: &Arc<RwLock<Config>>,
        on_change: &Arc<Mutex<Vec<Box<dyn Fn(&Config) + Send + Sync>>>>,
        path: &Path,
    ) -> Result<(), String> {
        let new_cfg = load(&path.to_string_lossy())?;
        *config.write() = new_cfg.clone();
        let callbacks = on_change.lock();
        for cb in callbacks.iter() {
            cb(&new_cfg);
        }
        Ok(())
    }

    /// Port of `Reload`.
    pub fn reload(&self) -> Result<(), String> {
        let path = self
            .abs_path
            .clone()
            .ok_or_else(|| "config path unknown".to_string())?;
        Self::reload_inner(&self.config, &self.on_change, &path)
    }

    /// Port of `Get`.
    pub fn get(&self) -> Config {
        self.config.read().clone()
    }

    /// Port of `OnChange`.
    pub fn on_change(&self, cb: Box<dyn Fn(&Config) + Send + Sync>) {
        self.on_change.lock().push(cb);
    }

    /// Port of `UpdateConfig`: mutate, validate, save, notify.
    pub fn update_config(&self, f: impl FnOnce(&mut Config)) -> Result<(), String> {
        let updated = {
            let mut cfg = self.config.write();
            f(&mut cfg);
            validate(&cfg).map_err(|e| format!("validate updated config: {e}"))?;
            if !cfg.file_path.is_empty() {
                save_to_file(&cfg.file_path, &cfg)?;
            }
            cfg.clone()
        };

        let callbacks = self.on_change.lock();
        for cb in callbacks.iter() {
            cb(&updated);
        }
        Ok(())
    }

    /// Stop watching. Port of `Close`.
    pub fn close(&mut self) {
        self.watcher = None;
    }
}

// The watcher field must exist to keep it alive; silence the dead-code lint.
#[allow(dead_code)]
impl Manager {
    fn has_watcher(&self) -> bool {
        self.watcher.is_some()
    }
}

// ---------------------------------------------------------------------------
// Default manager (global), mirroring DefaultManager / SetDefaultManager.
// ---------------------------------------------------------------------------

static DEFAULT_MANAGER: Lazy<Mutex<Option<Arc<Manager>>>> = Lazy::new(|| Mutex::new(None));

/// Port of `SetDefaultManager`.
pub fn set_default_manager(m: Arc<Manager>) {
    *DEFAULT_MANAGER.lock() = Some(m);
}

/// Port of `GetConfig`.
pub fn get_config() -> Config {
    let m = DEFAULT_MANAGER.lock().clone();
    match m {
        Some(m) => m.get(),
        None => default_config(),
    }
}

/// Access the shared default manager, if set.
pub fn default_manager() -> Option<Arc<Manager>> {
    DEFAULT_MANAGER.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_matches_go() {
        assert_eq!(clean_path("/a/b/../c"), "/a/c");
        assert_eq!(clean_path("/a//b/"), "/a/b");
        assert_eq!(clean_path("/administrator/"), "/administrator");
        assert_eq!(clean_path(""), ".");
        assert_eq!(clean_path("/"), "/");
        assert_eq!(clean_path("a/./b"), "a/b");
    }

    #[test]
    fn excludes_path_prefix_logic() {
        let site = SiteConfig {
            exclude_paths: vec!["/administrator".to_string()],
            ..Default::default()
        };
        assert!(site.excludes_path("/administrator"));
        assert!(site.excludes_path("/administrator/index.php"));
        assert!(site.excludes_path("/administrator/"));
        assert!(!site.excludes_path("/administratorX"));
        assert!(!site.excludes_path("/users"));
    }

    #[test]
    fn excludes_path_rejects_dotdot() {
        let site = SiteConfig {
            exclude_paths: vec!["/administrator".to_string()],
            ..Default::default()
        };
        // /administrator/../users must NOT be excluded.
        assert!(!site.excludes_path("/administrator/../users/index.php"));
    }

    #[test]
    fn root_exclude_matches_everything() {
        let site = SiteConfig {
            exclude_paths: vec!["/".to_string()],
            ..Default::default()
        };
        assert!(site.excludes_path("/anything"));
        assert!(site.excludes_path("/"));
    }

    #[test]
    fn validate_requires_site() {
        let c = default_config();
        assert!(validate(&c).unwrap_err().contains("at least one site"));
    }

    #[test]
    fn validate_rejects_duplicate_domain() {
        let mut c = default_config();
        c.sites = vec![
            SiteConfig {
                name: "a".into(),
                domains: vec!["example.com".into()],
                upstream: "http://x".into(),
                ..Default::default()
            },
            SiteConfig {
                name: "b".into(),
                domains: vec!["example.com".into()],
                upstream: "http://y".into(),
                ..Default::default()
            },
        ];
        assert!(validate(&c).unwrap_err().contains("already used by site"));
    }

    #[test]
    fn validate_rejects_duplicate_name() {
        let mut c = default_config();
        c.sites = vec![
            SiteConfig {
                name: "a".into(),
                domains: vec!["a.com".into()],
                upstream: "http://x".into(),
                ..Default::default()
            },
            SiteConfig {
                name: "a".into(),
                domains: vec!["b.com".into()],
                upstream: "http://y".into(),
                ..Default::default()
            },
        ];
        assert!(validate(&c).unwrap_err().contains("duplicate site name"));
    }

    #[test]
    fn validate_rejects_exclude_path_without_slash() {
        let mut c = default_config();
        c.sites = vec![SiteConfig {
            name: "a".into(),
            domains: vec!["a.com".into()],
            upstream: "http://x".into(),
            exclude_paths: vec!["admin".into()],
            ..Default::default()
        }];
        assert!(validate(&c).unwrap_err().contains("must start with"));
    }

    #[test]
    fn expand_env_refs_replaces_set_vars() {
        std::env::set_var("FWAF_TEST_SECRET", "s3cr3t");
        let out = expand_env_refs(b"secret: ${FWAF_TEST_SECRET}").unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "secret: s3cr3t");
    }

    #[test]
    fn expand_env_refs_leaves_unset() {
        let out = expand_env_refs(b"x: ${FWAF_DEFINITELY_UNSET_VAR_XYZ}").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "x: ${FWAF_DEFINITELY_UNSET_VAR_XYZ}"
        );
    }

    #[test]
    fn deep_merge_preserves_nonzero_defaults() {
        // Omit everything except sites. Non-zero defaults (prometheus.path,
        // db.driver, grpc.max_msg_size, ...) must survive the merge, matching
        // Go's unmarshal-into-populated-struct behaviour.
        let yaml = br#"
sites:
  - name: demo
    domains: ["localhost"]
    upstream: "http://127.0.0.1:8080"
"#;
        let cfg = merge_yaml_over_defaults(yaml).unwrap();
        assert_eq!(cfg.prometheus.path, "/metrics");
        assert_eq!(cfg.prometheus.port, 9090);
        assert_eq!(cfg.db.driver, "sqlite3");
        assert_eq!(cfg.grpc.max_msg_size, 4194304);
        assert_eq!(cfg.desync.max_body_size, 10485760);
        assert_eq!(cfg.sites.len(), 1);
        assert_eq!(cfg.sites[0].upstream, "http://127.0.0.1:8080");
    }

    #[test]
    fn deep_merge_user_overrides_default() {
        let yaml = br#"
sites:
  - name: demo
    domains: ["localhost"]
    upstream: "http://127.0.0.1:8080"
prometheus:
  port: 1234
"#;
        let cfg = merge_yaml_over_defaults(yaml).unwrap();
        assert_eq!(cfg.prometheus.port, 1234);
        // path still defaults
        assert_eq!(cfg.prometheus.path, "/metrics");
    }
}
