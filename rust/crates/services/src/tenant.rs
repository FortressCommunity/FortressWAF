//! Multi-tenant management.
//!
//! Port of `internal/tenant/tenant.go` (plus `isolation.go` and `mssp.go`).
//! Tenant CRUD, quotas, branding and status handling are preserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantSettings {
    pub timezone: String,
    pub language: String,
    pub date_format: String,
    pub log_retention_days: i32,
    pub max_log_age: i32,
    pub siem_export: bool,
    pub two_factor_auth: bool,
    pub session_timeout_mins: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Quotas {
    pub max_sites: i32,
    pub max_rules: i32,
    pub max_users: i32,
    pub max_api_keys: i32,
    pub max_api_calls_per_day: i64,
    pub max_storage_gb: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Branding {
    pub product_name: String,
    pub logo_url: String,
    pub favicon_url: String,
    pub primary_color: String,
    pub secondary_color: String,
    pub dashboard_domain: String,
    pub custom_email_from: String,
    pub support_email: String,
    pub support_url: String,
    pub hide_powered_by: bool,
    pub terms_url: String,
    pub privacy_url: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub org: String,
    pub status: String,
    pub tier: String,
    pub plan: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub settings: TenantSettings,
    pub quotas: Quotas,
    pub branding: Branding,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub parent_id: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

pub struct TenantManager {
    tenants: Arc<RwLock<HashMap<String, Tenant>>>,
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantManager {
    /// Port of `NewTenantManager`.
    pub fn new() -> Self {
        TenantManager {
            tenants: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Port of `Create`. Assigns an id/status/timestamps if missing.
    pub fn create(&self, mut t: Tenant) -> Result<(), String> {
        if t.id.is_empty() {
            t.id = format!("tenant-{}", now_nanos());
        }
        t.created_at = now_unix();
        t.updated_at = now_unix();
        t.status = "active".to_string();
        self.tenants.write().insert(t.id.clone(), t);
        Ok(())
    }

    /// Port of `Get`.
    pub fn get(&self, id: &str) -> Result<Tenant, String> {
        self.tenants
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| format!("tenant not found: {id}"))
    }

    /// Port of `List`.
    pub fn list(&self, parent_id: &str) -> Vec<Tenant> {
        self.tenants
            .read()
            .values()
            .filter(|t| {
                if parent_id.is_empty() {
                    t.parent_id.is_empty()
                } else {
                    t.parent_id == parent_id
                }
            })
            .cloned()
            .collect()
    }

    /// Port of `Update`.
    pub fn update(&self, mut t: Tenant) -> Result<(), String> {
        let mut tenants = self.tenants.write();
        if !tenants.contains_key(&t.id) {
            return Err(format!("tenant not found: {}", t.id));
        }
        t.updated_at = now_unix();
        tenants.insert(t.id.clone(), t);
        Ok(())
    }

    /// Port of `Delete`.
    pub fn delete(&self, id: &str) -> Result<(), String> {
        let mut tenants = self.tenants.write();
        if tenants.remove(id).is_none() {
            return Err(format!("tenant not found: {id}"));
        }
        Ok(())
    }

    /// Port of `Suspend`.
    pub fn suspend(&self, id: &str) -> Result<(), String> {
        let mut tenants = self.tenants.write();
        match tenants.get_mut(id) {
            Some(t) => {
                t.status = "suspended".to_string();
                t.updated_at = now_unix();
                Ok(())
            }
            None => Err(format!("tenant not found: {id}")),
        }
    }

    /// Port of `ValidateQuota`. A limit of -1 means unlimited.
    pub fn validate_quota(
        &self,
        tenant_id: &str,
        resource: &str,
        current: i32,
        _limit: i32,
    ) -> Result<(), String> {
        let tenants = self.tenants.read();
        let t = tenants.get(tenant_id).ok_or("tenant not found")?;
        match resource {
            "sites" => {
                if current >= t.quotas.max_sites && t.quotas.max_sites != -1 {
                    return Err(format!(
                        "site quota exceeded: {current}/{}",
                        t.quotas.max_sites
                    ));
                }
            }
            "rules" => {
                if current >= t.quotas.max_rules && t.quotas.max_rules != -1 {
                    return Err(format!(
                        "rule quota exceeded: {current}/{}",
                        t.quotas.max_rules
                    ));
                }
            }
            "users" => {
                if current >= t.quotas.max_users && t.quotas.max_users != -1 {
                    return Err(format!(
                        "user quota exceeded: {current}/{}",
                        t.quotas.max_users
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Port of `GetBranding`.
    pub fn get_branding(&self, tenant_id: &str) -> Option<Branding> {
        self.tenants
            .read()
            .get(tenant_id)
            .map(|t| t.branding.clone())
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get() {
        let tm = TenantManager::new();
        tm.create(Tenant {
            id: "t1".into(),
            name: "Acme".into(),
            ..Default::default()
        })
        .unwrap();
        let t = tm.get("t1").unwrap();
        assert_eq!(t.name, "Acme");
        assert_eq!(t.status, "active");
    }

    #[test]
    fn quota_enforced() {
        let tm = TenantManager::new();
        tm.create(Tenant {
            id: "t1".into(),
            quotas: Quotas {
                max_sites: 2,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        assert!(tm.validate_quota("t1", "sites", 1, 2).is_ok());
        assert!(tm.validate_quota("t1", "sites", 2, 2).is_err());
    }

    #[test]
    fn unlimited_quota() {
        let tm = TenantManager::new();
        tm.create(Tenant {
            id: "t1".into(),
            quotas: Quotas {
                max_sites: -1,
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
        assert!(tm.validate_quota("t1", "sites", 9999, -1).is_ok());
    }

    #[test]
    fn suspend_sets_status() {
        let tm = TenantManager::new();
        tm.create(Tenant {
            id: "t1".into(),
            ..Default::default()
        })
        .unwrap();
        tm.suspend("t1").unwrap();
        assert_eq!(tm.get("t1").unwrap().status, "suspended");
    }

    #[test]
    fn list_filters_by_parent() {
        let tm = TenantManager::new();
        tm.create(Tenant {
            id: "root".into(),
            ..Default::default()
        })
        .unwrap();
        tm.create(Tenant {
            id: "child".into(),
            parent_id: "root".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(tm.list("").len(), 1);
        assert_eq!(tm.list("root").len(), 1);
        assert_eq!(tm.list("root")[0].id, "child");
    }
}
