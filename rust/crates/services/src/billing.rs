//! Billing: tier features, signed licenses, Stripe webhooks, usage tracking.
//!
//! Port of `internal/billing` (features.go, license.go, stripe.go, usage.go).
//! Tier tables, license signing/verification, webhook handlers and usage
//! counters are preserved.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Features / tiers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Features {
    pub max_sites: i32,
    pub max_rules: i32,
    pub ml_engine: bool,
    pub multi_tenant: bool,
    pub fips_mode: bool,
    pub compliance_reports: bool,
    pub api_protection: bool,
    pub dlp: bool,
    pub bot_protection: bool,
    pub virtual_patching: bool,
    pub advanced_analytics: bool,
    pub priority_support: bool,
    pub sla_minutes: i32,
    pub max_tenants: i32,
    pub max_api_calls_per_day: i32,
}

/// Build the `TierFeatures` table.
pub fn tier_features() -> HashMap<String, Features> {
    let mut m = HashMap::new();
    m.insert(
        "community".to_string(),
        Features {
            max_sites: 1,
            max_rules: 100,
            ml_engine: false,
            multi_tenant: false,
            fips_mode: false,
            compliance_reports: false,
            api_protection: true,
            dlp: false,
            bot_protection: true,
            virtual_patching: true,
            advanced_analytics: false,
            priority_support: false,
            sla_minutes: 0,
            max_tenants: 0,
            max_api_calls_per_day: 10000,
        },
    );
    m.insert(
        "starter".to_string(),
        Features {
            max_sites: 5,
            max_rules: 500,
            ml_engine: false,
            multi_tenant: false,
            fips_mode: false,
            compliance_reports: false,
            api_protection: true,
            dlp: false,
            bot_protection: true,
            virtual_patching: true,
            advanced_analytics: false,
            priority_support: false,
            sla_minutes: 0,
            max_tenants: 0,
            max_api_calls_per_day: 50000,
        },
    );
    m.insert(
        "professional".to_string(),
        Features {
            max_sites: 25,
            max_rules: -1,
            ml_engine: true,
            multi_tenant: false,
            fips_mode: false,
            compliance_reports: true,
            api_protection: true,
            dlp: true,
            bot_protection: true,
            virtual_patching: true,
            advanced_analytics: true,
            priority_support: false,
            sla_minutes: 240,
            max_tenants: 0,
            max_api_calls_per_day: -1,
        },
    );
    m.insert(
        "enterprise".to_string(),
        Features {
            max_sites: -1,
            max_rules: -1,
            ml_engine: true,
            multi_tenant: true,
            fips_mode: true,
            compliance_reports: true,
            api_protection: true,
            dlp: true,
            bot_protection: true,
            virtual_patching: true,
            advanced_analytics: true,
            priority_support: true,
            sla_minutes: 60,
            max_tenants: -1,
            max_api_calls_per_day: -1,
        },
    );
    m
}

/// Port of `GetFeatures`.
pub fn get_features(tier: &str) -> Features {
    tier_features()
        .get(tier)
        .cloned()
        .unwrap_or_else(|| tier_features().get("community").cloned().unwrap())
}

/// Port of `CheckFeature`.
pub fn check_feature(tier: &str, feature_name: &str) -> bool {
    let f = get_features(tier);
    match feature_name {
        "ml_engine" => f.ml_engine,
        "multi_tenant" => f.multi_tenant,
        "fips_mode" => f.fips_mode,
        "compliance_reports" => f.compliance_reports,
        "api_protection" => f.api_protection,
        "dlp" => f.dlp,
        "bot_protection" => f.bot_protection,
        "virtual_patching" => f.virtual_patching,
        "advanced_analytics" => f.advanced_analytics,
        "priority_support" => f.priority_support,
        _ => false,
    }
}

/// Port of `ValidateSiteLimit`.
pub fn validate_site_limit(tier: &str, current_count: i32) -> Result<(), String> {
    let f = get_features(tier);
    if f.max_sites == -1 {
        return Ok(());
    }
    if current_count >= f.max_sites {
        return Err(format!(
            "site limit exceeded: {current_count}/{} (tier: {tier})",
            f.max_sites
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// License
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub tier: String,
    pub org: String,
    pub seats: i32,
    pub features: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub grace_until: String,
    pub version: String,
    pub license_id: String,
}

impl LicenseClaims {
    /// Port of `IsFeatureEnabled`.
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

pub struct License {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Default for License {
    fn default() -> Self {
        Self::new()
    }
}

impl License {
    /// Port of `NewLicense`: generate a fresh P-256 keypair.
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut rand_core_os());
        let verifying_key = *signing_key.verifying_key();
        License {
            signing_key,
            verifying_key,
        }
    }

    /// Build from an existing signing key (deterministic, for tests).
    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = *signing_key.verifying_key();
        License {
            signing_key,
            verifying_key,
        }
    }

    /// Port of `Generate`. Produces `FWL-<payload>.<sig>` with base64url-no-pad.
    pub fn generate(&self, claims: &LicenseClaims) -> Result<String, String> {
        let claims_json = serde_json::to_vec(claims).map_err(|e| e.to_string())?;
        let hash = Sha256::digest(&claims_json);
        // Go signed the SHA-256 hash directly (a prehash), so use sign_prehash.
        let signature: Signature = self
            .signing_key
            .sign_prehash(&hash)
            .map_err(|e| e.to_string())?;
        // Go used ASN.1 DER for the signature.
        let sig_der = signature.to_der().as_bytes().to_vec();

        let payload = b64url(&claims_json);
        let sig = b64url(&sig_der);
        Ok(format!("FWL-{payload}.{sig}"))
    }

    /// Port of `Validate`.
    pub fn validate(&self, token: &str) -> Result<LicenseClaims, String> {
        let claims = self.validate_with_key(token, &self.verifying_key)?;
        // Grace check.
        let now = now_unix() as f64;
        let grace = parse_rfc3339_to_unix(&claims.grace_until).unwrap_or(0.0);
        if now > grace {
            return Err("license expired".to_string());
        }
        Ok(claims)
    }

    /// Port of `ValidateWithPublicKey`.
    pub fn validate_with_key(
        &self,
        token: &str,
        pubkey: &VerifyingKey,
    ) -> Result<LicenseClaims, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err("invalid license format".to_string());
        }
        let payload = decode_b64url(parts[0])?;
        let sig_der = decode_b64url(parts[1])?;

        let hash = Sha256::digest(&payload);
        let signature = Signature::from_der(&sig_der).map_err(|e| e.to_string())?;
        pubkey
            .verify_prehash(&hash, &signature)
            .map_err(|_| "invalid signature".to_string())?;

        let claims: LicenseClaims = serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
        Ok(claims)
    }

    /// Port of `ValidateWithoutSignature` (used by the ID/expiry/tier helpers).
    pub fn validate_without_signature(&self, token: &str) -> Result<LicenseClaims, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            return Err("invalid license format".to_string());
        }
        let payload = decode_b64url(parts[0])?;
        serde_json::from_slice(&payload).map_err(|e| e.to_string())
    }

    /// Expose the verifying key (for the console/CLI).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

/// Port of `GenerateTrialLicense`. Returns (token, license_id).
pub fn generate_trial_license() -> Result<(String, String, License), String> {
    let l = License::new();
    let now = now_unix() as f64;
    let expires = now + 30.0 * 24.0 * 3600.0;
    let grace = expires + 7.0 * 24.0 * 3600.0;

    let claims = LicenseClaims {
        tier: "professional".to_string(),
        org: "Trial".to_string(),
        seats: 1,
        features: vec![
            "ml_engine".to_string(),
            "api_protection".to_string(),
            "dlp".to_string(),
            "compliance_reports".to_string(),
            "advanced_analytics".to_string(),
        ],
        issued_at: unix_to_rfc3339(now),
        expires_at: unix_to_rfc3339(expires),
        grace_until: unix_to_rfc3339(grace),
        version: "1.0.0".to_string(),
        license_id: format!("TRIAL-{}", now_nanos()),
    };
    let token = l.generate(&claims)?;
    Ok((token, claims.license_id.clone(), l))
}

/// Port of `ParseLicenseID`.
pub fn parse_license_id(token: &str) -> Result<String, String> {
    Ok(License::new().validate_without_signature(token)?.license_id)
}

/// Port of `GetLicenseExpiry` (returns the RFC3339 string).
pub fn get_license_expiry(token: &str) -> Result<String, String> {
    Ok(License::new().validate_without_signature(token)?.expires_at)
}

/// Port of `GetLicenseTier`.
pub fn get_license_tier(token: &str) -> Result<String, String> {
    Ok(License::new().validate_without_signature(token)?.tier)
}

// ---------------------------------------------------------------------------
// Stripe webhook handling
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub org: String,
    pub stripe_customer_id: String,
    pub stripe_sub_id: String,
    pub tier: String,
    pub status: String,
    pub current_period_end: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseRecord {
    pub id: String,
    pub org: String,
    pub token: String,
    pub tier: String,
    pub status: String,
    pub stripe_sub_id: String,
    pub expires_at: String,
    pub grace_until: String,
    pub created_at: String,
}

pub const EVENT_SUBSCRIPTION_CREATED: &str = "customer.subscription.created";
pub const EVENT_SUBSCRIPTION_UPDATED: &str = "customer.subscription.updated";
pub const EVENT_SUBSCRIPTION_DELETED: &str = "customer.subscription.deleted";
pub const EVENT_INVOICE_PAYMENT_FAILED: &str = "invoice.payment_failed";
pub const EVENT_INVOICE_PAID: &str = "invoice.paid";

/// The persistence surface the webhook handler needs. Port of `BillingDB`.
pub trait BillingDb: Send + Sync {
    fn create_subscription(&self, sub: Subscription) -> Result<(), String>;
    fn get_subscription(&self, stripe_sub_id: &str) -> Result<Option<Subscription>, String>;
    fn update_subscription(&self, sub: Subscription) -> Result<(), String>;
    fn create_license(&self, lic: LicenseRecord) -> Result<(), String>;
    fn get_license_by_org(&self, org: &str) -> Result<Option<LicenseRecord>, String>;
    fn update_license(&self, lic: LicenseRecord) -> Result<(), String>;
}

/// Port of `Emailer`.
pub trait Emailer: Send + Sync {
    fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), String>;
}

pub struct StripeWebhookHandler {
    webhook_secret: String,
    license: Arc<License>,
    db: Arc<dyn BillingDb>,
    emailer: Arc<dyn Emailer>,
}

impl StripeWebhookHandler {
    /// Port of `NewStripeWebhookHandler`.
    pub fn new(
        webhook_secret: &str,
        license: Arc<License>,
        db: Arc<dyn BillingDb>,
        emailer: Arc<dyn Emailer>,
    ) -> Self {
        StripeWebhookHandler {
            webhook_secret: webhook_secret.to_string(),
            license,
            db,
            emailer,
        }
    }

    /// Port of `HandleWebhook`. Returns an HTTP status code.
    pub fn handle_webhook(&self, body: &[u8], stripe_signature: &str) -> i32 {
        let _ = self.verify_webhook_signature(body, stripe_signature);

        let event: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return 400,
        };

        let event_type = match event.get("type").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => return 400,
        };
        let data = match event.get("data") {
            Some(d) => d,
            None => return 400,
        };

        match event_type.as_str() {
            EVENT_SUBSCRIPTION_CREATED => self.handle_subscription_created(data),
            EVENT_SUBSCRIPTION_UPDATED => self.handle_subscription_updated(data),
            EVENT_SUBSCRIPTION_DELETED => self.handle_subscription_deleted(data),
            EVENT_INVOICE_PAYMENT_FAILED => self.handle_payment_failed(data),
            EVENT_INVOICE_PAID => self.handle_invoice_paid(data),
            other => tracing::info!(r#type = other, "unhandled stripe event"),
        }

        200
    }

    fn verify_webhook_signature(&self, _body: &[u8], _sig: &str) -> Result<(), String> {
        if self.webhook_secret.is_empty() {
            return Ok(());
        }
        // Go's implementation was a no-op beyond the empty-secret guard.
        Ok(())
    }

    fn handle_subscription_created(&self, data: &serde_json::Value) {
        let obj = match data.get("object") {
            Some(o) => o,
            None => return,
        };
        let now = unix_to_rfc3339(now_unix() as f64);
        let mut sub = Subscription {
            stripe_sub_id: get_str(obj, "id"),
            stripe_customer_id: get_str(obj, "customer"),
            status: get_str(obj, "status"),
            current_period_end: unix_to_rfc3339(get_int(obj, "current_period_end") as f64),
            created_at: now.clone(),
            updated_at: now,
            ..Default::default()
        };
        if let Some(metadata) = obj.get("metadata") {
            sub.org = get_str(metadata, "org");
            sub.tier = get_str(metadata, "tier");
        }

        let issued = now_unix() as f64;
        let expires = get_int(obj, "current_period_end") as f64;
        let grace = expires + 7.0 * 24.0 * 3600.0;

        let claims = LicenseClaims {
            tier: sub.tier.clone(),
            org: sub.org.clone(),
            seats: 5,
            features: vec![],
            issued_at: unix_to_rfc3339(issued),
            expires_at: unix_to_rfc3339(expires),
            grace_until: unix_to_rfc3339(grace),
            version: "1.0.0".to_string(),
            license_id: format!("FWL-{}", now_nanos()),
        };
        let token = self.license.generate(&claims).unwrap_or_default();

        let lic_record = LicenseRecord {
            org: sub.org.clone(),
            token: token.clone(),
            tier: sub.tier.clone(),
            status: "active".to_string(),
            stripe_sub_id: sub.stripe_sub_id.clone(),
            expires_at: unix_to_rfc3339(expires),
            grace_until: unix_to_rfc3339(grace),
            created_at: unix_to_rfc3339(now_unix() as f64),
            ..Default::default()
        };

        let _ = self.db.create_subscription(sub.clone());
        let _ = self.db.create_license(lic_record);
        let _ = self.emailer.send_email(
            &sub.org,
            "Your FortressWAF License",
            &format!("Your license key: {token}"),
        );
    }

    fn handle_subscription_updated(&self, data: &serde_json::Value) {
        let obj = data.get("object");
        let sub_id = obj.map(|o| get_str(o, "id")).unwrap_or_default();
        let mut sub = match self.db.get_subscription(&sub_id) {
            Ok(Some(s)) => s,
            _ => return,
        };
        sub.status = obj.map(|o| get_str(o, "status")).unwrap_or_default();
        sub.current_period_end = obj
            .map(|o| unix_to_rfc3339(get_int(o, "current_period_end") as f64))
            .unwrap_or_default();
        sub.updated_at = unix_to_rfc3339(now_unix() as f64);
        let _ = self.db.update_subscription(sub);
    }

    fn handle_subscription_deleted(&self, data: &serde_json::Value) {
        let obj = data.get("object");
        let sub_id = obj.map(|o| get_str(o, "id")).unwrap_or_default();
        let mut sub = match self.db.get_subscription(&sub_id) {
            Ok(Some(s)) => s,
            _ => return,
        };
        sub.status = "canceled".to_string();
        sub.updated_at = unix_to_rfc3339(now_unix() as f64);
        let _ = self.db.update_subscription(sub.clone());

        if let Ok(Some(mut lic)) = self.db.get_license_by_org(&sub.org) {
            lic.status = "expired".to_string();
            let _ = self.db.update_license(lic);
        }
    }

    fn handle_payment_failed(&self, data: &serde_json::Value) {
        let obj = data.get("object");
        let sub_id = obj.map(|o| get_str(o, "subscription")).unwrap_or_default();
        let sub = match self.db.get_subscription(&sub_id) {
            Ok(Some(s)) => s,
            _ => return,
        };
        let _ = self.emailer.send_email(
            &sub.org,
            "Payment Failed - Action Required",
            "Your payment failed. Please update your payment method within 7 days to avoid service interruption.",
        );
    }

    fn handle_invoice_paid(&self, data: &serde_json::Value) {
        let obj = data.get("object");
        let sub_id = obj.map(|o| get_str(o, "subscription")).unwrap_or_default();
        let mut sub = match self.db.get_subscription(&sub_id) {
            Ok(Some(s)) => s,
            _ => return,
        };
        if sub.status == "past_due" {
            sub.status = "active".to_string();
            sub.updated_at = unix_to_rfc3339(now_unix() as f64);
            let _ = self.db.update_subscription(sub.clone());
            if let Ok(Some(mut lic)) = self.db.get_license_by_org(&sub.org) {
                lic.status = "active".to_string();
                let _ = self.db.update_license(lic);
            }
        }
    }

    /// Port of `CreateCheckoutSession`.
    pub fn create_checkout_session(
        &self,
        _org: &str,
        _tier: &str,
        _success_url: &str,
        _cancel_url: &str,
    ) -> Result<CheckoutSession, String> {
        let nanos = now_nanos();
        Ok(CheckoutSession {
            url: format!("https://checkout.stripe.com/pay/{nanos}"),
            session_id: format!("cs_{nanos}"),
        })
    }

    /// Port of `CreateBillingPortalSession`.
    pub fn create_billing_portal_session(
        &self,
        _customer_id: &str,
        _return_url: &str,
    ) -> Result<String, String> {
        Ok(format!(
            "https://billing.stripe.com/p/session/{}",
            now_nanos()
        ))
    }

    /// Port of `CancelSubscription`.
    pub fn cancel_subscription(&self, sub_id: &str) -> Result<(), String> {
        let mut sub = self
            .db
            .get_subscription(sub_id)?
            .ok_or_else(|| "subscription not found".to_string())?;
        sub.status = "canceled".to_string();
        sub.updated_at = unix_to_rfc3339(now_unix() as f64);
        self.db.update_subscription(sub)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    pub url: String,
    pub session_id: String,
}

/// Port of `ParseStripeWebhook`.
pub fn parse_stripe_webhook(body: &[u8], _secret: &str) -> Result<serde_json::Value, String> {
    serde_json::from_slice(body).map_err(|e| e.to_string())
}

/// Port of `GetStripeEventType`.
pub fn get_stripe_event_type(event: &serde_json::Value) -> String {
    event
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Port of `GetStripeSubscriptionID`.
pub fn get_stripe_subscription_id(event: &serde_json::Value) -> String {
    event
        .get("data")
        .and_then(|d| d.get("object"))
        .and_then(|o| o.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// Port of `BuildUsageReport`.
pub fn build_usage_report(records: &[UsageRecord]) -> String {
    let mut s = String::from("Usage Report\n============\n\n");
    for r in records {
        s.push_str(&format!("Tenant: {}\n", r.tenant_id));
        s.push_str(&format!("Date: {}\n", &r.date[..10.min(r.date.len())]));
        s.push_str(&format!("Requests: {}\n", r.request_count));
        s.push_str(&format!("Blocked: {}\n\n", r.blocked_count));
    }
    s
}

/// Port of `FormatAmount`.
pub fn format_amount(cents: i64) -> String {
    format!("${:.2}", cents as f64 / 100.0)
}

/// Port of `ParseAmount` (uses Sscanf-style leading float parse).
pub fn parse_amount(amount_str: &str) -> Result<i64, String> {
    let amount = parse_leading_float(amount_str).ok_or_else(|| "invalid amount".to_string())?;
    Ok((amount * 100.0) as i64)
}

/// Port of `IsSubscriptionActive`.
pub fn is_subscription_active(sub: Option<&Subscription>) -> bool {
    matches!(sub, Some(s) if s.status == "active" || s.status == "trialing")
}

/// Port of `IsLicenseActive`.
pub fn is_license_active(lic: Option<&LicenseRecord>) -> bool {
    match lic {
        Some(l) if l.status == "active" => {
            let grace = parse_rfc3339_to_unix(&l.grace_until).unwrap_or(0.0);
            (now_unix() as f64) < grace
        }
        _ => false,
    }
}

/// Port of `GetTierDisplayName`.
pub fn get_tier_display_name(tier: &str) -> String {
    match tier {
        "community" => "Community".to_string(),
        "starter" => "Starter".to_string(),
        "professional" => "Professional".to_string(),
        "enterprise" => "Enterprise".to_string(),
        other => other.to_string(),
    }
}

/// Port of `GetTierPrice`.
pub fn get_tier_price(tier: &str) -> i64 {
    match tier {
        "starter" => 4999,
        "professional" => 14999,
        "enterprise" => 49999,
        _ => 0,
    }
}

/// Port of `GetTierPriceMonthly`.
pub fn get_tier_price_monthly(tier: &str) -> i64 {
    match tier {
        "starter" => 4900,
        "professional" => 14900,
        "enterprise" => 49900,
        _ => 0,
    }
}

/// Port of `BuildFeatureList`.
pub fn build_feature_list(features: &[String]) -> String {
    features.join(", ")
}

/// Port of `ValidateWebhookTimestamp`.
pub fn validate_webhook_timestamp(timestamp: &str) -> Result<(), String> {
    let ts: i64 = timestamp
        .parse()
        .map_err(|e| format!("invalid timestamp: {e}"))?;
    if now_unix() - ts > 300 {
        return Err("webhook timestamp too old".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Usage tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantUsage {
    pub requests_today: i64,
    pub requests_this_month: i64,
    pub blocks_today: i64,
    #[serde(skip, default = "Instant::now")]
    last_reset: Instant,
    #[serde(skip, default = "Instant::now")]
    month_start: Instant,
}

impl Default for TenantUsage {
    fn default() -> Self {
        TenantUsage {
            requests_today: 0,
            requests_this_month: 0,
            blocks_today: 0,
            last_reset: Instant::now(),
            month_start: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageRecord {
    pub tenant_id: String,
    pub date: String,
    pub request_count: i64,
    pub blocked_count: i64,
}

pub struct UsageTracker {
    counters: RwLock<HashMap<String, TenantUsage>>,
    limits: RwLock<HashMap<String, i64>>,
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl UsageTracker {
    /// Port of `NewUsageTracker`.
    pub fn new() -> Self {
        UsageTracker {
            counters: RwLock::new(HashMap::new()),
            limits: RwLock::new(HashMap::new()),
        }
    }

    /// Port of `SetLimit`.
    pub fn set_limit(&self, tenant_id: &str, limit: i64) {
        self.limits.write().insert(tenant_id.to_string(), limit);
    }

    /// Port of `RecordRequest`.
    pub fn record_request(&self, tenant_id: &str, blocked: bool) {
        let now = Instant::now();
        let mut counters = self.counters.write();
        let usage = counters.entry(tenant_id.to_string()).or_default();

        if now.duration_since(usage.last_reset) > Duration::from_secs(24 * 3600) {
            usage.requests_today = 0;
            usage.blocks_today = 0;
            usage.last_reset = now;
        }
        if now.duration_since(usage.month_start) > Duration::from_secs(30 * 24 * 3600) {
            usage.requests_this_month = 0;
            usage.month_start = now;
        }
        usage.requests_today += 1;
        usage.requests_this_month += 1;
        if blocked {
            usage.blocks_today += 1;
        }
    }

    /// Port of `GetUsage`: (today, this_month, limit, blocked_today).
    pub fn get_usage(&self, tenant_id: &str) -> (i64, i64, i64, i64) {
        let counters = self.counters.read();
        let (today, this_month, blocked_today) = match counters.get(tenant_id) {
            Some(u) => (u.requests_today, u.requests_this_month, u.blocks_today),
            None => (0, 0, 0),
        };
        let limit = self.limits.read().get(tenant_id).copied().unwrap_or(0);
        (today, this_month, limit, blocked_today)
    }

    /// Port of `CheckLimit`.
    pub fn check_limit(&self, tenant_id: &str) -> Result<(), String> {
        let limit = self.limits.read().get(tenant_id).copied().unwrap_or(0);
        if limit <= 0 {
            return Ok(());
        }
        if let Some(usage) = self.counters.read().get(tenant_id) {
            if usage.requests_today >= limit {
                return Err(format!(
                    "daily request limit exceeded: {}/{}",
                    usage.requests_today, limit
                ));
            }
        }
        Ok(())
    }

    /// Port of `ResetDaily`.
    pub fn reset_daily(&self, tenant_id: &str) {
        if let Some(u) = self.counters.write().get_mut(tenant_id) {
            u.requests_today = 0;
            u.blocks_today = 0;
            u.last_reset = Instant::now();
        }
    }

    /// Port of `ResetMonthly`.
    pub fn reset_monthly(&self, tenant_id: &str) {
        if let Some(u) = self.counters.write().get_mut(tenant_id) {
            u.requests_this_month = 0;
            u.month_start = Instant::now();
        }
    }

    /// Port of `GetAllUsage`.
    pub fn get_all_usage(&self) -> HashMap<String, TenantUsage> {
        self.counters.read().clone()
    }

    /// Port of `RemoveTenant`.
    pub fn remove_tenant(&self, tenant_id: &str) {
        self.counters.write().remove(tenant_id);
        self.limits.write().remove(tenant_id);
    }

    /// Port of `Snapshot`.
    pub fn snapshot(&self, tenant_id: &str) -> UsageSnapshot {
        let (today, this_month, limit, blocked) = self.get_usage(tenant_id);
        UsageSnapshot {
            tenant_id: tenant_id.to_string(),
            requests_today: today,
            requests_this_month: this_month,
            blocks_today: blocked,
            limit,
            captured_at: unix_to_rfc3339(now_unix() as f64),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageSnapshot {
    pub tenant_id: String,
    pub requests_today: i64,
    pub requests_this_month: i64,
    pub blocks_today: i64,
    pub limit: i64,
    pub captured_at: String,
}

impl UsageSnapshot {
    /// Port of `UsagePercent`.
    pub fn usage_percent(&self) -> f64 {
        if self.limit <= 0 {
            return 0.0;
        }
        self.requests_today as f64 / self.limit as f64 * 100.0
    }

    /// Port of `RemainingRequests`.
    pub fn remaining_requests(&self) -> i64 {
        if self.limit <= 0 {
            return -1;
        }
        (self.limit - self.requests_today).max(0)
    }

    /// Port of `IsOverLimit`.
    pub fn is_over_limit(&self) -> bool {
        self.limit > 0 && self.requests_today >= self.limit
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn decode_b64url(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| e.to_string())
}

fn get_str(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn get_int(v: &serde_json::Value, key: &str) -> i64 {
    v.get(key)
        .and_then(|x| x.as_f64())
        .map(|f| f as i64)
        .unwrap_or(0)
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

fn unix_to_rfc3339(secs: f64) -> String {
    let secs = secs.max(0.0) as u64;
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn parse_rfc3339_to_unix(s: &str) -> Option<f64> {
    // Parse "YYYY-MM-DDTHH:MM:SS[.fff]Z".
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    let time = time.split('.').next().unwrap_or(time);
    let mut tp = time.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let sec: i64 = tp.next()?.parse().ok()?;
    let days = days_from_civil(y, mo, d);
    Some((days as f64) * 86400.0 + (h * 3600 + mi * 60 + sec) as f64)
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

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + (d as u64 - 1);
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Parse a leading float, matching `fmt.Sscanf("%f")` (leading numeric prefix).
fn parse_leading_float(s: &str) -> Option<f64> {
    let s = s.trim();
    let end = s
        .char_indices()
        .find(|(i, c)| {
            !(*i == 0 && (*c == '+' || *c == '-'))
                && !c.is_ascii_digit()
                && *c != '.'
                && *c != 'e'
                && *c != 'E'
                && *c != '+'
                && *c != '-'
        })
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    s[..end].parse::<f64>().ok()
}

/// A freshly-seeded OS RNG for key generation. Uses `getrandom` behind a
/// `CryptoRng`-compatible adapter.
fn rand_core_os() -> impl p256::elliptic_curve::rand_core::CryptoRngCore {
    struct OsRng;
    impl p256::elliptic_curve::rand_core::RngCore for OsRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            let _ = getrandom::getrandom(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            let _ = getrandom::getrandom(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let _ = getrandom::getrandom(dest);
        }
        fn try_fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
            getrandom::getrandom(dest).map_err(|e| p256::elliptic_curve::rand_core::Error::from(e))
        }
    }
    impl p256::elliptic_curve::rand_core::CryptoRng for OsRng {}
    OsRng
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dbg_prehash() {
        let sk = SigningKey::random(&mut rand_core_os());
        let vk = *sk.verifying_key();
        let hash = Sha256::digest(b"hello");
        let sig: Signature = sk.sign_prehash(&hash).unwrap();
        assert!(vk.verify_prehash(&hash, &sig).is_ok(), "direct verify");
        let der = sig.to_der();
        let sig2 = Signature::from_der(der.as_bytes()).unwrap();
        assert!(vk.verify_prehash(&hash, &sig2).is_ok(), "roundtrip verify");
    }

    #[test]
    fn generate_prepends_prefix_and_validate_matches_go_quirk() {
        // FAITHFUL GO QUIRK: Go's Generate() emits "FWL-<payload>.<sig>", but
        // Validate() decodes parts[0] which is the WHOLE "FWL-<payload>" string
        // (the "FWL-" chars happen to be valid base64url). It therefore hashes
        // different bytes than Generate() signed, so a token round-trip through
        // Generate -> Validate fails signature verification in Go too. This is
        // reproduced exactly rather than "fixed".
        let l = License::new();
        let now = now_unix() as f64;
        let claims = LicenseClaims {
            tier: "professional".to_string(),
            org: "Acme".to_string(),
            seats: 5,
            features: vec!["ml_engine".to_string()],
            issued_at: unix_to_rfc3339(now),
            expires_at: unix_to_rfc3339(now + 30.0 * 24.0 * 3600.0),
            grace_until: unix_to_rfc3339(now + 37.0 * 24.0 * 3600.0),
            version: "1.0.0".to_string(),
            license_id: "FWL-TEST".to_string(),
        };
        let token = l.generate(&claims).unwrap();
        assert!(token.starts_with("FWL-"));
        // Validate on the generated token fails signature verification, exactly
        // as it would in Go.
        assert!(l.validate(&token).is_err());
    }

    #[test]
    fn validate_accepts_self_consistent_token() {
        // A token whose parts[0] really is the signed payload validates.
        let l = License::new();
        let now = now_unix() as f64;
        let claims = LicenseClaims {
            tier: "professional".to_string(),
            org: "Acme".to_string(),
            expires_at: unix_to_rfc3339(now + 100.0),
            grace_until: unix_to_rfc3339(now + 200.0),
            license_id: "FWL-OK".to_string(),
            ..Default::default()
        };
        let payload = serde_json::to_vec(&claims).unwrap();
        let hash = Sha256::digest(&payload);
        let sig: Signature = l.signing_key.sign_prehash(&hash).unwrap();
        let token = format!("{}.{}", b64url(&payload), b64url(sig.to_der().as_bytes()));
        let got = l.validate(&token).unwrap();
        assert_eq!(got.org, "Acme");
        assert_eq!(got.license_id, "FWL-OK");
    }

    #[test]
    fn license_bad_signature_rejected() {
        let l = License::new();
        let token = format!("{}.{}", b64url(b"{}"), b64url(b"notasig"));
        assert!(l.validate(&token).is_err());
    }

    #[test]
    fn license_helpers_parse_without_signature() {
        // validate_without_signature decodes parts[0], so a self-consistent
        // token's payload parses without needing a valid signature.
        let now = now_unix() as f64;
        let claims = LicenseClaims {
            tier: "enterprise".to_string(),
            org: "Corp".to_string(),
            expires_at: unix_to_rfc3339(now + 100.0),
            grace_until: unix_to_rfc3339(now + 200.0),
            license_id: "FWL-XYZ".to_string(),
            ..Default::default()
        };
        let payload = serde_json::to_vec(&claims).unwrap();
        let token = format!("{}.{}", b64url(&payload), b64url(b"sig"));
        assert_eq!(get_license_tier(&token).unwrap(), "enterprise");
        assert_eq!(parse_license_id(&token).unwrap(), "FWL-XYZ");
    }

    #[test]
    fn tier_features_community_and_enterprise() {
        assert!(!check_feature("community", "ml_engine"));
        assert!(check_feature("community", "api_protection"));
        assert!(check_feature("enterprise", "multi_tenant"));
        assert!(check_feature("enterprise", "fips_mode"));
    }

    #[test]
    fn validate_site_limit_enterprise_unlimited() {
        assert!(validate_site_limit("enterprise", 1_000_000).is_ok());
        assert!(validate_site_limit("community", 1).is_err());
    }

    #[test]
    fn usage_tracker_records_and_limits() {
        let u = UsageTracker::new();
        u.set_limit("t1", 2);
        u.record_request("t1", true);
        u.record_request("t1", false);
        let (today, month, limit, blocked) = u.get_usage("t1");
        assert_eq!(today, 2);
        assert_eq!(month, 2);
        assert_eq!(limit, 2);
        assert_eq!(blocked, 1);
        assert!(u.check_limit("t1").is_err());
    }

    #[test]
    fn usage_snapshot_helpers() {
        let u = UsageTracker::new();
        u.set_limit("t1", 10);
        u.record_request("t1", false);
        let snap = u.snapshot("t1");
        assert_eq!(snap.remaining_requests(), 9);
        assert!((snap.usage_percent() - 10.0).abs() < 1e-9);
        assert!(!snap.is_over_limit());
    }

    #[test]
    fn amount_format_and_parse() {
        assert_eq!(format_amount(4999), "$49.99");
        assert_eq!(parse_amount("49.99").unwrap(), 4999);
    }

    struct MemDb {
        subs: RwLock<HashMap<String, Subscription>>,
        lics: RwLock<HashMap<String, LicenseRecord>>,
    }
    impl MemDb {
        fn new() -> Self {
            MemDb {
                subs: RwLock::new(HashMap::new()),
                lics: RwLock::new(HashMap::new()),
            }
        }
    }
    impl BillingDb for MemDb {
        fn create_subscription(&self, sub: Subscription) -> Result<(), String> {
            self.subs.write().insert(sub.stripe_sub_id.clone(), sub);
            Ok(())
        }
        fn get_subscription(&self, id: &str) -> Result<Option<Subscription>, String> {
            Ok(self.subs.read().get(id).cloned())
        }
        fn update_subscription(&self, sub: Subscription) -> Result<(), String> {
            self.subs.write().insert(sub.stripe_sub_id.clone(), sub);
            Ok(())
        }
        fn create_license(&self, lic: LicenseRecord) -> Result<(), String> {
            self.lics.write().insert(lic.org.clone(), lic);
            Ok(())
        }
        fn get_license_by_org(&self, org: &str) -> Result<Option<LicenseRecord>, String> {
            Ok(self.lics.read().get(org).cloned())
        }
        fn update_license(&self, lic: LicenseRecord) -> Result<(), String> {
            self.lics.write().insert(lic.org.clone(), lic);
            Ok(())
        }
    }

    struct NoopEmailer;
    impl Emailer for NoopEmailer {
        fn send_email(&self, _to: &str, _subject: &str, _body: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn webhook_subscription_created_issues_license() {
        let db = Arc::new(MemDb::new());
        let license = Arc::new(License::new());
        let h = StripeWebhookHandler::new("", license, db.clone(), Arc::new(NoopEmailer));
        let event = r#"{"type":"customer.subscription.created","data":{"object":{"id":"sub_1","customer":"cus_1","status":"active","current_period_end":2000000000,"metadata":{"org":"Acme","tier":"professional"}}}}"#;
        let code = h.handle_webhook(event.as_bytes(), "");
        assert_eq!(code, 200);
        let sub = db.get_subscription("sub_1").unwrap().unwrap();
        assert_eq!(sub.org, "Acme");
        assert_eq!(sub.tier, "professional");
        let lic = db.get_license_by_org("Acme").unwrap().unwrap();
        assert_eq!(lic.status, "active");
        // The issued token follows the Go "FWL-<payload>.<sig>" shape.
        assert!(lic.token.starts_with("FWL-"));
    }

    #[test]
    fn webhook_invalid_json_returns_400() {
        let h = StripeWebhookHandler::new(
            "",
            Arc::new(License::new()),
            Arc::new(MemDb::new()),
            Arc::new(NoopEmailer),
        );
        assert_eq!(h.handle_webhook(b"not json", ""), 400);
    }

    #[test]
    fn webhook_timestamp_validation() {
        let now = now_unix();
        assert!(validate_webhook_timestamp(&now.to_string()).is_ok());
        assert!(validate_webhook_timestamp(&(now - 1000).to_string()).is_err());
        assert!(validate_webhook_timestamp("notanumber").is_err());
    }
}
