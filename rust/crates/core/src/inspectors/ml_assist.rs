//! ML-assist inspector.
//!
//! Closes README Known Limitation #1 for the enforcement path: it puts the
//! Python ML sidecar in the request path as an *advisory* inspector. It is opt-in
//! (`ml.enabled: true`), and it is deliberately conservative:
//!
//! - **It never blocks on its own by default.** A positive classification is
//!   returned as [`Action::Monitor`] (scored and logged, forwarded). Set
//!   `ml.block: true` to let a high-confidence hit block, and then only above
//!   `ml.min_score`.
//! - **A failure is a pass.** If the sidecar is unreachable, times out, or
//!   returns junk, the inspector returns `Ok(None)` and records nothing. An ML
//!   outage must never turn into a denial of service, and the README already
//!   documents that the bundled model is untrained.
//! - **One HTTP call per request at most, bounded by a timeout.** The client is
//!   shared (constructed once in the factory), not built per request.
//!
//! The classifier is behind [`MlClassifier`] so the inspector is unit-testable
//! without a live sidecar, and [`HttpMlClassifier`] is the real `ureq`
//! implementation used in production.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

/// A classifier answers whether a request looks anomalous, and with what
/// confidence. Implementations must be cheap to call and must not panic.
pub trait MlClassifier: Send + Sync {
    fn classify(&self, req: &ClassificationRequest) -> Result<Classification, String>;
}

/// The request shape the sidecar's `/v1/classify` endpoint expects. Mirrors the
/// fields `ml-engine/api/schemas.py` reads.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClassificationRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub query_params: HashMap<String, String>,
    #[serde(default)]
    pub source_ip: String,
    #[serde(default)]
    pub user_agent: String,
}

/// The sidecar's classification answer.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Classification {
    #[serde(default)]
    pub attack_type: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub model_version: String,
}

/// Real classifier over an HTTP endpoint (the Python sidecar).
pub struct HttpMlClassifier {
    endpoint: String,
    timeout: Duration,
}

impl HttpMlClassifier {
    pub fn new(endpoint: &str, timeout_sec: i32) -> Self {
        HttpMlClassifier {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(timeout_sec.max(1) as u64),
        }
    }
}

impl MlClassifier for HttpMlClassifier {
    fn classify(&self, req: &ClassificationRequest) -> Result<Classification, String> {
        let url = format!("{}/v1/classify", self.endpoint);
        let body = serde_json::to_string(req).map_err(|e| e.to_string())?;
        let resp = ureq::post(&url)
            .timeout(self.timeout)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| e.to_string())?;
        let text = resp.into_string().map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| format!("decode classify response: {e}"))
    }
}

/// Options for [`MlInspector`].
#[derive(Debug, Clone)]
pub struct MlOptions {
    /// Allow a high-confidence classification to block. Default false: an ML hit
    /// is reported as [`Action::Monitor`].
    pub block: bool,
    /// Minimum confidence required to act on a classification.
    pub min_score: f64,
}

impl Default for MlOptions {
    fn default() -> Self {
        MlOptions {
            block: false,
            min_score: 0.5,
        }
    }
}

/// The ML-assist inspector.
pub struct MlInspector {
    pub dev_mode: bool,
    opts: MlOptions,
    classifier: Arc<dyn MlClassifier>,
}

impl MlInspector {
    pub fn new(dev_mode: bool, opts: MlOptions, classifier: Arc<dyn MlClassifier>) -> Self {
        MlInspector {
            dev_mode,
            opts,
            classifier,
        }
    }

    fn build_request(&self, ctx: &RequestContext) -> ClassificationRequest {
        let mut headers: HashMap<String, String> = HashMap::new();
        for (k, v) in &ctx.headers {
            headers.insert(k.clone(), v.clone());
        }
        let query_params: HashMap<String, String> = ctx
            .query_params
            .iter()
            .map(|(k, v)| (k.clone(), v.join(",")))
            .collect();
        ClassificationRequest {
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            headers,
            body: String::from_utf8_lossy(&ctx.body[..ctx.body.len().min(1 << 20)]).into_owned(),
            query_params,
            source_ip: ctx.real_ip.clone(),
            user_agent: ctx.user_agent.clone(),
        }
    }
}

impl Inspector for MlInspector {
    fn name(&self) -> &str {
        "ml_assist"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        let req = self.build_request(ctx);
        let result = match self.classifier.classify(&req) {
            Ok(c) => c,
            Err(e) => {
                // A failure is a pass. Never blocks, never errors the pipeline.
                if self.dev_mode {
                    tracing::debug!(error = e.as_str(), "ml classify failed; allowing");
                }
                return Ok(None);
            }
        };

        if result.confidence < self.opts.min_score || result.attack_type.is_empty() {
            return Ok(None);
        }

        // The score is the confidence scaled into the engine's 0-100 threat
        // scale, so it composes with the cumulative threshold like any other
        // inspector -- but only in block mode. In monitor mode a high
        // confidence (0.97 -> 97) must not tip the cumulative threshold into a
        // block, or "monitor" would enforce.
        let (action, score) = if self.opts.block {
            (Action::Block, (result.confidence * 100.0).min(100.0))
        } else {
            (Action::Monitor, 15.0)
        };
        Ok(Some(
            Decision::new(action, score)
                .with_rule_id("ML001")
                .with_rule_name("ML-Assisted Classification")
                .with_severity("medium")
                .with_evidence(format!(
                    "ml classified this request as {} ({:.0}% confidence)",
                    result.attack_type,
                    result.confidence * 100.0
                )),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpRequest;

    struct FixedClassifier {
        out: Result<Classification, String>,
    }
    impl MlClassifier for FixedClassifier {
        fn classify(&self, _req: &ClassificationRequest) -> Result<Classification, String> {
            self.out.clone()
        }
    }

    fn ctx() -> RequestContext {
        RequestContext::new(HttpRequest::new("GET", "/search"))
    }

    fn inspect(out: Result<Classification, String>, opts: MlOptions) -> Option<Decision> {
        let insp = MlInspector::new(false, opts, Arc::new(FixedClassifier { out }));
        let mut c = ctx();
        insp.inspect(&mut c).unwrap()
    }

    #[test]
    fn high_confidence_monitors_by_default() {
        let d = inspect(
            Ok(Classification {
                attack_type: "sql-injection".into(),
                confidence: 0.9,
                model_version: "v".into(),
            }),
            MlOptions::default(),
        )
        .unwrap();
        assert_eq!(d.action, Action::Monitor);
        assert_eq!(d.rule_id, "ML001");
    }

    #[test]
    fn high_confidence_blocks_when_enabled() {
        let d = inspect(
            Ok(Classification {
                attack_type: "sql-injection".into(),
                confidence: 0.9,
                model_version: "v".into(),
            }),
            MlOptions {
                block: true,
                min_score: 0.5,
            },
        )
        .unwrap();
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn low_confidence_is_ignored() {
        let d = inspect(
            Ok(Classification {
                attack_type: "sql-injection".into(),
                confidence: 0.2,
                model_version: "v".into(),
            }),
            MlOptions::default(),
        );
        assert!(d.is_none());
    }

    #[test]
    fn empty_attack_type_is_ignored() {
        let d = inspect(
            Ok(Classification {
                attack_type: String::new(),
                confidence: 0.99,
                model_version: "v".into(),
            }),
            MlOptions::default(),
        );
        assert!(d.is_none());
    }

    #[test]
    fn classifier_failure_is_a_pass() {
        let d = inspect(Err("connection refused".into()), MlOptions::default());
        assert!(d.is_none(), "an ML outage must never produce a decision");
        // Even with blocking enabled, a failure still passes.
        let d = inspect(
            Err("timeout".into()),
            MlOptions {
                block: true,
                min_score: 0.5,
            },
        );
        assert!(d.is_none());
    }
}
