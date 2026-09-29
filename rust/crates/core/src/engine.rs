//! The detection engine: ordered inspector pipeline and final decision.
//!
//! Port of `internal/engine/engine.go` (`Inspector`, `Engine`, `New`,
//! `Inspect`, `enrichExplainability`, `finalDecision`, `UpdateInspector`,
//! `Inspectors`, `ContextFromRequest`, `SetTrustedProxies`, `IsTrustedProxy`).

use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info};

use crate::action::{Action, Decision};
use crate::clientip::{parse_trusted_proxies, TrustedProxies};
use crate::confidence::ConfidenceScorer;
use crate::context::RequestContext;
use crate::http::HttpRequest;
use crate::performance::PerformanceManager;
use crate::shadow::LearningEngine;

/// Error returned by an inspector.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("{0}")]
    Message(String),
}

impl EngineError {
    pub fn new(msg: impl Into<String>) -> Self {
        EngineError::Message(msg.into())
    }
}

/// An inspector examines a request and may return a decision.
///
/// Direct port of the Go `Inspector` interface. `inspect` returns
/// `Ok(None)` for "no finding", `Ok(Some(dec))` for a finding, and
/// `Err` for an error (which the engine logs and skips).
///
/// The context is `&mut` because a few inspectors (notably the bot detector,
/// which sets `ctx.IsBot` for a verified good bot) mutate per-request state,
/// exactly as the Go inspectors did against `*RequestContext`.
pub trait Inspector: Send + Sync {
    fn name(&self) -> &str;
    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError>;
}

/// Engine configuration. Mirrors `EngineConfig`; inspectors are provided as
/// boxed trait objects in the same order the Go `New` assembled them.
#[derive(Default)]
pub struct EngineConfig {
    pub dev_mode: bool,
    pub shadow_mode: bool,
    pub learning_mode: bool,
    pub max_regex_duration: i64,
    pub max_wasm_duration: i64,
    pub performance_isolation: bool,

    pub parser: Option<Arc<dyn Inspector>>,
    pub desync: Option<Arc<dyn Inspector>>,
    pub ja3: Option<Arc<dyn Inspector>>,
    pub behavioral: Option<Arc<dyn Inspector>>,
    pub adaptive: Option<Arc<dyn Inspector>>,
    pub wasm: Option<Arc<dyn Inspector>>,
    pub captcha: Option<Arc<dyn Inspector>>,
    pub jwt: Option<Arc<dyn Inspector>>,
    pub oauth: Option<Arc<dyn Inspector>>,
    pub mtls: Option<Arc<dyn Inspector>>,
    pub graphql: Option<Arc<dyn Inspector>>,
    pub grpc: Option<Arc<dyn Inspector>>,
    pub soap: Option<Arc<dyn Inspector>>,
    pub bot: Option<Arc<dyn Inspector>>,
    pub ddos: Option<Arc<dyn Inspector>>,
    pub sqli: Option<Arc<dyn Inspector>>,
    pub xss: Option<Arc<dyn Inspector>>,
    pub api_protect: Option<Arc<dyn Inspector>>,
    pub rce: Option<Arc<dyn Inspector>>,
    pub protocol: Option<Arc<dyn Inspector>>,
    pub upload: Option<Arc<dyn Inspector>>,
    pub credential: Option<Arc<dyn Inspector>>,
    pub websocket: Option<Arc<dyn Inspector>>,
    pub response_inspect: Option<Arc<dyn Inspector>>,
    pub ebpf: Option<Arc<dyn Inspector>>,
}

/// The detection engine. Port of the Go `Engine`.
pub struct Engine {
    inspectors: RwLock<Vec<Arc<dyn Inspector>>>,
    dev_mode: bool,
    shadow_mode: bool,
    learning_mode: bool,
    perf_mgmt: Option<PerformanceManager>,
    learner: Arc<LearningEngine>,
    conf_scorer: Arc<ConfidenceScorer>,
    proxies: Arc<TrustedProxies>,
}

impl Engine {
    /// Port of `New`.
    pub fn new(cfg: EngineConfig) -> Self {
        // The Go code stored the inspector list in this exact order. The named
        // handles (bot, ddos, ...) were only used by UpdateInspector and the
        // ordered list drove Inspect. We keep the ordered list as the single
        // source of truth.
        let inspectors: Vec<Arc<dyn Inspector>> = [
            cfg.parser,
            cfg.desync,
            cfg.ja3,
            cfg.behavioral,
            cfg.adaptive,
            cfg.wasm,
            cfg.captcha,
            cfg.jwt,
            cfg.oauth,
            cfg.mtls,
            cfg.graphql,
            cfg.grpc,
            cfg.soap,
            cfg.bot,
            cfg.ddos,
            cfg.sqli,
            cfg.xss,
            cfg.api_protect,
            cfg.rce,
            cfg.protocol,
            cfg.upload,
            cfg.credential,
            cfg.websocket,
            cfg.response_inspect,
            cfg.ebpf,
        ]
        .into_iter()
        .flatten()
        .collect();

        let perf_mgmt = if cfg.performance_isolation {
            Some(PerformanceManager::new(
                cfg.max_regex_duration,
                cfg.max_wasm_duration,
            ))
        } else {
            None
        };

        Engine {
            inspectors: RwLock::new(inspectors),
            dev_mode: cfg.dev_mode,
            shadow_mode: cfg.shadow_mode,
            learning_mode: cfg.learning_mode,
            perf_mgmt,
            learner: Arc::new(LearningEngine::new()),
            conf_scorer: Arc::new(ConfidenceScorer::new()),
            proxies: Arc::new(TrustedProxies::new()),
        }
    }

    /// Port of `Inspect`. Returns the first blocking decision, or the final
    /// accumulated decision.
    pub fn inspect(&self, ctx: &mut RequestContext) -> Result<Decision, EngineError> {
        if self.dev_mode {
            debug!(
                method = ctx.method.as_str(),
                path = ctx.path.as_str(),
                ip = ctx.real_ip.as_str(),
                ua = ctx.user_agent.as_str(),
                "inspecting request"
            );
        }

        // Snapshot the inspector list to avoid holding the read lock across
        // inspector calls (Go held an RWMutex for the whole loop; this is
        // equivalent single-threaded and lets UpdateInspector take the write
        // lock without deadlock).
        let inspectors: Vec<Arc<dyn Inspector>> = self.inspectors.read().clone();

        for inspector in inspectors.iter() {
            let result = match &self.perf_mgmt {
                Some(pm) => pm.inspect(inspector.as_ref(), ctx)?,
                None => inspector.inspect(ctx)?,
            };
            let mut dec = match result {
                Some(d) => d,
                None => continue,
            };

            dec.inspector_name = inspector.name().to_string();

            self.conf_scorer.score_decision(&mut dec);

            if self.learning_mode {
                self.learner.record(inspector.name(), ctx, Some(&dec));
            }

            self.enrich_explainability(ctx, &mut dec);

            ctx.decisions.push(dec.clone());
            ctx.threat_score += dec.score;
            if dec.action == Action::Block {
                ctx.is_known_attack = true;
                ctx.bot_score = dec.score;
            }

            if self.dev_mode {
                debug!(
                    inspector = inspector.name(),
                    action = dec.action.as_str(),
                    rule_id = dec.rule_id.as_str(),
                    score = dec.score,
                    evidence = dec.evidence.as_str(),
                    request_id = ctx.request_id.as_str(),
                    "inspection decision"
                );
            }

            if dec.action == Action::Block {
                if self.shadow_mode {
                    dec.action = Action::Monitor;
                    dec.blocked = false;
                    info!(
                        rule_id = dec.rule_id.as_str(),
                        score = dec.score,
                        request_id = ctx.request_id.as_str(),
                        "shadow mode: would have blocked"
                    );
                    continue;
                }
                return Ok(dec);
            }
        }

        Ok(self.final_decision(ctx))
    }

    /// Port of `enrichExplainability`.
    fn enrich_explainability(&self, ctx: &RequestContext, dec: &mut Decision) {
        if !dec.explainability.is_empty() {
            return;
        }
        dec.explainability = match () {
            _ if dec.action == Action::Block && dec.score >= 90.0 => {
                "Critical threat detected with high confidence. Immediate blocking required."
                    .to_string()
            }
            _ if dec.action == Action::Block => {
                "Request matched blocking rule pattern with sufficient certainty.".to_string()
            }
            _ if dec.action == Action::Challenge => {
                "Request exhibits suspicious characteristics requiring additional verification."
                    .to_string()
            }
            _ if dec.action == Action::Monitor => {
                "Request flagged for observation. No action taken.".to_string()
            }
            _ if dec.action == Action::RateLimit => {
                "Request rate exceeds configured threshold for this endpoint.".to_string()
            }
            _ => "No actionable threat detected.".to_string(),
        };

        if self.learning_mode && dec.action == Action::Allow {
            if let Some(bsl) = self.learner.baseline(&ctx.path) {
                dec.explainability = format!(
                    "Request matches learned baseline for {} (mean={:.2}, std={:.2})",
                    ctx.path, bsl.mean_rate, bsl.std_dev
                );
            }
        }
    }

    /// Port of `finalDecision`.
    fn final_decision(&self, ctx: &RequestContext) -> Decision {
        let score = ctx.threat_score;

        let mut ban_req: Option<Decision> = None;
        let mut saw_rate_limit = false;
        for d in &ctx.decisions {
            if d.ban_request && ban_req.is_none() {
                ban_req = Some(d.clone());
            }
            if d.action == Action::RateLimit {
                saw_rate_limit = true;
            }
        }

        let apply = |mut dec: Decision| -> Decision {
            if let Some(breq) = &ban_req {
                dec.ban_request = true;
                dec.ban_duration = breq.ban_duration;
                if dec.rule_id.is_empty() {
                    dec.rule_id = breq.rule_id.clone();
                    dec.rule_name = breq.rule_name.clone();
                }
            }
            dec
        };

        if saw_rate_limit {
            return apply(
                Decision::new(Action::RateLimit, score).with_evidence("rate limit exceeded"),
            );
        }
        if score >= 90.0 {
            return apply(
                Decision::new(Action::Block, score)
                    .with_evidence("cumulative threat score exceeded threshold"),
            );
        }
        if score >= 50.0 {
            return apply(
                Decision::new(Action::Challenge, score)
                    .with_evidence("elevated threat score requires challenge"),
            );
        }

        apply(Decision::new(Action::Allow, 0.0))
    }

    /// Port of `InspectRequest` (build a context and inspect).
    pub fn inspect_request(&self, r: &HttpRequest) -> Result<Decision, EngineError> {
        let mut ctx = self.context_from_request(r);
        if self.dev_mode {
            debug!(
                request_id = ctx.request_id.as_str(),
                real_ip = ctx.real_ip.as_str(),
                "request context created"
            );
        }
        self.inspect(&mut ctx)
    }

    /// Port of `UpdateInspector`: replace the first inspector whose name
    /// matches. Returns true if a replacement happened.
    pub fn update_inspector(&self, name: &str, inspector: Arc<dyn Inspector>) -> bool {
        let mut inspectors = self.inspectors.write();
        for slot in inspectors.iter_mut() {
            if slot.name() == name {
                *slot = inspector;
                return true;
            }
        }
        false
    }

    /// Port of `Inspectors`.
    pub fn inspectors(&self) -> Vec<Arc<dyn Inspector>> {
        self.inspectors.read().clone()
    }

    /// Port of `ContextFromRequest`.
    pub fn context_from_request(&self, r: &HttpRequest) -> RequestContext {
        let mut ctx = RequestContext::new(r.clone());
        ctx.real_ip = self.client_ip(r);
        ctx
    }

    /// Port of `SetTrustedProxies`; returns the invalid CIDRs.
    pub fn set_trusted_proxies(&self, cidrs: &[String]) -> Vec<String> {
        self.proxies.set_trusted_proxies(cidrs);
        parse_trusted_proxies(cidrs)
    }

    /// Port of `IsTrustedProxy`.
    pub fn is_trusted_proxy(&self, ip: &str) -> bool {
        self.proxies.trusts(ip)
    }

    /// Port of `ClientIP`.
    pub fn client_ip(&self, r: &HttpRequest) -> String {
        self.proxies.client_ip(r)
    }

    /// Access the confidence scorer (for the admin API).
    pub fn confidence_scorer(&self) -> &Arc<ConfidenceScorer> {
        &self.conf_scorer
    }

    /// Access the learning engine (for the admin API / stats).
    pub fn learner(&self) -> &Arc<LearningEngine> {
        &self.learner
    }

    /// Access the performance manager, if isolation is enabled.
    pub fn performance_manager(&self) -> Option<&PerformanceManager> {
        self.perf_mgmt.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;

    struct FixedInspector {
        name: String,
        decision: Option<Decision>,
    }

    impl Inspector for FixedInspector {
        fn name(&self) -> &str {
            &self.name
        }
        fn inspect(&self, _ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
            Ok(self.decision.clone())
        }
    }

    fn ctx() -> RequestContext {
        RequestContext::new(HttpRequest::new("GET", "/"))
    }

    #[test]
    fn clean_request_allows() {
        let e = Engine::new(EngineConfig::default());
        let mut c = ctx();
        let dec = e.inspect(&mut c).unwrap();
        assert_eq!(dec.action, Action::Allow);
        assert_eq!(dec.score, 0.0);
    }

    #[test]
    fn blocking_inspector_short_circuits() {
        let sqli = Arc::new(FixedInspector {
            name: "sqli".into(),
            decision: Some(
                Decision::new(Action::Block, 90.0)
                    .with_rule_id("SQLI001")
                    .with_severity("critical"),
            ),
        });
        let xss = Arc::new(FixedInspector {
            name: "xss".into(),
            decision: Some(Decision::new(Action::Block, 50.0).with_rule_id("XSS001")),
        });
        let e = Engine::new(EngineConfig {
            sqli: Some(sqli),
            xss: Some(xss),
            ..Default::default()
        });
        let mut c = ctx();
        let dec = e.inspect(&mut c).unwrap();
        assert_eq!(dec.action, Action::Block);
        assert_eq!(dec.rule_id, "SQLI001");
        assert_eq!(dec.inspector_name, "sqli");
        // Confidence was scored.
        assert!(dec.confidence_score > 0.0);
    }

    #[test]
    fn shadow_mode_demotes_block_and_continues() {
        let sqli = Arc::new(FixedInspector {
            name: "sqli".into(),
            decision: Some(Decision::new(Action::Block, 95.0).with_rule_id("SQLI001")),
        });
        let e = Engine::new(EngineConfig {
            shadow_mode: true,
            sqli: Some(sqli),
            ..Default::default()
        });
        let mut c = ctx();
        let dec = e.inspect(&mut c).unwrap();
        // Score 95 >= 90 -> final decision is Block, but the block from the
        // inspector was demoted so inspection continued. The decision stored on
        // the context was appended BEFORE the shadow demotion (matching Go), so
        // it still records the original Block action.
        assert_eq!(dec.action, Action::Block);
        assert_eq!(c.threat_score, 95.0);
        assert_eq!(c.decisions[0].action, Action::Block);
    }

    #[test]
    fn rate_limit_takes_precedence_over_high_score() {
        let ddos = Arc::new(FixedInspector {
            name: "ddos".into(),
            decision: Some({
                let mut d = Decision::new(Action::RateLimit, 60.0).with_rule_id("DDoS000");
                d.ban_request = true;
                d.ban_duration = std::time::Duration::from_secs(300);
                d
            }),
        });
        let e = Engine::new(EngineConfig {
            ddos: Some(ddos),
            ..Default::default()
        });
        let mut c = ctx();
        let dec = e.inspect(&mut c).unwrap();
        assert_eq!(dec.action, Action::RateLimit);
        assert!(dec.ban_request);
        assert_eq!(dec.ban_duration, std::time::Duration::from_secs(300));
        assert_eq!(dec.rule_id, "DDoS000");
    }

    #[test]
    fn cumulative_score_challenge_between_50_and_90() {
        let a = Arc::new(FixedInspector {
            name: "a".into(),
            decision: Some(Decision::new(Action::Monitor, 30.0).with_rule_id("A")),
        });
        let b = Arc::new(FixedInspector {
            name: "b".into(),
            decision: Some(Decision::new(Action::Monitor, 30.0).with_rule_id("B")),
        });
        let e = Engine::new(EngineConfig {
            bot: Some(a),
            sqli: Some(b),
            ..Default::default()
        });
        let mut c = ctx();
        let dec = e.inspect(&mut c).unwrap();
        assert_eq!(dec.action, Action::Challenge);
        assert_eq!(dec.score, 60.0);
    }

    #[test]
    fn invalid_trusted_proxies_reported() {
        let e = Engine::new(EngineConfig::default());
        let invalid = e.set_trusted_proxies(&["10.0.0.0/8".into(), "nope".into()]);
        assert_eq!(invalid, vec!["nope".to_string()]);
    }
}
