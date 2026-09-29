//! Engine factory: build a fully-configured `Engine` from a `Config`.
//!
//! Port of `buildEngineConfig`, `engineRewriteConditions` and
//! `engineRewriteActions` from `cmd/proxy/main.go`.

use std::sync::Arc;
use std::time::Duration;

use fwaf_config::types::Config;
use fwaf_core::config_types::{GraphQlConfig, MtlsConfig, OAuthConfig};
use fwaf_core::engine::{Engine, EngineConfig, Inspector};
use fwaf_core::inspectors::auth::OAuthIntrospector;
use fwaf_core::inspectors::rewrite::{
    BodyAction, HeaderAction, RewriteAction, RewriteCondition, RewriteManager, RewriteRule,
};
use fwaf_core::inspectors::{
    adaptive::AdaptiveChallenge,
    api_protect::ApiProtection,
    auth::JwtValidator,
    behavioral::BehavioralEngine,
    bot::{BotDetector, BotOptions},
    credential::CredentialProtection,
    ddos::{DdosOptions, DdosProtection},
    desync::DesyncDetector,
    ebpf::EbpfTelemetry,
    graphql::GraphQlInspector,
    ja3::Ja3Inspector,
    mtls::MtlsInspector,
    parser::ParserHardener,
    protocol::ProtocolAnomaly,
    rce::RceInjection,
    response_leak::ResponseLeakInspector,
    sqli::SqlInjectionEngine,
    upload::FileUploadSecurity,
    wasm::WasmInspector,
    websocket::WebSocketInspector,
    xss::XssEngine,
};

/// Port of `buildEngineConfig`.
pub fn build_engine_config(cfg: &Config, dev: bool) -> EngineConfig {
    let mut e = EngineConfig {
        dev_mode: dev,
        shadow_mode: cfg.shadow_mode.enabled,
        learning_mode: cfg.learning_mode.enabled,
        performance_isolation: cfg.performance.enabled,
        max_regex_duration: cfg.performance.max_regex_ms as i64,
        max_wasm_duration: cfg.performance.max_wasm_ms as i64,
        ..Default::default()
    };

    // Inspectors are attached in the config-declared order, exactly as the Go
    // factory did.
    if cfg.sqli.enabled {
        e.sqli = Some(insp(Arc::new(SqlInjectionEngine::new(dev))));
    }
    if cfg.xss.enabled {
        e.xss = Some(insp(Arc::new(XssEngine::new(dev))));
    }
    if cfg.rce.enabled {
        e.rce = Some(insp(Arc::new(RceInjection::new(dev))));
    }
    if cfg.ddos.enabled {
        let ban = if cfg.ddos.ban_seconds != 0 {
            Some(Duration::from_secs(cfg.ddos.ban_seconds.max(0) as u64))
        } else {
            None
        };
        let opts = DdosOptions {
            global_rate: cfg.ddos.global_rate,
            per_ip_rate: cfg.ddos.per_ip_rate,
            per_endpoint_rate: cfg.ddos.per_endpoint_rate,
            per_session_rate: 0,
            per_ip_ban: ban,
            per_ip_ban_disabled: cfg.ddos.ban_seconds < 0,
        };
        e.ddos = Some(insp(Arc::new(DdosProtection::with_options(dev, opts))));
    }
    if cfg.protocol.enabled {
        e.protocol = Some(insp(Arc::new(ProtocolAnomaly::new(dev))));
    }
    if cfg.bot.enabled {
        let window = if cfg.bot.auto_ban_window_sec > 0 {
            Some(Duration::from_secs(cfg.bot.auto_ban_window_sec as u64))
        } else {
            None
        };
        let dur = if cfg.bot.auto_ban_seconds > 0 {
            Some(Duration::from_secs(cfg.bot.auto_ban_seconds as u64))
        } else {
            None
        };
        let after_n = cfg.bot.auto_ban_after;
        e.bot = Some(insp(Arc::new(BotDetector::with_options(
            dev,
            BotOptions {
                auto_ban_after: after_n,
                auto_ban_window: window,
                auto_ban_duration: dur,
            },
            Arc::new(fwaf_core::inspectors::bot::NoReverseDns),
        ))));
    }
    if cfg.api_protect.enabled {
        e.api_protect = Some(insp(Arc::new(ApiProtection::new(dev))));
    }
    if cfg.upload.enabled {
        e.upload = Some(insp(Arc::new(FileUploadSecurity::new(dev))));
    }
    if cfg.credential.enabled {
        e.credential = Some(insp(Arc::new(CredentialProtection::new(
            dev,
            cfg.credential.max_attempts,
            cfg.credential.window_sec,
            cfg.credential.block_duration_sec,
            cfg.credential.login_paths.clone(),
        ))));
    }
    if cfg.jwt.enabled {
        e.jwt = Some(insp(Arc::new(JwtValidator::new(
            fwaf_core::config_types::JwtConfig {
                jwks_url: cfg.jwt.jwks_url.clone(),
                issuers: cfg.jwt.issuers.clone(),
                audiences: cfg.jwt.audiences.clone(),
                algorithms: cfg.jwt.algorithms.clone(),
                secret: cfg.jwt.secret.clone(),
            },
        ))));
    }
    if cfg.oauth.enabled {
        e.oauth = Some(insp(Arc::new(OAuthIntrospector::new(OAuthConfig {
            introspection_url: cfg.oauth.introspection_url.clone(),
            client_id: cfg.oauth.client_id.clone(),
            client_secret: cfg.oauth.client_secret.clone(),
            token_type_hint: cfg.oauth.token_type_hint.clone(),
        }))));
    }
    if cfg.graphql.enabled {
        e.graphql = Some(insp(Arc::new(GraphQlInspector::new(GraphQlConfig {
            max_depth: cfg.graphql.max_depth,
            max_cost: cfg.graphql.max_cost,
            max_aliases: cfg.graphql.max_aliases,
            max_batch_size: cfg.graphql.max_batch_size,
            max_tokens: cfg.graphql.max_tokens,
            block_introspection: cfg.graphql.block_introspection,
            block_schema: cfg.graphql.block_schema,
            allowed_operations: cfg.graphql.allowed_operations.clone(),
            restricted_fields: cfg.graphql.restricted_fields.clone(),
            strict_validation: cfg.graphql.strict_validation,
        }))));
    }
    if cfg.websocket.enabled {
        e.websocket = Some(insp(Arc::new(WebSocketInspector::new(
            fwaf_core::config_types::WebSocketConfig {
                max_frame_size: cfg.websocket.max_frame_size,
                max_message_size: cfg.websocket.max_message_size,
                max_depth: cfg.websocket.max_depth,
                max_frames_per_min: cfg.websocket.max_frames_per_min,
                max_bytes_per_min: cfg.websocket.max_bytes_per_min,
                block_on_limit: cfg.websocket.block_on_limit,
                allowed_types: cfg.websocket.allowed_types.clone(),
                strict_mode: cfg.websocket.strict_mode,
                enable_ping: cfg.websocket.enable_ping,
                enable_pong: cfg.websocket.enable_pong,
                enable_close: cfg.websocket.enable_close,
                connection_timeout_sec: 0,
            },
        ))));
    }
    if cfg.mtls.enabled {
        match MtlsInspector::new(MtlsConfig {
            enabled: cfg.mtls.enabled,
            ca_file: cfg.mtls.ca_file.clone(),
            client_auth: cfg.mtls.client_auth.clone(),
            skip_verify: cfg.mtls.skip_verify,
            policy_oid: cfg.mtls.policy_oid.clone(),
            verify_depth: cfg.mtls.verify_depth,
            fail_on_error: cfg.mtls.fail_on_error,
            early_auth: cfg.mtls.early_auth,
            username_header: cfg.mtls.username_header.clone(),
        }) {
            Ok(m) => e.mtls = Some(insp(Arc::new(m))),
            Err(err) => tracing::warn!(error = err.as_str(), "mtls init failed"),
        }
    }
    if cfg.captcha.enabled {
        e.captcha = None; // CAPTCHAVerifier is wired via middleware in Go; see DEVIATIONS.md.
    }
    if cfg.soap.enabled {
        e.soap = Some(insp(Arc::new(fwaf_core::middleware::SoapValidator::new(
            cfg.soap.strict_schema,
            cfg.soap.max_depth,
        ))));
    }
    if cfg.grpc.enabled {
        e.grpc = Some(insp(Arc::new(fwaf_core::middleware::GrpcInspector::new(
            cfg.grpc.max_msg_size,
            cfg.grpc.rate_limit,
        ))));
    }
    if cfg.response_inspect.enabled {
        e.response_inspect = Some(insp(Arc::new(ResponseLeakInspector::new(
            cfg.response_inspect.inspect_body,
            cfg.response_inspect.block,
            1 << 20,
        ))));
    }
    if cfg.ja3.enabled {
        e.ja3 = Some(insp(Arc::new(Ja3Inspector::new(dev))));
    }
    if cfg.behavioral.enabled {
        e.behavioral = Some(insp(Arc::new(BehavioralEngine::new(
            dev,
            cfg.behavioral.reputation,
            cfg.behavioral.velocity,
            cfg.behavioral.path_entropy,
            cfg.behavioral.threshold,
            cfg.behavioral.window_sec,
            cfg.behavioral.max_requests,
        ))));
    }
    if cfg.wasm.enabled {
        e.wasm = Some(insp(Arc::new(WasmInspector::new(
            dev,
            cfg.wasm.module_dir.clone(),
            cfg.wasm.max_memory_pages,
            cfg.wasm.modules.clone(),
            Arc::new(fwaf_core::inspectors::wasm::NoWasmRuntime),
        ))));
    }
    if cfg.desync.enabled {
        e.desync = Some(insp(Arc::new(DesyncDetector::new(
            dev,
            cfg.desync.max_body_size,
            cfg.desync.strict_cl,
            cfg.desync.detect_obs_fold,
        ))));
    }
    if cfg.adaptive.enabled {
        e.adaptive = Some(insp(Arc::new(AdaptiveChallenge::new(
            dev,
            cfg.adaptive.js_script_path.clone(),
            cfg.adaptive.tarpit_delay_ms as i64,
            cfg.adaptive.captcha_score,
            cfg.adaptive.challenge_ttl as i64,
        ))));
    }
    if cfg.ebpf.enabled {
        e.ebpf = Some(insp(Arc::new(EbpfTelemetry::new(
            dev,
            cfg.ebpf.interface.clone(),
            cfg.ebpf.port,
            cfg.ebpf.sample_rate,
        ))));
    }
    if cfg.parser_hardening.enabled {
        e.parser = Some(insp(Arc::new(ParserHardener::new(dev))));
    }

    e
}

/// Coerce a concrete inspector to the trait object the engine stores.
fn insp<T: Inspector + 'static>(t: Arc<T>) -> Arc<dyn Inspector> {
    t
}

/// Build an Engine from config (convenience).
pub fn build_engine(cfg: &Config, dev: bool) -> Engine {
    Engine::new(build_engine_config(cfg, dev))
}

/// Build a rewrite manager from config rules. Port of the rewrite-rule loading
/// in `main` plus `engineRewriteConditions` / `engineRewriteActions`.
pub fn build_rewrite_manager(cfg: &Config) -> RewriteManager {
    let mut mgr = RewriteManager::new();
    for r in &cfg.rewrite_rules {
        if !r.enabled {
            continue;
        }
        let conditions: Vec<RewriteCondition> = r
            .conditions
            .iter()
            .map(|c| RewriteCondition {
                field: c.field.clone(),
                name: c.name.clone(),
                operator: c.operator.clone(),
                value: c.value.clone(),
            })
            .collect();

        let mut actions: Vec<Arc<dyn RewriteAction>> = Vec::new();
        for a in &r.actions {
            match a.r#type.as_str() {
                "set_header" => actions.push(Arc::new(HeaderAction {
                    operation: "set".to_string(),
                    name: a.name.clone(),
                    value: a.value.clone(),
                })),
                "remove_header" => actions.push(Arc::new(HeaderAction {
                    operation: "remove".to_string(),
                    name: a.name.clone(),
                    value: String::new(),
                })),
                "set_body" => {
                    if let Ok(ba) = BodyAction::new(&a.op, &a.pattern, &a.value) {
                        actions.push(Arc::new(ba));
                    }
                }
                _ => {}
            }
        }

        mgr.add_rule(RewriteRule {
            name: r.name.clone(),
            conditions,
            actions,
        });
    }
    mgr
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwaf_config::default_config;

    #[test]
    fn default_config_registers_parser_and_ja3() {
        // The default config enables parser_hardening and ja3 only.
        let cfg = default_config();
        let e = build_engine(&cfg, false);
        let names: Vec<String> = e
            .inspectors()
            .iter()
            .map(|i| i.name().to_string())
            .collect();
        assert_eq!(names, vec!["parser_hardener", "ja3"]);
    }

    #[test]
    fn enabled_inspectors_are_registered_in_order() {
        let mut cfg = default_config();
        cfg.sqli.enabled = true;
        cfg.xss.enabled = true;
        cfg.parser_hardening.enabled = true;
        let e = build_engine(&cfg, false);
        let names: Vec<String> = e
            .inspectors()
            .iter()
            .map(|i| i.name().to_string())
            .collect();
        // Ordered list: parser, ja3 (default-on), then sqli, then xss.
        assert_eq!(names, vec!["parser_hardener", "ja3", "sqli", "xss"]);
    }

    #[test]
    fn rewrite_manager_builds_rules() {
        let mut cfg = default_config();
        cfg.rewrite_rules
            .push(fwaf_config::types::RewriteRuleConfig {
                enabled: true,
                name: "add-header".into(),
                conditions: vec![],
                actions: vec![fwaf_config::types::RewriteActionConfig {
                    r#type: "set_header".into(),
                    name: "X-Test".into(),
                    value: "1".into(),
                    ..Default::default()
                }],
            });
        let mgr = build_rewrite_manager(&cfg);
        let mut ctx =
            fwaf_core::context::RequestContext::new(fwaf_core::http::HttpRequest::new("GET", "/"));
        mgr.apply_request(&mut ctx).unwrap();
        assert_eq!(ctx.headers.get("X-Test"), Some(&"1".to_string()));
    }
}
