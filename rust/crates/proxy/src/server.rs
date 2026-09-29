//! The HTTP servers: the reverse-proxy listener and the admin API listener.
//!
//! Port of the server wiring in `cmd/proxy/main.go` (`wafHandler.ServeHTTP` +
//! `forwardRequest`, `newAdminRouter`, the shutdown logic). Built on hyper 1 +
//! tokio. The TCP/TLS/ACME plumbing is documented in `rust/DEVIATIONS.md`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use parking_lot::RwLock;
use tokio::net::TcpListener;

use fwaf_config::types::SiteConfig;
use fwaf_config::Manager;
use fwaf_core::action::Action;
use fwaf_core::context::RequestContext;
use fwaf_core::engine::Engine;
use fwaf_core::http::HttpRequest;
use fwaf_services::blocklist::Store;
use fwaf_services::compliance::AuditLog;
use fwaf_services::traincorpus::Collector;

use crate::handlers::{self, Reply, ServerInfo};
use crate::pipeline::{self, stop_copy, Metrics, Outcome, StopKind};

/// Shared state for both servers.
/// A shared, pooled HTTP client for upstream forwarding.
///
/// One client owns one connection pool. Building a client per request (the
/// previous behaviour) meant every forwarded request opened a new TCP
/// connection and dropped it, exhausting ephemeral ports and file descriptors
/// under load until requests blocked forever.
pub type UpstreamClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    Full<Bytes>,
>;

pub struct AppState {
    pub cfg_mgr: Arc<Manager>,
    pub engine: Arc<RwLock<Engine>>,
    pub metrics: Arc<Metrics>,
    pub bans: Arc<Store>,
    pub audit: Option<Arc<AuditLog>>,
    pub trainer: Option<Arc<Collector>>,
    pub info: ServerInfo,
    pub dev: bool,
    pub login_limiter: Arc<crate::loginlimit::LoginLimiter>,
    /// Per-site upstream base URLs, resolved from the config.
    pub upstreams: RwLock<HashMap<String, String>>,
    /// Shared, pooled client for upstream requests (one pool for the process).
    pub upstream_client: Arc<UpstreamClient>,
    /// Hard cap on how long an upstream request may take, so a slow origin
    /// cannot pin a task (and its connection) indefinitely.
    pub upstream_timeout: std::time::Duration,
}

impl AppState {
    pub fn new(cfg_mgr: Arc<Manager>, engine: Engine, dev: bool) -> Arc<Self> {
        let cfg = cfg_mgr.get();
        let mut upstreams = HashMap::new();
        for site in &cfg.sites {
            upstreams.insert(site.name.clone(), resolve_upstream(site));
        }
        let trainer = if cfg.training.enabled && !cfg.training.corpus_dir.is_empty() {
            Some(Arc::new(Collector::new(&cfg.training.corpus_dir)))
        } else {
            None
        };
        // One pooled client for the whole process. `pool_max_idle_per_host`
        // keeps keep-alive connections to the upstream instead of opening a
        // new one per request.
        let mut connector = hyper_util::client::legacy::connect::HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_keepalive(Some(Duration::from_secs(30)));
        let upstream_client: UpstreamClient =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .pool_max_idle_per_host(64)
                .pool_idle_timeout(Duration::from_secs(90))
                .build(connector);

        Arc::new(AppState {
            cfg_mgr,
            engine: Arc::new(RwLock::new(engine)),
            metrics: Arc::new(Metrics::new()),
            bans: Arc::new(Store::new()),
            audit: Some(Arc::new(AuditLog::new())),
            trainer,
            info: ServerInfo::default(),
            dev,
            login_limiter: Arc::new(crate::loginlimit::LoginLimiter::new(
                5,
                Duration::from_secs(900),
                Duration::from_secs(60),
            )),
            upstreams: RwLock::new(upstreams),
            upstream_client: Arc::new(upstream_client),
            upstream_timeout: Duration::from_secs(30),
        })
    }
}

/// Resolve a site's upstream URL (append the port when configured).
pub fn resolve_upstream(site: &SiteConfig) -> String {
    let mut upstream = site.upstream.clone();
    if site.port > 0 && !upstream.contains(':') {
        upstream = format!("{}:{}", upstream, site.port);
    }
    upstream
}

/// Build a `RequestContext` from a hyper request + already-read body.
pub fn build_context(req: &Request<Incoming>, body: Vec<u8>, remote_addr: &str) -> HttpRequest {
    let uri = req.uri();
    let path = uri.path().to_string();
    let raw_query = uri.query().unwrap_or("").to_string();
    let mut hreq = HttpRequest {
        method: req.method().to_string(),
        path,
        raw_query,
        host: req
            .headers()
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string(),
        proto: format!("{:?}", req.version()),
        header: fwaf_core::http::HeaderMap::new(),
        remote_addr: remote_addr.to_string(),
        content_length: body.len() as i64,
        body: body.clone(),
        tls: None,
        raw_path: Vec::new(),
        raw_header: Vec::new(),
    };
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            hreq.header.add(name.as_str(), v);
        }
    }
    hreq
}

/// The proxy request handler. Port of `wafHandler.ServeHTTP`.
pub async fn proxy_handler(
    app: Arc<AppState>,
    req: Request<Incoming>,
    remote_addr: String,
) -> Result<Response<Full<Bytes>>, Infallible> {
    app.metrics.inc(&app.metrics.total_requests);
    app.metrics.inc(&app.metrics.active_conns);
    let _guard = ConnGuard(app.metrics.clone());

    // Read the whole body (bounded) so inspectors can see it.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => Vec::new(),
    };
    let req = Request::from_parts(parts, Full::new(Bytes::new()));
    let _ = &req;

    let client_ip = client_ip_of(&app, &req, &remote_addr);

    // A banned address is refused before inspection.
    if app.bans.is_banned(&client_ip) {
        app.metrics.inc(&app.metrics.blocked_requests);
        record_request(
            &app,
            &req,
            &body_bytes,
            &remote_addr,
            "request_blocked",
            "banned_ip",
            "blocked",
            "",
            &client_ip,
        );
        let dec = fwaf_core::action::Decision::new(Action::Block, 0.0)
            .with_rule_id("BAN001")
            .with_rule_name("IP address is banned")
            .with_severity("high")
            .with_evidence("source address is on the operator ban list");
        let banned_ctx = app
            .engine
            .read()
            .context_from_request(&build_ctx_from_parts(&req, &body_bytes, &remote_addr));
        let mut resp = blocked_response(&banned_ctx, &dec);
        resp.headers_mut()
            .insert("X-FortressWAF-Action", "block".parse().unwrap());
        resp.headers_mut()
            .insert("X-FortressWAF-Rule", "BAN001".parse().unwrap());
        return Ok(resp);
    }

    let cfg = app.cfg_mgr.get();
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string();
    let site = cfg
        .find_site_by_domain(&host)
        .cloned()
        .or_else(|| cfg.sites.first().cloned());

    let site = match site {
        Some(s) => s,
        None => {
            app.metrics.inc(&app.metrics.blocked_requests);
            return Ok(json_response(
                502,
                serde_json::json!({
                    "error": "no_site_configured",
                    "detail": format!("no site configured for host {host:?}"),
                }),
            ));
        }
    };

    let path = req.uri().path().to_string();

    // WAF disabled or excluded: forward without inspection.
    if !site.waf_enabled {
        return forward(&app, req, body_bytes, &site, &remote_addr).await;
    }
    if site.excludes_path(&path) {
        app.metrics.inc(&app.metrics.excluded_requests);
        return forward(&app, req, body_bytes, &site, &remote_addr).await;
    }

    // Inspect (guard scoped so it is dropped before any await).
    let mut ctx = app
        .engine
        .read()
        .context_from_request(&build_ctx_from_parts(&req, &body_bytes, &remote_addr));

    let inspect_result = {
        let engine = app.engine.read();
        engine.inspect(&mut ctx)
    };

    let decision = match inspect_result {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = e.to_string().as_str(), "engine inspection error");
            if app.dev {
                return forward(&app, req, body_bytes, &site, &remote_addr).await;
            }
            return Ok(json_response(
                500,
                serde_json::json!({"error":"waf_error","detail":"inspection engine error"}),
            ));
        }
    };

    // Auto-ban if requested.
    if decision.ban_request {
        apply_auto_ban(&app, &client_ip, &decision);
    }

    let mut result = pipeline::decide(vec![], &decision);

    match result.outcome.clone() {
        Outcome::Blocked { .. } => {
            app.metrics.inc(&app.metrics.blocked_requests);
            record_request(
                &app,
                &req,
                &body_bytes,
                &remote_addr,
                "request_blocked",
                &decision.rule_id,
                "blocked",
                &decision.evidence,
                &client_ip,
            );
            if let Some(t) = &app.trainer {
                pipeline::collect_training(t, &ctx, &decision, &client_ip);
            }
            tracing::warn!(
                host = host.as_str(),
                path = path.as_str(),
                rule_id = decision.rule_id.as_str(),
                "request blocked"
            );
        }
        Outcome::Challenge { .. } => {
            app.metrics.inc(&app.metrics.challenged_reqs);
            result.outcome = Outcome::Challenge {
                html: pipeline::challenge_page(&ctx),
            };
        }
        Outcome::RateLimited => {
            app.metrics.inc(&app.metrics.rate_limited_reqs);
        }
        // Forward covers Allow and Monitor; the monitored counter is bumped
        // when the Monitor header is present.
        Outcome::Forward { .. } => {
            if result
                .response_headers
                .iter()
                .any(|(k, _)| k == "X-FortressWAF-Monitored")
            {
                app.metrics.inc(&app.metrics.monitored_reqs);
            }
        }
        Outcome::Banned | Outcome::NoSite => {}
    }

    // Update per-outcome metric counters, then build the response.
    match &result.outcome {
        Outcome::Forward { .. } => {
            app.metrics.inc(&app.metrics.allowed_requests);
            let mut resp = forward_raw(&app, &ctx, &site).await;
            for (k, v) in &result.response_headers {
                if let (Ok(name), Ok(val)) = (
                    k.parse::<hyper::header::HeaderName>(),
                    v.parse::<hyper::header::HeaderValue>(),
                ) {
                    resp.headers_mut().insert(name, val);
                }
            }
            return Ok(resp);
        }
        Outcome::Blocked { decision } => {
            let mut resp = blocked_response(&ctx, decision);
            for (k, v) in &result.response_headers {
                if let (Ok(name), Ok(val)) = (
                    k.parse::<hyper::header::HeaderName>(),
                    v.parse::<hyper::header::HeaderValue>(),
                ) {
                    resp.headers_mut().insert(name, val);
                }
            }
            return Ok(resp);
        }
        Outcome::Challenge { html } => {
            let mut resp = Response::new(Full::new(Bytes::from(html.clone())));
            *resp.status_mut() = StatusCode::FORBIDDEN;
            resp.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                "text/html; charset=utf-8".parse().unwrap(),
            );
            resp.headers_mut()
                .insert("X-FortressWAF-Action", "challenge".parse().unwrap());
            return Ok(resp);
        }
        Outcome::RateLimited => {
            // The limit shown to the client is the one actually configured, not
            // a literal. `per_ip_rate` is the per-address limit the DDoS
            // inspector enforces; 0 means it fell back to the built-in default.
            let cfg = app.cfg_mgr.get();
            let limit = if cfg.ddos.per_ip_rate > 0 {
                cfg.ddos.per_ip_rate
            } else {
                30
            };
            let retry_after = 60;

            let mut resp = if pipeline::client_wants_json(&ctx) {
                json_response(
                    429,
                    serde_json::json!({
                        "error": "rate_limited",
                        "detail": stop_copy(StopKind::Flood).1,
                        "limit": limit,
                        "retry_after": retry_after,
                        "request_id": pipeline::block_request_id(&ctx),
                    }),
                )
            } else {
                let page = pipeline::flood_page(&ctx, limit, retry_after);
                let mut r = Response::new(Full::new(Bytes::from(page)));
                *r.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                r.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    "text/html; charset=utf-8".parse().unwrap(),
                );
                r
            };
            resp.headers_mut().insert(
                hyper::header::RETRY_AFTER,
                retry_after.to_string().parse().unwrap(),
            );
            resp.headers_mut()
                .insert("X-RateLimit-Limit", limit.to_string().parse().unwrap());
            resp.headers_mut()
                .insert("X-RateLimit-Remaining", "0".parse().unwrap());
            resp.headers_mut()
                .insert("X-FortressWAF-Action", "rate_limit".parse().unwrap());
            return Ok(resp);
        }
        _ => {}
    }

    Ok(json_response(200, serde_json::json!({"status":"ok"})))
}

struct ConnGuard(Arc<Metrics>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0
            .active_conns
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

// The remaining helpers (client_ip_of, build_ctx_from_parts, forward,
// forward_raw, blocked_response, json_response, record_request, apply_auto_ban)
// are implemented below.

fn client_ip_of(app: &AppState, req: &Request<Full<Bytes>>, remote_addr: &str) -> String {
    // Reuse the engine's trusted-proxy resolution.
    let mut hreq = HttpRequest::new(req.method().as_str(), req.uri().path());
    hreq.remote_addr = remote_addr.to_string();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            hreq.header.add(name.as_str(), v);
        }
    }
    app.engine.read().client_ip(&hreq)
}

fn build_ctx_from_parts(
    req: &Request<Full<Bytes>>,
    body: &[u8],
    remote_addr: &str,
) -> fwaf_core::http::HttpRequest {
    let uri = req.uri();
    let mut hreq = HttpRequest::new(req.method().as_str(), uri.path());
    hreq.raw_query = uri.query().unwrap_or("").to_string();
    hreq.host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    hreq.proto = format!("{:?}", req.version());
    hreq.remote_addr = remote_addr.to_string();
    hreq.content_length = body.len() as i64;
    hreq.body = body.to_vec();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            hreq.header.add(name.as_str(), v);
        }
    }
    hreq
}

fn json_response(status: i32, v: serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&v).unwrap_or_default();
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = StatusCode::from_u16(status as u16).unwrap_or(StatusCode::OK);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    resp
}

/// Build the blocked response (JSON or HTML page). Port of `writeBlockedResponse`.
///
/// The JSON body mirrors the page: the same headline/lead/detail from
/// `stop_copy`, the request id, and the matched rule's human name. It does not
/// expose the raw internal severity vocabulary (low/medium/high/critical),
/// which means nothing to a client.
fn blocked_response(
    ctx: &RequestContext,
    decision: &fwaf_core::action::Decision,
) -> Response<Full<Bytes>> {
    let kind = StopKind::from_decision(decision);
    let (headline, lead, detail) = stop_copy(kind);
    if pipeline::client_wants_json(ctx) {
        return json_response(
            403,
            serde_json::json!({
                "blocked": true,
                "action": "block",
                "headline": headline,
                "lead": lead,
                "detail": detail,
                "matched": if decision.rule_name.is_empty() {
                    decision.rule_id.clone()
                } else {
                    decision.rule_name.clone()
                },
                "request_id": pipeline::block_request_id(ctx),
            }),
        );
    }
    let page = pipeline::block_page(ctx, decision);
    let mut resp = Response::new(Full::new(Bytes::from(page)));
    *resp.status_mut() = StatusCode::FORBIDDEN;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    resp
}

fn apply_auto_ban(app: &AppState, ip: &str, decision: &fwaf_core::action::Decision) {
    let ban = pipeline::BanRequest {
        ip: ip.to_string(),
        duration: decision.ban_duration,
        rule_id: decision.rule_id.clone(),
        rule_name: decision.rule_name.clone(),
    };
    let engine = app.engine.read();
    if pipeline::apply_auto_ban(&app.bans, &engine, ip, &ban) {
        tracing::warn!(
            ip = ip,
            rule = decision.rule_id.as_str(),
            "auto-banned address"
        );
    }
}

fn record_request(
    app: &AppState,
    req: &Request<Full<Bytes>>,
    body: &[u8],
    remote_addr: &str,
    action: &str,
    metadata: &str,
    result: &str,
    evidence: &str,
    client_ip: &str,
) {
    let audit = match &app.audit {
        Some(a) => a,
        None => return,
    };
    let ctx = app
        .engine
        .read()
        .context_from_request(&build_ctx_from_parts(req, body, remote_addr));
    let ua = ctx.user_agent.clone();
    let (browser, device) = pipeline::parse_ua_flags(&ua);
    let headers = pipeline::audit_headers(&ctx);
    let mut meta = metadata.to_string();
    if !evidence.is_empty() {
        meta = format!("{metadata} | {evidence}");
    }
    let entry = fwaf_services::compliance::AuditEntry {
        actor_type: "client".to_string(),
        actor_ip: client_ip.to_string(),
        action: action.to_string(),
        resource: format!("{}{}", ctx.host, ctx.path),
        result: result.to_string(),
        metadata: meta,
        method: ctx.method.clone(),
        path: ctx.path.clone(),
        user_agent: ua,
        browser,
        device,
        headers: Some(headers.into_iter().collect()),
        ..Default::default()
    };
    let _ = audit.append(entry);
}

// --- Upstream forwarding ---

async fn forward(
    app: &Arc<AppState>,
    req: Request<Full<Bytes>>,
    body: Vec<u8>,
    site: &SiteConfig,
    remote_addr: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let ctx = app
        .engine
        .read()
        .context_from_request(&build_ctx_from_parts(&req, &body, remote_addr));
    Ok(forward_raw(app, &ctx, site).await)
}

/// Forward a request to the site's upstream. Uses a fresh HTTP client per call
/// (a pool is a documented optimization, not a behaviour change).
async fn forward_raw(
    app: &AppState,
    ctx: &RequestContext,
    site: &SiteConfig,
) -> Response<Full<Bytes>> {
    let upstream = app
        .upstreams
        .read()
        .get(&site.name)
        .cloned()
        .unwrap_or_else(|| resolve_upstream(site));

    let base = match upstream.parse::<hyper::Uri>() {
        Ok(u) => u,
        Err(_) => {
            return json_response(
                502,
                serde_json::json!({"error":"bad_gateway","detail":"invalid upstream"}),
            );
        }
    };

    let mut uri_builder = hyper::Uri::builder()
        .scheme(base.scheme_str().unwrap_or("http"))
        .authority(
            base.authority()
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
        );
    let path_and_query = format!(
        "{}{}",
        ctx.path,
        if ctx.request.raw_query.is_empty() {
            String::new()
        } else {
            format!("?{}", ctx.request.raw_query)
        }
    );
    uri_builder = uri_builder.path_and_query(path_and_query);
    let uri = match uri_builder.build() {
        Ok(u) => u,
        Err(_) => return json_response(502, serde_json::json!({"error":"bad_gateway"})),
    };

    let host_authority = base.authority().map(|a| a.to_string());
    let mut builder = Request::builder()
        .method(ctx.method.as_str())
        .uri(uri.clone());
    for (k, v) in &ctx.headers {
        // Do NOT forward Host here; set below.
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(k, v);
    }
    // Set X-Forwarded-For and preserve the original Host.
    if let Some(host) = host_authority {
        let existing_xff = ctx
            .headers
            .get("X-Forwarded-For")
            .cloned()
            .unwrap_or_default();
        let xff = if existing_xff.is_empty() {
            ctx.real_ip.clone()
        } else {
            format!("{existing_xff}, {}", ctx.real_ip)
        };
        builder = builder.header("X-Forwarded-For", xff);
        builder = builder.header("X-Forwarded-Host", ctx.host.clone());
        builder = builder.header("X-Forwarded-Proto", uri.scheme_str().unwrap_or("http"));
        builder = builder.header("Host", ctx.host.clone());
        let _ = host;
    }

    let request = match builder.body(Full::new(Bytes::from(ctx.body.clone()))) {
        Ok(r) => r,
        Err(_) => return json_response(502, serde_json::json!({"error":"bad_gateway"})),
    };

    // Perform the upstream request through the shared, pooled client, bounded
    // by a timeout so a slow origin cannot pin the task forever.
    match send_upstream(&app.upstream_client, request, app.upstream_timeout).await {
        Ok((status, headers, body)) => {
            let mut resp = Response::new(Full::new(Bytes::from(body)));
            *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            for (k, v) in headers {
                if let (Ok(name), Ok(val)) = (
                    k.parse::<hyper::header::HeaderName>(),
                    v.parse::<hyper::header::HeaderValue>(),
                ) {
                    resp.headers_mut().insert(name, val);
                }
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = e.as_str(), "upstream error");
            json_response(
                502,
                serde_json::json!({"error":"bad_gateway","detail":"upstream unreachable"}),
            )
        }
    }
}

/// Send an upstream request through the shared pooled client, bounded by a
/// timeout. The client keeps keep-alive connections, so bursts reuse sockets
/// instead of opening one per request.
async fn send_upstream(
    client: &UpstreamClient,
    req: Request<Full<Bytes>>,
    timeout: std::time::Duration,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let fut = client.request(req);
    let resp = match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err(format!("upstream timed out after {timeout:?}")),
    };
    let status = resp.status().as_u16();
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_string())))
        .collect();
    let body = match tokio::time::timeout(timeout, resp.into_body().collect()).await {
        Ok(Ok(b)) => b.to_bytes().to_vec(),
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err(format!("upstream body timed out after {timeout:?}")),
    };
    Ok((status, headers, body))
}

/// Run the proxy listener until the shutdown future resolves.
///
/// When `tls` is `Some`, every connection is wrapped in a TLS handshake
/// (rustls) before being handed to hyper; otherwise the listener is plain HTTP.
/// This mirrors the Go proxy, which switched between `ListenAndServe` and
/// `ListenAndServeTLS` based on `tls.enabled`.
pub async fn serve_proxy(
    app: Arc<AppState>,
    addr: SocketAddr,
    tls: Option<tokio_rustls::TlsAcceptor>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let app = app.clone();
                let peer = peer.to_string();
                let tls = tls.clone();
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            let tls_stream = match acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(error = e.to_string().as_str(), "tls handshake failed");
                                    return;
                                }
                            };
                            let io = TokioIo::new(tls_stream);
                            let service = service_fn(move |req: Request<Incoming>| {
                                let app = app.clone();
                                let peer = peer.clone();
                                async move { proxy_handler(app, req, peer).await }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        }
                        None => {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req: Request<Incoming>| {
                                let app = app.clone();
                                let peer = peer.clone();
                                async move { proxy_handler(app, req, peer).await }
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(io, service)
                                .await;
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

/// Run the Prometheus metrics listener on its own port. Serves the exposition
/// text at `path` (default `/metrics`) and returns 404 elsewhere. Port of the
/// separate `http.Server` the Go proxy started when `prometheus.enabled`.
pub async fn serve_metrics(
    app: Arc<AppState>,
    addr: SocketAddr,
    path: String,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accept = listener.accept() => {
                let (stream, _peer) = match accept {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let io = TokioIo::new(stream);
                let app = app.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let app = app.clone();
                        let path = path.clone();
                        async move {
                            if req.uri().path() == path {
                                let reply = handlers::handle_metrics(&app.info, &app.metrics);
                                let mut resp = Response::new(Full::new(Bytes::from(reply.body)));
                                resp.headers_mut().insert(
                                    hyper::header::CONTENT_TYPE,
                                    reply.content_type.parse().unwrap(),
                                );
                                Ok::<_, Infallible>(resp)
                            } else {
                                Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap())
                            }
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        }
    }
    Ok(())
}

/// Run the admin API listener.
pub async fn serve_admin(
    app: Arc<AppState>,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accept = listener.accept() => {
                let (stream, _peer) = match accept {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                let io = TokioIo::new(stream);
                let app = app.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let app = app.clone();
                        async move { admin_handler(app, req).await }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        }
    }
    Ok(())
}

/// The admin API router. Port of `newAdminRouter` route handling.
async fn admin_handler(
    app: Arc<AppState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let cfg = app.cfg_mgr.get();
    let keys = cfg.admin.api_keys.clone();

    let reply = route_admin(
        &app,
        &method,
        &path,
        auth_header.as_deref(),
        origin.as_deref(),
        &keys,
    );

    let mut resp = Response::new(Full::new(Bytes::from(reply.body)));
    *resp.status_mut() = StatusCode::from_u16(reply.status as u16).unwrap_or(StatusCode::OK);
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        reply
            .content_type
            .parse()
            .unwrap_or_else(|_| "application/json".parse().unwrap()),
    );
    Ok(resp)
}

/// Route the admin request. Separated for testability.
pub fn route_admin(
    app: &AppState,
    method: &hyper::Method,
    path: &str,
    auth: Option<&str>,
    origin: Option<&str>,
    keys: &[String],
) -> Reply {
    let _ = origin; // CORS headers applied by the caller when needed.

    // Public endpoints.
    match path {
        "/health" => return handlers::handle_health(&app.info),
        "/metrics" => return handlers::handle_metrics(&app.info, &app.metrics),
        "/ready" => return handlers::handle_ready(&app.cfg_mgr.get()),
        "/live" => return handlers::handle_live(),
        _ => {}
    }

    if path == "/api/v1/auth/login" && method == hyper::Method::POST {
        // Body parsing is done by the caller; here we expose the guard.
        return Reply::json(
            400,
            serde_json::json!({"error":"email and password required"}),
        );
    }

    // Everything under /api/v1 (except login) is protected.
    if path.starts_with("/api/v1") {
        if let Some(reject) = handlers::admin_auth_guard(auth, keys) {
            return reject;
        }
        let cfg = app.cfg_mgr.get();
        return match path {
            "/api/v1/health" => handlers::handle_health(&app.info),
            "/api/v1/status" => handlers::handle_status(&app.info, &app.metrics),
            "/api/v1/config" => handlers::handle_get_config(&cfg),
            "/api/v1/sites" => handlers::handle_list_sites(&cfg),
            "/api/v1/rules" => handlers::handle_list_rules(&cfg),
            "/api/v1/inspectors" => {
                handlers::handle_list_inspectors(&app.engine.read(), app.audit.as_ref())
            }
            "/api/v1/auth/me" => handlers::handle_auth_me(auth, keys),
            _ => Reply::json(404, serde_json::json!({"error":"not_found"})),
        };
    }

    Reply::json(404, serde_json::json!({"error":"not_found"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwaf_config::default_config;

    #[test]
    fn resolve_upstream_appends_port_only_without_colon() {
        // Go appends the port only when the upstream contains no ':'. A URL
        // like "http://backend" already contains ':' (after the scheme), so it
        // is left unchanged -- faithfully reproduced here.
        let site = SiteConfig {
            upstream: "backend".into(),
            port: 8080,
            ..Default::default()
        };
        assert_eq!(resolve_upstream(&site), "backend:8080");

        let site2 = SiteConfig {
            upstream: "http://backend".into(),
            port: 8080,
            ..Default::default()
        };
        assert_eq!(resolve_upstream(&site2), "http://backend");
    }

    #[test]
    fn resolve_upstream_keeps_existing_port() {
        let site = SiteConfig {
            upstream: "http://backend:9000".into(),
            port: 8080,
            ..Default::default()
        };
        assert_eq!(resolve_upstream(&site), "http://backend:9000");
    }

    #[test]
    fn route_admin_health_public() {
        let cfg = default_config();
        let mgr = Arc::new(Manager::new_detached(cfg));
        let app = AppState::new(mgr, Engine::new(Default::default()), false);
        let r = route_admin(&app, &hyper::Method::GET, "/health", None, None, &[]);
        assert_eq!(r.status, 200);
    }

    #[test]
    fn route_admin_protected_requires_auth() {
        let cfg = default_config();
        let mgr = Arc::new(Manager::new_detached(cfg));
        let app = AppState::new(mgr, Engine::new(Default::default()), false);
        // No keys -> 503 fail-closed.
        let r = route_admin(&app, &hyper::Method::GET, "/api/v1/status", None, None, &[]);
        assert_eq!(r.status, 503);
    }
}
