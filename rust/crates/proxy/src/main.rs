//! FortressWAF proxy server entry point.
//!
//! Port of `cmd/proxy/main.go` (flag parsing, server startup and graceful
//! shutdown). The TLS/ACME/Prometheus/DB wiring carries documented deviations;
//! see `rust/DEVIATIONS.md`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use fwaf_config::Manager;
use fwaf_proxy::engine_factory::build_engine;
use fwaf_proxy::server::{serve_admin, serve_proxy, AppState};

#[derive(Parser, Debug)]
#[command(
    name = "fortresswaf",
    about = "FortressWAF - Enterprise WAF & API Security Gateway"
)]
struct Args {
    /// Path to the YAML config file.
    #[arg(long, default_value = "config.yaml")]
    config: String,
    /// Enable dev mode (verbose logging, rule debug).
    #[arg(long)]
    dev: bool,
    /// Admin API server port.
    #[arg(long, default_value_t = 8443)]
    admin_port: u16,
    /// Reverse proxy listening port.
    #[arg(long, default_value_t = 80)]
    proxy_port: u16,
}

#[tokio::main]
async fn main() {
    // rustls 0.23 needs one process-level CryptoProvider when more than one
    // backend feature is visible. Install ring explicitly before any TLS use.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = Args::parse();

    // The docker image passes the config path via CONFIG_PATH.
    if args.config == "config.yaml" {
        if let Ok(env_path) = std::env::var("CONFIG_PATH") {
            if !env_path.is_empty() {
                args.config = env_path;
            }
        }
    }

    // Logging: JSON to stdout, level from --dev (matching slog.NewJSONHandler).
    let level = if args.dev { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();

    tracing::info!(
        config = args.config.as_str(),
        dev = args.dev,
        admin_port = args.admin_port,
        proxy_port = args.proxy_port,
        "fortresswaf starting"
    );

    let cfg_mgr = match Manager::new(&args.config) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(
                path = args.config.as_str(),
                error = e.as_str(),
                "failed to load config"
            );
            std::process::exit(1);
        }
    };
    let cfg_mgr = Arc::new(cfg_mgr);

    let cfg = cfg_mgr.get();
    for site in &cfg.sites {
        tracing::info!(
            name = site.name.as_str(),
            domains = site.domains.join(",").as_str(),
            upstream = site.upstream.as_str(),
            waf_enabled = site.waf_enabled,
            "site configured"
        );
    }

    let engine = build_engine(&cfg, args.dev);

    let app = AppState::new(cfg_mgr.clone(), engine, args.dev);

    // TLS termination: build a rustls acceptor when tls.enabled. Mirrors the Go
    // proxy switching between ListenAndServe and ListenAndServeTLS.
    let tls_acceptor = if cfg.tls.enabled {
        if cfg.tls.cert_file.is_empty() || cfg.tls.key_file.is_empty() {
            tracing::error!("tls.enabled is true but cert_file/key_file are not set");
            std::process::exit(1);
        }
        match fwaf_proxy::tls::build_server_config(
            &cfg.tls.cert_file,
            &cfg.tls.key_file,
            &cfg.tls.min_version,
            cfg.tls.http2_enabled,
            &cfg.mtls.ca_file,
        ) {
            Ok(sc) => {
                tracing::info!(
                    min_version = cfg.tls.min_version.as_str(),
                    http2 = cfg.tls.http2_enabled,
                    mtls = cfg.mtls.enabled,
                    "TLS enabled"
                );
                Some(tokio_rustls::TlsAcceptor::from(sc))
            }
            Err(e) => {
                tracing::error!(error = e.as_str(), "failed to configure TLS");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let proxy_addr: SocketAddr = format!("0.0.0.0:{}", args.proxy_port).parse().unwrap();
    let admin_addr: SocketAddr = format!("0.0.0.0:{}", args.admin_port).parse().unwrap();

    // Shutdown signal shared by the proxy, admin, and metrics listeners.
    let (tx, _rx) = tokio::sync::broadcast::channel::<()>(1);
    let signal_tx = tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received shutdown signal");
        let _ = signal_tx.send(());
    });

    let mut rx_proxy = tx.subscribe();
    let mut rx_admin = tx.subscribe();

    let proxy_shutdown = async move {
        let _ = rx_proxy.recv().await;
    };
    let admin_shutdown = async move {
        let _ = rx_admin.recv().await;
    };

    tracing::info!(port = args.proxy_port, "proxy server listening");
    tracing::info!(port = args.admin_port, "admin server listening");

    let proxy_task = tokio::spawn(serve_proxy(
        app.clone(),
        proxy_addr,
        tls_acceptor,
        proxy_shutdown,
    ));
    let admin_task = tokio::spawn(serve_admin(app.clone(), admin_addr, admin_shutdown));

    // Prometheus exposition on its own listener, matching the Go proxy which
    // started a separate http.Server when prometheus.enabled.
    let metrics_task = if cfg.prometheus.enabled {
        let metrics_addr: SocketAddr = format!("0.0.0.0:{}", cfg.prometheus.port).parse().unwrap();
        tracing::info!(
            port = cfg.prometheus.port,
            path = cfg.prometheus.path.as_str(),
            "prometheus metrics listening"
        );
        let mut rx_metrics = tx.subscribe();
        let metrics_shutdown = async move {
            let _ = rx_metrics.recv().await;
        };
        Some(tokio::spawn(fwaf_proxy::server::serve_metrics(
            app.clone(),
            metrics_addr,
            cfg.prometheus.path.clone(),
            metrics_shutdown,
        )))
    } else {
        None
    };

    match metrics_task {
        Some(m) => {
            let _ = tokio::join!(proxy_task, admin_task, m);
        }
        None => {
            let _ = tokio::join!(proxy_task, admin_task);
        }
    }

    tracing::info!(
        total_requests = app.metrics.get(&app.metrics.total_requests),
        blocked = app.metrics.get(&app.metrics.blocked_requests),
        allowed = app.metrics.get(&app.metrics.allowed_requests),
        excluded = app.metrics.get(&app.metrics.excluded_requests),
        "fortresswaf stopped"
    );

    // Give in-flight work a moment to drain, matching the 30s graceful window.
    tokio::time::sleep(Duration::from_millis(50)).await;
}
