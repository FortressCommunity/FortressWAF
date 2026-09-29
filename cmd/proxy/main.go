package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/FortressWAF/FortressWAF/internal/blocklist"
	"github.com/FortressWAF/FortressWAF/internal/compliance"
	"github.com/FortressWAF/FortressWAF/internal/config"
	"github.com/FortressWAF/FortressWAF/internal/engine"
	"github.com/FortressWAF/FortressWAF/internal/siem"
	"github.com/FortressWAF/FortressWAF/internal/sites"
	"github.com/FortressWAF/FortressWAF/internal/traincorpus"
	"github.com/FortressWAF/FortressWAF/internal/uaparse"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme/autocert"
)

var (
	cyan   = "\033[36m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	bold   = "\033[1m"
	reset  = "\033[0m"
	dim    = "\033[2m"
)

func init() {
	flag.Usage = func() {
		ver := Version
		if ver == "dev" {
			ver = "v1.4.0"
		}
		c := cyan
		g := green
		y := yellow
		b := bold
		n := reset
		d := dim

		s := c + n + `  ╔══════════════════════════════════════════════╗
` + c + `  ║        ` + b + y + `FORTRESS WAF` + b + c + `               ║
` + c + `  ║     Enterprise WAF & API Security Gateway    ║
` + c + `  ╚══════════════════════════════════════════════╝` + n + `

  ` + b + `Version` + n + ` : ` + g + ver + n + `
  ` + d + `Commit` + b + n + ` : ` + g + Commit + n + `

  ` + b + y + `USAGE` + n + `
    fortresswaf [options]

  ` + b + y + `OPTIONS` + n + `
    -config  string     path to YAML config file ` + d + `(default: "config.yaml")` + n + `
                             ` + d + `(overridden by the CONFIG_PATH env var)` + n + `
    -dev                enable dev mode (verbose logging, rule debug)
    -admin-port int     admin API server port ` + d + `(default: 8443)` + n + `
    -proxy-port int     reverse proxy listening port ` + d + `(default: 80)` + n + `

  ` + b + y + `EXAMPLES` + n + `
    fortresswaf                      ` + d + `(uses config.yaml in current dir)` + n + `
    fortresswaf -dev -admin-port 9000
    fortresswaf -proxy-port 8080 -config /etc/fortresswaf/config.yaml
`
		os.Stderr.WriteString(s)
	}
}

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
	startedAt time.Time

	totalRequests    atomic.Int64
	blockedRequests  atomic.Int64
	allowedRequests  atomic.Int64
	excludedRequests atomic.Int64
	challengedReqs   atomic.Int64
	rateLimitedReqs  atomic.Int64
	monitoredReqs    atomic.Int64
	activeConns      atomic.Int64
	bytesSent        atomic.Int64
	bytesReceived    atomic.Int64
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	dev := flag.Bool("dev", false, "enable dev mode: verbose logging and rule debug")
	adminPort := flag.Int("admin-port", 8443, "admin API server port")
	proxyPort := flag.Int("proxy-port", 80, "reverse proxy listening port")
	flag.Parse()

	// The docker image passes the config path via CONFIG_PATH. Use it unless
	// -config was given explicitly on the command line.
	configExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			configExplicit = true
		}
	})
	if !configExplicit {
		if envPath := os.Getenv("CONFIG_PATH"); envPath != "" {
			*configPath = envPath
		}
	}

	level := slog.LevelInfo
	if *dev {
		level = slog.LevelDebug
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))

	startedAt = time.Now()

	slog.Info("fortresswaf starting",
		"version", Version,
		"commit", Commit,
		"build_date", BuildDate,
		"dev", *dev,
		"config", *configPath,
	)

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}

	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		slog.Error("failed to create config manager", "error", err)
		os.Exit(1)
	}
	defer cfgMgr.Close()

	slog.Info("configuration loaded",
		"sites", len(cfg.Sites),
		"rules", len(cfg.Rules),
		"admin_port", *adminPort,
		"proxy_port", *proxyPort,
	)

	for _, site := range cfg.Sites {
		slog.Info("site configured",
			"name", site.Name,
			"domains", strings.Join(site.Domains, ","),
			"upstream", site.Upstream,
			"waf_enabled", site.WAFEnabled,
		)
	}

	eCfg := buildEngineConfig(cfg, *dev)
	e := engine.New(eCfg)

	// Only peers listed under admin.trusted_proxies may set forwarding
	// headers. With no list configured the proxy treats itself as the edge,
	// so a client cannot pick the address its traffic is attributed to.
	if invalid := e.SetTrustedProxies(cfg.Admin.TrustedProxies); len(invalid) > 0 {
		slog.Warn("ignoring invalid trusted_proxies entries",
			"invalid", invalid, "kept", cfg.Admin.TrustedProxies)
	}
	if len(cfg.Admin.TrustedProxies) > 0 {
		slog.Info("trusted proxies configured", "cidrs", cfg.Admin.TrustedProxies)
	}

	// Initialize rewrite manager
	rewriteMgr := engine.NewRewriteManager()
	for _, r := range cfg.RewriteRules {
		if !r.Enabled {
			continue
		}
		rewriteMgr.AddRule(engine.RewriteRule{
			Name:       r.Name,
			Conditions: engineRewriteConditions(r.Conditions),
			Actions:    engineRewriteActions(r.Actions),
		})
		slog.Debug("rewrite rule loaded", "rule", r.Name)
	}

	// Initialize SIEM if enabled
	var siemMgr *siem.Manager
	if cfg.SIEM.Enabled {
		var err error
		siemCfg := siem.SIEMConfig{
			Enabled:        cfg.SIEM.Enabled,
			ExportInterval: cfg.SIEM.ExportInterval,
			BatchSize:      cfg.SIEM.BatchSize,
		}
		for _, e := range cfg.SIEM.Exporters {
			siemCfg.Exporters = append(siemCfg.Exporters, siem.ExporterConfig{
				Type:      e.Type,
				Enabled:   e.Enabled,
				URL:       e.URL,
				Token:     e.Token,
				Index:     e.Index,
				Username:  e.Username,
				Password:  e.Password,
				VerifySSL: e.VerifySSL,
			})
		}
		siemMgr, err = siem.NewManager(siemCfg)
		if err != nil {
			slog.Warn("siem init failed", "error", err)
		} else {
			slog.Info("siem manager initialized", "exporters", len(cfg.SIEM.Exporters))
		}
	}

	cfgMgr.OnChange(func(newCfg *config.Config) {
		slog.Info("config reloaded",
			"sites", len(newCfg.Sites),
			"rules", len(newCfg.Rules),
		)
	})

	// Initialize PostgreSQL if configured
	if cfg.DB.Driver == "postgres" && cfg.DB.DSN != "" {
		go initDatabase(cfg.DB.Driver, cfg.DB.DSN, cfg.DB.MaxOpen, cfg.DB.MaxIdle)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Hash-chained audit trail for security events. The compliance engine
	// verifies the PCI/SOC2/HIPAA audit controls against it, and blocked
	// requests append to it in the WAF handler below.
	auditLog := compliance.NewAuditLog()
	compEngine := compliance.NewComplianceEngine(buildComplianceInput(cfg, auditLog))

	proxyHandler := newWAFHandler(cfgMgr, e, rewriteMgr, siemMgr, auditLog, *dev)

	proxySrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *proxyPort),
		Handler:           proxyHandler,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	// Configure TLS with HTTP/2, OCSP, ACME support
	if cfg.TLS.Enabled {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if cfg.TLS.HTTP2Enabled {
			tlsCfg.NextProtos = []string{"h2", "http/1.1"}
		}
		if cfg.TLS.OCSPEnabled {
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				return nil
			}
		}
		if cfg.TLS.ACMEEnabled && cfg.TLS.ACMEEmail != "" {
			m := &autocert.Manager{
				Cache:      autocert.DirCache(cfg.TLS.ACMECacheDir),
				Prompt:     autocert.AcceptTOS,
				Email:      cfg.TLS.ACMEEmail,
				HostPolicy: autocert.HostWhitelist(cfg.TLS.ACMEDomains...),
			}
			proxySrv.TLSConfig = m.TLSConfig()
			proxySrv.TLSConfig.MinVersion = tls.VersionTLS12
		} else if cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
			proxySrv.TLSConfig = tlsCfg
		}
	}

	adminRouter := newAdminRouter(cfgMgr, e, auditLog, compEngine, *adminPort)

	// Add prometheus metrics on separate listener if enabled
	if cfg.Prometheus.Enabled {
		go func() {
			mux := http.NewServeMux()
			mux.Handle(cfg.Prometheus.Path, promhttp.Handler())
			addr := fmt.Sprintf(":%d", cfg.Prometheus.Port)
			slog.Info("prometheus metrics listening", "addr", addr, "path", cfg.Prometheus.Path)
			if err := http.ListenAndServe(addr, mux); err != nil {
				slog.Warn("prometheus server stopped", "error", err)
			}
		}()
	}
	adminSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *adminPort),
		Handler:           adminRouter,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig.String())
		cancel()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	proxyErr := make(chan error, 1)
	adminErr := make(chan error, 1)

	go func() {
		defer wg.Done()
		slog.Info("proxy server listening", "port", *proxyPort)
		var err error
		if cfg.TLS.Enabled && (cfg.TLS.CertFile != "" || cfg.TLS.ACMEEnabled) {
			err = proxySrv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			err = proxySrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("proxy server fatal error", "error", err)
			proxyErr <- err
		}
	}()

	go func() {
		defer wg.Done()
		slog.Info("admin server listening", "port", *adminPort)
		if err := adminSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("admin server fatal error", "error", err)
			adminErr <- err
		}
	}()

	select {
	case err := <-proxyErr:
		slog.Error("proxy server exited", "error", err)
	case err := <-adminErr:
		slog.Error("admin server exited", "error", err)
	case <-ctx.Done():
	}

	slog.Info("draining connections...", "active", activeConns.Load())

	var wgShutdown sync.WaitGroup
	wgShutdown.Add(2)

	proxyCtx, proxyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	adminCtx, adminCancel := context.WithTimeout(context.Background(), 30*time.Second)

	go func() {
		defer wgShutdown.Done()
		defer proxyCancel()
		if err := proxySrv.Shutdown(proxyCtx); err != nil {
			slog.Error("proxy server shutdown error", "error", err)
		} else {
			slog.Info("proxy server shut down")
		}
	}()

	go func() {
		defer wgShutdown.Done()
		defer adminCancel()
		if err := adminSrv.Shutdown(adminCtx); err != nil {
			slog.Error("admin server shutdown error", "error", err)
		} else {
			slog.Info("admin server shut down")
		}
	}()

	wgShutdown.Wait()

	wg.Wait()

	slog.Info("fortresswaf stopped",
		"uptime", time.Since(startedAt).Round(time.Second),
		"total_requests", totalRequests.Load(),
		"blocked", blockedRequests.Load(),
		"allowed", allowedRequests.Load(),
		"excluded", excludedRequests.Load(),
	)
}

type wafHandler struct {
	mu           sync.RWMutex
	cfgMgr       *config.Manager
	engine       *engine.Engine
	rewriteMgr   *engine.RewriteManager
	siemMgr      *siem.Manager
	auditLog     *compliance.AuditLog
	responseLeak *engine.ResponseLeakInspector
	bans         *blocklist.Store
	trainer      *traincorpus.Collector
	dev          bool
	proxies      map[string]*httputil.ReverseProxy
}

// globalBans and globalTrainer are shared with the admin API so the console can
// list bans and the collector reports the same counters the request path feeds.
var (
	globalBans    = blocklist.New()
	globalTrainer *traincorpus.Collector
)

func newWAFHandler(cfgMgr *config.Manager, e *engine.Engine, rm *engine.RewriteManager, sm *siem.Manager, al *compliance.AuditLog, dev bool) http.Handler {
	respInspect := cfgMgr.Get().RespInspect
	cfg := cfgMgr.Get()
	if globalTrainer == nil && cfg.Training.Enabled && cfg.Training.CorpusDir != "" {
		globalTrainer = traincorpus.NewCollector(cfg.Training.CorpusDir)
	}
	h := &wafHandler{
		cfgMgr:       cfgMgr,
		engine:       e,
		rewriteMgr:   rm,
		siemMgr:      sm,
		auditLog:     al,
		responseLeak: engine.NewResponseLeakInspector(respInspect.Enabled && respInspect.InspectBody, respInspect.Block, 1<<20),
		bans:         globalBans,
		trainer:      globalTrainer,
		dev:          dev,
		proxies:      make(map[string]*httputil.ReverseProxy),
	}

	for _, site := range cfgMgr.Get().Sites {
		if err := h.buildProxy(&site); err != nil {
			slog.Error("failed to build proxy for site", "site", site.Name, "error", err)
		}
	}

	cfgMgr.OnChange(func(newCfg *config.Config) {
		h.mu.Lock()
		defer h.mu.Unlock()
		for _, site := range newCfg.Sites {
			if _, ok := h.proxies[site.Name]; !ok {
				if err := h.buildProxy(&site); err != nil {
					slog.Error("failed to build proxy for new site", "site", site.Name, "error", err)
				}
			}
		}
	})

	return h
}

func (h *wafHandler) buildProxy(site *config.SiteConfig) error {
	upstream := site.Upstream
	if site.Port > 0 && !strings.Contains(upstream, ":") {
		upstream = fmt.Sprintf("%s:%d", upstream, site.Port)
	}

	target, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("parse upstream %q: %w", upstream, err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.SetXForwarded()
			r.Out.Host = r.In.Host
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			ResponseHeaderTimeout: 30 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("upstream error",
				"error", err,
				"host", r.Host,
				"path", r.URL.Path,
			)
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":  "bad_gateway",
				"detail": "upstream unreachable",
			})
		},
	}

	h.proxies[site.Name] = proxy
	return nil
}

func (h *wafHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	activeConns.Add(1)
	defer activeConns.Add(-1)

	clientIP := h.engine.ClientIP(r)

	// A banned address is refused before inspection: no rule needs to run.
	if h.bans != nil && h.bans.IsBanned(clientIP) {
		blockedRequests.Add(1)
		h.recordRequest(r, "request_blocked", "banned_ip", "blocked", "", clientIP)
		w.Header().Set("X-FortressWAF-Action", "block")
		w.Header().Set("X-FortressWAF-Rule", "BAN001")
		writeBlockedResponse(w, r, &engine.Decision{
			Action:   engine.ActionBlock,
			RuleID:   "BAN001",
			RuleName: "IP address is banned",
			Severity: "high",
			Evidence: "source address is on the operator ban list",
		})
		return
	}

	host := strings.Split(r.Host, ":")[0]
	cfg := h.cfgMgr.Get()
	site := cfg.FindSiteByDomain(host)

	if site == nil {
		if len(cfg.Sites) > 0 {
			site = &cfg.Sites[0]
		} else {
			writeJSON(w, http.StatusBadGateway, map[string]interface{}{
				"error":  "no_site_configured",
				"detail": fmt.Sprintf("no site configured for host %q", host),
			})
			blockedRequests.Add(1)
			return
		}
	}

	if !site.WAFEnabled {
		h.forwardRequest(w, r, site)
		return
	}

	// Paths the operator excluded are forwarded without inspection. Counted
	// separately so an exempt prefix shows up in /metrics instead of looking
	// like ordinary allowed traffic.
	if site.ExcludesPath(r.URL.Path) {
		excludedRequests.Add(1)
		h.forwardRequest(w, r, site)
		return
	}

	decision, err := h.engine.InspectRequest(r)
	if err != nil {
		slog.Error("engine inspection error", "error", err, "host", r.Host, "path", r.URL.Path)
		if h.dev {
			h.forwardRequest(w, r, site)
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error":  "waf_error",
			"detail": "inspection engine error",
		})
		return
	}

	// An inspector can ask for the source to be banned (a DDoS flood, or a
	// repeat bot offender). Enforce it here, in the proxy, so the engine keeps
	// no ban state. The ban is time-limited and reversible, and it is logged.
	if decision != nil && decision.BanRequest {
		h.applyAutoBan(r, clientIP, decision)
	}

	switch decision.Action {
	case engine.ActionAllow:
		allowedRequests.Add(1)
		h.recordRequest(r, "request_allowed", "", "allowed", "", clientIP)
		h.forwardRequest(w, r, site)

	case engine.ActionBlock:
		blockedRequests.Add(1)
		h.recordRequest(r, "request_blocked", decision.RuleID+": "+decision.RuleName, "blocked", decision.Evidence, clientIP)
		h.collectTraining(r, decision, clientIP)
		slog.Warn("request blocked",
			"host", r.Host,
			"path", r.URL.Path,
			"ip", r.RemoteAddr,
			"rule_id", decision.RuleID,
			"rule_name", decision.RuleName,
			"severity", decision.Severity,
			"evidence", decision.Evidence,
			"score", decision.Score,
		)
		w.Header().Set("X-FortressWAF-Action", "block")
		w.Header().Set("X-FortressWAF-Rule", decision.RuleID)
		// Raise an alert for high-severity blocks so the operator inbox and the
		// dashboard reflect live activity. The store deduplicates repeats.
		if decision.Severity == "critical" || decision.Severity == "high" {
			serverAlerts.add(
				decision.Severity,
				decision.RuleName,
				fmt.Sprintf("%s %s from %s blocked (%s)", r.Method, r.URL.Path, h.engine.ClientIP(r), decision.Evidence),
				decision.RuleID,
			)
		}
		writeBlockedResponse(w, r, decision)

	case engine.ActionChallenge:
		challengedReqs.Add(1)
		h.recordRequest(r, "request_challenged", decision.RuleID, "challenged", decision.Evidence, clientIP)
		slog.Info("challenge issued",
			"host", r.Host,
			"path", r.URL.Path,
			"ip", r.RemoteAddr,
			"rule_id", decision.RuleID,
		)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-FortressWAF-Action", "challenge")
		w.WriteHeader(http.StatusForbidden)
		w.Write(challengePage(r))

	case engine.ActionMonitor:
		monitoredReqs.Add(1)
		h.recordRequest(r, "request_monitored", decision.RuleID, "monitored", decision.Evidence, clientIP)
		slog.Info("monitor: request passed through",
			"host", r.Host,
			"path", r.URL.Path,
			"ip", r.RemoteAddr,
			"rule_id", decision.RuleID,
			"severity", decision.Severity,
			"score", decision.Score,
		)
		w.Header().Set("X-FortressWAF-Monitored", "true")
		w.Header().Set("X-FortressWAF-Rule", decision.RuleID)
		h.forwardRequest(w, r, site)

	case engine.ActionRateLimit:
		rateLimitedReqs.Add(1)
		h.recordRequest(r, "request_rate_limited", "RATE", "rate_limited", "", clientIP)
		slog.Warn("rate limited",
			"host", r.Host,
			"path", r.URL.Path,
			"ip", r.RemoteAddr,
		)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.Header().Set("X-RateLimit-Limit", "100")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(60*time.Second).Unix()))
		w.Header().Set("X-FortressWAF-Action", "rate_limit")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":       "rate_limited",
			"detail":      "too many requests",
			"retry_after": 60,
		})

	default:
		allowedRequests.Add(1)
		h.recordRequest(r, "request_allowed", "", "allowed", "", clientIP)
		h.forwardRequest(w, r, site)
	}
}

// applyAutoBan bans an address that an inspector flagged, for the requested
// duration (or the default). It is skipped when the blocklist is unavailable,
// the address is loopback or a trusted proxy (banning a hop would lock out
// everyone behind it), or the duration is negative (auto-ban disabled).
// It is idempotent — re-banning refreshes the expiry — and it raises an alert.
func (h *wafHandler) applyAutoBan(r *http.Request, ip string, decision *engine.Decision) {
	if h.bans == nil || ip == "" || net.ParseIP(ip) == nil {
		return
	}
	if net.ParseIP(ip).IsLoopback() || h.engine.IsTrustedProxy(ip) {
		return
	}
	dur := decision.BanDuration
	if dur <= 0 {
		dur = 10 * time.Minute
	}
	entry, err := h.bans.Ban(ip, "auto: "+decision.RuleID+" "+decision.RuleName, "waf", dur)
	if err != nil {
		slog.Warn("auto-ban failed", "ip", ip, "rule", decision.RuleID, "error", err)
		return
	}
	slog.Warn("auto-banned address", "ip", ip, "rule", decision.RuleID, "for", dur.String())
	serverAlerts.add("high", "Auto-ban: "+decision.RuleName,
		fmt.Sprintf("banned %s for %s (%s)", ip, dur, decision.RuleID), decision.RuleID)
	if h.auditLog != nil {
		_ = h.auditLog.Append(compliance.AuditEntry{
			ActorType: "waf",
			ActorIP:   ip,
			Action:    "ip_auto_banned",
			Resource:  r.Host + r.URL.Path,
			Result:    "banned",
			Metadata:  fmt.Sprintf("%s: %s (expires %s)", decision.RuleID, decision.RuleName, entry.ExpiresAt.Format(time.RFC3339)),
		})
	}
}

// recordRequest writes one enriched audit entry for a request: method, path,
// source IP, parsed browser/device, and the request headers. It is called for
// every inspected request so the console log is complete, not just for blocks.
func (h *wafHandler) recordRequest(r *http.Request, action, metadata, result, evidence, clientIP string) {
	if h.auditLog == nil {
		return
	}
	ua := r.UserAgent()
	info := uaparse.Parse(ua)
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		if len(v) == 0 {
			continue
		}
		if isSensitiveHeader(k) {
			headers[k] = "[redacted]"
			continue
		}
		headers[k] = v[0]
	}
	meta := metadata
	if evidence != "" {
		meta = metadata + " | " + evidence
	}
	_ = h.auditLog.Append(compliance.AuditEntry{
		ActorType: "client",
		ActorIP:   clientIP,
		Action:    action,
		Resource:  r.Host + r.URL.Path,
		Result:    result,
		Metadata:  meta,
		Method:    r.Method,
		Path:      r.URL.Path,
		UserAgent: ua,
		Browser:   info.Browser,
		Device:    info.Device,
		Headers:   headers,
	})
}

// collectTraining offers a high-confidence block to the corpus collector. It
// uses the request's own payload (query, form, or body) as the sample text and
// the rule family as the label; anything the collector deems unfit is dropped.
func (h *wafHandler) collectTraining(r *http.Request, decision *engine.Decision, clientIP string) {
	if h.trainer == nil || !h.trainer.Enabled() {
		return
	}
	payload := bestPayload(r, decision)
	if payload == "" {
		return
	}
	kept, reason := h.trainer.Consider(traincorpus.Sample{
		RuleID:     decision.RuleID,
		Payload:    payload,
		Source:     decision.InspectorName,
		ActorIP:    clientIP,
		Score:      decision.Score,
		ObservedAt: time.Now(),
	})
	if kept {
		slog.Info("training sample collected", "rule", decision.RuleID, "category", decision.RuleID)
	} else if h.dev {
		slog.Debug("training sample rejected", "rule", decision.RuleID, "reason", reason)
	}
}

// isSensitiveHeader reports whether a header's value must never be written to
// the audit log. HTTP header names are case-insensitive, so the check lowercases
// the name, and it matches a prefix/substring rule rather than an exact list:
// the previous exact-case check missed X-API-Key (which this very system uses
// for auth) and any differently-cased spelling, leaking credentials into logs.
func isSensitiveHeader(name string) bool {
	n := strings.ToLower(name)
	switch n {
	case "authorization", "proxy-authorization", "cookie", "set-cookie",
		"x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
		"x-xsrf-token", "x-session-token", "x-forwarded-authorization":
		return true
	}
	// Anything that looks like a credential by name.
	for _, marker := range []string{"token", "secret", "password", "passwd", "api-key", "apikey", "auth", "credential", "session", "cookie"} {
		if strings.Contains(n, marker) {
			return true
		}
	}
	return false
}

// bestPayload extracts the most attack-like string from a request: the offending
// query value, form value, or body. It is deliberately narrow -- it returns the
// request's own bytes, never a synthesized string -- and prefers the decoded
// value over the "key=value" pair so the corpus holds the payload itself.
func bestPayload(r *http.Request, decision *engine.Decision) string {
	// Prefer the longest decoded query value: that is the untrusted input the
	// inspector actually matched, without the parameter name.
	best := ""
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if len(v) > len(best) {
				best = v
			}
		}
	}
	if best != "" {
		return best
	}
	if r.Method == "POST" && r.ContentLength > 0 && r.ContentLength <= 4096 {
		buf := make([]byte, r.ContentLength)
		if n, err := io.ReadFull(r.Body, buf); err == nil {
			r.Body = io.NopCloser(bytes.NewReader(buf))
			return string(buf[:n])
		}
	}
	if r.URL.RawQuery != "" {
		return r.URL.RawQuery
	}
	return decision.Evidence
}

func (h *wafHandler) forwardRequest(w http.ResponseWriter, r *http.Request, site *config.SiteConfig) {
	h.mu.Lock()
	proxy, ok := h.proxies[site.Name]

	if !ok {
		if err := h.buildProxy(site); err != nil {
			h.mu.Unlock()
			slog.Error("failed to build proxy on-the-fly", "site", site.Name, "error", err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		proxy = h.proxies[site.Name]
	}
	h.mu.Unlock()

	// When response inspection is on, buffer the origin response so it can be
	// scanned for leaked secrets before any byte reaches the client. The writer
	// holds the response until Commit, so a leak can still be blocked.
	if h.responseLeak != nil && h.responseLeak.Enabled() {
		rw := engine.NewResponseWriter(w, true, 1<<20)
		proxy.ServeHTTP(rw, r)

		contentType := rw.Header().Get("Content-Type")
		if decision := h.responseLeak.InspectResponse(contentType, rw.StatusCode, rw.Body); decision != nil {
			if !decision.Blocked {
				// Monitor mode (the default): log the leak but let the response
				// through. Content scanning stays advisory until an operator
				// opts into blocking.
				monitoredReqs.Add(1)
				slog.Warn("response leak detected (monitor mode, not blocked)",
					"host", r.Host,
					"path", r.URL.Path,
					"ip", r.RemoteAddr,
					"rule_id", decision.RuleID,
					"rule_name", decision.RuleName,
					"severity", decision.Severity,
				)
				rw.Commit()
				return
			}

			blockedRequests.Add(1)
			serverAlerts.add(
				decision.Severity,
				"Data leak blocked: "+decision.RuleName,
				fmt.Sprintf("upstream response for %s leaked data to %s", r.URL.Path, h.engine.ClientIP(r)),
				decision.RuleID,
			)
			slog.Warn("response blocked: data leak",
				"host", r.Host,
				"path", r.URL.Path,
				"ip", r.RemoteAddr,
				"rule_id", decision.RuleID,
				"rule_name", decision.RuleName,
				"severity", decision.Severity,
			)
			if h.auditLog != nil {
				_ = h.auditLog.Append(compliance.AuditEntry{
					ActorType: "upstream",
					ActorIP:   h.engine.ClientIP(r),
					Action:    "response_blocked",
					Resource:  r.Host + r.URL.Path,
					Result:    "blocked",
					Metadata:  decision.RuleID + ": " + decision.RuleName,
				})
			}
			// The origin response was buffered, not sent, so replace it with a
			// generic block reply. The leaked value never left the process.
			out := rw.Discard()
			out.Header().Set("Content-Type", "application/json")
			out.Header().Set("X-FortressWAF-Action", "block")
			out.Header().Set("X-FortressWAF-Rule", decision.RuleID)
			out.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(out).Encode(map[string]interface{}{
				"blocked":   true,
				"action":    "block",
				"rule_id":   decision.RuleID,
				"rule_name": decision.RuleName,
				"severity":  decision.Severity,
				"reason":    "response contained sensitive data",
			})
			return
		}
		rw.Commit()
		return
	}

	proxy.ServeHTTP(w, r)
}

func newAdminRouter(cfgMgr *config.Manager, e *engine.Engine, al *compliance.AuditLog, ce *compliance.ComplianceEngine, adminPort int) http.Handler {
	r := mux.NewRouter()
	r.Use(corsMiddleware(cfgMgr))

	// 5 wrong attempts per minute per source address, then a 15-minute lock.
	// The admin key grants full admin access, so grinding it must not be
	// cheaper than any other credential the WAF protects.
	limiter := newLoginLimiter(5, 15*time.Minute, time.Minute)
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			limiter.gc()
		}
	}()

	// Browsers send an OPTIONS preflight before the real request when it
	// carries an Authorization header. gorilla/mux runs middleware only for
	// routes that match, so a preflight against a GET-only route would 404
	// and the browser would block the follow-up request. Answer preflight for
	// the whole API prefix here, before method-specific matching.
	r.PathPrefix("/api/").Methods("OPTIONS").Handler(corsPreflightHandler(cfgMgr))

	r.HandleFunc("/health", handleHealth).Methods("GET")
	r.HandleFunc("/metrics", handleMetrics).Methods("GET")
	r.HandleFunc("/ready", handleReady(cfgMgr)).Methods("GET")
	r.HandleFunc("/live", handleLive).Methods("GET")

	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/auth/login", handleAuthLogin(cfgMgr, limiter)).Methods("POST", "OPTIONS")

	protected := r.PathPrefix("/api/v1").Subrouter()
	protected.Use(adminAuthMiddleware(cfgMgr))
	protected.HandleFunc("/health", handleHealth).Methods("GET")
	protected.HandleFunc("/status", handleStatus).Methods("GET")
	protected.HandleFunc("/config", handleGetConfig(cfgMgr)).Methods("GET")
	protected.HandleFunc("/reload", handleReload(cfgMgr)).Methods("POST")
	protected.HandleFunc("/sites", handleListSites(cfgMgr)).Methods("GET")
	protected.HandleFunc("/rules", handleListRules(cfgMgr)).Methods("GET")
	protected.HandleFunc("/inspectors", handleListInspectors(e, al)).Methods("GET")
	protected.HandleFunc("/inspectors/{name}", handleInspectorDetail(e, al)).Methods("GET")

	// Operator console extras: metrics snapshot, threat analytics, live traffic,
	// alert inbox, and a secret-free config view.
	protected.HandleFunc("/metrics/snapshot", handleMetricsSnapshot()).Methods("GET")
	protected.HandleFunc("/analytics", handleAnalytics(al)).Methods("GET")
	protected.HandleFunc("/traffic", handleTrafficLog(al)).Methods("GET")
	protected.HandleFunc("/config/detail", handleConfigDetail(cfgMgr)).Methods("GET")
	protected.HandleFunc("/alerts", handleAlerts()).Methods("GET", "POST")
	protected.HandleFunc("/alerts/{id}/ack", handleAlertByID(authIdentity(cfgMgr))).Methods("POST", "OPTIONS")
	protected.HandleFunc("/alerts/{id}", handleAlertByID(authIdentity(cfgMgr))).Methods("DELETE", "OPTIONS")

	// Protected domains: list, add (with DNS verification), remove.
	domainMgr := sites.NewManager(cfgMgr, func(action, detail string) {
		if al != nil {
			_ = al.Append(compliance.AuditEntry{
				ActorType: "operator",
				Action:    action,
				Resource:  detail,
				Result:    "ok",
			})
		}
	})
	protected.HandleFunc("/domains", handleDomains(domainMgr, cfgMgr)).Methods("GET", "POST", "OPTIONS")
	protected.HandleFunc("/domains/{domain}", handleDomainDelete(domainMgr)).Methods("DELETE", "OPTIONS")
	protected.HandleFunc("/domains/{domain}/verify", handleDomainVerify(cfgMgr)).Methods("POST", "OPTIONS")

	// IP ban list: list, ban, unban.
	protected.HandleFunc("/bans", handleBans()).Methods("GET", "POST", "OPTIONS")
	protected.HandleFunc("/bans/{ip}", handleBanDelete()).Methods("DELETE", "OPTIONS")

	// Training corpus status for the live collector.
	protected.HandleFunc("/training/status", handleTrainingStatus(cfgMgr)).Methods("GET")

	// Compliance + audit trail: verified against live runtime state.
	protected.HandleFunc("/compliance/frameworks", handleComplianceFrameworks(ce)).Methods("GET")
	protected.HandleFunc("/compliance/{framework}/assessment", handleComplianceAssessment(ce)).Methods("GET")
	protected.HandleFunc("/audit", handleAuditLog(al)).Methods("GET")

	// /auth/me returns the caller's identity, so it must be authenticated like
	// every other protected route. Registering it on the public subrouter made
	// it echo any bearer token back as an admin.
	protected.HandleFunc("/auth/me", handleAuthMe(cfgMgr)).Methods("GET")

	return r
}

// corsMiddleware allows only the origins listed under admin.cors_origins.
// Sending "Access-Control-Allow-Origin: *" alongside an Authorization header
// lets any website read authenticated API responses, so the origin is echoed
// back only when it is explicitly permitted.
func corsMiddleware(cfgMgr *config.Manager) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && originAllowed(origin, cfgMgr.Get().Admin.CORSOrigins) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// corsPreflightHandler answers the CORS preflight (OPTIONS) for any API path.
// It mirrors the allow rules of corsMiddleware; an unlisted origin gets a bare
// 204, which the browser treats as a failed preflight.
func corsPreflightHandler(cfgMgr *config.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && originAllowed(origin, cfgMgr.Get().Admin.CORSOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "600")
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// originAllowed reports whether origin is in the allow list. An empty list
// means no cross-origin access is granted.
func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(origin, a) {
			return true
		}
	}
	return false
}

type authLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func handleAuthLogin(cfgMgr *config.Manager, limiter *loginLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Stop credential grinding against the admin console. The lock is per
		// source address; a locked-out caller gets 429 with a Retry-After.
		if locked, retryAfter := limiter.isLocked(r); locked {
			w.Header().Set("Retry-After", fmt.Sprintf("%.0f", retryAfter.Seconds()))
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":  "too_many_attempts",
				"detail": "too many failed login attempts, try again later",
			})
			return
		}

		var req authLoginRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
		if req.Email == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password required"})
			return
		}

		cfg := cfgMgr.Get()

		// Nothing to authenticate against: without configured API keys the
		// login endpoint used to index cfg.Admin.APIKeys[0] and panic.
		if len(cfg.Admin.APIKeys) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error":  "admin credentials not configured",
				"detail": "set admin.api_keys in the config file",
			})
			return
		}

		// Credentials. Each entry in api_keys is a secret the console may hold:
		// with two entries the first is the username and the second the
		// password, and BOTH must match -- a correct username with a wrong
		// password must not log in. With a single entry (legacy/demo) that one
		// value is accepted in either field. Every comparison is constant time.
		validUser := false
		validPass := false
		if len(cfg.Admin.APIKeys) >= 2 {
			user := []byte(cfg.Admin.APIKeys[0])
			pass := []byte(cfg.Admin.APIKeys[1])
			validUser = subtle.ConstantTimeCompare([]byte(req.Email), user) == 1
			validPass = subtle.ConstantTimeCompare([]byte(req.Password), pass) == 1
		} else {
			key := []byte(cfg.Admin.APIKeys[0])
			validUser = subtle.ConstantTimeCompare([]byte(req.Email), key) == 1
			validPass = subtle.ConstantTimeCompare([]byte(req.Password), key) == 1
		}
		if !validUser || !validPass {
			limiter.recordFailure(r)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		limiter.recordSuccess(r)

		// The bearer token is the username key; it is compared against the full
		// key list on every subsequent request.
		token := cfg.Admin.APIKeys[0]
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"token": token,
			"user": map[string]interface{}{
				"id":    req.Email,
				"email": req.Email,
				"name":  req.Email,
				"role":  "admin",
			},
		})
	}
}

// authIdentity returns a function that reads the caller's identity from the
// bearer token (the configured admin key). It is used to attribute an action
// such as acknowledging an alert.
func authIdentity(cfgMgr *config.Manager) func(*http.Request) string {
	return func(r *http.Request) string {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		cfg := cfgMgr.Get()
		if validAPIKey(token, cfg.Admin.APIKeys) {
			return token
		}
		return "operator"
	}
}

func handleAuthMe(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == auth {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		// The token must be a real configured key. Previously any string was
		// accepted and reflected back as an admin identity.
		cfg := cfgMgr.Get()
		if !validAPIKey(token, cfg.Admin.APIKeys) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"id":    token,
			"email": token,
			"name":  "Admin",
			"role":  "admin",
		})
	}
}

// validAPIKey reports whether key matches one of the configured keys using a
// constant-time comparison, so the response time does not leak how much of a
// guessed key was correct.
func validAPIKey(key string, keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	kb := []byte(key)
	var ok bool
	for _, configured := range keys {
		cb := []byte(configured)
		if subtle.ConstantTimeCompare(kb, cb) == 1 {
			ok = true
		}
	}
	return ok
}

func adminAuthMiddleware(cfgMgr *config.Manager) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg := cfgMgr.Get()
			// Fail closed: with no keys configured there is nothing to
			// authenticate against, so the protected endpoints stay locked
			// rather than becoming open.
			if len(cfg.Admin.APIKeys) == 0 {
				writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
					"error":  "admin credentials not configured",
					"detail": "set admin.api_keys in the config file",
				})
				return
			}

			auth := r.Header.Get("Authorization")
			if auth == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"error":  "unauthorized",
					"detail": "missing Authorization header",
				})
				return
			}

			token := strings.TrimPrefix(auth, "Bearer ")
			if token == auth {
				writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
					"error":  "unauthorized",
					"detail": "Authorization must be Bearer token",
				})
				return
			}

			if !validAPIKey(token, cfg.Admin.APIKeys) {
				writeJSON(w, http.StatusForbidden, map[string]interface{}{
					"error":  "forbidden",
					"detail": "invalid API key",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"version":   Version,
		"commit":    Commit,
		"uptime":    time.Since(startedAt).String(),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startedAt).Seconds()
	rps := float64(0)
	if uptime > 0 {
		rps = float64(totalRequests.Load()) / uptime
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP fortresswaf_requests_total Total number of requests\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_total counter\n")
	fmt.Fprintf(w, "fortresswaf_requests_total %d\n", totalRequests.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_requests_allowed Total allowed requests\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_allowed counter\n")
	fmt.Fprintf(w, "fortresswaf_requests_allowed %d\n", allowedRequests.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_requests_blocked Total blocked requests\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_blocked counter\n")
	fmt.Fprintf(w, "fortresswaf_requests_blocked %d\n", blockedRequests.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_requests_excluded Requests forwarded by an exclude_paths rule\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_excluded counter\n")
	fmt.Fprintf(w, "fortresswaf_requests_excluded %d\n", excludedRequests.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_requests_challenged Total challenged requests\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_challenged counter\n")
	fmt.Fprintf(w, "fortresswaf_requests_challenged %d\n", challengedReqs.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_requests_rate_limited Total rate-limited requests\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_rate_limited counter\n")
	fmt.Fprintf(w, "fortresswaf_requests_rate_limited %d\n", rateLimitedReqs.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_requests_monitored Total monitored requests\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_monitored counter\n")
	fmt.Fprintf(w, "fortresswaf_requests_monitored %d\n", monitoredReqs.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_active_connections Current active connections\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_active_connections gauge\n")
	fmt.Fprintf(w, "fortresswaf_active_connections %d\n", activeConns.Load())

	fmt.Fprintf(w, "# HELP fortresswaf_uptime_seconds Uptime in seconds\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_uptime_seconds gauge\n")
	fmt.Fprintf(w, "fortresswaf_uptime_seconds %f\n", uptime)

	fmt.Fprintf(w, "# HELP fortresswaf_requests_per_second Current requests per second\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_requests_per_second gauge\n")
	fmt.Fprintf(w, "fortresswaf_requests_per_second %f\n", rps)

	fmt.Fprintf(w, "# HELP fortresswaf_version_info FortressWAF version info\n")
	fmt.Fprintf(w, "# TYPE fortresswaf_version_info gauge\n")
	fmt.Fprintf(w, "fortresswaf_version_info{version=%q,commit=%q} 1\n", Version, Commit)
}

func handleReady(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(cfgMgr.Get().Sites) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"status": "not_ready",
				"reason": "no sites configured",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "ready",
		})
	}
}

func handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "alive",
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startedAt)
	rps := float64(0)
	secs := uptime.Seconds()
	if secs > 0 {
		rps = float64(totalRequests.Load()) / secs
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"version":            Version,
		"commit":             Commit,
		"build_date":         BuildDate,
		"uptime":             uptime.String(),
		"uptime_seconds":     int(secs),
		"requests_per_sec":   rps,
		"total_requests":     totalRequests.Load(),
		"blocked_requests":   blockedRequests.Load(),
		"allowed_requests":   allowedRequests.Load(),
		"active_connections": activeConns.Load(),
		"challenged":         challengedReqs.Load(),
		"rate_limited":       rateLimitedReqs.Load(),
		"monitored":          monitoredReqs.Load(),
	})
}

func handleGetConfig(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cfgMgr.Get()
		resp := map[string]interface{}{
			"sites_count":   len(cfg.Sites),
			"rules_count":   len(cfg.Rules),
			"ml_enabled":    cfg.ML.Enabled,
			"redis_enabled": cfg.Redis.Enabled,
			"admin_port":    cfg.Admin.Port,
			"sites":         make([]map[string]interface{}, 0, len(cfg.Sites)),
		}
		for _, s := range cfg.Sites {
			resp["sites"] = append(resp["sites"].([]map[string]interface{}), map[string]interface{}{
				"name":        s.Name,
				"domains":     s.Domains,
				"upstream":    s.Upstream,
				"waf_enabled": s.WAFEnabled,
			})
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleReload(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := cfgMgr.Reload(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":  "reload_failed",
				"detail": err.Error(),
			})
			return
		}
		cfg := cfgMgr.Get()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status": "reloaded",
			"sites":  len(cfg.Sites),
			"rules":  len(cfg.Rules),
		})
	}
}

// handleListInspectors reports the detection modules the engine actually
// registered, together with how many audit entries each one is responsible
// for. The audit metadata carries the rule id ("SQLI016: ..."), so hits are
// attributed by rule-id prefix.
func handleListInspectors(e *engine.Engine, al *compliance.AuditLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := al.Query(compliance.AuditFilter{})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":  "audit_query_failed",
				"detail": err.Error(),
			})
			return
		}
		// Inspector names and the rule-id prefixes they emit do not share a
		// common stem ("protocol" issues PROT001, api_protect issues API001),
		// so attribution goes through an explicit map rather than a string
		// prefix of the inspector name.
		// Keys are the names the inspectors report via Name(), which are the
		// display names, not the config section keys.
		prefixes := map[string]string{
			"sqli":                  "SQLI",
			"xss":                   "XSS",
			"rce":                   "RCE",
			"ddos_protection":       "DDoS",
			"protocol_anomaly":      "PROT",
			"bot_detector":          "BOT",
			"api_protection":        "API",
			"file_upload":           "UPL",
			"ja3":                   "JA3",
			"desync":                "DSYNC",
			"parser_hardener":       "PARSER_",
			"credential_protection": "CRED",
			"response_inspect":      "LEAK",
		}

		inspectors := e.Inspectors()
		hits := make(map[string]int, len(inspectors))
		for _, ent := range entries {
			ruleID := ent.Metadata
			if i := strings.Index(ruleID, ":"); i > 0 {
				ruleID = ruleID[:i]
			}
			for _, ins := range inspectors {
				if ins == nil {
					continue
				}
				if prefix, ok := prefixes[ins.Name()]; ok && strings.HasPrefix(ruleID, prefix) {
					hits[ins.Name()]++
					break
				}
			}
		}

		// Inspectors() returns one slot per config section; disabled modules
		// are nil and are skipped.
		out := make([]map[string]interface{}, 0, len(inspectors))
		for _, ins := range inspectors {
			if ins == nil {
				continue
			}
			out = append(out, map[string]interface{}{
				"name":    ins.Name(),
				"enabled": true,
				"hits":    hits[ins.Name()],
			})
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"inspectors": out,
			"count":      len(out),
		})
	}
}

func handleListSites(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cfgMgr.Get()
		sites := make([]map[string]interface{}, 0, len(cfg.Sites))
		for _, s := range cfg.Sites {
			sites = append(sites, map[string]interface{}{
				"name":        s.Name,
				"domains":     s.Domains,
				"upstream":    s.Upstream,
				"port":        s.Port,
				"tls":         s.TLS,
				"waf_enabled": s.WAFEnabled,
			})
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"sites": sites,
			"count": len(sites),
		})
	}
}

func handleListRules(cfgMgr *config.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := cfgMgr.Get()
		rules := make([]map[string]interface{}, 0, len(cfg.Rules))
		for _, r := range cfg.Rules {
			rules = append(rules, map[string]interface{}{
				"id":          r.ID,
				"name":        r.Name,
				"description": r.Description,
				"enabled":     r.Enabled,
				"severity":    r.Severity,
				"action":      r.Action,
				"tags":        r.Tags,
			})
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"rules": rules,
			"count": len(rules),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("json encode failed", "error", err, "status", status)
	}
}

// writeBlockedResponse replies to a blocked request. A browser (which sends
// Accept: text/html) gets a readable block page naming the rule and the reason;
// an API client (Accept: application/json, or no Accept) gets JSON. Both carry
// the X-FortressWAF-* headers.
func writeBlockedResponse(w http.ResponseWriter, r *http.Request, decision *engine.Decision) {
	requestID := r.Header.Get("X-Request-ID")
	// Default to the human-readable page: anyone hitting the site in a browser
	// should see a proper block page, never a raw JSON blob. Only a client that
	// explicitly asks for JSON (an API call that sets Accept: application/json)
	// gets the machine-readable body.
	if clientWantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"blocked":    true,
			"action":     "block",
			"rule_id":    decision.RuleID,
			"rule_name":  decision.RuleName,
			"severity":   decision.Severity,
			"evidence":   decision.Evidence,
			"request_id": requestID,
		}); err != nil {
			slog.Warn("json encode failed", "error", err, "rule_id", decision.RuleID)
		}
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(blockPage(r, decision))
}

// htmlEscape escapes a value for safe interpolation into the block page.
func htmlEscape(s string) string {
	return html.EscapeString(s)
}

// clientWantsJSON reports whether the caller explicitly asked for a JSON reply.
// Everything else -- a browser navigation, a plain curl, a request with no
// Accept header -- gets the HTML block page. A request is treated as an API
// call only when it clearly wants JSON: an Accept header naming JSON without
// html, or a JSON content-type, or an XHR/fetch marker.
func clientWantsJSON(r *http.Request) bool {
	// A top-level browser navigation always includes text/html in Accept.
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		return false
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return true
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return true
	}
	// No Accept at all: show the page rather than a JSON blob.
	return false
}

// blockPage renders the human-readable block page shown to anyone hitting the
// site in a browser. It states, in plain language, that the request was held
// because it looked like an attack, and names the rule so an operator can
// correlate it with the audit log. Rule name and path are HTML-escaped, so a
// crafted value cannot inject markup.
func blockPage(r *http.Request, decision *engine.Decision) []byte {
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Request blocked — FortressWAF</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:#0d1117; color:#e6edf3; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; }
  .card { max-width:600px; padding:40px; margin:24px; border:1px solid #21262d; border-radius:14px; background:#161b22; }
  .badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:600;
           letter-spacing:.04em; text-transform:uppercase; background:#3d1414; color:#ff6b6b; border:1px solid #4d1a1a; }
  h1 { font-size:22px; margin:18px 0 6px; }
  p { color:#9da7b3; line-height:1.6; margin:8px 0; }
  dl { margin:22px 0 0; display:grid; grid-template-columns:auto 1fr; gap:8px 16px; font-size:13px; }
  dt { color:#6e7681; }
  dd { margin:0; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:#e6edf3; word-break:break-all; }
  .foot { margin-top:26px; font-size:12px; color:#6e7681; }
</style>
</head>
<body>
  <div class="card">
    <span class="badge">Blocked by FortressWAF</span>
    <h1>Maaf, permintaan Anda kami tahan</h1>
    <p>Permintaan ini dihentikan oleh <strong>FortressWAF</strong> karena isinya terdeteksi
       menyerupai pola serangan terhadap aplikasi web (misalnya SQL injection, XSS, atau
       command injection). Demi keamanan, permintaan tersebut tidak diteruskan ke server.</p>
    <p>Jika Anda merasa ini keliru — misalnya Anda hanya mengetik teks biasa di sebuah form —
       silakan hubungi pengelola situs dan sebutkan ID permintaan di bawah ini.</p>
    <dl>
      <dt>Alasan</dt><dd>%s — %s</dd>
      <dt>Tingkat</dt><dd>%s</dd>
      <dt>Jalur</dt><dd>%s</dd>
      <dt>ID Permintaan</dt><dd>%s</dd>
    </dl>
    <p class="foot">FortressWAF — Web Application Firewall</p>
  </div>
</body>
</html>`,
		htmlEscape(decision.RuleID),
		htmlEscape(decision.RuleName),
		htmlEscape(decision.Severity),
		htmlEscape(r.URL.Path),
		htmlEscape(r.Header.Get("X-Request-ID")),
	))
}

func challengePage(r *http.Request) []byte {
	var tokenBytes [16]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return []byte("<h1>Internal error</h1>")
	}
	challengeToken := hex.EncodeToString(tokenBytes[:])
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Security Challenge</title></head>
<body style="display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:monospace;background:#1a1a2e;color:#e0e0e0;">
<div style="text-align:center;padding:40px;border:1px solid #333;border-radius:8px;background:#16213e;">
<h2>Security Verification</h2>
<p>Please wait while we verify your browser...</p>
<form id="cf-form" action="/__challenge" method="POST">
<input type="hidden" name="challenge_token" value="%s">
<input type="hidden" name="original_path" value="%s">
</form>
<script>
setTimeout(function(){
  var elapsed = (Date.now() / 1000 | 0) - %d;
  if(elapsed > 2) {
    document.getElementById("cf-form").submit();
  }
}, 2500);
</script>
<noscript><p>JavaScript is required. Please enable JavaScript and try again.</p>
<button type="submit" form="cf-form">Continue</button></noscript>
</div>
</body>
</html>`, challengeToken, r.URL.Path, time.Now().Unix()))
}

func buildEngineConfig(cfg *config.Config, dev bool) engine.EngineConfig {
	eCfg := engine.EngineConfig{
		DevMode:              dev,
		ShadowMode:           cfg.ShadowMode.Enabled,
		LearningMode:         cfg.LearningMode.Enabled,
		PerformanceIsolation: cfg.Performance.Enabled,
		MaxRegexDuration:     int64(cfg.Performance.MaxRegexMs),
		MaxWASMDuration:      int64(cfg.Performance.MaxWASMMs),
	}

	if cfg.SQLI.Enabled {
		eCfg.SQLI = engine.NewSQLInjectionEngine(dev)
	}
	if cfg.XSS.Enabled {
		eCfg.XSS = engine.NewXSSEngine(dev)
	}
	if cfg.RCE.Enabled {
		eCfg.RCE = engine.NewRCEInjection(dev)
	}
	if cfg.DDoS.Enabled {
		var ban time.Duration
		if cfg.DDoS.BanSeconds != 0 {
			ban = time.Duration(cfg.DDoS.BanSeconds) * time.Second
		}
		eCfg.DDoS = engine.NewDDoSProtectionWithOptions(dev, engine.DDoSOptions{
			GlobalRate:      cfg.DDoS.GlobalRate,
			PerIPRate:       cfg.DDoS.PerIPRate,
			PerEndpointRate: cfg.DDoS.PerEndpointRate,
			PerIPBan:        ban,
		})
	}
	if cfg.Protocol.Enabled {
		eCfg.Protocol = engine.NewProtocolAnomaly(dev)
	}
	if cfg.Bot.Enabled {
		var window, dur time.Duration
		if cfg.Bot.AutoBanWindowSec > 0 {
			window = time.Duration(cfg.Bot.AutoBanWindowSec) * time.Second
		}
		if cfg.Bot.AutoBanSeconds > 0 {
			dur = time.Duration(cfg.Bot.AutoBanSeconds) * time.Second
		}
		var afterN int
		if cfg.Bot.AutoBanAfter != 0 {
			afterN = cfg.Bot.AutoBanAfter
		}
		eCfg.Bot = engine.NewBotDetectorWithOptions(dev, engine.BotOptions{
			AutoBanAfter:    afterN,
			AutoBanWindow:   window,
			AutoBanDuration: dur,
		})
	}
	if cfg.APIProtect.Enabled {
		eCfg.APIProtect = engine.NewAPIProtection(dev)
	}
	if cfg.Upload.Enabled {
		eCfg.Upload = engine.NewFileUploadSecurity(dev)
	}
	if cfg.Credential.Enabled {
		eCfg.Credential = engine.NewCredentialProtection(dev, cfg.Credential.MaxAttempts, cfg.Credential.WindowSec, cfg.Credential.BlockDurationSec, cfg.Credential.LoginPaths)
	}
	if cfg.JWT.Enabled {
		eCfg.JWT = engine.NewJWTValidator(cfg.JWT)
	}
	if cfg.OAuth.Enabled {
		eCfg.OAuth = engine.NewOAuthIntrospector(cfg.OAuth)
	}
	if cfg.GraphQL.Enabled {
		eCfg.GraphQL = engine.NewGraphQLInspector(cfg.GraphQL)
	}
	if cfg.WebSocket.Enabled {
		eCfg.WebSocket = engine.NewWebSocketInspector(cfg.WebSocket)
	}
	if cfg.MTLS.Enabled {
		inspector, err := engine.NewMTLSInspector(cfg.MTLS)
		if err != nil {
			slog.Warn("mtls init failed", "error", err)
		} else {
			eCfg.MTLS = inspector
		}
	}
	if cfg.CAPTCHA.Enabled {
		eCfg.CAPTCHA = engine.NewCAPTCHAVerifier(cfg.CAPTCHA.Provider, cfg.CAPTCHA.Secret, cfg.CAPTCHA.SiteKey, cfg.CAPTCHA.Score)
	}
	if cfg.SOAP.Enabled {
		eCfg.SOAP = engine.NewSOAPValidator(cfg.SOAP.StrictSchema, cfg.SOAP.MaxDepth)
	}
	if cfg.GRPC.Enabled {
		eCfg.GRPC = engine.NewGRPCInspector(cfg.GRPC.MaxMsgSize, cfg.GRPC.RateLimit)
	}
	if cfg.RespInspect.Enabled {
		eCfg.RespInspect = engine.NewResponseInspector()
	}

	if cfg.JA3.Enabled {
		eCfg.JA3 = engine.NewJA3Inspector(dev)
	}
	if cfg.Behavioral.Enabled {
		eCfg.Behavioral = engine.NewBehavioralEngine(dev,
			cfg.Behavioral.Reputation,
			cfg.Behavioral.Velocity,
			cfg.Behavioral.PathEntropy,
			cfg.Behavioral.Threshold,
			cfg.Behavioral.WindowSec,
			cfg.Behavioral.MaxRequests,
		)
	}
	if cfg.WASM.Enabled {
		eCfg.WASM = engine.NewWASMInspector(dev, cfg.WASM.ModuleDir, cfg.WASM.MaxMemoryPages, cfg.WASM.Modules)
	}
	if cfg.Desync.Enabled {
		eCfg.Desync = engine.NewDesyncDetector(dev, cfg.Desync.MaxBodySize, cfg.Desync.StrictCL, cfg.Desync.DetectOBSFold)
	}
	if cfg.Adaptive.Enabled {
		eCfg.Adaptive = engine.NewAdaptiveChallenge(dev, cfg.Adaptive.JSScriptPath, cfg.Adaptive.TarpitDelayMs, cfg.Adaptive.CAPTCHAScore, cfg.Adaptive.ChallengeTTL)
	}
	if cfg.EBPF.Enabled {
		eCfg.EBPF = engine.NewEBPFTelemetry(dev, cfg.EBPF.Interface, cfg.EBPF.Port, cfg.EBPF.SampleRate)
	}

	if cfg.ParserHardening.Enabled {
		eCfg.Parser = engine.NewParserHardener(dev)
	}

	return eCfg
}

func engineRewriteConditions(conds []config.RewriteConditionConfig) []engine.RewriteCondition {
	result := make([]engine.RewriteCondition, 0, len(conds))
	for _, c := range conds {
		result = append(result, engine.RewriteCondition{
			Field:    c.Field,
			Name:     c.Name,
			Operator: c.Operator,
			Value:    c.Value,
		})
	}
	return result
}

func engineRewriteActions(actions []config.RewriteActionConfig) []engine.RewriteAction {
	result := make([]engine.RewriteAction, 0, len(actions))
	for _, a := range actions {
		switch a.Type {
		case "set_header":
			result = append(result, &engine.HeaderAction{
				Operation: "set",
				Name:      a.Name,
				Value:     a.Value,
			})
		case "remove_header":
			result = append(result, &engine.HeaderAction{
				Operation: "remove",
				Name:      a.Name,
			})
		case "set_body":
			result = append(result, &engine.BodyAction{
				Operation: a.Op,
				Pattern:   a.Pattern,
				Value:     a.Value,
			})
		}
	}
	return result
}

func initDatabase(driver, dsn string, maxOpen, maxIdle int) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		slog.Warn("database connection failed", "driver", driver, "error", err)
		return
	}
	defer db.Close()

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)

	if err := db.Ping(); err != nil {
		slog.Warn("database ping failed", "error", err)
		return
	}

	slog.Info("database connected", "driver", driver)

	if driver == "postgres" {
		schema := `
		CREATE TABLE IF NOT EXISTS fortresswaf_rules (
			id SERIAL PRIMARY KEY,
			rule_id VARCHAR(255) UNIQUE NOT NULL,
			name VARCHAR(255),
			enabled BOOLEAN DEFAULT true,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS fortresswaf_audit_log (
			id SERIAL PRIMARY KEY,
			event_type VARCHAR(255),
			detail JSONB,
			created_at TIMESTAMP DEFAULT NOW()
		);
		CREATE TABLE IF NOT EXISTS fortresswaf_events (
			id SERIAL PRIMARY KEY,
			event_type VARCHAR(255),
			source_ip INET,
			rule_id VARCHAR(255),
			score FLOAT,
			detail JSONB,
			created_at TIMESTAMP DEFAULT NOW()
		);
		`
		if _, err := db.Exec(schema); err != nil {
			slog.Warn("database schema init failed", "error", err)
			return
		}
		slog.Info("database schema initialized")
	}

	<-make(chan struct{})
}
