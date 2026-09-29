# Changelog

All notable changes to FortressWAF are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Protected-domain management with DNS verification.** Add a domain from the
  console; it is protected only after the WAF itself resolves its A/AAAA records
  and confirms one points at this server (`server.expected_ips`). Removal and a
  re-check action are included. New package `internal/sites`.
- **Full request log.** Every inspected request is recorded with method, path,
  source IP, parsed browser/device, and the full header set. New package
  `internal/uaparse` turns a User-Agent into "Chrome 120 on Android" etc.
- **IP ban / unban.** Banned addresses are refused before inspection, on every
  site; bans can expire. New package `internal/blocklist`.
- **Live training corpus + validated retrain.** High-confidence blocks
  (named attack families, score ≥ 70) are labelled by rule and appended to a
  shared corpus volume (`internal/traincorpus`). The ML sidecar retrains from it
  and adopts the new model only if it scores at least as well as the incumbent;
  a worse or unjudgeable candidate is rejected. New ML endpoints
  `/v1/model/retrain` (validated) and `/v1/model/training-status`.
- **Dashboard pages**: Overview, Live traffic, Alerts, Analytics, IP bans,
  Domains, Detection, Audit trail, Compliance, System. Route error boundaries so
  a client error shows a retry screen instead of a blank page.
- **`scripts/deploy.sh`**: rebuild → recreate → restart Caddy (refresh service
  DNS) → verify the browser path end to end.

### Changed
- **Login now requires username AND password.** Previously a match on either
  field authenticated, so a correct username with a wrong password logged in.
  With two configured keys the first is the username, the second the password.
- **Admin API bodies are capped** at 1 MiB; oversized bodies return `413`.
- **Config is written atomically** (temp file + rename) instead of truncated in
  place, and the runtime config lives in a writable directory so the nonroot
  container can rewrite it. Duplicate site names and duplicate domains are now
  rejected by validation.
- **Upstream URLs are validated** (http/https + host) before being written.
- **Caddy serves the admin API on the same origin as the dashboard** (`/api/*`
  on the dashboard host), removing the separate API hostname.
- **False-positive fixes:** standard HTTP methods (OPTIONS/HEAD/PATCH/PUT/DELETE)
  are no longer "verb tampering"; ordinary clients (curl, axios, okhttp, Postman)
  and real browsers are no longer bots; contact-form fields (`email`, `phone`,
  `address`) are not honeypots; sensitive-path matching is segment-anchored;
  response inspection runs in monitor mode by default; non-ASCII text and encoded
  values in URLs/headers/cookies are not attacks.
- **Security fixes:** `decodePathValue` no longer recurses without bound (was a
  remote stack-overflow DoS); double-encoding detection requires the decoded
  byte to be SQL-significant; credential headers are redacted case-insensitively.

### Removed
- `internal/api` and its orphaned `internal/rules` dependency: dead code that
  carried an auth bypass, a no-op rate limiter, and an unauthenticated WebSocket.

## [1.2.0] - 2026-05-25

### Added
- HTTP/2 support via TLS configuration (`http2_enabled: true`)
- ACME/LetsEncrypt automatic certificate management (autocert)
- OCSP stapling placeholder via TLS VerifyConnection hook
- Prometheus metrics endpoint on configurable port/path
- PostgreSQL event storage with schema auto-init (rules, audit log, events tables)
- CAPTCHA verification (reCAPTCHA v2/v3, hCaptcha) with configurable score threshold
- gRPC inspector with per-service rate limiting and message size limits
- SOAP/XML validator with nesting depth enforcement
- Response inspector middleware (body capture via ResponseWriter wrapper)
- Credential protection: brute force, credential stuffing, password spray detection with configurable thresholds
- Elasticsearch SIEM dashboard definitions (`deploy/monitoring/elasticsearch/`)
- Kibana security dashboard definitions (`deploy/monitoring/kibana/`)
- Config fields for all new features in `internal/config/config.go`

### Changed
- Engine refactor: removed 6 unused Inspector fields (Rules, ML, RateLimit, Reputation, Session, Geo) that were never assigned
- RequestContext: removed 8 unused fields (AnomalyScore, RiskScore, IsMobile, IsTor, IsProxy, TLSVersion, Fingerprint, Tags)
- Removed dead code: custom min(), slog import suppression in 5 files, unused EndpointCounter, parseRSAPublicKey, ScanWithClamAV, jwtSecret/hmacSHA256
- README rewritten with positioning, Mermaid architecture diagram, accurate feature list
- architecture.md updated with Mermaid pipeline diagram, Auth and Protocol stages
- CI workflow fixed (branch targets, build paths, lint accuracy)
- Benchmark workflow fixed (correct test package path)

### Removed
- Fake "Community vs Enterprise" feature table from README
- Fake CLI commands that referenced non-existent fortressctl subcommands
- Always-nil ScanWithClamAV method and clamavAvailable flag

### Added
- JWT/OAuth authentication and token validation
  - JWKS-based signature verification with caching
  - Standard claims validation (exp, nbf, iat, iss, aud)
  - OAuth 2.0 token introspection (RFC 7662)
  - Scope and role-based access control
- GraphQL protection engine
  - Query depth limiting (configurable max nesting)
  - Query cost analysis (operation-based scoring)
  - Alias and batch query limiting
  - Introspection and schema query blocking
  - Injection pattern detection in queries
- mTLS client certificate authentication
  - X.509 certificate chain validation against CA
  - Certificate policy OID enforcement
  - Client cert subject injection into upstream headers
  - Configurable client auth modes (require/verify/skip)
- WebSocket inspection
  - Connection upgrade handshake validation
  - Frame type allowlisting (text/binary/ping/pong/close)
  - Frame rate limiting per IP address
  - Injection pattern detection in text messages
  - JSON depth validation in frames
  - Raw frame parsing (masking, fragmentation)
- SIEM integration (Splunk HEC + Elasticsearch)
  - Batched event export with configurable interval
  - Splunk HTTP Event Collector (HEC) support
  - Elasticsearch bulk API export with daily index rotation
  - CEF (Common Event Format) output
  - Rich event schema with attack context
- Request/Response rewriting engine
  - Header manipulation (set/add/remove/rename)
  - Body content replacement and regex rewriting
  - URL redirection with template variables
  - Condition-based rule matching (path/header/query/method/ip)
- Credential stuffing and brute force protection
  - Rate-based login attempt tracking (per IP/user/session)
  - Automated credential stuffing pattern detection
  - Response-based brute force detection
- File upload security
  - MIME type validation (declared vs magic bytes)
  - Dangerous file type blocking
  - Content-based malicious payload scanning
- HTTP protocol compliance enforcement
  - HTTP smuggling detection (CL.TE, TE.CL, TE.TE)
  - Strict header/URI size limits
  - HTTP method allowlisting
  - HTTP version enforcement
- Comprehensive feature documentation
  - 9 new feature docs (auth, graphql, mtls, websocket, siem, rewrite, credential, upload, protocol)
  - Updated mkdocs.yml navigation

## [1.0.0] - 2024-03-15

### Added
- Core WAF engine with OWASP Top 10 coverage
  - SQL injection detection (1,200+ patterns)
  - Cross-site scripting detection (1,500+ patterns)
  - Remote code execution detection (800+ patterns)
  - Path traversal/LFI detection (400+ patterns)
  - SSRF detection (200+ patterns)
- ML anomaly detection engine
  - Ensemble model (Random Forest + XGBoost + Transformer)
  - 256 extracted features per request
  - Configurable threshold (default 0.7)
  - gRPC sidecar deployment
  - Continuous learning pipeline
- Real-time dashboard
  - Live request metrics via WebSocket
  - Attack visualization with category breakdowns
  - Top attackers and targets
  - Latency heatmaps and percentiles
  - Compliance status overview
- IP reputation engine
  - Real-time threat intelligence feed integration
  - Geo-IP blocking
  - TOR exit node detection
  - Proxy/VPN detection
  - Custom allow/block lists
- Rate limiting
  - Sliding window algorithm
  - Token bucket for burst control
  - Per-route and global limits
  - Configurable windows and thresholds
- Bot detection (500+ signatures)
  - Known bad bot user agents
  - Scanner and crawler detection
  - JS challenge integration
  - CAPTCHA support
- Virtual patching
  - Zero-day vulnerability protection
  - No application code changes required
  - Hot-reloadable rules
- Docker Compose deployment
  - Development, staging, production profiles
  - Redis for rate limiting state
  - PostgreSQL for configuration and audit logs
  - ML engine sidecar
  - Dashboard with WebSocket support
- Helm chart for Kubernetes
  - Configurable replica counts
  - Resource limits and requests
  - Redis and PostgreSQL subcharts
  - Prometheus ServiceMonitor
  - Ingress controller integration
- REST API + CLI tool
  - Health, metrics, events endpoints
  - Rule management (CRUD + reload)
  - IP reputation management
  - Rate limit configuration
  - ML engine management
  - Audit log export
  - Compliance report generation
- 10,000+ attack payload test corpus
  - 50 SQL injection payloads
  - 50 XSS payloads
  - 30 RCE payloads
  - 20 LFI payloads
  - 15 SSRF payloads
  - 30 bad bot user agents
  - 20 scanner signatures
  - 50 legitimate requests
- Comprehensive documentation
  - Getting started guide
  - Architecture deep dive
  - Rule language reference
  - API reference with examples
  - Deployment guides (Docker, K8s, bare metal, Terraform, cloud)
  - Compliance documentation (PCI DSS, GDPR, HIPAA, SOC 2, ISO 27001)
  - Troubleshooting guide
- CI/CD pipeline
  - GitHub Actions with lint, test, build, security scan, release jobs
  - Go, Python, Node.js linting
  - Docker image building (multi-arch: amd64, arm64)
  - Trivy container scanning
  - Cosign image signing
  - Automated releases
- Security features
  - TLS 1.3 with strong cipher suites
  - mTLS support for inter-service communication
  - API authentication with Bearer tokens
  - Request tracing and debugging
  - Audit logging for all configuration changes
  - TLS configuration support

### Changed
- N/A (initial release)

### Deprecated
- N/A (initial release)

### Removed
- N/A (initial release)

### Fixed
- N/A (initial release)

### Security
- N/A (initial release)

## [0.9.0] - 2024-02-01

### Added
- Beta release with core WAF functionality
- Initial rule engine with rule sets
- Basic rate limiting
- CLI tool
- Docker deployment

### Known Issues
- ML engine not yet integrated
- Dashboard in alpha state
- Limited documentation

## [0.8.0] - 2024-01-01

### Added
- Alpha release for internal testing
- Basic request inspection
- Simple rule matching
- Proof of concept

---

## Release Schedule

| Version | Expected | Status |
|---------|----------|--------|
| 1.0.0 | March 2024 | ✅ Released |
| 1.1.0 | June 2024 | 🔄 In Development |
| 1.2.0 | September 2024 | 📋 Planned |
| 2.0.0 | Q1 2025 | 📋 Planned |

### Upcoming (1.1.0)

- GraphQL security introspection
- WebSocket deep inspection
- Advanced bot fingerprinting
- Enhanced compliance reporting
- Performance improvements (target 20% throughput increase)
- Additional cloud marketplace listings

## How to Upgrade

### Docker Compose

```bash
docker compose pull
docker compose up -d
```

### Kubernetes (Helm)

```bash
helm repo update fortresswaf
helm upgrade fortresswaf fortresswaf/fortresswaf
```

### Manual Binary

```bash
wget https://github.com/fortresswaf/fortresswaf/releases/download/v1.0.0/fortresswaf-linux-amd64.tar.gz
tar -xzf fortresswaf-linux-amd64.tar.gz
sudo mv fortresswaf fortressctl /usr/local/bin/
sudo systemctl restart fortresswaf
```
