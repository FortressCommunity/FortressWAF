# Component Architecture

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

This document provides in-depth coverage of FortressWAF's internal components: the detection engine, configuration system, REST API, rate limiter, IP reputation, session manager, and SIEM exporter.

## Engine

**Package**: `rust/crates/core/src/` (inspectors in `inspectors/`)

The engine is the core of FortressWAF. It implements a pipeline of inspectors that each analyze incoming requests independently.

### Inspector Interface

```rust
pub trait Inspector: Send + Sync {
    fn name(&self) -> &str;
    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError>;
}
```

Each inspector returns a `Decision` containing:
- **Action**: `block`, `allow`, `challenge`, `monitor`, `rate_limit`
- **RuleID**: Rule identifier string
- **Severity**: `critical`, `high`, `medium`, `low`, `info`
- **Score**: Threat score contribution (0–100)
- **Evidence**: Human-readable match description

### Pipeline Execution

```
Request → CAPTCHA → JWT → OAuth → mTLS → GraphQL → gRPC → SOAP → Bot → DDoS → SQLi → XSS → API Protect → RCE → Protocol → Upload → Credential → WebSocket → Response Inspect → Decision
```

Execution rules:
1. Inspectors run in fixed priority order
2. `nil` inspectors are skipped
3. A `block` decision short-circuits the pipeline
4. Non-block decisions accumulate into `ThreatScore`
5. After all inspectors run, `finalDecision()` applies thresholds

### Threat Scoring

| Score Range | Action | Description |
|-------------|--------|-------------|
| ≥ 90 | Block | High-confidence attack |
| ≥ 50 | Challenge | Suspicious — requires JS challenge |
| Any | RateLimit | If any inspector returned rate_limit |
| Else | Allow | Normal request |

### 25 Inspectors

Files live in `rust/crates/core/src/inspectors/` (and `middleware.rs` for the
last few).

| # | Inspector | File | Detection Method |
|---|-----------|------|------------------|
| 1 | Parser hardener | `parser.rs` | Normalization/unicode/traversal, parser differentials |
| 2 | Desync | `desync.rs` | CL.TE / TE.CL request smuggling, obs-fold |
| 3 | JA3 | `ja3.rs` | TLS fingerprint (known-bad scanner hashes) |
| 4 | Behavioral | `behavioral.rs` | Velocity, IP reputation, path entropy |
| 5 | Adaptive | `adaptive.rs` | JS / CAPTCHA / tarpit / block escalation |
| 6 | WASM | `wasm.rs` | WASM module sandbox (off by default) |
| 7 | CAPTCHA | `middleware.rs` | Token verification with reCAPTCHA/hCaptcha |
| 8 | JWT | `auth.rs` | Token validation, JWKS caching, claims check |
| 9 | OAuth | `auth.rs` | Token introspection (RFC 7662) |
| 10 | mTLS | `mtls.rs` | Client certificate validation, CA chain, policy OID |
| 11 | GraphQL | `graphql.rs` | Query depth, cost analysis, alias/batch limits |
| 12 | gRPC | `middleware.rs` | Message size limits, per-service rate limiting |
| 13 | SOAP | `middleware.rs` | XML schema validation, nesting depth |
| 14 | Bot | `bot.rs` | User-Agent matching, headless browser detection, JS challenge |
| 15 | DDoS | `ddos.rs` | Slow loris, slow POST, cache busting, adaptive rate limits |
| 16 | SQLi | `sqli.rs` | Tokenizer + 15 regex patterns, encoding bypass detection |
| 17 | XSS | `xss.rs` | HTML tag / event handler / JS sink / polyglot detection |
| 18 | API Protect | `api_protect.rs` | Sensitive paths, GraphQL abuse, XXE, shadow API |
| 19 | RCE | `rce.rs` | Shell injection, SSTI, EL injection, deserialization, Log4Shell |
| 20 | Protocol | `protocol.rs` | Verb tampering, header smuggling, malformed requests |
| 21 | Upload | `upload.rs` | MIME validation, magic bytes, extension allow/block lists |
| 22 | Credential | `credential.rs` | Brute force, credential stuffing, password spray detection |
| 23 | WebSocket | `websocket.rs` | Frame type validation, rate limiting, origin check |
| 24 | Response Inspect | `response_leak.rs` | Response body analysis for data leakage |
| 25 | eBPF | `ebpf.rs` | Packet telemetry counters (off by default) |

Rewrite rules (`rewrite.rs`) are applied by the proxy, not run as an inspector.

### Concurrency

- The engine holds its inspector list behind `parking_lot::RwLock`, so an
  inspector can be swapped at runtime via `Engine::update_inspector()`.
- Inspectors that keep per-IP state (DDoS, bot, adaptive, behavioral) use their
  own `Mutex`/`RwLock` around plain maps.
- `InspectRequest()` is safe for concurrent use

## Configuration System

**Package**: `rust/crates/config/`

### Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  YAML File  │────►│   Load()     │────►│   Config    │
└─────────────┘     └──────────────┘     └─────────────┘
                           │                      │
                    ┌──────▼──────┐        ┌──────▼──────┐
                    │  Manager    │        │  Validate() │
                    │  (fsnotify) │        │             │
                    │  Hot-Reload │        │  Get()      │
                    └─────────────┘        └─────────────┘
```

### Key Features

- **YAML-based** with full struct mapping via `gopkg.in/yaml.v3`
- **Environment variable expansion**: `${VAR:-default}` syntax
- **Hot-reload** via `fsnotify` file watcher
- **Default values** provided by `DefaultConfig()`
- **Validation** via `Config.Validate()` ensuring required fields

### Config Structure (30+ sections)

```rust
pub struct Config {
    pub sites: Vec<SiteConfig>,
    pub rules: Vec<RuleConfig>,
    pub tls: TlsConfig,
    pub admin: AdminConfig,
    pub ml: MlConfig,
    pub redis: RedisConfig,
    pub db: DbConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
    pub graphql: GraphQlConfig,
    pub mtls: MtlsConfig,
    pub websocket: WebSocketConfig,
    pub siem: SiemConfig,
    pub rewrite_rules: Vec<RewriteRuleConfig>,
    pub sqli: FeatureConfig,
    pub xss: FeatureConfig,
    pub rce: FeatureConfig,
    pub ddos: DDoSConfig,
    pub protocol: FeatureConfig,
    pub bot: BotConfig,
    pub api_protect: FeatureConfig,
    pub upload: FeatureConfig,
    pub credential: CredentialConfig,
    // ... and more
}
```

### Hot-Reload

The `Manager` watches the config file directory for changes. On write events, it triggers `Reload()` and notifies registered callbacks via `OnChange()`. This allows:

- Adding/removing sites without restart
- Updating rule configurations
- Toggling feature flags

## REST API

**Package**: implemented in `rust/crates/proxy/src/server.rs` (the admin router).

### Server Architecture

```
Admin Server (:8443)
├── /health              Health check
├── /metrics             Prometheus metrics
├── /ready               Readiness probe
├── /live                Liveness probe
├── /api/v1/health       Authenticated health
├── /api/v1/status       System status
├── /api/v1/config       Get current config
├── /api/v1/reload       Force config reload
├── /api/v1/sites        List/Manage sites
└── /api/v1/rules        List/Manage rules
```

### Authentication

All `/api/v1/*` endpoints require a Bearer token from the configured `admin.api_keys`.

### Handlers

- **handleHealth**: Returns `{"status":"ok"}`
- **handleMetrics**: Prometheus format output via `promhttp.Handler`
- **handleReady**: Verifies config manager is responding
- **handleStatus**: Returns version, uptime, request stats
- **handleGetConfig**: Returns sanitized config (secrets masked)
- **handleReload**: Triggers config hot-reload
- **handleListSites**: Returns configured sites
- **handleListRules**: Returns configured rules

## Rate Limiter

**Package**: `rust/crates/services/src/ratelimit.rs`

### Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| **Fixed Window** | Count per fixed time interval | Simple per-IP limits |
| **Sliding Window** | Count per rolling time window | Smooth rate limiting |
| **Token Bucket** | Burst allowance with refill | API rate limits |
| **Leaky Bucket** | Constant processing rate | Queue management |

### Granularity Levels

- Per IP address
- Per user (via JWT claims)
- Per session
- Per API key
- Per endpoint
- Per geo region

### Implementation

- In-memory counters with optional Redis backend
- Explicit `cleanup()` calls evict stale entries (callers schedule them)
- Priority queue with double-burst for priority keys

## IP Reputation

**Package**: `rust/crates/services/src/reputation.rs`

### Features

- **TOR detection**: Known TOR exit node IPs
- **Proxy/VPN detection**: Commercial proxy and VPN provider ranges
- **ASN filtering**: Allow/block by autonomous system number
- **CIDR matching**: Custom allowlist and blocklist CIDR ranges
- **GeoIP integration**: Country-based allow/block via `rust/crates/services/src/geo.rs`

### Data Sources

- Checks are performed against embedded CIDR lists
- No external API calls (all data is built-in)
- Lists are loaded at startup and are static

### Performance

- CIDR matching uses binary search on sorted ranges
- Typical lookup time: ~10μs

## Session Manager

**Package**: `rust/crates/services/src/session.rs`

### Features

- Cookie-based session management
- Configurable TTL
- Optional Redis backend for distributed deployments
- Session data stored as signed cookies or Redis key-value pairs

### Session Flow

```
Request → Session Middleware → Parse Cookie → Load Session → Attach to Context
```

### Storage Backends

| Backend | Persistence | Cluster Support |
|---------|-------------|-----------------|
| Memory | Volatile | No |
| Redis | Persistent | Yes |

## SIEM Exporter

**Package**: `rust/crates/services/src/siem.rs`

### Architecture

```
Engine Events → SIEM Manager → Batch Buffer → Exporters
                                              ├── Elasticsearch
                                              ├── Splunk (HTTP Event Collector)
                                              ├── Syslog (RFC 5424)
                                              ├── JSON File
                                              └── Webhook (Slack, Teams, etc.)
```

### Event Types

- **Request Events**: Per-request inspection results
- **Alert Events**: High-severity matches requiring attention
- **Audit Events**: Configuration changes, admin actions

### Configuration

```yaml
siem:
  enabled: true
  export_interval: 10s
  batch_size: 100
  exporters:
    - type: elasticsearch
      url: http://elasticsearch:9200
      index: fortresswaf-events
    - type: slack
      url: https://hooks.slack.com/services/xxx
```

### Batching

Events are batched per exporter and flushed on interval or when batch size is reached. Failed exports are retried with exponential backoff.
