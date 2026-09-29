> **Note:** Some configuration keys shown here are aspirational placeholders (HTTP/2, OCSP, database). Only file-based config is currently supported.

# Configuration Reference

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

This document provides a reference for FortressWAF configuration options. The configuration file is written in YAML format and is typically located at `/app/config/config.yaml` or specified via the `--config` command-line flag.

## Configuration File Structure

```yaml
# ===========================================
# FortressWAF Configuration Reference
# ===========================================

# Server configuration
server:
  host: string
  port: integer
  api_port: integer
  tls:
    enabled: boolean
    cert_path: string
    key_path: string
    min_version: string  # "1.0" | "1.1" | "1.2" | "1.3"
    prefer_server_cipher: boolean

# Logging configuration
logging:
  level: string  # "debug" | "info" | "warn" | "error"
  format: string  # "json" | "text" | "logfmt"
  outputs:
    - type: string  # "stdout" | "file" | "syslog" | "journald"
      path: string
      host: string
      port: integer

# Redis configuration
redis:
  host: string
  port: integer
  password: string
  db: integer
  pool_size: integer
  ssl: boolean
  cluster_mode: boolean
  max_retries: integer
  retry_timeout: string
  read_timeout: string
  write_timeout: string

# Database configuration
database:
  host: string
  port: integer
  name: string
  user: string
  password: string
  ssl_mode: string  # "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
  max_open_conns: integer
  max_idle_conns: integer
  conn_max_lifetime: string
  conn_max_idle_time: string

# Engine configuration
engine:
  workers: integer | "auto"
  max_request_size: string  # e.g., "10MB"
  request_timeout: string   # e.g., "60s"
  keep_alive_timeout: string
  disable_internal_errors: boolean
  client_max_body_size: string
  client_body_buffer_size: string

# Rule configuration
rules:
  owasp_enabled: boolean
  community_rules_enabled: boolean
  custom_rules_path: string
  reload_interval: string
  cache_size: integer

# ML Engine configuration
ml:
  enabled: boolean
  model_path: string
  anomaly_threshold: float  # 0.0 - 1.0
  fallback_enabled: boolean
  model_update_interval: string
  feature_cache_size: integer

# Rate limiting
rate_limiting:
  enabled: boolean
  global:
    requests_per_minute: integer
    burst: integer
    algorithm: string  # "fixed" | "sliding" | "token_bucket" | "leaky_bucket"
  per_ip:
    requests_per_minute: integer
    burst: integer
  per_user:
    requests_per_minute: integer
    burst: integer
  per_session:
    requests_per_minute: integer
    burst: integer
  per_endpoint:
    requests_per_minute: integer
    burst: integer

# Bot detection
bot_detection:
  enabled: boolean
  fingerprint_enabled: boolean
  headless_browser_detection: boolean
  captcha_threshold: float  # 0.0 - 1.0
  honeypot_enabled: boolean
  tarpit_enabled: boolean
  tarpit_delay_ms: integer

# DDoS protection
ddos:
  enabled: boolean
  http_flood_threshold: integer
  http_flood_window: string
  slowloris_timeout: string
  slow_post_timeout: string
  connection_limit_per_ip: integer

# Audit logging
audit:
  enabled: boolean
  log_all_requests: boolean
  log_blocked_requests: boolean
  log_suspicious_requests: boolean
  log_request_body: boolean
  log_response_body: boolean
  retention_days: integer
  compression_enabled: boolean

# Secret management
secrets:
  provider: string  # "vault" | "aws-secrets-manager" | "gcp-secrets-manager" | "azure-keyvault"
  vault:
    address: string
    token: string
    path: string
    ca_cert: string
  aws:
    region: string
    secret_name: string
    profile: string
```

## Server Configuration

### Basic Server Settings

```yaml
server:
  # IP address to bind to (0.0.0.0 for all interfaces)
  host: 0.0.0.0

  # Main dashboard/API port
  port: 8443

  # Dedicated API port (optional, can share with port)
  api_port: 8444

  # Connection settings
  read_timeout: 60s
  write_timeout: 60s
  idle_timeout: 120s
  max_header_bytes: 16384
```

### TLS Configuration

```yaml
server:
  tls:
    # Enable TLS
    enabled: true

    # Path to TLS certificate (PEM format)
    cert_path: /certs/server.crt

    # Path to TLS private key
    key_path: /certs/server.key

    # Minimum TLS version
    min_version: "1.2"

    # Prefer server cipher suites (recommended for performance)
    prefer_server_cipher: true

    # Cipher suites (leave empty for defaults)
    cipher_suites:
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305

    # Enable HTTP/2
    http2_enabled: true

    # OCSP stapling
    ocsp_stapling_enabled: true
    ocsp_stapling_cache_timeout: 1h
```

#### Generating Self-Signed Certificates

```bash
# Generate self-signed certificate for testing
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=localhost/O=FortressWAF/C=US" \
  -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# Generate certificate signed by Let's Encrypt
certbot certonly --nginx -d waf.example.com

# Convert certificate to PEM format
openssl x509 -in /etc/letsencrypt/live/waf.example.com/fullchain.pem \
  -out server.crt
openssl rsa -in /etc/letsencrypt/live/waf.example.com/privkey.pem \
  -out server.key
```

## Redis Configuration

FortressWAF uses Redis for session management, rate limiting state, and caching.

### Basic Redis Settings

```yaml
redis:
  # Redis server hostname
  host: localhost

  # Redis server port
  port: 6379

  # Redis password (if authentication enabled)
  password: ""

  # Redis database number (0-15)
  db: 0

  # Connection pool size
  pool_size: 10

  # Enable TLS connection
  ssl: false
```

### Redis Sentinel (High Availability)

```yaml
redis:
  host: ""
  cluster_mode: false
  sentinels:
    - host: redis-sentinel-1
      port: 26379
    - host: redis-sentinel-2
      port: 26379
    - host: redis-sentinel-3
      port: 26379
  master_name: mymaster
  sentinel_password: ""
  # Password for Redis nodes (if authentication enabled)
  node_password: ""
```

### Redis Cluster (Cluster Mode)

```yaml
redis:
  cluster_mode: true
  cluster_nodes:
    - host: redis-cluster-1
      port: 6379
    - host: redis-cluster-2
      port: 6379
    - host: redis-cluster-3
      port: 6379
    - host: redis-cluster-4
      port: 6379
    - host: redis-cluster-5
      port: 6379
    - host: redis-cluster-6
      port: 6379
```

### Redis Performance Tuning

```yaml
redis:
  # Timeouts
  read_timeout: 5s
  write_timeout: 5s
  connect_timeout: 5s

  # Retry configuration
  max_retries: 3
  retry_timeout: 1s

  # Keepalive
  tcp_keepalive: 1m

  # Pipeline configuration
  pipeline_window: 1ms
  pipeline_capacity: 10000
```

## Database Configuration

FortressWAF uses PostgreSQL for persistent storage of configuration, logs, and analytics.

### Basic PostgreSQL Settings

```yaml
database:
  # PostgreSQL server hostname
  host: localhost

  # PostgreSQL server port
  port: 5432

  # Database name
  name: fortresswaf

  # Database username
  user: fortresswaf

  # Database password
  password: ""

  # SSL mode
  ssl_mode: prefer  # "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"

  # Connection pool settings
  max_open_conns: 25
  max_idle_conns: 10
  conn_max_lifetime: 5m
  conn_max_idle_time: 1m
```

### PostgreSQL with TLS

```yaml
database:
  host: postgres.example.com
  port: 5432
  name: fortresswaf
  user: fortresswaf
  password: ""
  ssl_mode: verify-full
  ssl_cert_path: /certs/postgres-client.crt
  ssl_key_path: /certs/postgres-client.key
  ssl_root_cert_path: /certs/postgres-ca.crt
```

### PostgreSQL Connection String

You can also specify the database connection using a connection string:

```yaml
database:
  # Connection string format (alternative to individual settings)
  connection_string: "postgres://fortresswaf:password@localhost:5432/fortresswaf?sslmode=require"

  # Or use individual settings:
  host: localhost
  port: 5432
  name: fortresswaf
  user: fortresswaf
  password: password
```

## Engine Configuration

```yaml
engine:
  # Number of worker threads ("auto" uses CPU cores)
  workers: auto

  # Maximum request size
  max_request_size: 10MB

  # Request timeout
  request_timeout: 60s

  # Keep-alive timeout
  keep_alive_timeout: 30s

  # Disable detailed error messages (security best practice)
  disable_internal_errors: true

  # Client body settings
  client_max_body_size: 10MB
  client_body_buffer_size: 128KB

  # Response buffering
  response_buffer_size: 128KB

  # Request ID tracking
  request_id_header: X-Request-ID
  generate_request_id: true
```

## Rule Configuration

```yaml
rules:
  # Enable OWASP Top 10 protection rules
  owasp_enabled: true

  # Enable community-contributed rules
  community_rules_enabled: true

  # Path to custom rules directory
  custom_rules_path: /app/config/rules

  # Hot reload interval for rule changes
  reload_interval: 30s

  # Maximum number of rules to cache
  cache_size: 10000

  # Rule evaluation order (priority-based)
  evaluation_mode: first_match  # "first_match" | "all_match"

  # Maximum rule execution time
  max_execution_time: 100ms
```

### Rule Loading

```yaml
rules:
  # Built-in OWASP rules
  owasp:
    sql_injection: true
    xss: true
    command_injection: true
    lfi: true
    rfi: true
    xxe: true
    path_traversal: true
    ssrf: true
   csrf: true

  # Community rules
  community:
    enabled: true
    ruleset_version: "2024.01"
    auto_update: true
    update_interval: 24h

  # Custom rules
  custom:
    enabled: true
    paths:
      - /app/config/rules
      - /app/config/rules/custom
    file_pattern: "*.yaml"
```

## ML Engine Configuration

```yaml
ml:
  # Enable ML-based detection
  enabled: true

  # Path to ML models
  model_path: /app/config/models

  # Anomaly score threshold (0.0 - 1.0)
  # Higher = more strict, lower = more permissive
  anomaly_threshold: 0.75

  # Fallback to rule-based detection if ML fails
  fallback_enabled: true

  # Model update interval
  model_update_interval: 1h

  # Feature cache size
  feature_cache_size: 100000

  # Model configuration
  models:
    # Isolation Forest for anomaly detection
    isolation_forest:
      enabled: true
      contamination: 0.1
      n_estimators: 100
      max_samples: 256

    # DistilBERT for NLP-based threat detection
    distilbert:
      enabled: true
      model_name: "distilbert-base-uncased"
      max_length: 512
      batch_size: 32

    # Random Forest for classification
    random_forest:
      enabled: true
      n_estimators: 100
      max_depth: 10

    # Gradient Boosting for scoring
    gradient_boosting:
      enabled: true
      n_estimators: 100
      learning_rate: 0.1
      max_depth: 5
```

## Rate Limiting Configuration

```yaml
rate_limiting:
  # Enable rate limiting
  enabled: true

  # Global rate limit (applies to all requests)
  global:
    requests_per_minute: 10000
    burst: 500
    algorithm: token_bucket  # "fixed" | "sliding" | "token_bucket" | "leaky_bucket"

  # Per-IP rate limit
  per_ip:
    requests_per_minute: 100
    burst: 20
    algorithm: sliding_window

  # Per-user rate limit (requires authentication)
  per_user:
    requests_per_minute: 1000
    burst: 100

  # Per-session rate limit
  per_session:
    requests_per_minute: 500
    burst: 50

  # Per-endpoint rate limit
  per_endpoint:
    requests_per_minute: 100
    burst: 10

  # Response headers
  headers:
    enabled: true
    include_limit: true
    include_remaining: true
    include_reset: true

  # Rate limit key composition
  key:
    # Variables to use for rate limit key
    # Can combine: ip, user, session, endpoint, header
    template: "ip:endpoint"
    header_name: X-Client-ID

  # Exemptions
  exemptions:
    - ip: "10.0.0.0/8"
      rpm: 100000
    - ip: "192.168.0.0/16"
      rpm: 100000
    - user: admin
      rpm: 100000
```

### Rate Limiting Algorithms

#### Fixed Window

```yaml
algorithm: fixed
# Simple counter that resets at the window boundary
# Pros: Low memory, simple
# Cons: Burst at window boundaries
```

#### Sliding Window

```yaml
algorithm: sliding_window
# Rolling window using Redis sorted sets
# Pros: Accurate, no burst at boundaries
# Cons: Higher memory usage
```

#### Token Bucket

```yaml
algorithm: token_bucket
# Tokens added at constant rate, requests consume tokens
# Pros: Allows bursts, smooth rate
# Cons: More complex
bucket_size: 100
refill_rate: 10  # tokens per second
```

#### Leaky Bucket

```yaml
algorithm: leaky_bucket
# Requests processed at constant rate
# Pros: Strict rate enforcement
# Cons: Higher latency under burst
leak_rate: 10  # requests per second
bucket_size: 100
```

## Bot Detection Configuration

```yaml
bot_detection:
  # Enable bot detection
  enabled: true

  # Device fingerprinting
  fingerprint_enabled: true
  fingerprint_cache_ttl: 24h

  # Headless browser detection
  headless_browser_detection: true
  detection_methods:
    - navigator_webdriver
    - navigator_languages
    - screen_resolution
    - timezone
    - canvas_fingerprint
    - webgl_vendor
    - plugins

  # CAPTCHA threshold (0.0 - 1.0)
  # Requests above this threshold will be challenged with CAPTCHA
  captcha_threshold: 0.8

  # Honeypot fields
  honeypot_enabled: true
  honeypot_field_names:
    - email_address
    - username
    - password

  # Tarpit mode (adds delays to suspected bots)
  tarpit_enabled: true
  tarpit_delay_ms: 5000

  # Good bot allowlisting
  known_bots:
    - googlebot
    - bingbot
    - yandexbot
    - baiduspider
    - facebookexternalhit
    - twitterbot
    - applebot

  # Behavioral analysis
  behavioral:
    enabled: true
    mouse_movement_threshold: 10
    keyboard_input_threshold: 5
    scroll_depth_threshold: 0.8
```

## DDoS Protection Configuration

```yaml
ddos:
  # Enable DDoS protection
  enabled: true

  # HTTP flood detection
  http_flood:
    enabled: true
    threshold: 500  # requests per minute
    window: 1m
    sensitivity: high  # "low" | "medium" | "high"
    action: block  # "block" | "captcha" | "rate_limit"

  # Slowloris protection
  slowloris:
    enabled: true
    timeout: 30s
    min_headers: 5
    action: block

  # Slow POST protection
  slow_post:
    enabled: true
    timeout: 60s
    content_length_threshold: 1024  # bytes
    read_rate_threshold: 10  # bytes per second
    action: block

  # Cache-busting attack detection
  cache_busting:
    enabled: true
    threshold: 50  # unique query params per minute
    action: rate_limit

  # Connection limits
  connection_limits:
    max_connections_per_ip: 100
    max_connections_per_subnet: 1000
    connection_timeout: 30s
```

## Audit Logging Configuration

```yaml
audit:
  # Enable audit logging
  enabled: true

  # What to log
  log_all_requests: false
  log_blocked_requests: true
  log_suspicious_requests: true

  # Log request/response bodies
  log_request_body: false
  log_response_body: false

  # Sensitive fields to redact
  redact_fields:
    - password
    - credit_card
    - ssn
    - api_key
    - authorization

  # Log retention
  retention_days: 90

  # Log compression
  compression_enabled: true

  # Log rotation
  rotation:
    max_size: 100MB
    max_age: 7d
    max_backups: 10
    compress: true
```

## Logging Configuration

```yaml
logging:
  # Log level: debug, info, warn, error
  level: info

  # Log format: json, text, logfmt
  format: json

  # Log outputs
  outputs:
    # Standard output
    - type: stdout
      format: json

    # File output
    - type: file
      path: /app/logs/fortresswaf.log
      rotation:
        max_size: 100MB
        max_age: 7d
        max_backups: 10
        compress: true

    # Syslog output
    - type: syslog
      host: localhost
      port: 514
      protocol: tcp  # "tcp" | "udp"
      facility: local0

    # Journald output
    - type: journald

  # Component-specific log levels
  components:
    rule_engine: info
    ml_engine: debug
    bot_detection: info
    rate_limiter: warn
    redis: error
    postgres: error
```

## Secret Management

### HashiCorp Vault

```yaml
secrets:
  provider: vault

  vault:
    # Vault server address
    address: https://vault.example.com:8200

    # Vault token (or use AppRole)
    token: s.XXXXXXXXXXXXXX

    # Kubernetes auth (alternative to token)
    kubernetes:
      enabled: true
      role: fortresswaf
      mount_path: kubernetes

    # Secret path
    path: secret/fortresswaf

    # CA certificate for TLS
    ca_cert: /certs/vault-ca.crt

    # TLS certificate for mTLS
    client_cert: /certs/vault-client.crt
    client_key: /certs/vault-client.key

    # Secret keys mapping
    keys:
      admin_password: admin-password
      api_key: api-key
      postgres_password: postgres-password
      redis_password: redis-password
      tls_cert: tls-cert
      tls_key: tls-key
```

### AWS Secrets Manager

```yaml
secrets:
  provider: aws-secrets-manager

  aws:
    # AWS region
    region: us-east-1

    # Secret name
    secret_name: fortresswaf/production

    # Optional: Use specific KMS key for decryption
    kms_key_id: arn:aws:kms:us-east-1:123456789012:key/xxxx-xxxx-xxxx

    # AWS profile (optional, uses default)
    profile: production

    # Secret keys mapping
    keys:
      admin_password: admin-password
      api_key: api-key
```

### Azure Key Vault

```yaml
secrets:
  provider: azure-keyvault

  azure:
    # Azure Key Vault URL
    vault_url: https://fortresswaf.vault.azure.net/

    # Authentication method
    auth:
      method: service_principal  # "service_principal" | "managed_identity"
      client_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      client_secret: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
      tenant_id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

    # Secret keys mapping
    keys:
      admin_password: AdminPassword
      api_key: ApiKey
```

## Environment Variables

FortressWAF can be configured using environment variables. Environment variables take precedence over configuration file values.

### General Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `FW_CONFIG_PATH` | Path to config file | `/app/config/config.yaml` |
| `FW_LOG_LEVEL` | Log level | `info` |
| `FW_LOG_FORMAT` | Log format | `json` |

### Server Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `FW_SERVER_HOST` | Bind address | `0.0.0.0` |
| `FW_SERVER_PORT` | Dashboard port | `8443` |
| `FW_API_PORT` | API port | `8444` |
| `FW_TLS_ENABLED` | Enable TLS | `true` |

### Redis Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `FW_REDIS_HOST` | Redis hostname | `localhost` |
| `FW_REDIS_PORT` | Redis port | `6379` |
| `FW_REDIS_PASSWORD` | Redis password | `` |
| `FW_REDIS_DB` | Redis database | `0` |
| `FW_REDIS_SSL` | Use TLS | `false` |

### PostgreSQL Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `FW_POSTGRES_HOST` | PostgreSQL hostname | `localhost` |
| `FW_POSTGRES_PORT` | PostgreSQL port | `5432` |
| `FW_POSTGRES_DB` | Database name | `fortresswaf` |
| `FW_POSTGRES_USER` | Database user | `fortresswaf` |
| `FW_POSTGRES_PASSWORD` | Database password | `` |

### ML Engine Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `FW_ML_ENABLED` | Enable ML engine | `true` |
| `FW_ML_THRESHOLD` | Anomaly threshold | `0.75` |

### Example Environment File

```bash
# .env file
FW_CONFIG_PATH=/app/config/config.yaml
FW_LOG_LEVEL=info
FW_SERVER_PORT=8443
FW_TLS_ENABLED=true

# Redis
FW_REDIS_HOST=redis
FW_REDIS_PORT=6379

# PostgreSQL
FW_POSTGRES_HOST=postgres
FW_POSTGRES_DB=fortresswaf
FW_POSTGRES_USER=fortresswaf
FW_POSTGRES_PASSWORD=changeme

# ML Engine
FW_ML_ENABLED=true
FW_ML_THRESHOLD=0.75
```

## Hot Reload Behavior

FortressWAF supports hot reloading of configuration and rules without requiring a restart.

### What Can Be Hot Reloaded

| Component | Hot Reloadable | Method |
|-----------|----------------|--------|
| Rules | Yes | File watch or API |
| Rate limits | Yes | API |
| IP blacklist/whitelist | Yes | API |
| Logging level | Yes | API |
| ML models | Yes | API |

### Hot Reload Methods

1. **File Watch**: Changes to files in `custom_rules_path` are detected automatically
2. **API Call**: `POST /api/v1/reload` to trigger a reload
3. **CLI**: `fortressctl reload --type rules`
4. **SIGHUP**: Send `kill -HUP <pid>` to the process

### Hot Reload API

```bash
# Reload all components
curl -X POST https://localhost:8444/api/v1/reload \
  -H "Authorization: Bearer $API_KEY"

# Reload only rules
curl -X POST https://localhost:8444/api/v1/reload/rules \
  -H "Authorization: Bearer $API_KEY"

# Reload rate limits
curl -X POST https://localhost:8444/api/v1/reload/rate-limits \
  -H "Authorization: Bearer $API_KEY"
```

## Configuration Validation

Validate your configuration before starting FortressWAF:

```bash
# Validate configuration file
fortressctl config validate --path /app/config/config.yaml

# Test configuration and show resolved values
fortressctl config show --path /app/config/config.yaml

# Validate rules directory
fortressctl rules validate --path /app/config/rules
```

## Complete Example Configuration

```yaml
# Complete FortressWAF Configuration
# Production-ready configuration with all options

server:
  host: 0.0.0.0
  port: 8443
  api_port: 8444
  tls:
    enabled: true
    cert_path: /certs/server.crt
    key_path: /certs/server.key
    min_version: "1.2"
    prefer_server_cipher: true
  read_timeout: 60s
  write_timeout: 60s
  idle_timeout: 120s
  max_header_bytes: 16384

logging:
  level: info
  format: json
  outputs:
    - type: stdout
    - type: file
      path: /app/logs/fortresswaf.log
      rotation:
        max_size: 100MB
        max_age: 7d
        max_backups: 10
        compress: true

redis:
  host: redis
  port: 6379
  password: ""
  db: 0
  pool_size: 20
  ssl: false
  cluster_mode: false
  max_retries: 3
  read_timeout: 5s
  write_timeout: 5s

database:
  host: postgres
  port: 5432
  name: fortresswaf
  user: fortresswaf
  password: ""
  ssl_mode: prefer
  max_open_conns: 25
  max_idle_conns: 10
  conn_max_lifetime: 5m

engine:
  workers: auto
  max_request_size: 10MB
  request_timeout: 60s
  keep_alive_timeout: 30s
  disable_internal_errors: true

rules:
  owasp_enabled: true
  community_rules_enabled: true
  custom_rules_path: /app/config/rules
  reload_interval: 30s
  cache_size: 10000

ml:
  enabled: true
  model_path: /app/config/models
  anomaly_threshold: 0.75
  fallback_enabled: true
  model_update_interval: 1h

rate_limiting:
  enabled: true
  global:
    requests_per_minute: 10000
    burst: 500
    algorithm: token_bucket
  per_ip:
    requests_per_minute: 100
    burst: 20

bot_detection:
  enabled: true
  fingerprint_enabled: true
  headless_browser_detection: true
  captcha_threshold: 0.8
  honeypot_enabled: true
  tarpit_enabled: true
  tarpit_delay_ms: 5000

ddos:
  enabled: true
  http_flood_threshold: 500
  slowloris_timeout: 30s
  slow_post_timeout: 60s

audit:
  enabled: true
  log_blocked_requests: true
  log_suspicious_requests: true
  retention_days: 90
  redact_fields:
    - password
    - credit_card
    - ssn
    - api_key
```
