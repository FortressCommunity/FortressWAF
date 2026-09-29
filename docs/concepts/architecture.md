> **Note:** This document describes the intended architecture. Components shown here (auto-scaling, multi-node clustering) are not yet implemented. PostgreSQL, Prometheus, CAPTCHA, gRPC, response inspection, HTTP/2, and credential protection are implemented. See [architecture.md](../architecture.md) for the current implementation.

# Architecture Deep Dive

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

This document outlines FortressWAF's target architecture. Current implementation covers only reverse proxy mode with file-based config.

## System Architecture Overview

FortressWAF is designed as a distributed, microservices-based system that can scale horizontally to handle high-throughput traffic while maintaining low latency. The architecture follows a pipeline-based request processing model with multiple inspection layers.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              FORTRESSWAF CLUSTER                                 │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                         REQUEST INGRESS LAYER                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │   │
│  │  │   TLS      │  │   TLS      │  │   TLS      │  │   HTTP/2    │       │   │
│  │  │ Termination│  │ Termination│  │ Termination│  │   Support   │       │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                         │
│                                        ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                        INSPECTION PIPELINE                                │   │
│  │                                                                          │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌───────────┐  │   │
│  │  │     1.      │───▶│     2.      │───▶│     3.      │───▶│     4.    │  │   │
│  │  │    IP       │    │   Rate      │    │   Bot       │    │   Rule    │  │   │
│  │  │ Reputation  │    │  Limiting   │    │  Detection  │    │  Engine   │  │   │
│  │  │   Check     │    │             │    │             │    │           │  │   │
│  │  └─────────────┘    └─────────────┘    └─────────────┘    └───────────┘  │   │
│  │                                                                      │    │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌───────────┐  │   │
│  │  │     5.      │───▶│     6.      │───▶│     7.      │───▶│     8.    │  │   │
│  │  │    ML       │    │  Session    │    │  Response   │    │  Decision │  │   │
│  │  │  Anomaly    │    │  Tracking   │    │ Inspection  │    │  & Action │  │   │
│  │  │   Score     │    │             │    │             │    │           │  │   │
│  │  └─────────────┘    └─────────────┘    └─────────────┘    └───────────┘  │   │
│  │                                                                          │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                         │
│                                        ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                      RESPONSE HANDLING LAYER                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │   │
│  │  │   Block     │  │  Challenge  │  │   Allow     │  │   Redirect  │       │   │
│  │  │  Response   │  │  (CAPTCHA)  │  │   Pass      │  │             │       │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                         │
│                                        ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                        BACKEND ORCHESTRATION                              │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │   │
│  │  │  Health    │  │   Load     │  │   SSL       │  │   Origin   │       │   │
│  │  │  Checks    │  │  Balancing │  │   Passthrough│ │  Failover  │       │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                        │                                         │
│                                        ▼                                         │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │                    PROTECTED APPLICATIONS                                 │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │   │
│  │  │  K8s Pods  │  │   Docker    │  │    VMs      │  │  Functions  │       │   │
│  │  │            │  │  Containers │  │             │  │   (Lambda)  │       │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘       │   │
│  └──────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATA LAYER                                           │
│  ┌─────────────────────┐        ┌─────────────────────┐        ┌───────────────┐ │
│  │       Redis         │        │    PostgreSQL       │        │    Object     │ │
│  │   Session State     │        │   Persistent Data   │        │    Storage    │ │
│  │   Rate Limits       │        │   Rules & Config    │        │   (Models)    │ │
│  │   IP Reputation     │        │   Audit Logs        │        │               │ │
│  │   ML Features       │        │   Analytics         │        │               │ │
│  └─────────────────────┘        └─────────────────────┘        └───────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Request Router

The Request Router handles incoming traffic and distributes requests across worker threads.

**Responsibilities:**
- TLS termination
- HTTP/2 support
- Request parsing and validation
- Connection management
- Load balancing across workers

**Technical Details:**
- Uses epoll/kqueue for high-performance I/O
- Zero-copy request parsing
- Connection pooling to backends

### 2. IP Reputation Service

Maintains dynamic lists of IP addresses categorized by threat level.

**IP Categories:**
| Category | Description | Default Action |
|----------|-------------|----------------|
| `trusted` | Whitelisted IPs | Allow |
| `suspicious` | Possibly malicious | Challenge |
| `malicious` | Known attackers | Block |
| `tor_exit` | Tor exit nodes | Challenge |
| `vpn` | VPN exit points | Log |
| `cloud_provider` | Cloud infrastructure | Rate limit |

**Data Sources:**
- Third-party threat intelligence feeds
- FortressWAF global reputation network
- Community-driven blocklists
- Machine learning predictions

### 3. Rate Limiting Engine

Implements multiple rate limiting algorithms with distributed state.

**Supported Algorithms:**
- Fixed Window
- Sliding Window
- Token Bucket
- Leaky Bucket

**Rate Limit Scopes:**
- Global (entire WAF cluster)
- Per-IP address
- Per-user (authenticated)
- Per-session
- Per-endpoint (URL path)

### 4. Bot Detection Engine

Identifies and manages automated bot traffic using multiple detection methods.

**Detection Methods:**
1. **Device Fingerprinting**
   - Canvas fingerprint
   - WebGL renderer
   - Navigator properties
   - Screen resolution
   - Timezone
   - Language settings

2. **Behavioral Analysis**
   - Mouse movement patterns
   - Keyboard input timing
   - Scroll behavior
   - Click patterns

3. **Headless Browser Detection**
   - WebDriver detection
   - Chrome headless mode
   - PhantomJS signatures

4. **Challenge/Response**
   - JavaScript challenges
   - CAPTCHA challenges
   - Cookie challenges

### 5. Rule Engine

The core pattern matching engine that evaluates requests against security rules.

**Rule Components:**
- Conditions (IP, headers, body, path, etc.)
- Operators (regex, equals, contains, etc.)
- Actions (block, allow, challenge, log)
- Transforms (lowercase, url_decode, base64_decode)

### 6. ML Anomaly Scoring

Machine learning models analyze request patterns for anomalies.

**Models:**
- **Isolation Forest**: Anomaly detection on request features
- **DistilBERT**: NLP-based threat classification
- **Random Forest**: Structured feature classification
- **Gradient Boosting**: Ensemble scoring

### 7. Session Tracker

Maintains stateful session information using Redis.

**Session Data:**
- User authentication state
- Client fingerprint
- Request history
- Challenge state
- Rate limit counters

### 8. Response Inspector

Analyzes responses for data leakage and policy violations.

**Checks:**
- Credit card detection (PCI DSS)
- PII detection (GDPR)
- Error message leakage
- Server version disclosure
- Custom header checks

### 9. Decision Engine

Aggregates signals from all inspection layers and makes final decisions.

**Decision Factors:**
- Rule matches
- ML anomaly score
- Bot score
- Rate limit status
- IP reputation
- Session state

## Request Flow Through Inspection Layers

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         REQUEST FLOW                                     │
└─────────────────────────────────────────────────────────────────────────┘

     ┌───────────────┐
     │  Client       │
     │  Request      │
     └───────┬───────┘
             │
             ▼
     ┌───────────────┐      ┌────────────────┐
     │ TLS Termination│─────▶│ Parse Request  │
     └───────────────┘      └───────┬────────┘
                                   │
                                   ▼
     ┌───────────────┐      ┌────────────────┐
     │   IP          │      │   Add Request  │
     │ Reputation    │◀─────▶│   Context      │
     │   Check       │      │   (Headers,    │
     └───────┬───────┘      │   Body, Meta)  │
             │              └───────┬────────┘
             │                      │
             │ YES                  ▼
             │              ┌────────────────┐
             ├─────────────▶│     Rate      │
             │              │    Limiting    │
             │              │     Check      │
             │              └───────┬────────┘
             │                      │
             ▼                      ▼
     ┌───────────────┐      ┌────────────────┐
     │    Block      │      │   Bot          │
     │   Request     │◀─────│  Detection      │
     │               │      │                 │
     └───────────────┘      └───────┬────────┘
                                    │
                                    ▼
     ┌───────────────┐      ┌────────────────┐
     │   Challenge   │◀─────│     Rule       │
     │  (CAPTCHA)    │      │    Engine      │
     └───────────────┘      └───────┬────────┘
                                    │
                                    ▼
     ┌───────────────┐      ┌────────────────┐
     │   Challenge   │◀─────│      ML        │
     │  (JS/Cookie)   │      │   Anomaly      │
     └───────────────┘      │    Score       │
                            └───────┬────────┘
                                    │
                                    ▼
                            ┌────────────────┐
                            │   Session     │
                            │   Tracking    │
                            └───────┬────────┘
                                    │
                                    ▼
                            ┌────────────────┐
                            │    Decision   │
                            │    Engine     │
                            └───────┬────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
            ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
            │     Allow     │ │     Block     │ │   Challenge   │
            │   Request     │ │   Request     │ │    Request    │
            └───────┬───────┘ └───────────────┘ └───────────────┘
                    │
                    ▼
            ┌───────────────┐      ┌────────────────┐
            │   Response   │─────▶│    Response   │
            │   Inspection  │      │    Processing  │
            └───────┬───────┘      └───────┬────────┘
                    │                      │
                    ▼                      ▼
            ┌───────────────┐      ┌────────────────┐
            │   Backend     │      │     Audit      │
            │   Request     │      │     Log        │
            └───────────────┘      └────────────────┘
```

## Deployment Modes

### Inline Mode (Recommended for Production)

All traffic flows through FortressWAF for full inspection.

```
Internet ──▶ FortressWAF ──▶ Backend Applications
                │
                ├── Block malicious requests
                ├── Challenge suspicious requests
                └── Pass legitimate requests
```

**Use Cases:**
- Maximum security requirements
- Real-time threat mitigation
- Full compliance logging

### Mirror Mode (SPAN/TAP)

Traffic is mirrored to FortressWAF for analysis only.

```
Internet ──┬──▶ FortressWAF (mirror) ──▶ Analysis Only
           │
           └──▶ Direct to Backend (no inspection)
```

**Use Cases:**
- Compliance logging without latency impact
- Testing new rule sets
- Staging environment testing

### Hybrid Mode

Combines inline blocking with out-of-band analysis.

```
Internet ──▶ FortressWAF (inline)
                │
                ├── Block obvious attacks
                └── Mirror traffic to Analysis Cluster

Analysis Cluster ──▶ Recommendations ──▶ Update Rules
```

**Use Cases:**
- Production with deep analysis
- Gradual rule testing
- Zero false positive tuning

### Out-of-Band API Mode

FortressWAF acts as an API for existing proxies.

```
Existing Proxy ──▶ FortressWAF API ──▶ Allow/Block Decision
                            │
                            └──▶ Returns verdict
```

**Use Cases:**
- Legacy WAF migration
- Integration with existing load balancers
- Gradual adoption

## Clustering Architecture

### Stateless Worker Nodes

FortressWAF workers are stateless, enabling horizontal scaling:

```
                    ┌─────────────────────────┐
                    │   Load Balancer / Ingress│
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│   Worker 1    │       │   Worker 2    │       │   Worker N    │
│   (stateless) │       │   (stateless) │       │   (stateless) │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                       │
        │    ┌───────────────────┼───────────────────┐   │
        │    │                   │                   │   │
        ▼    ▼                   ▼                   ▼   ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│     Redis     │       │   PostgreSQL  │       │   ML Models   │
│   (Shared)    │       │   (Shared)    │       │   (Read-only) │
└───────────────┘       └───────────────┘       └───────────────┘
```

### Redis Data Model

Redis stores shared state across all workers:

| Key Pattern | Type | Description | TTL |
|-------------|------|-------------|-----|
| `ratelimit:global:{minute}` | String | Global rate counter | 2 min |
| `ratelimit:ip:{ip}:{minute}` | String | Per-IP counter | 2 min |
| `session:{session_id}` | Hash | Session data | 24h |
| `fingerprint:{hash}` | Hash | Device fingerprint | 24h |
| `ip:reputation:{ip}` | Hash | IP reputation data | 1h |
| `ml:features:{request_id}` | List | Request features | 5 min |
| `blocklist:v4` | Set | IPv4 blocklist | - |
| `blocklist:v6` | Set | IPv6 blocklist | - |
| `allowlist:v4` | Set | IPv4 allowlist | - |

### PostgreSQL Schema

```
┌─────────────────────────────────────────────────────────────────┐
│                     FORTRESSWAF DATABASE                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    sites        │     │     rules       │     │    events       │
├─────────────────┤     ├─────────────────┤     ├─────────────────┤
│ id (PK)         │     │ id (PK)         │     │ id (PK)         │
│ name            │     │ site_id (FK)    │     │ site_id (FK)    │
│ domain          │◀────│ name            │     │ timestamp       │
│ backend_url     │     │ priority        │     │ request_id      │
│ tls_mode        │     │ condition        │     │ client_ip       │
│ health_check_url│     │ action          │     │ request_method  │
│ created_at      │     │ enabled         │     │ request_path    │
│ updated_at      │     │ created_at      │     │ request_headers │
└─────────────────┘     │ updated_at      │     │ request_body    │
        │               └─────────────────┘     │ response_status │
        │                       │               │ rule_id         │
        │                       │               │ action_taken    │
        │                       ▼               │ ml_score        │
        │               ┌─────────────────┐       │ bot_score       │
        │               │   rule_audit    │       │ created_at      │
        │               ├─────────────────┤       └─────────────────┘
        │               │ id (PK)         │
        │               │ rule_id (FK)    │       ┌─────────────────┐
        │               │ match_count     │       │   api_keys      │
        │               │ block_count     │       ├─────────────────┤
        │               │ last_matched    │       │ id (PK)         │
        │               └─────────────────┘       │ site_id (FK)    │
        │                                         │ key_hash        │
        │               ┌─────────────────┐       │ name            │
        │               │    users        │       │ permissions     │
        │               ├─────────────────┤       │ last_used       │
        │               │ id (PK)         │       │ expires_at      │
        └───────────────▶│ username       │       │ created_at      │
                        │ password_hash   │       └─────────────────┘
                        │ email           │
                        │ role            │
                        │ created_at      │
                        └─────────────────┘
```

### Key Tables

#### `sites` Table

Stores protected application configurations:

```sql
CREATE TABLE sites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    backend_url TEXT NOT NULL,
    backend_host_header VARCHAR(255),
    tls_mode VARCHAR(50) NOT NULL DEFAULT 'terminate',
    tls_cert_id UUID,
    health_check_url VARCHAR(255),
    health_check_interval INTEGER DEFAULT 10,
    health_check_timeout INTEGER DEFAULT 5,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sites_domain ON sites(domain);
CREATE INDEX idx_sites_is_active ON sites(is_active);
```

#### `rules` Table

Stores WAF rule configurations:

```sql
CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id UUID REFERENCES sites(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL DEFAULT 100,
    condition JSONB NOT NULL,
    action JSONB NOT NULL,
    transformation JSONB DEFAULT '[]',
    is_enabled BOOLEAN DEFAULT true,
    is_system BOOLEAN DEFAULT false,
    match_count BIGINT DEFAULT 0,
    block_count BIGINT DEFAULT 0,
    last_matched TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_rules_site_id ON rules(site_id);
CREATE INDEX idx_rules_priority ON rules(priority);
CREATE INDEX idx_rules_enabled ON rules(is_enabled);
CREATE INDEX idx_rules_condition ON rules USING GIN(condition);
```

#### `events` Table

Stores audit log events:

```sql
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id UUID REFERENCES sites(id) ON DELETE SET NULL,
    request_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    client_ip INET NOT NULL,
    client_port INTEGER,
    server_ip INET,
    request_method VARCHAR(10) NOT NULL,
    request_path TEXT NOT NULL,
    request_query TEXT,
    request_headers JSONB,
    request_body BYTEA,
    request_body_truncated BOOLEAN DEFAULT false,
    response_status INTEGER,
    response_headers JSONB,
    response_body BYTEA,
    response_body_truncated BOOLEAN DEFAULT false,
    rule_id UUID,
    action_taken VARCHAR(50) NOT NULL,
    action_reason TEXT,
    ml_score REAL,
    ml_threshold REAL,
    bot_score REAL,
    ip_reputation_category VARCHAR(50),
    rate_limit_category VARCHAR(50),
    session_id VARCHAR(64),
    user_id UUID,
    duration_ms INTEGER,
    bytes_sent BIGINT,
    bytes_received BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_events_site_id ON events(site_id);
CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_events_client_ip ON events(client_ip);
CREATE INDEX idx_events_action ON events(action_taken);
CREATE INDEX idx_events_rule_id ON events(rule_id);
CREATE PARTITION BY RANGE (timestamp);

-- Create monthly partitions
CREATE TABLE events_2024_01 PARTITION OF events
    FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');
CREATE TABLE events_2024_02 PARTITION OF events
    FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
```

## High Availability Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           HIGH AVAILABILITY SETUP                        │
└─────────────────────────────────────────────────────────────────────────┘

                         ┌─────────────────┐
                         │   Load Balancer  │
                         │   (Nginx/HAProxy)│
                         └────────┬────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
            ▼                     ▼                     ▼
    ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
    │  FortressWAF  │     │  FortressWAF  │     │  FortressWAF  │
    │    Node 1     │     │    Node 2     │     │    Node 3     │
    │ (Primary AZ)  │     │(Secondary AZ)  │     │ (Tertiary AZ) │
    └───────┬───────┘     └───────┬───────┘     └───────┬───────┘
            │                     │                     │
            │    ┌────────────────┼────────────────┐    │
            │    │                │                │    │
            ▼    ▼                ▼                ▼    ▼
    ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
    │    Redis      │     │   Redis       │     │   Redis       │
    │   Sentinel    │◀───▶│   Sentinel    │◀───▶│   Sentinel    │
    │   Primary     │     │   Replica     │     │   Replica     │
    └───────────────┘     └───────────────┘     └───────────────┘
            │
            │ Replication
            ▼
    ┌───────────────┐     ┌───────────────┐
    │  PostgreSQL   │◀───▶│  PostgreSQL   │
    │   Primary     │     │   Replica     │
    └───────────────┘     └───────────────┘
```

### Failure Handling

| Component Failure | Detection | Recovery |
|------------------|-----------|----------|
| Worker node down | Health check | Load balancer removes from pool |
| Redis primary down | Sentinel election | Automatic failover to replica |
| PostgreSQL primary down | Streaming replication | Manual failover with pg_pool |
| ML model unavailable | Health check | Fallback to rule-based only |
| Backend unavailable | Health check | Failover to backup origin |

## Performance Characteristics

### Latency Budget

A typical request latency breakdown:

| Component | P50 | P95 | P99 |
|-----------|-----|-----|-----|
| TLS termination | 0.5ms | 1ms | 2ms |
| IP reputation check | 0.1ms | 0.2ms | 0.5ms |
| Rate limiting | 0.2ms | 0.5ms | 1ms |
| Bot detection | 1ms | 3ms | 5ms |
| Rule engine | 0.5ms | 2ms | 5ms |
| ML scoring | 5ms | 15ms | 30ms |
| Session tracking | 0.3ms | 1ms | 2ms |
| Decision engine | 0.1ms | 0.2ms | 0.5ms |
| **Total overhead** | **8ms** | **25ms** | **50ms** |

### Throughput

| Deployment | Requests/Second | Bandwidth |
|------------|-----------------|-----------|
| Single node (4 cores) | 50,000 | 1 Gbps |
| Single node (8 cores) | 100,000 | 2 Gbps |
| 3-node cluster | 250,000 | 5 Gbps |
| 10-node cluster | 1,000,000 | 20 Gbps |

### Resource Usage

| Resource | Per Worker (idle) | Per Worker (max load) |
|----------|-------------------|----------------------|
| CPU | 5% | 80% |
| Memory | 512 MB | 2 GB |
| Network | 0 Mbps | 500 Mbps |
| Redis ops/sec | 1,000 | 50,000 |
