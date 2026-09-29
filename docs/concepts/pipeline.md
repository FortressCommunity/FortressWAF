# Inspection Pipeline

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF processes requests through a multi-stage inspection pipeline. Each stage performs specific security checks and contributes to the final decision. This document details the complete pipeline architecture and processing flow.

## Pipeline Overview

The inspection pipeline consists of sequential stages, each handling specific aspects of request analysis. The pipeline is designed for:

- **Determinism**: Same request always produces same decision
- **Performance**: Early stages filter obvious threats
- **Scalability**: Stateless processing enables horizontal scaling
- **Observability**: Each stage logs its findings

## Pipeline Stages

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     REQUEST INSPECTION PIPELINE                          │
└─────────────────────────────────────────────────────────────────────────┘

     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 0: Request Parsing & Context Building                  │
     │  ──────────────────────────────────────────────────────────── │
     │  - Parse HTTP request line                                     │
     │  - Parse headers                                               │
     │  - Parse body (if applicable)                                 │
     │  - Build request context                                       │
     │  - Extract metadata                                            │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 1: IP Reputation Check                                  │
     │  ──────────────────────────────────────────────────────────── │
     │  - Check IP against blocklist/allowlist                       │
     │  - Query IP reputation score                                   │
     │  - Check GeoIP data                                            │
     │  - Check VPN/Tor/Proxy indicators                              │
     │  - Determine IP reputation category                           │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 2: Rate Limiting                                         │
     │  ──────────────────────────────────────────────────────────── │
     │  - Check global rate limit                                     │
     │  - Check per-IP rate limit                                      │
     │  - Check per-session rate limit                                │
     │  - Check per-endpoint rate limit                               │
     │  - Calculate rate limit headers                               │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 3: Session Tracking                                     │
     │  ──────────────────────────────────────────────────────────── │
     │  - Extract/Generate session ID                                │
     │  - Load session from Redis                                     │
     │  - Update session metadata                                     │
     │  - Store updated session                                       │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 4: Bot Detection                                         │
     │  ──────────────────────────────────────────────────────────── │
     │  - Collect device fingerprint                                  │
     │  - Check fingerprint against known bots                        │
     │  - Behavioral analysis                                         │
     │  - Headless browser detection                                 │
     │  - Calculate bot score                                         │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 5: Rule Evaluation                                      │
     │  ──────────────────────────────────────────────────────────── │
     │  - Load applicable rules (by priority)                         │
     │  - Apply transformations                                       │
     │  - Evaluate conditions                                        │
     │  - Aggregate rule matches                                     │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 6: ML Anomaly Scoring                                   │
     │  ──────────────────────────────────────────────────────────── │
     │  - Extract features from request                               │
     │  - Query ML models                                             │
     │  - Aggregate anomaly scores                                   │
     │  - Compare against threshold                                  │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 7: Threat Aggregation                                   │
     │  ──────────────────────────────────────────────────────────── │
     │  - Combine scores from all sources                            │
     │  - Apply weight factors                                        │
     │  - Determine threat category                                  │
     │  - Calculate final threat score                               │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 8: Decision & Action                                    │
     │  ──────────────────────────────────────────────────────────── │
     │  - Apply decision policy                                       │
     │  - Select action (block/challenge/allow)                       │
     │  - Execute action                                              │
     │  - Generate response                                          │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 9: Response Inspection                                  │
     │  ──────────────────────────────────────────────────────────── │
     │  - Inspect response headers                                    │
     │  - Inspect response body (if enabled)                        │
     │  - Check for data leakage                                     │
     │  - Check for compliance violations                            │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
     ┌────────────────────────────────────────────────────────────────┐
     │  STAGE 10: Audit Logging                                       │
     │  ──────────────────────────────────────────────────────────── │
     │  - Log request details                                         │
     │  - Log decision and action                                     │
     │  - Log scores and metadata                                     │
     │  - Store in PostgreSQL                                         │
     └────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                            ┌────────────────┐
                            │  Forward to   │
                            │   Backend     │
                            └────────────────┘
```

## Detailed Stage Description

### Stage 0: Request Parsing

**Purpose**: Parse and validate incoming HTTP request

**Processing**:
1. Read raw request from connection
2. Parse request line (`METHOD URI HTTP/VERSION`)
3. Parse and validate headers
4. Parse query string
5. Parse body (form, JSON, XML as applicable)
6. Build request context object
7. Extract request metadata (size, duration tracking)

**Output**: `RequestContext` with all parsed data

**Error Handling**:
- Malformed requests: Return 400 Bad Request
- Oversized requests: Return 413 Payload Too Large
- Invalid HTTP version: Return 505 HTTP Version Not Supported

### Stage 1: IP Reputation Check

**Purpose**: Determine if the client IP is trustworthy

**Data Sources**:
- Local blocklist/allowlist (Redis)
- Third-party threat intelligence feeds
- FortressWAF global reputation network
- GeoIP database
- ASN database

**IP Categories**:
| Category | Description | Default Score |
|----------|-------------|---------------|
| `trusted` | Whitelisted IP | 0.0 |
| `clean` | No negative history | 0.1 |
| `suspicious` | Suspicious activity | 0.5 |
| `malicious` | Known attacker | 0.9 |
| `tor_exit` | Tor exit node | 0.7 |
| `vpn` | VPN exit point | 0.4 |
| `proxy` | HTTP proxy | 0.5 |
| `cloud` | Cloud provider IP | 0.2 |
| `datacenter` | Hosting provider | 0.3 |

**Reputation Factors**:
- Historical attack data
- Current threat intelligence
- Geographic anomalies
- Network behavior
- ASN reputation

**Output**: `IPReputationResult` with category, score, and factors

### Stage 2: Rate Limiting

**Purpose**: Enforce request rate policies

**Rate Limit Types**:

```yaml
rate_limits:
  global:
    requests_per_minute: 10000
    algorithm: token_bucket

  per_ip:
    requests_per_minute: 100
    burst: 20

  per_session:
    requests_per_minute: 500
    burst: 50

  per_endpoint:
    requests_per_minute: 30
    burst: 5
```

**Rate Limit Key Generation**:
```
global: "ratelimit:global"
per_ip: "ratelimit:ip:{client_ip}"
per_session: "ratelimit:session:{session_id}"
per_user: "ratelimit:user:{user_id}"
per_endpoint: "ratelimit:endpoint:{path}:{method}"
```

**Response Headers**:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
X-RateLimit-Window: 60
```

**Algorithms**:

1. **Token Bucket**: Tokens added at constant rate, requests consume tokens
2. **Leaky Bucket**: Requests processed at constant rate
3. **Sliding Window**: Rolling time window
4. **Fixed Window**: Counter resets at window boundary

### Stage 3: Session Tracking

**Purpose**: Maintain stateful session information

**Session ID Sources** (in order of preference):
1. Cookie: `fw_session_id`
2. Header: `X-Session-ID`
3. Query param: `session_id`
4. Generated: New session ID created

**Session Data Structure**:
```json
{
  "session_id": "abc123...",
  "created_at": "2024-01-01T00:00:00Z",
  "last_active": "2024-01-01T00:05:00Z",
  "user_authenticated": false,
  "is_bot": false,
  "request_count": 42,
  "challenge_passed": false,
  "challenge_count": 0,
  "fingerprints": ["hash1", "hash2"],
  "metadata": {}
}
```

**TTL**: Sessions expire after 24 hours of inactivity

### Stage 4: Bot Detection

**Purpose**: Identify automated/bot traffic

**Detection Methods**:

1. **Device Fingerprinting**
   - Canvas fingerprint
   - WebGL renderer
   - Screen resolution
   - Timezone
   - Language
   - Platform
   - Plugins (if detectable)

2. **JavaScript Challenges**
   - Execute JS to collect browser details
   - Measure execution time anomalies
   - Check for automation frameworks

3. **Headless Browser Detection**
   - WebDriver property check
   - Chrome headless mode detection
   - PhantomJS signatures
   - Automation tool detection

4. **Behavioral Analysis**
   - Mouse movement patterns
   - Keyboard timing
   - Click patterns
   - Scroll behavior

5. **Known Bot Signatures**
   - User-agent matching
   - IP reputation
   - ASN filtering

**Bot Categories**:
| Category | Score Range | Action |
|----------|-------------|--------|
| `human` | 0.0 - 0.3 | Allow |
| `likely_human` | 0.3 - 0.5 | Allow with monitoring |
| `suspicious` | 0.5 - 0.7 | Challenge |
| `likely_bot` | 0.7 - 0.9 | Challenge or block |
| `confirmed_bot` | 0.9 - 1.0 | Block |

### Stage 5: Rule Evaluation

**Purpose**: Evaluate request against custom security rules

**Processing Flow**:
1. Load rules applicable to the site/endpoint
2. Sort rules by priority
3. For each rule:
   a. Apply transformations to request data
   b. Evaluate condition against request
   c. If matched: execute action, stop processing
4. If no rule matched: proceed with default allow

**Transformation Pipeline**:
```
Raw Input → lowercase → url_decode → remove_nulls → normalize_path → Match
```

**Rule Match Aggregation**:
- Multiple rules can match simultaneously
- Highest priority rule action is taken
- `allow` action short-circuits evaluation

### Stage 6: ML Anomaly Scoring

**Purpose**: Score requests for anomaly against learned traffic baselines

**Feature Extraction**:
```
Features:
  - Request size, path length, query length
  - Character frequency distribution
  - Entropy measures
  - Known attack pattern indicators
  - Header anomalies
  - Temporal patterns
```

**Models Used**:

1. **Isolation Forest**
   - Anomaly detection on numerical features
   - Fast, efficient for real-time scoring
   - Good for detecting novel patterns

2. **DistilBERT NLP**
   - Natural language processing
   - Detects malicious content in text
   - Understands context and obfuscation

3. **Random Forest**
   - Classification based on structured features
   - Robust to overfitting
   - Provides feature importance

4. **Gradient Boosting**
   - Ensemble scoring
   - Combines multiple weak learners
   - High accuracy

**Scoring**:
```
anomaly_score = w1 * isolation_forest +
                w2 * distilbert +
                w3 * random_forest +
                w4 * gradient_boosting

where weights sum to 1.0
```

**Threshold**: Default 0.75, configurable per site

### Stage 7: Threat Aggregation

**Purpose**: Combine all signals into final decision

**Score Weights**:
| Source | Weight | Description |
|--------|--------|-------------|
| IP Reputation | 0.15 | IP-based threat score |
| Rate Limit | 0.10 | Rate limit exceeded indicator |
| Bot Score | 0.20 | Bot detection score |
| Rule Matches | 0.25 | Traditional rule matches |
| ML Score | 0.30 | Machine learning score |

**Threat Categories**:
| Category | Score Range | Default Action |
|----------|-------------|----------------|
| `low` | 0.0 - 0.3 | Allow |
| `medium` | 0.3 - 0.5 | Monitor/Challenge |
| `high` | 0.5 - 0.7 | Challenge |
| `critical` | 0.7 - 1.0 | Block |

### Stage 8: Decision & Action

**Purpose**: Make final decision and execute action

**Decision Matrix**:
| IP Score | Bot Score | ML Score | Rule Match | Action |
|----------|-----------|-----------|------------|--------|
| < 0.3 | < 0.3 | < 0.3 | None | Allow |
| < 0.3 | < 0.3 | > 0.75 | None | Challenge |
| < 0.3 | < 0.3 | Any | Any | Match Priority |
| > 0.7 | Any | Any | Any | Block |
| Any | > 0.8 | Any | Any | Block |
| Any | Any | Any | Block Rule | Block |

**Action Execution**:

1. **Block**
   - Generate block response
   - Set appropriate headers
   - Log event
   - Return 403 Forbidden

2. **Challenge**
   - Generate challenge (CAPTCHA/JS/Cookie)
   - Present to client
   - Track challenge completion

3. **Allow**
   - Forward request to backend
   - Track in session
   - Log if configured

### Stage 9: Response Inspection

**Purpose**: Analyze responses for policy violations

**Checks Performed**:
1. **Data Leakage Detection**
   - Credit card numbers (PCI DSS)
   - Social Security Numbers
   - API keys/secrets
   - Passwords

2. **Error Message Screening**
   - Stack traces
   - Database errors
   - Internal paths

3. **Security Header Validation**
   - Missing security headers
   - Weak security headers

4. **Content Type Validation**
   - MIME type checking
   - Content-Disposition validation

**Actions on Violation**:
- Log the violation
- Mask sensitive data in logs
- Alert security team
- Optionally block response (rare)

### Stage 10: Audit Logging

**Purpose**: Record all relevant events for security and compliance

**Logged Data**:
```json
{
  "event_id": "uuid",
  "timestamp": "ISO8601",
  "site_id": "uuid",
  "request_id": "uuid",
  "client_ip": "1.2.3.4",
  "request": {
    "method": "POST",
    "path": "/api/users",
    "headers": {},
    "body": "[truncated]"
  },
  "response": {
    "status": 200,
    "headers": {}
  },
  "decision": {
    "action": "allow",
    "reason": "pass",
    "scores": {
      "ip_reputation": 0.1,
      "bot": 0.2,
      "ml": 0.3,
      "threat": 0.1
    }
  },
  "duration_ms": 15
}
```

## Pipeline Configuration

### Enable/Disable Stages

```yaml
pipeline:
  enabled_stages:
    - ip_reputation    # Default: true
    - rate_limiting   # Default: true
    - session         # Default: true
    - bot_detection   # Default: true
    - rules           # Default: true
    - ml_scoring      # Default: true
    - aggregation     # Default: true
    - decision        # Default: true
    - response        # Default: false
    - audit           # Default: true

  stage_config:
    ip_reputation:
      cache_ttl: 5m
      external_feed_enabled: true

    rate_limiting:
      redis_pool_size: 20

    bot_detection:
      fingerprint_ttl: 24h
      challenge_enabled: true

    ml_scoring:
      timeout: 100ms
      fallback_to_rules: true
```

### Custom Stage Ordering

```yaml
pipeline:
  stage_order:
    - parsing
    - ip_reputation
    - rate_limiting
    - session
    - bot_detection
    - rules
    - ml_scoring
    - aggregation
    - decision
    - response
    - audit
```

## Performance Considerations

### Pipeline Latency Budget

| Stage | P50 | P95 | P99 |
|-------|-----|-----|-----|
| Parsing | 0.1ms | 0.3ms | 0.5ms |
| IP Reputation | 0.2ms | 0.5ms | 1ms |
| Rate Limiting | 0.3ms | 1ms | 2ms |
| Session | 0.5ms | 2ms | 5ms |
| Bot Detection | 1ms | 5ms | 10ms |
| Rule Engine | 0.5ms | 3ms | 10ms |
| ML Scoring | 5ms | 15ms | 30ms |
| Aggregation | 0.1ms | 0.2ms | 0.5ms |
| Decision | 0.05ms | 0.1ms | 0.2ms |
| Response | 0.1ms | 0.5ms | 1ms |
| Audit | 0.5ms | 2ms | 5ms |
| **Total** | **8ms** | **30ms** | **65ms** |

### Optimization Strategies

1. **Early Exit**: Block obviously malicious requests as early as possible
2. **Caching**: Cache IP reputation, session data, rule compilations
3. **Async Processing**: Some stages can run in parallel
4. **Connection Pooling**: Reuse connections to Redis/PostgreSQL
5. **Pipeline Batching**: Batch ML model queries
