# Rate Limiting

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides comprehensive rate limiting capabilities to protect your applications from abuse, brute force attacks, and API overuse.

## Rate Limiting Overview

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| Fixed Window | Simple counter resets at window | Basic rate limiting |
| Sliding Window | Rolling time window | More accurate limiting |
| Token Bucket | Tokens added at constant rate | Burst handling |
| Leaky Bucket | Requests processed at constant rate | Smoothing traffic |

## Algorithm Details

### Fixed Window

```
Window: 1 minute

Request 1 ──▶ ████████████ 1/100
Request 2 ──▶ ████████████ 2/100
...
Request 100 ──▶ ████████████ 100/100
Request 101 ──▶ BLOCKED (limit exceeded)
[Window resets]
Request 1 ──▶ ████████████ 1/100
```

**Pros**: Simple, memory efficient
**Cons**: Burst at window boundaries

```yaml
rate_limiting:
  algorithm: fixed
  window: 1m
  limit: 100
```

### Sliding Window

```
Current time: 12:00:45

Window: 1 minute (12:00:00 - 12:01:00)
Weighted requests in window: 0.75 * 100 + 0.25 * 80 = 95

Request arrives at 12:00:45
Check requests from 11:59:45 - 12:00:45
Calculated count: 95
95 < 100 → Allow
```

**Pros**: Accurate, no burst
**Cons**: Higher memory usage (Redis sorted sets)

```yaml
rate_limiting:
  algorithm: sliding_window
  window: 1m
  limit: 100
```

### Token Bucket

```
Bucket capacity: 100 tokens
Refill rate: 10 tokens/second

Initial: 100 tokens
Request 1: 99 tokens remaining
Request 2: 98 tokens remaining
...
Request 100: 0 tokens remaining (bucket empty)
Wait 1 second: 10 tokens refilled
Request 101: 9 tokens remaining
```

**Pros**: Allows bursts, smooth rate
**Cons**: More complex implementation

```yaml
rate_limiting:
  algorithm: token_bucket
  bucket_size: 100
  refill_rate: 10  # tokens per second
```

### Leaky Bucket

```
Leak rate: 10 requests/second
Bucket capacity: 100

Requests arrive at high rate
Processed at constant rate of 10/second
Overflow is blocked

Request 1: Leaks immediately (1 in bucket)
Request 2: 0.1s delay
Request 3: 0.2s delay
...
Request 11: Bucket full, blocked
```

**Pros**: Strict rate enforcement
**Cons**: Higher latency under burst

```yaml
rate_limiting:
  algorithm: leaky_bucket
  leak_rate: 10
  bucket_size: 100
```

## Rate Limit Scopes

### Global Rate Limiting

Apply rate limits across all requests:

```yaml
rate_limiting:
  global:
    enabled: true
    algorithm: token_bucket
    bucket_size: 10000
    refill_rate: 1000  # requests per second
```

### Per-IP Rate Limiting

Protect against individual IP abuse:

```yaml
rate_limiting:
  per_ip:
    enabled: true
    algorithm: sliding_window
    requests_per_minute: 100
    burst: 20
    key: client_ip
```

### Per-User Rate Limiting

For authenticated users:

```yaml
rate_limiting:
  per_user:
    enabled: true
    algorithm: sliding_window
    requests_per_minute: 1000
    burst: 100
    key: user_id
    # Requires authentication
    require_auth: true
```

### Per-Session Rate Limiting

```yaml
rate_limiting:
  per_session:
    enabled: true
    algorithm: token_bucket
    requests_per_minute: 500
    burst: 50
    key: session_id
```

### Per-Endpoint Rate Limiting

Different limits for different endpoints:

```yaml
rate_limiting:
  per_endpoint:
    - path: "/api/auth/login"
      method: POST
      rpm: 10
      burst: 3
    - path: "/api/auth/register"
      method: POST
      rpm: 5
      burst: 2
    - path: "/api/search"
      method: GET
      rpm: 30
      burst: 10
    - path: "/api/export"
      method: POST
      rpm: 5
      burst: 1
```

### Per-API-Key Rate Limiting

```yaml
rate_limiting:
  per_api_key:
    enabled: true
    algorithm: sliding_window
    requests_per_minute: 5000
    burst: 500
    key: api_key
```

## Rate Limit Response Headers

FortressWAF adds informative headers to all responses:

```yaml
rate_limiting:
  headers:
    enabled: true
    include_limit: true        # X-RateLimit-Limit
    include_remaining: true    # X-RateLimit-Remaining
    include_reset: true        # X-RateLimit-Reset
    include_retry_after: true  # Retry-After (when blocked)
    header_prefix: X-RateLimit
```

### Header Examples

**Allowed request:**
```
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

**Blocked request:**
```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640995200
Retry-After: 30
```

## Rate Limit Actions

### Block Action

```yaml
rate_limiting:
  action: block
  block_response:
    status: 429
    body: |
      {"error": "rate_limit_exceeded", "message": "Too many requests", "retry_after": ${retry_after}}
    headers:
      Retry-After: "${retry_after}"
```

### Challenge Action

```yaml
rate_limiting:
  action: challenge
  challenge_type: captcha  # or "cookie", "javascript"
  challenge_threshold: 0.8  # Challenge when 80% of limit reached
```

### Redirect Action

```yaml
rate_limiting:
  action: redirect
  redirect_url: "https://example.com/rate-limit-exceeded"
  redirect_status: 303
```

## Priority Queues

Priority queues ensure high-priority traffic gets through during high load:

```yaml
rate_limiting:
  priority_queues:
    enabled: true
    queues:
      - name: critical
        priority: 1
        weight: 50  # % of capacity reserved
        burst_allowance: 200
      - name: normal
        priority: 2
        weight: 30
        burst_allowance: 100
      - name: background
        priority: 3
        weight: 20
        burst_allowance: 50
    # Assign priority based on request characteristics
    priority_detection:
      - condition: request.headers.x-priority == "critical"
        priority: critical
      - condition: request.headers.authorization exists
        priority: normal
      - condition: true
        priority: background
```

## Burst Configuration

Allow controlled bursts while maintaining average rate:

```yaml
rate_limiting:
  burst:
    enabled: true
    # Allow bursts up to this multiple of the base rate
    max_multiplier: 3
    # How long burst can last
    burst_duration: 10s
    # Cooldown after burst
    cooldown: 60s
    # Requires token bucket or leaky bucket algorithm
    algorithm: token_bucket
```

## Distributed Rate Limiting

When running multiple FortressWAF instances, rate limiting state is shared via Redis:

```yaml
rate_limiting:
  distributed:
    enabled: true
    backend: redis
    redis:
      pool_size: 20
      read_timeout: 5s
      write_timeout: 5s
    # Lua scripts for atomic operations
    atomic_increment: true
    # Consistency level
    consistency: eventual  # "strong" or "eventual"
```

### Redis Key Structure

```
ratelimit:global:minute:{timestamp}     # Global counter
ratelimit:ip:{ip}:minute:{timestamp}   # Per-IP counter
ratelimit:user:{user_id}:minute:{timestamp}  # Per-user counter
ratelimit:endpoint:{path}:method:minute:{timestamp}  # Per-endpoint counter
```

## Exemptions

Allow certain IPs or users to bypass rate limiting:

```yaml
rate_limiting:
  exemptions:
    # IP exemptions
    - type: ip
      value: "10.0.0.0/8"
      rpm: 1000000
    - type: ip
      value: "192.168.0.0/16"
      rpm: 1000000

    # User exemptions
    - type: user
      value: "admin"
      rpm: 1000000

    # API key exemptions
    - type: api_key
      value: "internal-service-key"
      rpm: 100000

    # Path exemptions
    - type: path
      value: "/health"
      rpm: 1000000
    - type: path
      value: "/metrics"
      rpm: 1000000
```

## Custom Rate Limit Keys

Define custom keys based on request attributes:

```yaml
rate_limiting:
  custom_keys:
    # Key based on API key and endpoint
    - name: api_endpoint
      template: "${api_key}:${request.path}"
      rpm: 100

    # Key based on user and action type
    - name: user_action
      template: "${user_id}:${request.method}"
      rpm: 50

    # Key based on session and hour
    - name: session_hour
      template: "${session_id}:${hour_of_day}"
      rpm: 1000
```

## Adaptive Rate Limiting

Automatically adjust limits based on traffic patterns:

```yaml
rate_limiting:
  adaptive:
    enabled: true
    # Baseline limits
    baseline:
      rpm: 100
    # Reduce limits when under attack
    attack_mode:
      rpm: 10
      trigger_conditions:
        - blocked_requests_ratio > 0.1
        - error_rate > 0.05
        - latency_p99 > 500ms
    # Recovery settings
    recovery:
      rate: 1.1  # Increase limits by 10% when stable
      interval: 60s
      min_rpm: 10
      max_rpm: 10000
```

## Graceful Degradation

When rate limiting system is overloaded, gracefully degrade:

```yaml
rate_limiting:
  graceful_degradation:
    enabled: true
    # When Redis unavailable, fall back to local counting
    fallback_to_local: true
    # Local fallback limits (more restrictive)
    local_rpm: 50
    # Prioritize authenticated users when degraded
    prefer_authenticated: true
    # Log degradation events
    log_degradation: true
```

## Rate Limit Monitoring

### Metrics

```yaml
metrics:
  rate_limiting:
    - rate_limit_requests_total        # Counter of requests by limit type
    - rate_limit_blocks_total          # Counter of blocked requests
    - rate_limit_remaining histogram   # Remaining capacity
    - rate_limit_reset_seconds         # Time until limit reset
    - rate_limit_exemptions_total      # Exempted requests
```

### Alerts

```yaml
alerts:
  - name: high_rate_limit_blocks
    condition: rate_limit_blocks_per_minute > 100
    severity: warning

  - name: rate_limit_near_capacity
    condition: rate_limit_remaining < 0.1  # Less than 10% remaining
    severity: info
```

## Configuration Examples

### Basic API Rate Limiting

```yaml
rate_limiting:
  enabled: true

  global:
    requests_per_minute: 10000
    burst: 500

  per_ip:
    requests_per_minute: 100
    burst: 20

  per_endpoint:
    - path: "/api/*"
      rpm: 60
      burst: 10
```

### Strict Login Protection

```yaml
rate_limiting:
  enabled: true

  per_ip:
    requests_per_minute: 5
    burst: 2

  per_endpoint:
    - path: "/api/auth/login"
      method: POST
      rpm: 5
      burst: 2
    - path: "/api/auth/forgot-password"
      method: POST
      rpm: 3
      burst: 1
    - path: "/api/auth/verify-2fa"
      method: POST
      rpm: 5
      burst: 2
```

### E-commerce Protection

```yaml
rate_limiting:
  enabled: true

  per_ip:
    requests_per_minute: 200
    burst: 30

  per_user:
    requests_per_minute: 500
    burst: 50

  per_endpoint:
    # Product browsing - higher limits
    - path: "/api/products"
      method: GET
      rpm: 100
      burst: 20
    # Cart operations - medium limits
    - path: "/api/cart"
      rpm: 30
      burst: 5
    # Checkout - strict limits
    - path: "/api/checkout"
      rpm: 10
      burst: 2
    # Payment - very strict
    - path: "/api/payment"
      rpm: 5
      burst: 1
```

### File Upload Protection

```yaml
rate_limiting:
  enabled: true

  per_ip:
    requests_per_minute: 10
    burst: 2

  per_endpoint:
    - path: "/api/upload"
      method: POST
      rpm: 5
      burst: 1
      # Size limit per interval
      size_limit_mb: 100
      size_window: 1h
```

## CLI Management

```bash
# View rate limit status
fortressctl rate-limit status

# View top limited IPs
fortressctl rate-limit top-ips --limit 20

# Temporarily whitelist an IP
fortressctl rate-limit exempt add 1.2.3.4 --duration 1h

# View current limits for an IP
fortressctl rate-limit lookup 1.2.3.4

# Reset rate limit for an IP
fortressctl rate-limit reset 1.2.3.4

# Export rate limit configuration
fortressctl rate-limit export --format yaml

# Import rate limit configuration
fortressctl rate-limit import --file config.yaml
```
