> **Note:** Current DDoS protection covers application-layer rate limiting only. Volumetric (SYN flood, UDP flood) and protocol-level mitigation are not implemented.

# DDoS Protection

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides rate limiting and connection throttling for application-layer attacks.

## DDoS Protection Overview

| Attack Type | Target Layer | Detection Method | Mitigation |
|-------------|--------------|------------------|------------|
| HTTP Flood | Application | Request rate analysis | Rate limiting, challenge |
| SYN Flood | Network | Connection tracking | TCP proxy, syn cookies |
| UDP Flood | Network | Packet rate analysis | Packet filtering |
| Slowloris | Application | Header timeout | Connection limits |
| Slow POST | Application | Body read rate | Read timeout enforcement |
| Cache-busting | Application | Query pattern analysis | Rate limiting |
| Amplification | Network | Reflection detection | ACL filtering |

## HTTP Flood Protection

### Request Rate Analysis

```yaml
ddos:
  http_flood:
    enabled: true
    detection:
      # Requests per minute threshold
      threshold: 500
      # Time window for analysis
      window: 1m
      # Sensitivity: low, medium, high
      sensitivity: medium
      # Minimum requests before detection
      min_requests: 100
    response:
      action: block  # block, challenge, rate_limit
      block_duration: 300  # seconds
      challenge_type: captcha
```

### Per-IP Rate Limiting

```yaml
ddos:
  http_flood:
    per_ip_limits:
      requests_per_minute: 100
      requests_per_hour: 1000
      concurrent_connections: 50
      burst: 20
```

### Global Rate Limiting

```yaml
ddos:
  http_flood:
    global_limits:
      requests_per_second: 10000
      requests_per_minute: 500000
      bandwidth_mbps: 1000
```

## Slowloris Protection

Slowloris attacks hold connections open by sending partial HTTP requests.

### Detection Configuration

```yaml
ddos:
  slowloris:
    enabled: true
    # Timeout for receiving headers
    header_timeout: 30s
    # Minimum headers required
    min_headers: 8
    # Check interval
    check_interval: 5s
    # Maximum connection duration
    max_connection_duration: 120s
    # Action when detected
    action: block
    # Block duration
    block_duration: 600
```

### Protection Mechanisms

1. **Header Timeout Enforcement**

```yaml
ddos:
  slowloris:
    header_timeout:
      # Time to wait for headers
      wait_time: 10s
      # Time between header reads
      read_interval: 5s
      # Total timeout
      total_timeout: 30s
```

2. **Connection Limits**

```yaml
ddos:
  slowloris:
    connection_limits:
      max_connections_per_ip: 20
      max_idle_connections: 100
      idle_timeout: 10s
```

### Slowloris Detection Logic

```python
def detect_slowloris(connection) -> bool:
    """Detect slowloris attack pattern"""
    elapsed = time.now() - connection.start_time

    # Check if headers taking too long
    if not connection.headers_complete:
        if elapsed > slowloris_config.header_timeout:
            return True

    # Check header send rate
    if connection.header_send_duration > slowloris_config.header_timeout:
        return True

    # Check if reading body too slowly
    if connection.body_expected and not connection.body_complete:
        body_read_rate = connection.body_bytes_read / elapsed
        if body_read_rate < slowloris_config.min_body_read_rate:
            return True

    return False
```

## Slow POST Protection

Slow POST attacks send POST requests with a legitimate Content-Length but transmit data very slowly.

### Configuration

```yaml
ddos:
  slow_post:
    enabled: true
    # Timeout for reading POST body
    body_timeout: 60s
    # Minimum read rate (bytes per second)
    min_read_rate: 100
    # Content-Length threshold for checking
    content_length_threshold: 1024  # bytes
    # Action
    action: block
    block_duration: 300
```

### Detection Rules

```yaml
name: Detect Slow POST Attack
description: Block clients reading POST body too slowly
priority: 20
condition:
  all:
    - request.method: equals "POST"
    - request.headers.content-length: "> 1024"
    - request.body_read_rate: "< 100"  # bytes per second
action:
  type: block
  status: 408
  body: "Request timeout - data received too slowly"
```

## Cache-busting Attack Protection

Cache-busting attacks bypass CDN caches by varying query parameters on every request.

### Detection Configuration

```yaml
ddos:
  cache_busting:
    enabled: true
    # Unique query patterns per minute threshold
    unique_patterns_per_minute: 50
    # Patterns to ignore (legitimate cache busters)
    ignore_patterns:
      - "v=*"  # Version parameter
      - "t=*"  # Timestamp parameter
    # Action
    action: rate_limit
    rate_limit:
      requests_per_minute: 100
      burst: 10
```

### Detection Logic

```python
def detect_cache_busting(request, session) -> bool:
    """Detect cache-busting attack pattern"""
    query = request.query

    # Extract query parameter pattern (ignoring values)
    pattern = extract_pattern(query)

    # Check if this is a new pattern
    if pattern in session.unique_cache_patterns_last_minute:
        return False  # Legitimate cache miss

    # Check unique pattern count
    unique_count = len(session.unique_cache_patterns_last_minute)

    if unique_count > ddos_config.cache_busting.threshold:
        return True

    return False
```

### Protection Rule

```yaml
name: Block Cache-busting Attack
description: Block rapid requests with varying cache busters
priority: 25
condition:
  all:
    - request.query: regex "\\d+\\.\\d+\\.\\d+"  # Version-like pattern
    - session.unique_query_patterns_per_minute: "> 50"
action:
  type: rate_limit
  rate_limit:
    requests_per_minute: 30
    burst: 5
```

## Adaptive Rate Limiting

FortressWAF automatically adjusts rate limits based on traffic patterns:

```yaml
ddos:
  adaptive:
    enabled: true
    # Baseline thresholds
    baseline:
      requests_per_minute: 100
      requests_per_second: 50
    # Aggressive thresholds during attack
    aggressive:
      requests_per_minute: 50
      requests_per_second: 20
    # Attack detection triggers
    triggers:
      # CPU usage threshold
      cpu_usage: 0.8
      # Memory usage threshold
      memory_usage: 0.9
      # Request latency threshold
      latency_ms: 500
      # Error rate threshold
      error_rate: 0.05
    # How quickly to adjust
    adjustment_rate: 2x  # Reduce limits by 2x when under attack
    # Recovery rate
    recovery_rate: 1.1x  # Increase limits by 10% when recovering
```

## Per-Endpoint Rate Limits

Different endpoints may have different rate limit requirements:

```yaml
ddos:
  endpoint_limits:
    - path: "/api/search"
      method: GET
      rpm: 30
      burst: 5
    - path: "/api/users"
      method: POST
      rpm: 20
      burst: 3
    - path: "/api/auth/login"
      method: POST
      rpm: 10
      burst: 3
    - path: "/api/data"
      method: GET
      rpm: 100
      burst: 20
    - path: "/"
      method: GET
      rpm: 1000
      burst: 100
```

## Global DDoS Mitigation

### Traffic Scrubbing Centers

```yaml
ddos:
  scrubbing:
    enabled: true
    # Enable traffic scrubbing via upstream provider
    provider: cloudflare  # or "akamai", "aws-shield", "none"
    # Trigger scrubbing at this traffic level (Gbps)
    trigger_threshold_gbps: 10
    # Always use scrubbing center
    always_scrub: false
```

### Geographic-based Blocking

```yaml
ddos:
  geo:
    enabled: true
    # Block traffic from specific countries
    block_countries:
      - KP  # North Korea
      - IR  # Iran
      - RU  # Russia (during certain conflicts)
    # Rate limit countries
    rate_limit_countries:
      - CN  # China
    rate_limit_multiplier: 0.5  # 50% of normal limits
```

## Attack Detection Algorithms

### Moving Average Detection

```python
class DDoSDetector:
    def __init__(self, window_size: int = 60):
        self.window_size = window_size
        self.requests = deque(maxlen=window_size)
        self.baseline = None

    def add_request(self, timestamp: float, client_ip: str):
        self.requests.append((timestamp, client_ip))

    def detect_http_flood(self) -> bool:
        """Detect HTTP flood using statistical analysis"""
        now = time.time()
        window_start = now - self.window_size

        # Count requests in window
        recent = [r for r in self.requests if r[0] > window_start]
        request_count = len(recent)

        # Calculate requests per minute
        rpm = request_count * (60 / self.window_size)

        # Update baseline using exponential moving average
        if self.baseline is None:
            self.baseline = rpm
        else:
            self.baseline = 0.9 * self.baseline + 0.1 * rpm

        # Calculate standard deviation
        if len(recent) > 1:
            mean = sum(r[0] for r in recent) / len(recent)
            std = sqrt(sum((r[0] - mean) ** 2 for r in recent) / len(recent))

            # Detect anomaly
            if rpm > self.baseline + 3 * std:
                return True

        # Simple threshold check
        if rpm > ddos_config.http_flood.threshold:
            return True

        return False
```

### Signature-based Detection

```yaml
ddos:
  signatures:
    - name: flood_curl
      pattern: "curl/.*"
      threshold: 50  # requests per minute
    - name: flood_python
      pattern: "python-requests/.*"
      threshold: 50
    - name: flood_scanner
      pattern: "(nikto|sqlmap|nmap|metasploit)"
      threshold: 5
```

## Connection Tracking

### Connection Limits

```yaml
ddos:
  connection_tracking:
    enabled: true
    # Maximum connections per IP
    max_per_ip: 100
    # Maximum connections per subnet
    max_per_subnet: 1000
    # Connection timeout
    timeout: 30s
    # Purge idle connections
    purge_interval: 10s
```

### TCP State Tracking

```yaml
ddos:
  tcp:
    # Enable SYN cookies
    syn_cookies: true
    # SYN backlog size
    syn_backlog: 1000
    # Half-open connection timeout
    half_open_timeout: 30s
    # Full connection timeout
    full_open_timeout: 120s
```

## Logging and Alerts

### DDoS Event Logging

```yaml
ddos:
  logging:
    enabled: true
    log_attacks: true
    log_blocks: true
    log_rate_limits: true
    retention_days: 90
```

### DDoS Alerts

```yaml
alerts:
  - name: ddos_attack_detected
    condition: ddos.attack_detected == true
    severity: critical
    channels:
      - email
      - slack
      - pagerduty

  - name: high_rate_limit_blocks
    condition: ddos.blocks_per_minute > 100
    severity: warning

  - name: slowloris_detected
    condition: ddos.slowloris_detected == true
    severity: critical
```

## Recovery Procedures

### Automatic Recovery

```yaml
ddos:
  recovery:
    enabled: true
    # Block duration for attackers
    block_duration: 300  # 5 minutes
    # Gradually reduce block duration as traffic normalizes
    decay_rate: 0.9  # Multiply by 0.9 each interval
    # Minimum block duration
    min_block_duration: 60  # 1 minute
    # Check interval for decay
    check_interval: 60  # seconds
```

### Manual Intervention

```bash
# View current DDoS status
fortressctl ddos status

# View top attackers
fortressctl ddos top-attackers --limit 20

# Block an IP manually
fortressctl ip block 1.2.3.4 --duration 1h --reason "Manual block"

# Unblock an IP
fortressctl ip unblock 1.2.3.4

# View blocked IPs
fortressctl ip blocked list

# Export current blocklist
fortressctl ddos export-blocklist --format json

# Import blocklist
fortressctl ddos import-blocklist --format json --merge
```

## Performance Considerations

### DDoS Processing Latency

| Component | Latency | Notes |
|-----------|---------|-------|
| Connection tracking | 0.1ms | In-memory |
| Rate limit check | 0.2ms | Redis-backed |
| Slowloris detection | 0.5ms | Per-connection |
| Adaptive limiting | 1ms | Background task |

### Resource Usage Under Attack

| Resource | Normal | Under Attack (10x traffic) |
|----------|--------|---------------------------|
| CPU | 20% | 60% |
| Memory | 40% | 50% |
| Redis ops/sec | 1,000 | 10,000 |
| Network | 100 Mbps | 1 Gbps |
