# Troubleshooting Guide

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

## Common Issues

### Proxy Won't Start

**Symptoms:**
- `fortresswaf` exits immediately
- `docker logs` shows error on startup
- Systemd service shows `failed` status

**Checks:**

```bash
# 1. Validate configuration syntax
fortressctl config validate

# 2. Check if ports are already in use
sudo lsof -i :8080
sudo lsof -i :8443

# 3. Verify config file permissions
ls -la /etc/fortresswaf/config.yaml
# Should be readable by fortresswaf user (0640)

# 4. Check log output
fortresswaf --config /etc/fortresswaf/config.yaml --log-level debug
```

**Solutions:**
- Fix YAML syntax errors in config
- Kill process on conflicting port: `sudo kill $(sudo lsof -t -i:8080)`
- Fix file permissions: `chmod 640 /etc/fortresswaf/config.yaml`
- Ensure `upstream_url` is reachable from the WAF node

### Rules Not Applying

**Symptoms:**
- Expected attacks are not being blocked
- Newly added rules have no effect
- `fortressctl rules list` shows rules but they don't fire

**Checks:**

```bash
# 1. Verify rules are loaded
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/rules
# Check the count matches expectations

# 2. Test a specific rule
fortressctl rules test --rule-id SQLI_001 --payload "1' OR '1'='1"

# 3. Force reload rules from disk
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/rules/reload

# 4. Check rule engine status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config | jq .rules_enabled
```

**Solutions:**
- Ensure `rules_enabled: true` in config
- Check rule YAML syntax: `fortressctl rules validate --file /etc/fortresswaf/rules/custom.yaml`
- Verify the rule action is `block` (not `log` or `allow`)
- Check for rule ID conflicts (duplicate IDs are ignored)
- Ensure request matches all conditions (check AND/OR logic)

### High Latency

**Symptoms:**
- P99 latency > 50ms
- Upstream services timing out
- Users reporting slow page loads

**Diagnostics:**

```bash
# 1. Check current latency metrics
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/metrics | jq '.latency_p50_ms, .latency_p95_ms, .latency_p99_ms'

# 2. Enable profiling endpoint
curl http://localhost:8080/debug/pprof/profile?seconds=30 > profile.pprof
go tool pprof -http=:8081 profile.pprof

# 3. Check upstream latency (network issue?)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/metrics | jq '.upstream_latency_p50_ms, .upstream_latency_p95_ms, .upstream_latency_p99_ms'
```

**Solutions:**

| Cause | Solution |
|-------|----------|
| Too many rules | Reduce rule count, use more specific patterns |
| Complex regex rules | Optimize regex patterns, use `contains` instead of `regex` when possible |
| ML engine enabled | Increase ML threshold, reduce feature count, use more ML sidecar replicas |
| Upstream slow | Check upstream health, increase proxy timeouts |
| Network congestion | Scale horizontally, use connection pooling |
| Body inspection | Increase `max_body_size` or skip body parsing for large uploads |
| TLS overhead | Enable TLS session resumption, use TLS 1.3 |

**Performance Tuning Checklist:**

```yaml
# Performance-optimized configuration
performance:
  rule_cache_size: 10000        # Cache compiled rules
  connection_pool_size: 256     # Reduce connection churn
  body_buffer_size: 32768       # 32KB buffer for body parsing
  max_header_size: 8192         # Limit header size
  enable_compression: true      # Compress responses
  tls_session_cache: 10000      # Reuse TLS sessions
  worker_threads: 4             # Match CPU count
  io_uring_enabled: true        # Linux 5.1+ async I/O

ml_engine:
  inference_timeout_ms: 100     # Timeout ML inference
  batch_size: 4                 # Batch requests for GPU efficiency
  feature_cache_size: 1000      # Cache feature vectors
```

### False Positives (Legitimate Traffic Blocked)

**Symptoms:**
- Valid users receiving 403 errors
- CI/CD pipelines failing
- API clients getting blocked

**Diagnosis:**

```bash
# 1. Check recent blocked events
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/v1/events?limit=10&action=block&since=5m"

# 2. Identify the triggering rule from event
# Look for rule_id in the response

# 3. Test the specific request
fortressctl rules test --rule-id SQLI_001 \
  --request "GET /api/search?q=legitimate+query"
```

**Solutions:**

```bash
# Option 1: Disable the specific rule
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}' \
  http://localhost:8080/api/v1/rules/SQLI_001

# Option 2: Whitelist the IP
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cidr": "192.168.1.0/24", "reason": "Internal network"}' \
  http://localhost:8080/api/v1/reputation/whitelist

# Option 3: Add an exception to the rule
# Add a "not" condition for the trusted source
```

**False Positive Reduction Strategy:**

1. Set new rules to `log` action first, monitor for a week
2. Review logs for false positives
3. Add exclude conditions (by IP, path, header)
4. Gradually move to `challenge` then `block`
5. Use ML engine in "monitoring only" mode before enabling blocking

### WebSocket Issues

**Symptoms:**
- WebSocket connections drop immediately
- `101 Switching Protocols` not returned
- WebSocket frames not forwarded

**Checks:**
```bash
# Verify WebSocket support is enabled
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/config | jq '.websocket_enabled'
```

**Solution:**
```yaml
# Ensure config has websocket support
websocket:
  enabled: true
  buffer_size: 32768
  max_message_size: 1048576
  handshake_timeout: 10s
```

### Memory Issues

**Symptoms:**
- OOM kills
- High memory usage ( > 80% of limit)
- Swap usage increasing

**Checks:**
```bash
# Check memory usage
docker stats fortresswaf-proxy
# or
ps aux | grep fortresswaf | awk '{print $6/1024 " MB"}'

# Check Go runtime metrics
curl http://localhost:8080/debug/vars | jq '.memstats.HeapInuse'
```

**Solutions:**

| Setting | Default | Recommendation |
|---------|---------|---------------|
| `max_connections` | 10000 | Reduce to 5000 |
| `buffer_size` | 65536 | Reduce to 32768 |
| `rule_cache_size` | 50000 | Reduce to 10000 |
| `max_body_size` | 10MB | Reduce to 1MB if not needed |
| `connection_pool_size` | 256 | Reduce to 128 |
| `log_buffer_size` | 10000 | Reduce to 5000 |

## Debug Mode

### Enable Debug Logging

```bash
# In-place without restart
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"log_level": "debug"}' \
  http://localhost:8080/api/v1/config/reload

# Or via environment
FORTRESS_LOG_LEVEL=debug fortresswaf --config /etc/fortresswaf/config.yaml
```

### Request Tracing

Enable per-request tracing for debugging:

```bash
# Send a request with trace header
curl -H "X-Fortress-Debug: true" \
  -H "Authorization: Bearer your-token" \
  "http://localhost:8080/api/search?q=test"

# Response headers will include trace info
# X-Fortress-Trace-Id: abc123
# X-Fortress-Decision: allow
# X-Fortress-Rules-Matched: 0
# X-Fortress-ML-Score: 0.02
# X-Fortress-Duration-Us: 1245
```

### Health Check Endpoint

```bash
curl http://localhost:8080/api/v1/health | jq .
```

If components show unhealthy:

| Component | Check |
|-----------|-------|
| `redis` | `redis-cli ping` should return `PONG` |
| `postgres` | `pg_isready` should return `accepting connections` |
| `ml_engine` | `grpcurl -plaintext localhost:50051 health.v1.Health/Check` |
| `dashboard` | `curl http://localhost:3001/api/health` |

## Log Analysis

### Log Formats

**JSON format (default):**

```json
{
  "timestamp": "2024-03-15T12:00:00.123456Z",
  "level": "info",
  "source": "proxy",
  "request_id": "req_abc123",
  "client_ip": "185.220.101.1",
  "method": "GET",
  "path": "/search?q=test",
  "status": 403,
  "duration_ms": 2.34,
  "rule_id": "SQLI_001",
  "rule_name": "Union Select Detection",
  "action": "block",
  "body_size": 0,
  "response_size": 245,
  "user_agent": "curl/7.68.0"
}
```

**Text format:**

```
2024-03-15T12:00:00Z INFO proxy[req_abc123] 185.220.101.1 - GET /search?q=test
  403 2.34ms rule=SQLI_001 action=block
```

### Querying Logs with jq

```bash
# Find all blocked requests in the last hour
cat /var/log/fortresswaf/access.log | jq 'select(.action == "block" and .timestamp > "2024-03-15T11:00:00Z")'

# Top attacking IPs
cat /var/log/fortresswaf/access.log | jq -r '.client_ip' | sort | uniq -c | sort -rn | head -10

# Most triggered rules
cat /var/log/fortresswaf/access.log | jq -r 'select(.rule_id != null) | .rule_id' | sort | uniq -c | sort -rn | head -10

# Requests by HTTP method
cat /var/log/fortresswaf/access.log | jq -r '.method' | sort | uniq -c | sort -rn

# Latency > 1 second
cat /var/log/fortresswaf/access.log | jq 'select(.duration_ms > 1000)'
```

### Log Retention

```yaml
logging:
  retention:
    access_logs: 90d     # Keep 90 days of access logs
    audit_logs: 365d     # Keep 1 year of audit logs
    error_logs: 30d      # Keep 30 days of error logs
  compression: gzip      # Compress rotated logs
  archive:
    enabled: true
    destination: s3://fortresswaf-logs/
    interval: daily
```

## Rule Debugging

### Step-by-Step Rule Debugging

```bash
# 1. Enable debug logging for rule evaluation
fortressctl config set log_level debug

# 2. Send a test request with trace enabled
curl -H "X-Fortress-Debug: true" \
  "http://localhost:8080/api/search?q=1%27%20OR%20%271%27%3D%271"

# 3. Check trace response headers
# X-Fortress-Rules-Matched: SQLI_001
# X-Fortress-Decision: block

# 4. Check detailed logs
journalctl -u fortresswaf -n 50 --no-pager | grep req_abc123

# 5. Test specific rule in isolation
fortressctl rules test \
  --rule-id SQLI_001 \
  --method GET \
  --path "/search" \
  --query "q=1' OR '1'='1" \
  --verbose
```

### Rule Performance Analysis

```bash
# Check which rules are slow (> 10ms evaluation time)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/metrics | jq '.slow_rules'

# Profile rule compilation time
fortressctl rules profile --file /etc/fortresswaf/rules/*.yaml
```

## Performance Tuning Guide

### 1. Identify Bottlenecks

```bash
# Check system resources
htop
iostat -x 1
netstat -s

# Check proxy metrics
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/metrics | jq '.'
```

### 2. Tune System Parameters

```bash
# /etc/sysctl.d/99-fortresswaf.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
```

### 3. Scale Horizontally

```bash
# Docker Compose
docker compose up -d --scale proxy=5

# Kubernetes
kubectl scale deployment fortresswaf-proxy --replicas=5

# Terraform
# Increase instance_count in the module
```

### 4. Tune Proxy Configuration

```yaml
performance:
  # Connection pooling
  connection_pool:
    max_idle: 1000
    max_active: 5000
    idle_timeout: 90s
  
  # Buffer management
  read_buffer_size: 4096
  write_buffer_size: 4096
  
  # Rule optimization
  rule_compilation: lazy       # Compile rules only when first matched
  regex_timeout_ms: 100        # Kill slow regex matches
  max_rule_evaluations: 10000  # Stop evaluating after N rules
  
  # ML optimization
  ml_batch_interval_ms: 10     # Batch ML requests
  ml_score_cache_ttl: 60       # Cache ML scores for identical requests
  
  # Logging
  log_buffer_size: 100000
  log_flush_interval: 1s
  sampling_rate: 1.0           # 1.0 = log all, 0.1 = log 10%
```

## Support Escalation

### Gathering Diagnostic Information

Before contacting support, collect:

```bash
# 1. Version information
fortressctl version

# 2. Configuration (redact secrets)
fortressctl config show --redact-secrets

# 3. Health status
curl http://localhost:8080/api/v1/health | jq .

# 4. Metrics snapshot
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/v1/metrics | jq .

# 5. Recent error logs
journalctl -u fortresswaf --since "1 hour ago" --no-pager | grep -i error | tail -50

# 6. Go runtime profile
curl http://localhost:8080/debug/vars > debug-vars.json

# 7. Network connectivity test
curl -v --connect-timeout 5 http://your-upstream-url/health
```

### Support Channels

| Channel | Contact | Availability |
|---------|---------|-------------|
| Documentation | https://docs.fortresswaf.io | 24/7 |
| Community Slack | https://slack.fortresswaf.io | 24/7 |
| GitHub Issues | https://github.com/fortresswaf/fortresswaf/issues | 24/7 |
| Email Support | support@fortresswaf.io | Business hours |
| Enterprise Support | enterprise-support@fortresswaf.io | 24/7 (SLA) |
| Emergency | +1-888-FORTRESS | 24/7 (Enterprise) |
