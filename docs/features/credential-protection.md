> **Note:** Credential stuffing and brute force detection use in-memory per-IP tracking by default. For multi-node deployments, consider a shared Redis-backed implementation.

# Credential Protection

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides rate limiting for login endpoints. Credential stuffing and brute force detection are on the roadmap.

## Configuration

```yaml
rules:
  - id: CRED-001
    name: Credential Stuffing Detection
    enabled: true
    severity: high
    action: block
    phase: access
    field: request.path
    operator: contains
    value: "/login"
    params:
      max_attempts: 5
      window: 300           # seconds
      block_duration: 900   # 15 minutes
      track_by: ip          # ip, user, session
```

## Detection Methods

### Rate-Based Detection

Tracks failed login attempts per IP, user, or session within a time window:

```yaml
params:
  max_attempts: 5           # Allow 5 attempts
  window: 300               # Within 5 minutes
  track_by: ip              # Track by source IP
  block_duration: 900       # Block for 15 minutes
```

### Credential Pattern Detection

Identifies automated credential stuffing tools by analyzing request patterns:

- High volume of distinct usernames from single IP
- Repeated login failures with different credentials
- Non-interactive form submission patterns
- Missing or invalid CSRF tokens

### Response Analysis

Detects brute force by monitoring login response patterns:

```yaml
- id: CRED-002
  name: Brute Force Detection
  field: response.status
  operator: equals
  value: "401"
  params:
    max_count: 10
    window: 60
```

## Storage Backends

| Backend | Configuration | Use Case |
|---------|--------------|----------|
| Memory | Default | Single instance, development |
| Redis | `redis.enabled: true` | Distributed deployments |

## Example: Login Protection

```yaml
rules:
  - id: CRED-001
    name: Login Brute Force Protection
    enabled: true
    severity: high
    action: block
    phase: access
    field: request.path
    operator: eq
    value: "/api/auth/login"
    params:
      max_attempts: 5
      window: 300
      block_duration: 1800
      track_by: ip
      response_fields:
        - field: response.status
          value_eq: 401
        - field: response.body
          contains: "invalid_password"
```

## Example: Admin Login Hardening

```yaml
- id: CRED-002
  name: Admin Login Protection
  enabled: true
  severity: critical
  action: block
  phase: access
  field: request.path
  operator: eq
  value: "/admin/login"
  params:
    max_attempts: 3
    window: 300
    block_duration: 3600
    track_by: ip
```

## Best Practices

- Combine credential protection with rate limiting for maximum effectiveness
- Use Redis backend for multi-instance deployments
- Set stricter limits for admin endpoints
- Monitor credential protection metrics in SIEM
- Implement CAPTCHA after failed attempts
- Log all credential stuffing events for forensic analysis
