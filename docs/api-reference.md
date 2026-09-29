# REST API Reference

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides a comprehensive REST API for integration and automation. This document details all available endpoints, authentication methods, and usage examples.

## Base URL

```
Production: https://api.fortresswaf.io/v1
Staging: https://api-staging.fortresswaf.io/v1
Local: https://localhost:8444/v1
```

## Authentication

### API Key Authentication

Include your API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" \
  https://api.fortresswaf.io/v1/sites
```

### JWT Token Authentication

Obtain a JWT token and include it in the `Authorization` header:

```bash
# Login to get JWT
curl -X POST https://api.fortresswaf.io/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "your-password"}'

# Response:
# {
#   "access_token": "eyJhbGciOiJIUzI1NiIs...",
#   "token_type": "Bearer",
#   "expires_in": 3600
# }

# Use JWT token
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..." \
  https://api.fortresswaf.io/v1/sites
```

## Rate Limiting

API requests are rate limited:

| Plan | Requests/minute | Burst |
|------|-----------------|-------|
| Free | 60 | 10 |
| Pro | 600 | 100 |
| Enterprise | 6000 | 1000 |

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 600
X-RateLimit-Remaining: 599
X-RateLimit-Reset: 1640995200
```

## Pagination

List endpoints support pagination:

```bash
# Get first page (default 20 items)
GET /v1/sites

# Get specific page
GET /v1/sites?page=2&per_page=50

# Response includes pagination metadata:
{
  "data": [...],
  "meta": {
    "current_page": 1,
    "per_page": 20,
    "total": 100,
    "total_pages": 5
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid or missing credentials |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation error |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error |
| 503 | Service Unavailable |

Error response format:

```json
{
  "error": {
    "code": "validation_error",
    "message": "Invalid request parameters",
    "details": [
      {"field": "domain", "message": "Domain format is invalid"}
    ]
  }
}
```

---

## Authentication Endpoints

### POST /auth/login

Login and obtain JWT token.

**Request:**
```json
{
  "username": "admin",
  "password": "your-password"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### POST /auth/refresh

Refresh access token.

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### POST /auth/logout

Invalidate current token.

**Response (204):** No content

### POST /auth/change-password

Change user password.

**Request:**
```json
{
  "current_password": "old-password",
  "new_password": "new-secure-password"
}
```

**Response (200):**
```json
{
  "message": "Password changed successfully"
}
```

---

## Sites Endpoints

### GET /sites

List all sites.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| page | int | Page number (default: 1) |
| per_page | int | Items per page (default: 20, max: 100) |
| sort | string | Sort field (name, created_at) |
| order | string | Sort order (asc, desc) |
| filter | string | Filter by status (active, paused, deleted) |

**Response (200):**
```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "production-app",
      "domain": "app.example.com",
      "backend_url": "https://internal.example.com",
      "status": "active",
      "tls_enabled": true,
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-15T12:30:00Z"
    }
  ],
  "meta": {
    "current_page": 1,
    "per_page": 20,
    "total": 5,
    "total_pages": 1
  }
}
```

### POST /sites

Create a new site.

**Request:**
```json
{
  "name": "production-app",
  "domain": "app.example.com",
  "backend_url": "https://internal.example.com",
  "backend_host_header": "app.example.com",
  "tls_mode": "terminate",
  "tls_cert_id": "cert-uuid",
  "health_check_url": "/health",
  "health_check_interval": 10,
  "health_check_timeout": 5,
  "is_active": true,
  "tags": {
    "environment": "production",
    "team": "platform"
  }
}
```

**Response (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "production-app",
  "domain": "app.example.com",
  "backend_url": "https://internal.example.com",
  "status": "active",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### GET /sites/{id}

Get site details.

**Response (200):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "production-app",
  "domain": "app.example.com",
  "backend_url": "https://internal.example.com",
  "backend_host_header": "app.example.com",
  "tls_mode": "terminate",
  "tls_cert_id": "cert-uuid",
  "health_check_url": "/health",
  "health_check_interval": 10,
  "health_check_timeout": 5,
  "is_active": true,
  "stats": {
    "requests_today": 1500000,
    "blocked_today": 1234,
    "avg_latency_ms": 15
  },
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-15T12:30:00Z"
}
```

### PUT /sites/{id}

Update a site.

**Request:**
```json
{
  "name": "updated-app",
  "backend_url": "https://new-backend.example.com",
  "is_active": true
}
```

**Response (200):** Updated site object

### DELETE /sites/{id}

Delete a site.

**Response (204):** No content

### POST /sites/{id}/pause

Pause site protection.

**Response (200):**
```json
{
  "status": "paused"
}
```

### POST /sites/{id}/resume

Resume site protection.

**Response (200):**
```json
{
  "status": "active"
}
```

---

## Rules Endpoints

### GET /sites/{site_id}/rules

List rules for a site.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| page | int | Page number |
| per_page | int | Items per page |
| enabled | bool | Filter by enabled status |
| tag | string | Filter by tag |

**Response (200):**
```json
{
  "data": [
    {
      "id": "rule-uuid",
      "name": "Block SQL Injection",
      "priority": 10,
      "enabled": true,
      "condition": {...},
      "action": {...},
      "match_count": 1234,
      "block_count": 100,
      "last_matched": "2024-01-15T12:30:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "meta": {...}
}
```

### POST /sites/{site_id}/rules

Create a new rule.

**Request:**
```json
{
  "name": "Block SQL Injection",
  "description": "Blocks SQL injection attempts",
  "priority": 10,
  "enabled": true,
  "condition": {
    "any": [
      {"request_query_sql_injection_score": {"gt": 0.75}},
      {"request_body_sql_injection_score": {"gt": 0.75}}
    ]
  },
  "action": {
    "type": "block",
    "status": 403,
    "body": "SQL injection detected"
  },
  "tags": ["sql-injection", "owasp"]
}
```

**Response (201):** Created rule object

### GET /sites/{site_id}/rules/{id}

Get rule details.

**Response (200):** Rule object

### PUT /sites/{site_id}/rules/{id}

Update a rule.

**Request:** Same as POST

**Response (200):** Updated rule object

### DELETE /sites/{site_id}/rules/{id}

Delete a rule.

**Response (204):** No content

### POST /sites/{site_id}/rules/validate

Validate rule syntax without creating.

**Request:**
```json
{
  "condition": {...},
  "action": {...}
}
```

**Response (200):**
```json
{
  "valid": true,
  "warnings": []
}
```

### POST /sites/{site_id}/rules/test

Test rule against sample requests.

**Request:**
```json
{
  "rule_id": "rule-uuid",
  "test_cases": [
    {
      "name": "SQL injection test",
      "request": {
        "method": "GET",
        "path": "/search",
        "query": "id=1' OR '1'='1"
      },
      "expected": "match"
    }
  ]
}
```

**Response (200):**
```json
{
  "results": [
    {
      "name": "SQL injection test",
      "matched": true,
      "actual": "match"
    }
  ]
}
```

---

## Rate Limiting Endpoints

### GET /sites/{site_id}/rate-limits

Get rate limit configuration.

**Response (200):**
```json
{
  "global": {
    "enabled": true,
    "requests_per_minute": 10000,
    "burst": 500,
    "algorithm": "token_bucket"
  },
  "per_ip": {
    "enabled": true,
    "requests_per_minute": 100,
    "burst": 20
  },
  "endpoint_limits": [
    {
      "path": "/api/auth/login",
      "method": "POST",
      "requests_per_minute": 5,
      "burst": 2
    }
  ]
}
```

### PUT /sites/{site_id}/rate-limits

Update rate limit configuration.

**Request:**
```json
{
  "global": {
    "enabled": true,
    "requests_per_minute": 20000,
    "burst": 1000
  }
}
```

**Response (200):** Updated rate limit configuration

### POST /sites/{site_id}/rate-limits/exempt

Add IP exemption.

**Request:**
```json
{
  "ip": "10.0.0.0/8",
  "requests_per_minute": 1000000,
  "expires_at": "2025-12-31T23:59:59Z"
}
```

**Response (201):** Created exemption

---

## IP List Endpoints

### GET /ip-lists

List all IP lists.

**Response (200):**
```json
{
  "data": [
    {
      "id": "list-uuid",
      "name": "blocked-ips",
      "type": "block",
      "ip_count": 150,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### POST /ip-lists

Create IP list.

**Request:**
```json
{
  "name": "blocked-ips",
  "description": "Blocked IP addresses",
  "type": "block"
}
```

**Response (201):** Created IP list

### POST /ip-lists/{id}/ips

Add IPs to list.

**Request:**
```json
{
  "ips": ["1.2.3.4/32", "5.6.7.0/24"]
}
```

**Response (200):**
```json
{
  "added": 2,
  "total": 152
}
```

### DELETE /ip-lists/{id}/ips

Remove IPs from list.

**Request:**
```json
{
  "ips": ["1.2.3.4/32"]
}
```

**Response (200):**
```json
{
  "removed": 1,
  "total": 151
}
```

---

## Certificate Endpoints

### GET /certificates

List certificates.

**Response (200):**
```json
{
  "data": [
    {
      "id": "cert-uuid",
      "name": "example.com",
      "common_name": "example.com",
      "expires_at": "2025-01-01T00:00:00Z",
      "issuer": "Let's Encrypt",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### POST /certificates

Upload certificate.

**Request (multipart/form-data):**
```
cert: <file>
key: <file>
name: example-com
passphrase: <optional>
```

**Response (201):** Created certificate

### DELETE /certificates/{id}

Delete certificate.

**Response (204):** No content

---

## API Keys Endpoints

### GET /sites/{site_id}/api-keys

List API keys for site.

**Response (200):**
```json
{
  "data": [
    {
      "id": "key-uuid",
      "name": "CI/CD Key",
      "key_hint": "fw_prod_abc123...xyz",
      "permissions": ["read", "write"],
      "last_used": "2024-01-15T12:30:00Z",
      "expires_at": "2025-12-31T23:59:59Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### POST /sites/{site_id}/api-keys

Create API key.

**Request:**
```json
{
  "name": "CI/CD Key",
  "permissions": ["read", "write"],
  "expires_at": "2025-12-31T23:59:59Z",
  "tags": {"team": "devops"}
}
```

**Response (201):**
```json
{
  "id": "key-uuid",
  "name": "CI/CD Key",
  "key": "fw_prod_abc123...xyz789",
  "permissions": ["read", "write"],
  "expires_at": "2025-12-31T23:59:59Z"
}
```

### DELETE /api-keys/{id}

Revoke API key.

**Response (204):** No content

---

## Virtual Patches Endpoints

### GET /sites/{site_id}/patches

List virtual patches.

**Response (200):**
```json
{
  "data": [
    {
      "id": "patch-uuid",
      "name": "CVE-2024-1234 Patch",
      "cve_id": "CVE-2024-1234",
      "priority": 1,
      "enabled": true,
      "status": "active",
      "blocked_attempts": 1234,
      "expires_at": "2025-01-01T00:00:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### POST /sites/{site_id}/patches

Create virtual patch.

**Request:**
```json
{
  "name": "CVE-2024-1234 Patch",
  "cve_id": "CVE-2024-1234",
  "priority": 1,
  "enabled": true,
  "expires_at": "2025-12-31T23:59:59Z",
  "condition": {
    "all": [
      {"request_path": {"prefix": "/api/vulnerable"}},
      {"request_query_sql_injection_score": {"gt": 0.8}}
    ]
  },
  "action": {
    "type": "block",
    "status": 403
  }
}
```

**Response (201):** Created patch

### POST /sites/{site_id}/patches/import

Import patches from vulnerability scanner.

**Request:**
```json
{
  "scanner": "nessus",
  "content": "<nessus report>...</nessus>"
}
```

**Response (200):**
```json
{
  "imported": 5,
  "skipped": 2,
  "errors": []
}
```

---

## Statistics Endpoints

### GET /sites/{site_id}/stats

Get site statistics.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| period | string | Period (1h, 24h, 7d, 30d, custom) |
| start | string | Start datetime (ISO 8601) |
| end | string | End datetime (ISO 8601) |

**Response (200):**
```json
{
  "period": {
    "start": "2024-01-14T00:00:00Z",
    "end": "2024-01-15T00:00:00Z"
  },
  "requests": {
    "total": 1500000,
    "allowed": 1498766,
    "blocked": 1234
  },
  "latency": {
    "p50_ms": 10,
    "p95_ms": 25,
    "p99_ms": 50
  },
  "bandwidth": {
    "bytes_in": 5000000000,
    "bytes_out": 15000000000
  },
  "top_threats": [
    {"type": "sql_injection", "count": 500},
    {"type": "xss", "count": 300}
  ]
}
```

### GET /sites/{site_id}/stats/realtime

Get real-time statistics (WebSocket recommended for live updates).

**Response (200):**
```json
{
  "requests_per_second": 150,
  "active_connections": 450,
  "blocked_per_minute": 12,
  "avg_latency_ms": 15,
  "cpu_usage": 0.35,
  "memory_usage": 0.6
}
```

### GET /sites/{site_id}/stats/attacks

Get attack analytics.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| period | string | Period |
| group_by | string | Group by (type, ip, path, country) |

**Response (200):**
```json
{
  "data": [
    {
      "type": "sql_injection",
      "count": 500,
      "blocked": 450,
      "top_ips": [
        {"ip": "1.2.3.4", "count": 50}
      ]
    }
  ]
}
```

---

## Events (Audit Log) Endpoints

### GET /sites/{site_id}/events

Query audit events.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| page | int | Page number |
| per_page | int | Items per page |
| start | string | Start time (ISO 8601) |
| end | string | End time |
| action | string | Filter by action (block, allow, challenge) |
| ip | string | Filter by client IP |
| rule_id | string | Filter by rule |
| request_id | string | Filter by request ID |

**Response (200):**
```json
{
  "data": [
    {
      "id": "event-uuid",
      "timestamp": "2024-01-15T12:30:00Z",
      "request_id": "req-uuid",
      "client_ip": "1.2.3.4",
      "request_method": "GET",
      "request_path": "/search",
      "action": "block",
      "rule_id": "rule-uuid",
      "ml_score": 0.85,
      "bot_score": 0.2
    }
  ],
  "meta": {...}
}
```

### GET /events/{id}

Get event details.

**Response (200):**
```json
{
  "id": "event-uuid",
  "timestamp": "2024-01-15T12:30:00Z",
  "request": {
    "id": "req-uuid",
    "method": "GET",
    "path": "/search",
    "query": "id=1' OR '1'='1",
    "headers": {...},
    "body": null,
    "size": 256
  },
  "response": {
    "status": 403,
    "size": 128
  },
  "decision": {
    "action": "block",
    "reason": "rule_match",
    "rule_id": "rule-uuid",
    "ml_score": 0.85,
    "bot_score": 0.2
  },
  "client": {
    "ip": "1.2.3.4",
    "country": "US",
    "asn": 15169,
    "is_tor": false,
    "is_vpn": false
  }
}
```

---

## Webhooks Endpoints

### GET /sites/{site_id}/webhooks

List webhooks.

**Response (200):**
```json
{
  "data": [
    {
      "id": "webhook-uuid",
      "url": "https://example.com/webhook",
      "events": ["attack.blocked", "attack.challenge_failed"],
      "secret": "whsec_...",
      "enabled": true,
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

### POST /sites/{site_id}/webhooks

Create webhook.

**Request:**
```json
{
  "name": "Security Webhook",
  "url": "https://example.com/webhook",
  "events": ["attack.blocked", "attack.detected"],
  "secret": "your-webhook-secret"
}
```

**Response (201):** Created webhook

### DELETE /webhooks/{id}

Delete webhook.

**Response (204):** No content

---

## System Endpoints

### GET /health

Health check.

**Response (200):**
```json
{
  "status": "healthy",
  "version": "2.0.0",
  "timestamp": "2024-01-15T12:30:00Z"
}
```

### GET /version

Get version information.

**Response (200):**
```json
{
  "version": "2.0.0",
  "build": "abc123",
  "commit": "def456",
  "release_date": "2024-01-01T00:00:00Z"
}
```

### GET /metrics

Prometheus metrics.

**Response (200):** Prometheus text format

---

## Complete curl Examples

### Create a Site

```bash
curl -X POST https://api.fortresswaf.io/v1/sites \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "domain": "app.example.com",
    "backend_url": "https://internal.example.com",
    "is_active": true
  }'
```

### Upload a Certificate

```bash
curl -X POST https://api.fortresswaf.io/v1/certificates \
  -H "Authorization: Bearer $TOKEN" \
  -F "cert=@/path/to/cert.pem" \
  -F "key=@/path/to/key.pem" \
  -F "name=example-com"
```

### Create a Rule

```bash
curl -X POST https://api.fortresswaf.io/v1/sites/$SITE_ID/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block SQL Injection",
    "priority": 10,
    "enabled": true,
    "condition": {
      "any": [
        {"request_query_sql_injection_score": {"gt": 0.75}}
      ]
    },
    "action": {
      "type": "block",
      "status": 403
    }
  }'
```

### Get Attack Statistics

```bash
curl "https://api.fortresswaf.io/v1/sites/$SITE_ID/stats/attacks?period=24h&group_by=type" \
  -H "Authorization: Bearer $TOKEN"
```

### Query Events

```bash
curl "https://api.fortresswaf.io/v1/sites/$SITE_ID/events?action=block&limit=50" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Webhook Events

Webhook payloads for real-time notifications:

### attack.blocked

```json
{
  "event": "attack.blocked",
  "timestamp": "2024-01-15T12:30:00Z",
  "site_id": "site-uuid",
  "data": {
    "request_id": "req-uuid",
    "attack_type": "sql_injection",
    "client_ip": "1.2.3.4",
    "path": "/search",
    "action": "block",
    "ml_score": 0.85
  }
}
```

### attack.detected

```json
{
  "event": "attack.detected",
  "timestamp": "2024-01-15T12:30:00Z",
  "site_id": "site-uuid",
  "data": {
    "request_id": "req-uuid",
    "attack_type": "sql_injection",
    "client_ip": "1.2.3.4",
    "action": "challenge",
    "ml_score": 0.65
  }
}
```

### bot.detected

```json
{
  "event": "bot.detected",
  "timestamp": "2024-01-15T12:30:00Z",
  "site_id": "site-uuid",
  "data": {
    "request_id": "req-uuid",
    "client_ip": "1.2.3.4",
    "bot_score": 0.9,
    "bot_type": "headless_browser"
  }
}
```

### rate_limit.exceeded

```json
{
  "event": "rate_limit.exceeded",
  "timestamp": "2024-01-15T12:30:00Z",
  "site_id": "site-uuid",
  "data": {
    "request_id": "req-uuid",
    "client_ip": "1.2.3.4",
    "limit_type": "per_ip",
    "requests_made": 150,
    "limit": 100
  }
}
```
