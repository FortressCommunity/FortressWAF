# Request & Response Rewriting

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF can modify HTTP requests and responses in real-time, enabling header manipulation, body transformation, and URL redirection based on configurable conditions.

## Architecture

```
Request --> Condition Matching --> Rewrite Actions --> Modified Request --> Upstream
Response <-- Modified Response <-- Rewrite Actions <-- Condition Matching <-- Upstream
```

## Configuration

```yaml
rewrite_rules:
  - name: "Add Security Headers"
    conditions:
      - field: path
        operator: prefix
        value: "/"
    actions:
      - type: header
        operation: set
        name: X-Frame-Options
        value: DENY
      - type: header
        operation: set
        name: X-Content-Type-Options
        value: nosniff

  - name: "Remove Internal Headers"
    conditions:
      - field: path
        operator: contains
        value: "/api"
    actions:
      - type: header
        operation: remove
        name: X-Internal

  - name: "Redirect Legacy URLs"
    conditions:
      - field: path
        operator: prefix
        value: "/old-api"
    actions:
      - type: url
        operation: redirect
        value: "/api/v2"
        code: 301
```

## Rewrite Actions

### Header Manipulation

| Operation | Description | Example |
|-----------|-------------|---------|
| `set` | Add or overwrite header | `X-Custom: value` |
| `add` | Add header (multiple values allowed) | `Set-Cookie: session=...` |
| `remove` | Delete header | `X-Internal` removed |
| `rename` | Rename header | `X-Old-Name` → `X-New-Name` |

#### Set Security Headers

```yaml
- type: header
  operation: set
  name: Strict-Transport-Security
  value: max-age=31536000; includeSubDomains
- type: header
  operation: set
  name: Content-Security-Policy
  value: default-src 'self'
```

#### Remove Sensitive Headers

```yaml
- type: header
  operation: remove
  name: X-Powered-By
- type: header
  operation: remove
  name: Server
```

### Body Manipulation

| Operation | Description |
|-----------|-------------|
| `replace` | Simple string replacement |
| `regex_replace` | Regex pattern replacement |

#### Replace Sensitive Data

```yaml
- type: body
  operation: replace
  pattern: "password=[^&]+"
  value: "password=REDACTED"
```

#### Regex Body Rewrite

```yaml
- type: body
  operation: regex_replace
  pattern: "(\\b\\d{4}[- ]?){3}\\d{4}\\b"
  value: "****-****-****-****"
```

### URL Redirection

```yaml
- type: url
  operation: redirect
  value: "https://new.example.com{{.path}}"
  code: 301
```

Template variables supported in redirect URLs:

| Variable | Description |
|----------|-------------|
| `{{.path}}` | Original request path |
| `{{.host}}` | Original host |
| `{{.ip}}` | Client IP |
| `{{.method}}` | HTTP method |

## Conditions

| Field | Operators | Description |
|-------|-----------|-------------|
| `path` | equals, contains, prefix, suffix, regex | Request URL path |
| `headers` | equals, contains, exists, not* | Request header value |
| `query` | equals, exists, not* | Query parameter value |
| `method` | equals | HTTP method (GET, POST, etc.) |
| `ip` | equals, prefix | Client IP address |

### Condition Examples

```yaml
conditions:
  - field: path
    operator: regex
    value: "^/api/v[0-9]/"

  - field: headers
    name: Content-Type
    operator: contains
    value: "application/json"

  - field: query
    name: debug
    operator: exists

  - field: method
    operator: equals
    value: "DELETE"
```

## Response Rewriting

Response rewriting works the same way as request rewriting, but applies when the upstream response is being processed.

```yaml
- name: "Inject CSP Header in Responses"
    conditions:
      - field: path
        operator: prefix
        value: "/"
    actions:
      - type: header
        operation: set
        name: Content-Security-Policy
        value: "default-src 'self'"
```

## Best Practices

- Place rewrite rules early in the pipeline for request rewrites
- Use `monitor` action first to verify conditions match correctly
- Avoid excessive regex operations on large response bodies
- Test redirect rules before enabling in production
- Combine with rate limiting to prevent abuse of redirect endpoints
