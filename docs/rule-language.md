# FortressWAF Rule Language Reference

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF uses a **YAML-based Domain Specific Language (DSL)** for defining security rules. Rules are compiled into an efficient trie-based matcher at startup and can be hot-reloaded without service interruption.

**Note:** The exact number of pre-built rules varies by release. Rule coverage is documented in the release notes.

## Rule Structure

```yaml
# Minimum viable rule
- id: "BLOCK_SQLI_001"
  name: "Basic SQL Injection - OR 1=1"
  severity: critical
  phase: request
  conditions:
    - field: query_string
      operator: contains
      value: ["' OR '1'='1", " OR 1=1", "' OR 1=1 --"]
  action: block
  status_code: 403
  tags: [sqli, owasp-top10, a1]
```

## Rule File Format

Rules are defined in YAML files placed in `/etc/fortresswaf/rules/`. Each file can contain multiple rules:

```yaml
# /etc/fortresswaf/rules/01-sqli.yaml
rules:
  - id: "SQLI_001"
    name: "Union Select Detection"
    ...

  - id: "SQLI_002"
    name: "Comment Injection"
    ...
```

You can also define **rule templates** for reuse:

```yaml
templates:
  - id: "block_pattern"
    action: block
    status_code: 403
    tags: [auto-generated]

rules:
  - id: "CUSTOM_001"
    name: "Block specific path"
    template: "block_pattern"
    conditions:
      - field: path
        operator: exact
        value: "/.env"
```

## Field Reference

### Request Fields

| Field | Description | Example |
|-------|-------------|---------|
| `path` | URL path | `/admin/login` |
| `method` | HTTP method | `POST` |
| `query_string` | Raw query string | `id=1&debug=true` |
| `query_param.<name>` | Specific query parameter | `query_param.id` |
| `header.<name>` | Request header (lowercase) | `header.user-agent` |
| `cookie.<name>` | Cookie value | `cookie.session` |
| `body` | Raw request body | `{"user":"admin"}` |
| `body_param.<name>` | Form/JSON body parameter | `body_param.username` |
| `body_raw` | Unparsed body bytes | - |
| `content_type` | Content-Type header | `application/json` |
| `host` | Host header | `api.example.com` |
| `port` | Request port | `443` |
| `scheme` | http or https | `https` |
| `remote_addr` | Client IP | `192.168.1.1` |
| `remote_asn` | Client ASN (Enterprise) | `15169` |
| `remote_country` | Client country code | `US` |
| `headers` | All headers as map | - |
| `cookies` | All cookies as map | - |
| `protocol` | HTTP protocol version | `HTTP/1.1` |

### Response Fields

| Field | Description |
|-------|-------------|
| `response.status` | Response status code |
| `response.header.<name>` | Response header |
| `response.body` | Response body content |
| `response.body_param.<name>` | Parsed response body field |
| `response.content_type` | Response content type |

### Derived Fields

| Field | Description |
|-------|-------------|
| `request_length` | Total request size in bytes |
| `body_length` | Body size in bytes |
| `parameter_count` | Number of parameters |
| `header_count` | Number of headers |
| `cookie_count` | Number of cookies |
| `path_depth` | Number of path segments |
| `path_length` | Path string length |
| `has_query_string` | Boolean, true if query exists |
| `has_body` | Boolean, true if body exists |
| `is_ajax` | Boolean, X-Requested-With check |
| `is_websocket` | Boolean, Upgrade header check |

## Operators

### String Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match (case-sensitive) | `field: method, operator: equals, value: "POST"` |
| `equals_any` | Match any in list | `value: ["GET", "POST"]` |
| `contains` | Substring match | `value: "union select"` |
| `contains_any` | Any substring match | `value: ["' OR", "1=1--"]` |
| `starts_with` | Prefix match | `value: "/api/"` |
| `ends_with` | Suffix match | `value: ".php"` |
| `regex` | Regular expression | `value: "^/api/v[0-9]/"` |
| `not_equals` | Negated exact match | - |
| `not_contains` | Negated substring | - |
| `matches` | Case-insensitive regex | - |

### Numeric Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `gt` | Greater than | `field: body_length, operator: gt, value: 10000` |
| `gte` | Greater than or equal | - |
| `lt` | Less than | - |
| `lte` | Less than or equal | - |
| `in_range` | Within range | `value: [100, 1000]` |
| `eq` | Numeric equals | - |
| `neq` | Numeric not equals | - |

### IP Operators

| Operator | Description |
|----------|-------------|
| `in_subnet` | IP in CIDR range |
| `in_country` | IP in country (GeoIP) |
| `in_asn` | IP in ASN |
| `is_tor` | Is TOR exit node |
| `is_proxy` | Is known proxy/VPN |
| `reputation_lt` | Reputation score below threshold |

### List Operators

| Operator | Description |
|----------|-------------|
| `in` | Value in list |
| `not_in` | Value not in list |
| `contains_all` | List contains all values |
| `contains_any` | List contains any value |
| `length_gt` | List length > N |
| `length_lt` | List length < N |

### Time Operators

| Operator | Description |
|----------|-------------|
| `within_hours` | Current time within range |
| `within_days` | Current day of week in set |
| `rate_gt` | Request rate exceeds threshold |

## Condition Groups

Combine multiple conditions with boolean logic:

```yaml
conditions:
  all:                              # AND - all must match
    - field: path
      operator: starts_with
      value: "/api/"
    - field: method
      operator: equals
      value: "POST"
    - field: query_param.key
      operator: exists
```

```yaml
conditions:
  any:                              # OR - any match triggers
    - field: body
      operator: contains
      value: "DROP TABLE"
    - field: body
      operator: contains
      value: "UNION SELECT"
```

```yaml
conditions:
  not:                              # NOT - negate the inner condition
    field: remote_addr
    operator: in_subnet
    value: "10.0.0.0/8"
```

```yaml
conditions:                         # Complex nested logic
  all:
    - field: method
      operator: equals
      value: "POST"
    - any:
        - field: body
          operator: contains
          value: "eval("
        - field: body
          operator: contains
          value: "exec("
    - not:
        field: remote_addr
        operator: in_subnet
        value: "10.0.0.0/8"
```

## Actions

| Action | Description | HTTP Status |
|--------|-------------|-------------|
| `block` | Block request, return error page | 403 |
| `allow` | Allow request, skip remaining rules | - |
| `challenge` | Present JS challenge or CAPTCHA | 200 |
| `log` | Log the match, continue processing | - |
| `rate_limit` | Apply rate limit to this request | 429 |
| `redirect` | Redirect to another URL | 302 |
| `custom_response` | Return custom response | Configurable |

## Response Customization

Customize the block/response page:

```yaml
- id: "CUSTOM_BLOCK"
  name: "Custom Block Page"
  action: block
  response:
    status_code: 403
    content_type: "text/html"
    body: |
      <!DOCTYPE html>
      <html>
      <head><title>Access Denied</title></head>
      <body>
        <h1>Access Denied</h1>
        <p>Your request has been blocked by security policy.</p>
        <p>Reference ID: {{.RequestID}}</p>
      </body>
      </html>
    headers:
      X-Blocked-By: "FortressWAF"
      Retry-After: "60"
```

## Variables and Templates

Template variables available in response bodies:

| Variable | Description |
|----------|-------------|
| `{{.RequestID}}` | Unique request identifier |
| `{{.RuleID}}` | ID of matching rule |
| `{{.RuleName}}` | Name of matching rule |
| `{{.ClientIP}}` | Client IP address |
| `{{.Path}}` | Requested path |
| `{{.Method}}` | HTTP method |
| `{{.Timestamp}}` | Current timestamp |
| `{{.BlockReason}}` | Human-readable block reason |
| `{{.BlockedBy}}` | Component that blocked (rule/ml/reputation) |
| `{{.ContactEmail}}` | From config |
| `{{.ReferenceID}}` | For support cases |

## Severity Levels

| Level | Color | Default Action |
|-------|-------|----------------|
| `critical` | Red | Block |
| `high` | Orange | Block |
| `medium` | Yellow | Log + Challenge |
| `low` | Blue | Log |
| `info` | Green | Log |

## Rule Metadata

```yaml
- id: "SQLI_001"
  name: "Union Select Detection"
  description: "Detects SQL UNION SELECT injection attempts"
  severity: critical
  cve: "CVE-2024-XXXX"         # Related CVE (optional)
  owasp: "A1: Injection"       # OWASP category
  mitre: "T1190"               # MITRE ATT&CK ID
  created: "2024-01-15"
  updated: "2024-03-01"
  author: "FortressWAF Research"
  references:
    - "https://owasp.org/www-community/attacks/SQL_Injection"
    - "https://cwe.mitre.org/data/definitions/89.html"
```

## Rule Testing

Test rules before deploying:

```bash
fortressctl rules test --rule-id SQLI_001 --payload "1' OR '1'='1"
# Output: MATCH - SQLI_001 (severity: critical)

fortressctl rules test --rule-id SQLI_001 --payload "hello world"
# Output: NO MATCH
```

## Rule Profiles

Apply pre-configured rule profiles:

```bash
# OWASP Top 10 coverage
fortressctl rules apply --profile owasp-top-10

# API security
fortressctl rules apply --profile api-security

# Compliance-specific
fortressctl rules apply --profile pci-dss
fortressctl rules apply --profile hipaa

# Custom profile
fortressctl rules apply --file my-profile.yaml
```

## Performance Optimizations

- Rules are compiled into a **trie-based Aho-Corasick automaton** for patterns
- **Regex rules** are compiled once and cached
- **Field-specific matchers** only run on relevant requests
- **Rule pruning**: rules that cannot match are skipped based on request properties
- **Early exit**: action=allow rules exit early to avoid unnecessary processing

## Complete Example

```yaml
rules:
  - id: "BLOCK_PATH_TRAVERSAL"
    name: "Path Traversal - etc/passwd"
    description: "Block attempts to read /etc/passwd via path traversal"
    severity: critical
    phase: request
    conditions:
      any:
        - field: path
          operator: regex
          value: "(\.\./|\.\.\\)+.*(etc/passwd|etc/shadow|win\.ini)"
        - field: query_string
          operator: regex
          value: "(\.\./|\.\.\\)+.*(etc/passwd|etc/shadow|win\.ini)"
        - field: body
          operator: regex
          value: "file:///etc/passwd|php://filter.*base64.*encode"
    action: block
    status_code: 403
    response:
      body: |
        {"error":"blocked","reason":"path_traversal","request_id":"{{.RequestID}}"}
      content_type: "application/json"
      headers:
        X-Security: "FortressWAF"
    tags: [lfi, path-traversal, critical]
    severity: critical
    cwe: "CWE-22"
    owasp: "A1: Injection"
```

## Templates Library

FortressWAF organizes rules into template sets. The available sets and approximate rule counts vary by release.

| Template Set | Description |
|-------------|-------------|
| `base/owasp-sqli` | SQL injection patterns |
| `base/owasp-xss` | Cross-site scripting patterns |
| `base/owasp-rce` | Remote code execution patterns |
| `base/owasp-lfi` | Path traversal patterns |
| `base/bot-block` | Bad bot signatures |
| `base/scanner-block` | Scanner detection |
| `base/api-protect` | API-specific protections |
