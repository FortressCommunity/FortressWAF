# Rule Engine Deep Dive

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF's rule engine is a powerful, flexible system that allows you to define custom security policies using a domain-specific language (DSL). This document provides comprehensive documentation for writing rules.

## Rule Structure

A rule consists of the following components:

```yaml
name: string                    # Unique rule name
description: string              # Human-readable description
priority: integer               # Evaluation order (lower = first)
enabled: boolean                # Whether rule is active
condition: Condition            # When to match
action: Action                  # What to do when matched
transformations: []             # Pre-processing transforms
tags: []                        # Categorization tags
metadata: {}                    # Custom metadata
```

### Example Rule

```yaml
name: Block SQL Injection Attempts
description: Blocks common SQL injection patterns in query parameters
priority: 10
enabled: true
tags:
  - owasp
  - sql-injection
  - critical
condition:
  any:
    - request.query.sql_injection_score: "> 0.75"
    - request.body.sql_injection_score: "> 0.75"
action:
  type: block
  status: 403
  body: "Attack detected: SQL injection attempt"
  headers:
    X-Block-Reason: "sql-injection"
    X-Request-ID: "${request_id}"
transformations:
  - lowercase
  - url_decode
  - remove_comments
```

## Condition Syntax

Conditions define when a rule should trigger. They support logical operators and can reference any part of the request.

### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `all` | All conditions must match | `all: [{...}, {...}]` |
| `any` | Any condition must match | `any: [{...}, {...}]` |
| `none` | No condition must match | `none: [{...}]` |
| `not` | Negate a condition | `not: {...}` |

### Field Reference

Request fields use dot notation:

| Category | Field | Type | Description |
|----------|-------|------|-------------|
| **Basic** | `request.method` | string | HTTP method |
| | `request.path` | string | URL path |
| | `request.query` | string | Query string |
| | `request.query_param.{name}` | string | Specific query param |
| | `request.headers` | object | All headers |
| | `request.header.{name}` | string | Specific header |
| | `request.body` | string | Request body |
| | `request.body_param.{name}` | string | Form body param |
| | `request.cookies` | object | All cookies |
| | `request.cookie.{name}` | string | Specific cookie |
| **Advanced** | `request.json` | object | JSON body (if JSON) |
| | `request.xml` | object | XML body (if XML) |
| | `request.uri` | string | Full URI |
| | `request.protocol` | string | HTTP protocol version |
| | `request.client_ip` | ip | Client IP address |
| | `request.client_port` | integer | Client port |
| | `request.server_ip` | ip | Server IP address |
| | `request.scheme` | string | http or https |
| | `request.host` | string | Host header |
| **Computed** | `request.size` | integer | Request size in bytes |
| | `request.duration` | integer | Request duration in ms |
| | `ip.reputation` | float | IP reputation score (0-1) |
| | `ip.country` | string | GeoIP country code |
| | `ip.asn` | integer | AS number |
| | `ip.is_tor` | boolean | Is Tor exit node |
| | `ip.is_vpn` | boolean | Is VPN |
| | `ip.is_cloud` | boolean | Is cloud provider |
| | `session.user_authenticated` | boolean | User is authenticated |
| | `session.is_bot` | boolean | Session identified as bot |
| | `ml.anomaly_score` | float | ML anomaly score (0-1) |
| | `ml.threat_type` | string | Detected threat type |

## Operators

### String Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Exact match | `request.path: equals "/admin"` |
| `not_equals` | Not equal | `request.method: not_equals "GET"` |
| `contains` | Contains substring | `request.headers.user-agent: contains "curl"` |
| `not_contains` | Doesn't contain | `request.path: not_contains "/api/"` |
| `starts_with` | Starts with | `request.path: starts_with "/api/v1"` |
| `ends_with` | Ends with | `request.path: ends_with ".php"` |
| `prefix` | URL path prefix | `request.path: prefix "/admin"` |
| `suffix` | URL path suffix | `request.path: suffix ".jpg"` |
| `regex` | Regular expression | `request.path: regex "^/api/v[0-9]+/"` |
| `not_regex` | Not regex match | `request.query: not_regex "\\.\\./"` |
| `glob` | Glob pattern | `request.path: glob "/api/**/users"` |
| `length_eq` | Length equals | `request.query: length_eq 0` |
| `length_gt` | Length greater than | `request.body: length_gt 10000` |
| `length_lt` | Length less than | `request.body: length_lt 100` |
| `in` | Value in list | `request.method: in ["GET", "POST"]` |
| `not_in` | Not in list | `request.path: not_in ["/health", "/metrics"]` |

### Numeric Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `==` | Equal | `request.size: == 0` |
| `!=` | Not equal | `request.size: != 0` |
| `>` | Greater than | `request.size: > 1000` |
| `>=` | Greater or equal | `request.size: >= 1000` |
| `<` | Less than | `request.size: < 100` |
| `<=` | Less or equal | `request.size: <= 100` |
| `>` | Greater than (alternate) | `ml.anomaly_score: "> 0.75"` |
| `range` | In range | `request.size: range 100-1000` |

### IP Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `ip_match` | IP in list | `request.client_ip: ip_match ["1.2.3.4", "5.6.7.8"]` |
| `ip_match_cidr` | IP in CIDR | `request.client_ip: ip_match_cidr "10.0.0.0/8"` |
| `geo_match` | IP in country | `request.client_ip: geo_match ["US", "CA"]` |
| `asn_match` | IP in ASN | `request.client_ip: asn_match [15169, 12345]` |

### Compound Score Operators

These operators work with computed scores:

| Operator | Description | Example |
|----------|-------------|---------|
| `sql_injection_score` | SQL injection probability | `request.query.sql_injection_score: "> 0.75"` |
| `xss_score` | XSS probability | `request.body.xss_score: "> 0.8"` |
| `rce_score` | RCE probability | `request.path.rce_score: "> 0.7"` |
| `lfi_score` | LFI probability | `request.path.lfi_score: "> 0.75"` |
| `cmdi_score` | Command injection score | `request.body.cmdi_score: "> 0.75"` |

## Actions

When a rule matches, an action is taken:

```yaml
action:
  type: ActionType           # block, allow, challenge, monitor, redirect, rate_limit
  status: integer            # HTTP status code (for block/redirect)
  body: string               # Response body
  headers: object            # Response headers
  redirect_url: string       # Redirect URL (for redirect action)
  rate_limit: object         # Rate limit config (for rate_limit action)
  challenge_type: string     # "captcha", "cookie", "javascript" (for challenge)
```

### Action Types

#### `block`

Block the request and return an error response:

```yaml
action:
  type: block
  status: 403
  body: |
    <html>
    <head><title>Access Denied</title></head>
    <body>
    <h1>403 Forbidden</h1>
    <p>Request blocked by FortressWAF security policy.</p>
    <p>Request ID: ${request_id}</p>
    </body>
    </html>
  headers:
    X-Block-Reason: "sql-injection-detected"
    X-Frame-Options: DENY
    X-Content-Type-Options: nosniff
```

#### `allow`

Allow the request (used to create exceptions):

```yaml
action:
  type: allow
  # No other configuration needed
```

#### `challenge`

Present a challenge to verify the client is human:

```yaml
action:
  type: challenge
  challenge_type: captcha     # "captcha", "cookie", "javascript"
  captcha_provider: google    # "google", "hcaptcha", "turnstile"
  captcha_theme: light        # "light", "dark"
  captcha_size: normal        # "compact", "normal"
  cookie_name: fw_challenge
  cookie_ttl: 3600            # seconds
```

#### `monitor`

Log the match but don't take action:

```yaml
action:
  type: monitor
  log_level: warning          # "debug", "info", "warning", "error"
  log_message: "Suspicious activity detected"
```

#### `redirect`

Redirect to a different URL:

```yaml
action:
  type: redirect
  status: 302
  redirect_url: "https://example.com/blocked"
  # Or use a template:
  # redirect_url: "https://example.com/blocked?reason=${block_reason}"
```

#### `rate_limit`

Apply rate limiting to the client:

```yaml
action:
  type: rate_limit
  rate_limit:
    requests_per_minute: 10
    burst: 5
    duration: 300            # seconds (how long to rate limit)
    key: ip                 # "ip", "user", "session"
```

## Transformations

Transformations are applied to the request data before evaluation:

```yaml
transformations:
  - lowercase              # Convert to lowercase
  - uppercase              # Convert to uppercase
  - trim                   # Remove leading/trailing whitespace
  - url_decode             # URL decode the value
  - url_encode             # URL encode the value
  - base64_decode          # Base64 decode the value
  - base64_encode          # Base64 encode the value
  - html_entity_decode     # Decode HTML entities
  - remove_nulls           # Remove null bytes
  - remove_comments        # Remove SQL comments
  - normalize_path         # Normalize URL path (../ etc)
  - compress_whitespace     # Collapse multiple spaces
  - remove_whitespace      # Remove all whitespace
  - sha256                 # Hash the value
  - md5                    # Hash the value
```

## Rule Templates

FortressWAF includes pre-built rule templates for common scenarios:

### Block Common Attacks

```yaml
# Blocks SQL injection, XSS, and command injection
name: Block Common Web Attacks
priority: 1
enabled: true
condition:
  any:
    - request.query.sql_injection_score: "> 0.7"
    - request.body.sql_injection_score: "> 0.7"
    - request.query.xss_score: "> 0.7"
    - request.body.xss_score: "> 0.7"
    - request.path.rce_score: "> 0.7"
    - request.body.cmdi_score: "> 0.7"
action:
  type: block
  status: 403
  body: "Attack detected and blocked"
```

### Protect Admin Paths

```yaml
name: Protect Admin Paths
priority: 5
enabled: true
condition:
  all:
    - request.path: prefix "/admin"
    - not ip.match_cidr: "10.0.0.0/8"
action:
  type: challenge
  challenge_type: captcha
```

### Rate Limit API Endpoints

```yaml
name: Rate Limit API
priority: 10
enabled: true
condition:
  any:
    - request.path: prefix "/api/"
    - request.path: prefix "/graphql"
condition:
  request.method: in ["POST", "PUT", "DELETE", "PATCH"]
action:
  type: rate_limit
  rate_limit:
    requests_per_minute: 60
    burst: 10
```

### Block Specific Countries

```yaml
name: Block Specific Countries
priority: 20
enabled: true
condition:
  any:
    - request.client_ip: geo_match ["RU", "CN", "KP", "IR"]
condition:
  not request.path: prefix "/public"
action:
  type: block
  status: 403
  body: "Access denied from your region"
```

### OWASP Top 10 Coverage

#### SQL Injection

```yaml
name: OWASP - SQL Injection Protection
description: Blocks SQL injection attempts
priority: 10
enabled: true
tags:
  - owasp
  - sql-injection
condition:
  any:
    # SQL keywords and patterns
    - request.query: regex "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|exec\\(|execute\\(|xp_)"
    - request.body: regex "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|exec\\(|execute\\(|xp_)"
    # SQL injection score
    - request.query.sql_injection_score: "> 0.8"
    - request.body.sql_injection_score: "> 0.8"
    # Common attack patterns
    - request.query: contains "'"
    - request.query: contains "\""
    - request.query: contains "--"
    - request.query: contains ";"
    - request.query: contains "/*"
transformations:
  - lowercase
  - remove_comments
action:
  type: block
  status: 403
  body: "SQL injection attempt detected"
```

#### Cross-Site Scripting (XSS)

```yaml
name: OWASP - XSS Protection
description: Blocks Cross-Site Scripting attempts
priority: 10
enabled: true
tags:
  - owasp
  - xss
condition:
  any:
    - request.query.xss_score: "> 0.8"
    - request.body.xss_score: "> 0.8"
    # Script tags
    - request.query: regex "(?i)<script[^>]*>.*?</script>"
    - request.body: regex "(?i)<script[^>]*>.*?</script>"
    # Event handlers
    - request.query: regex "(?i)on\\w+\\s*="
    - request.body: regex "(?i)on\\w+\\s*="
    # JavaScript URIs
    - request.query: regex "(?i)javascript\\s*:"
    # HTML entities
    - request.query: contains "&lt;"
    - request.query: contains "&gt;"
    - request.query: contains "&amp;"
transformations:
  - lowercase
  - html_entity_decode
action:
  type: block
  status: 403
  body: "Cross-site scripting attempt detected"
```

#### Local File Inclusion (LFI)

```yaml
name: OWASP - LFI Protection
description: Blocks Local File Inclusion attempts
priority: 10
enabled: true
tags:
  - owasp
  - lfi
condition:
  any:
    - request.path.lfi_score: "> 0.8"
    # Path traversal patterns
    - request.query: regex "\\.\\.\\/|"      # ../ or ..|
    - request.query: regex "\\.\\.\\\\"      # ..\
    - request.query: contains "/etc/passwd"
    - request.query: contains "/etc/shadow"
    - request.query: contains "c:\\\\windows"
    - request.query: contains "/proc/self"
    # Null byte injection
    - request.query: contains "%00"
    - request.query: contains "\\x00"
transformations:
  - lowercase
  - url_decode
  - normalize_path
action:
  type: block
  status: 403
  body: "Path traversal attempt detected"
```

#### Remote File Inclusion (RFI)

```yaml
name: OWASP - RFI Protection
description: Blocks Remote File Inclusion attempts
priority: 10
enabled: true
tags:
  - owasp
  - rfi
condition:
  any:
    # URL patterns in parameters
    - request.query: regex "(?i)https?://[^\\s]+"
    - request.body: regex "(?i)https?://[^\\s]+"
    # PHP wrappers
    - request.query: regex "(?i)(php://|expect://|file://|ftp://|sftp://)"
    - request.body: regex "(?i)(php://|expect://|file://|ftp://|sftp://)"
transformations:
  - lowercase
action:
  type: block
  status: 403
  body: "Remote file inclusion attempt detected"
```

#### Command Injection

```yaml
name: OWASP - Command Injection Protection
description: Blocks OS Command Injection attempts
priority: 10
enabled: true
tags:
  - owasp
  - command-injection
condition:
  any:
    - request.body.cmdi_score: "> 0.8"
    # Shell metacharacters
    - request.query: regex "[;&|`$]"
    - request.body: regex "[;&|`$]"
    # Common commands
    - request.query: regex "(?i)(wget|curl|nc|netcat|bash|sh|cmd|powershell)"
    - request.body: regex "(?i)(wget|curl|nc|netcat|bash|sh|cmd|powershell)"
    # Pipe to shell
    - request.query: regex "\\|\\s*\\w+"
    - request.body: regex "\\|\\s*\\w+"
transformations:
  - lowercase
  - remove_whitespace
action:
  type: block
  status: 403
  body: "Command injection attempt detected"
```

## Rule Ordering and Priority

Rules are evaluated in priority order (lower number = higher priority):

```
Priority 1  ──▶ First evaluated (highest priority)
Priority 10 ──▶
Priority 50 ──▶
Priority 100 ──▶ Last evaluated (lowest priority)
```

**Important**: When multiple rules match, only the action of the HIGHEST priority rule is executed (unless the action is `allow`, which short-circuits evaluation).

### Rule Evaluation Algorithm

1. Sort rules by priority (ascending)
2. For each rule (in order):
   a. Apply transformations to request data
   b. Evaluate condition
   c. If condition matches:
      - If action is `allow`: stop evaluation, allow request
      - Otherwise: execute action, stop evaluation
3. If no rules match: allow the request (default allow)

## Import from ModSecurity

FortressWAF can import existing ModSecurity rules:

```bash
# Import from ModSecurity CRS
fortressctl rules import \
  --input /path/to/crs/crs-setup.conf \
  --input /path/to/crs/rules/*.conf \
  --format modsecurity \
  --site-id <site-uuid>

# Import from specific ModSecurity rules
fortressctl rules import \
  --input /path/to/modsecurity.conf \
  --format modsecurity \
  --transform owasp \
  --site-id <site-uuid>
```

### ModSecurity to FortressWAF Mapping

| ModSecurity | FortressWAF |
|-------------|--------------|
| `SecRule` | `condition` + `action` |
| `REQUEST_METHOD` | `request.method` |
| `REQUEST_URI` | `request.uri` |
| `ARGS` | `request.query` + `request.body` |
| `REQUEST_HEADERS` | `request.headers` |
| `ARGS_GET` | `request.query` |
| `ARGS_POST` | `request.body` |
| `ctl` | `action` |
| `chain` | Nested `all` condition |

### Example ModSecurity Rule Conversion

**ModSecurity:**
```apache
SecRule REQUEST_URI|REQUEST_HEADERS|ARGS|ARGS_POST|REQUEST_BODY "@rx (union\s+select|select\s+from|insert\s+into|delete\s+from)" \
    "id:1001,\
    phase:2,\
    deny,\
    status:403,\
    msg:'SQL Injection Attempt',\
    logdata:'Matched Data: %{TX.0} seen against %{MATCHED_VAR_NAME}',\
    severity:CRITICAL,\
    t:lowercase,\
    ctl:auditLogParts=ABE"
```

**FortressWAF:**
```yaml
name: SQL Injection Detection (Imported)
description: SQL injection detection converted from ModSecurity rule 1001
priority: 10
enabled: true
tags:
  - modsecurity-imported
  - sql-injection
condition:
  any:
    - request.uri: regex "(?i)(union\\s+select|select\\s+from|insert\\s+into|delete\\s+from)"
    - request.headers: regex "(?i)(union\\s+select|select\\s+from|insert\\s+into|delete\\s+from)"
    - request.query: regex "(?i)(union\\s+select|select\\s+from|insert\\s+into|delete\\s+from)"
    - request.body: regex "(?i)(union\\s+select|select\\s+from|insert\\s+into|delete\\s+from)"
transformations:
  - lowercase
action:
  type: block
  status: 403
  body: "SQL injection attempt detected"
  headers:
    X-Block-Reason: "sql-injection"
    X-Request-ID: "${request_id}"
```

## Debugging Rules

### Test Mode

Enable rule testing without blocking:

```bash
fortressctl rules test --rule-id <rule-uuid> --input '{"request": {"path": "/admin"}}'
```

### Rule Simulation

Simulate rule evaluation:

```bash
fortressctl rules simulate \
  --condition '{"any": [{"request.path": {"prefix": "/admin"}}]}' \
  --request '{"method": "GET", "path": "/admin/test"}'
```

### Debug Logging

Enable debug logging for rule evaluation:

```yaml
logging:
  level: debug
  components:
    rule_engine: debug
```

### Rule Statistics

View rule match statistics:

```bash
fortressctl rules stats --site-id <site-uuid>

# Output:
# Rule Name                    | Matches | Blocks | Last Matched
# ---------------------------- | ------- | ------ | ------------
# SQL Injection Protection     | 1,234   | 456    | 2 minutes ago
# XSS Protection               | 789     | 123    | 5 minutes ago
# Admin Path Protection        | 56      | 12     | 1 hour ago
```

## Hot Reload Behavior

Rules are automatically reloaded when changes are detected:

```yaml
rules:
  reload_interval: 30s  # Check for changes every 30 seconds
```

You can also manually trigger a reload:

```bash
fortressctl reload --type rules
```

During hot reload:
1. New rules are validated
2. Rules with invalid syntax are rejected
3. Valid rules replace the current rule set
4. Statistics are preserved
5. Active sessions continue with old rules until completion

## Best Practices

1. **Order rules logically**: Put more specific rules before general ones
2. **Use priorities**: Assign priorities based on rule importance
3. **Test thoroughly**: Use simulation and test mode before deploying
4. **Monitor performance**: Watch rule evaluation times
5. **Use transformations**: Normalize input before matching
6. **Log strategically**: Use `monitor` action for suspicious but uncertain matches
7. **Group related rules**: Use tags for organization
8. **Review statistics**: Regularly check rule match/performance stats
