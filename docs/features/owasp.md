# OWASP Protection

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF includes detection rules for common OWASP Top 10 attack categories. This document shows example rule configurations. Actual coverage depends on the rule set loaded.

## OWASP Top 10 Coverage

| OWASP Category | Status |
|----------------|--------|
| A01 Broken Access Control | Partial — IP/path rules |
| A02 Cryptographic Failures | TLS enforcement only |
| A03 Injection | SQLi, XSS, command injection rules |
| A04 Insecure Design | Rate limiting |
| A05 Security Misconfiguration | Header checks |
| A06 Vulnerable Components | Virtual patching |
| A07 Authentication Failures | Rate limiting |
| A08 Software Integrity Failures | Request signing |
| A09 Logging Failures | Audit logging |
| A10 SSRF | On roadmap |

**Note:** Detection accuracy varies by traffic patterns, rule configuration, and may produce false positives. No WAF achieves 100% detection.

## A01: Broken Access Control

Access control vulnerabilities allow attackers to access unauthorized functionality or data.

### Protection Mechanisms

#### 1. Path-Based Access Control

```yaml
name: Protect Admin Endpoints
description: Restrict admin access to authorized networks
priority: 5
condition:
  all:
    - request.path: prefix "/admin"
    - not ip.match_cidr: "10.0.0.0/8"
    - not ip.match_cidr: "192.168.0.0/16"
action:
  type: block
  status: 403
  body: "Access denied to admin area"
```

#### 2. Method Enforcement

```yaml
name: Enforce Allowed Methods
description: Only allow specified HTTP methods per endpoint
priority: 1
condition:
  any:
    - and:
        - request.path: prefix "/api/users"
        - not request.method: in ["GET", "POST"]
    - and:
        - request.path: prefix "/api/settings"
        - not request.method: in ["GET", "PUT", "PATCH"]
action:
  type: block
  status: 405
  body: "Method not allowed for this endpoint"
```

#### 3. IDOR Protection

```yaml
name: Prevent IDOR Attacks
description: Detect unauthorized resource access attempts
priority: 20
condition:
  any:
    # Accessing other users' resources by manipulating IDs
    - request.path: regex "/users/[0-9]+/profile"
    - request.path: regex "/orders/[0-9]+/cancel"
    - request.path: regex "/api/v[0-9]+/[a-z]+/[0-9]+"
action:
  type: monitor
  log_level: warning
  # Additional verification via ML
  ml_threshold_override: 0.5
```

#### 4. Horizontal Privilege Escalation

```yaml
name: Detect Horizontal Privilege Escalation
description: Block attempts to access resources at same privilege level
priority: 30
condition:
  all:
    - request.headers.authorization: exists
    - request.headers.x-user-id: exists
action:
  type: challenge
  challenge_type: cookie
```

### ML-Based Access Pattern Analysis

```python
# Access anomaly detection
def detect_access_anomaly(request, session):
    features = {
        'hour': request.timestamp.hour,
        'day': request.timestamp.weekday(),
        'endpoint_diversity': len(session.unique_endpoints),
        'request_rate': session.requests_last_hour,
        'known_endpoint': request.path in session.known_paths,
    }

    model = gradient_boosting_model
    score = model.predict_proba([features])[0]

    return score > 0.75
```

## A02: Cryptographic Failures

Formerly "Sensitive Data Exposure" - failures in cryptography that lead to exposure of sensitive data.

### Protection Mechanisms

#### 1. TLS Configuration Enforcement

```yaml
name: Enforce HTTPS
description: Redirect all HTTP traffic to HTTPS
priority: 1
condition:
  all:
    - request.scheme: equals "http"
    - not request.host: contains "localhost"
action:
  type: redirect
  status: 301
  redirect_url: "https://${request.host}${request.uri}"
```

#### 2. Sensitive Data Detection

```yaml
name: Detect Sensitive Data in Transit
description: Block requests containing sensitive data over HTTP
priority: 5
condition:
  all:
    - request.scheme: equals "http"
    - any:
        - request.query: regex "[0-9]{3}-[0-9]{2}-[0-9]{4}"  # SSN pattern
        - request.query: regex "[0-9]{16}"  # Credit card pattern
        - request.query: contains "password"
        - request.query: contains "secret"
action:
  type: block
  status: 403
  body: "Sensitive data cannot be sent over unencrypted connection"
```

#### 3. Security Header Enforcement

```yaml
name: Set Security Headers
description: Ensure security headers are present in responses
priority: 100
condition:
  all:
    - request.path: prefix "/"
action:
  type: monitor  # Applied to responses
  # Response inspection will add headers
```

#### 4. Weak Cipher Detection

```yaml
# Configuration to block weak TLS configurations
server:
  tls:
    min_version: "1.2"
    cipher_suites:
      - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
```

## A03: Injection

Injection flaws occur when untrusted data is sent to an interpreter.

### SQL Injection Protection

#### Detection Mechanisms

1. **Pattern-Based Detection**

```yaml
name: SQL Injection Pattern Detection
description: Block common SQL injection patterns
priority: 10
condition:
  any:
    # SQL keywords and operators
    - request.query: regex "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|exec\\(|execute\\(|xp_|openrowset|oledb)"
    - request.body: regex "(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|exec\\(|execute\\(|xp_|openrowset|oledb)"

    # SQL comment injection
    - request.query: contains "--"
    - request.query: contains "/*"
    - request.query: contains "*/"

    # SQL string escaping
    - request.query: contains "'"
    - request.query: contains "\""

    # UNION-based injection
    - request.query: regex "(?i)union\\s+all\\s+select"

    # Boolean-based blind injection
    - request.query: regex "(?i)and\\s+[0-9]\\s*=\\s*[0-9]"
    - request.query: regex "(?i)or\\s+[0-9]\\s*=\\s*[0-9]"

    # Time-based blind injection
    - request.query: regex "(?i)(waitfor|delay|sleep)\\s*\\("

    # Stack queries
    - request.query: regex "(?i);\\s*(select|insert|update|delete)"
transformations:
  - lowercase
  - remove_comments
action:
  type: block
  status: 403
  body: "SQL injection attempt detected"
  headers:
    X-Block-Reason: "sql-injection"
```

2. **ML-Based Detection**

```yaml
ml:
  models:
    sql_injection_detector:
      enabled: true
      threshold: 0.75
      features:
        - path_length
        - query_length
        - special_char_ratio
        - sql_keyword_count
        - quote_count
        - bracket_count
```

#### SQL Injection Score Calculation

```python
def calculate_sql_injection_score(request) -> float:
    score = 0.0

    # Pattern matches (high weight)
    sql_patterns = [
        r"union\s+select",
        r"select\s+from",
        r"insert\s+into",
        r"delete\s+from",
        r"drop\s+table",
        r"exec\s*\(",
        r"--",
        r"/\*",
    ]

    for pattern in sql_patterns:
        if re.search(pattern, request.query, re.IGNORECASE):
            score += 0.3

    # Character analysis
    if "'" in request.query:
        score += 0.1
    if "--" in request.query:
        score += 0.2
    if ";" in request.query:
        score += 0.15

    # ML model contribution
    ml_score = ml_model.predict(request)
    score = 0.6 * score + 0.4 * ml_score

    return min(score, 1.0)
```

### Cross-Site Scripting (XSS) Protection

#### Detection Mechanisms

1. **Pattern-Based Detection**

```yaml
name: XSS Pattern Detection
description: Block common XSS attack patterns
priority: 10
condition:
  any:
    # Script tags
    - request.query: regex "(?i)<script[^>]*>.*?</script>"
    - request.body: regex "(?i)<script[^>]*>.*?</script>"

    # Event handlers
    - request.query: regex "(?i)on\\w+\\s*="
    - request.body: regex "(?i)on\\w+\\s*="

    # JavaScript URIs
    - request.query: regex "(?i)javascript\\s*:"
    - request.body: regex "(?i)javascript\\s*:"

    # Data URIs
    - request.query: regex "data\\s*:\\s*text/html"
    - request.body: regex "data\\s*:\\s*text/html"

    # HTML entities (potential XSS)
    - request.query: contains "&lt;"
    - request.query: contains "&gt;"
    - request.query: contains "&amp;"
    - request.query: contains "&quot;"

    # img/src attributes
    - request.query: regex "(?i)src\\s*=\\s*['\"]?\\s*javascript:"
    - request.body: regex "(?i)src\\s*=\\s*['\"]?\\s*javascript:"

    # Expression attributes
    - request.query: regex "(?i)expression\\s*\\("
    - request.body: regex "(?i)expression\\s*\\("

    # SVG-based attacks
    - request.query: regex "(?i)<svg[^>]*>"
    - request.body: regex "(?i)<svg[^>]*>"

    # DOM-based XSS indicators
    - request.query: regex "(?i)(innerHTML|outerHTML|insertAdjacentHTML|document\\.write|document\\.writeln)"
transformations:
  - lowercase
  - html_entity_decode
action:
  type: block
  status: 403
  body: "Cross-site scripting attempt detected"
```

2. **ML-Based XSS Detection**

```python
def calculate_xss_score(request) -> float:
    features = {
        'html_tag_count': len(re.findall(r'<[^>]+>', request.query)),
        'js_uri_count': len(re.findall(r'javascript:', request.query, re.I)),
        'event_handler_count': len(re.findall(r'on\w+\s*=', request.query, re.I)),
        'entity_encoded_chars': len(re.findall(r'&[#\w]+;', request.query)),
        'special_char_ratio': len(re.findall(r'[<>"\';]', request.query)) / len(request.query),
    }

    # Combine rule-based and ML
    rule_score = calculate_rule_based_xss_score(request)
    ml_score = xss_ml_model.predict_proba([features])[0]

    return 0.5 * rule_score + 0.5 * ml_score
```

### Command Injection Protection

#### Detection Mechanisms

```yaml
name: OS Command Injection Detection
description: Block OS command injection attempts
priority: 10
condition:
  any:
    # Shell metacharacters
    - request.query: regex "[;&|`$<>]"
    - request.body: regex "[;&|`$<>]"

    # Command separators
    - request.query: regex "\\|\\s*\\w+"
    - request.body: regex "\\|\\s*\\w+"
    - request.query: regex ";\\s*\\w+"
    - request.body: regex ";\\s*\\w+"

    # Common commands
    - request.query: regex "(?i)(wget|curl|nc|netcat|bash|sh|cmd|powershell|rm|rw|ls|cat|grep|find|telnet|ssh|ftp)"
    - request.body: regex "(?i)(wget|curl|nc|netcat|bash|sh|cmd|powershell|rm|rw|ls|cat|grep|find|telnet|ssh|ftp)"

    # Command substitution
    - request.query: regex "\\$\\([^)]+\\)"
    - request.query: regex "`[^`]+`"

    # Path traversal with commands
    - request.query: regex "\\.\\./.*\\|"
    - request.body: regex "\\.\\./.*\\|"

    # Environment variables
    - request.query: regex "\\$\\{?\\w+\\}?"

    # Known malicious patterns
    - request.query: contains "/etc/passwd"
    - request.query: contains "/etc/shadow"
    - request.query: contains "c:\\\\windows"
    - request.query: contains "cmd.exe"
transformations:
  - lowercase
action:
  type: block
  status: 403
  body: "Command injection attempt detected"
```

### Path Traversal (LFI/RFI) Protection

```yaml
name: Local File Inclusion Protection
description: Block path traversal attacks
priority: 10
condition:
  any:
    # Path traversal patterns
    - request.query: regex "\\.\\.\\/|\\.\\.\\\\"
    - request.body: regex "\\.\\.\\/|\\.\\.\\\\"

    # Null byte injection
    - request.query: contains "%00"
    - request.query: contains "\\x00"
    - request.query: contains "\\0"

    # Common file access attempts
    - request.query: regex "(?i)/etc/(passwd|shadow|hosts|issue)"
    - request.query: regex "(?i)c:\\\\(windows|system32)"
    - request.query: regex "(?i)/proc/(self|environ)"

    # File inclusion patterns
    - request.query: regex "(?i)include\\s*\\("
    - request.query: regex "(?i)require\\s*\\("
    - request.query: regex "(?i)include_once\\s*\\("
    - request.query: regex "(?i)require_once\\s*\\("

    # PHP wrapper attacks
    - request.query: regex "(?i)(php://|expect://|file://|ftp://|sftp://|glob://|phar://)"

    #敏感文件路径
    - request.query: contains ".env"
    - request.query: contains ".git"
    - request.query: contains ".htaccess"
    - request.query: contains "config.php"
transformations:
  - lowercase
  - url_decode
  - normalize_path
action:
  type: block
  status: 403
  body: "Path traversal attempt detected"
```

### XXE (XML External Entity) Protection

```yaml
name: XXE Protection
description: Block XML External Entity attacks
priority: 10
condition:
  any:
    # XXE patterns
    - request.body: regex "(?i)<!DOCTYPE\\s+html\\s+\\["
    - request.body: regex "(?i)<!ENTITY"
    - request.body: regex "(?i)SYSTEM\\s+['\"]"
    - request.body: regex "(?i)PUBLIC\\s+['\"]"

    # Common XXE vectors
    - request.body: contains "file://"
    - request.body: contains "http://"
    - request.body: contains "ftp://"

    # xinclude攻击
    - request.body: contains "xinclude"

    # SVG XXE
    - request.body: regex "(?i)<svg[^>]*xmlns\\s*="
transformations:
  - lowercase
action:
  type: block
  status: 403
  body: "XXE attack detected"
```

### LDAP Injection Protection

```yaml
name: LDAP Injection Protection
description: Block LDAP injection attempts
priority: 10
condition:
  any:
    # LDAP metacharacters
    - request.query: regex "[*()\\\\]|\\)\\(|/\\(|&|\\|"
    - request.body: regex "[*()\\\\]|\\)\\(|/\\(|&|\\|"

    # LDAP injection patterns
    - request.query: regex "(?i)(dn|uid|sn|cn|ou|dc)=[^,]+,"
    - request.query: contains "(objectClass=*)"
    - request.query: contains "(userPassword=*)"
transformations:
  - lowercase
action:
  type: block
  status: 403
  body: "LDAP injection attempt detected"
```

### NoSQL Injection Protection

```yaml
name: NoSQL Injection Protection
description: Block MongoDB and other NoSQL injection attempts
priority: 10
condition:
  any:
    # MongoDB operators in query strings
    - request.query: regex "\\$where"
    - request.query: regex "\\$ne"
    - request.query: regex "\\$gt"
    - request.query: regex "\\$lt"
    - request.query: regex "\\$regex"
    - request.query: regex "\\$exists"
    - request.query: regex "\\$type"

    # JavaScript injection for $where
    - request.query: regex "(?i)function\\s*\\("
    - request.query: regex "(?i)return\\s+"
action:
  type: block
  status: 403
  body: "NoSQL injection attempt detected"
```

## A04: Insecure Design

Protection against architectural and design weaknesses.

### Rate Limiting for API Abuse

```yaml
name: API Abuse Prevention
description: Prevent API abuse through rate limiting
priority: 20
condition:
  request.path: prefix "/api/"
action:
  type: rate_limit
  rate_limit:
    requests_per_minute: 60
    burst: 10
    key: ip
```

### Mass Data Enumeration Detection

```yaml
name: Detect Mass Enumeration
description: Block rapid access to sequential resources
priority: 30
condition:
  all:
    - request.path: regex "/(users|accounts|orders|records)/[0-9]+"
    - not ip.match_cidr: "10.0.0.0/8"
action:
  type: monitor
  log_level: warning
```

## A05: Security Misconfiguration

Detection and prevention of security misconfigurations.

### Default Credentials Detection

```yaml
name: Detect Default Credentials Usage
description: Block login attempts with common default credentials
priority: 5
condition:
  all:
    - request.path: regex "(login|signin|auth)"
    - request.method: equals "POST"
    - any:
        - request.body: contains "admin"
        - request.body: contains "root"
        - request.body: contains "password123"
        - request.body: contains "123456"
action:
  type: challenge
  challenge_type: captcha
```

### Security Header Validation

Response inspection to ensure security headers:

```yaml
response_inspection:
  enabled: true
  checks:
    - header: "X-Frame-Options"
      expected: "DENY" or "SAMEORIGIN"
    - header: "X-Content-Type-Options"
      expected: "nosniff"
    - header: "Strict-Transport-Security"
      expected: "max-age="
    - header: "Content-Security-Policy"
      expected: "default-src"
```

## A06: Vulnerable Components

See [Virtual Patching](features/virtual-patching.md) documentation.

## A07: Authentication Failures

### Brute Force Protection

```yaml
name: Brute Force Login Protection
description: Rate limit login attempts
priority: 10
condition:
  all:
    - request.path: regex "(login|signin|auth)"
    - request.method: equals "POST"
action:
  type: rate_limit
  rate_limit:
    requests_per_minute: 5
    burst: 3
    duration: 3600
    key: ip
```

### Credential Stuffing Detection

```yaml
name: Detect Credential Stuffing
description: Block rapid login attempts with different credentials
priority: 15
condition:
  all:
    - request.path: regex "(login|signin|auth)"
    - request.method: equals "POST"
    - session.failed_logins: "> 3"
    - session.last_failed_login_within: "5m"
action:
  type: block
  status: 429
  body: "Too many failed login attempts"
```

## A08: Software and Data Integrity Failures

### Request Tampering Detection

```yaml
name: Detect Request Tampering
description: Block requests with manipulated parameters
priority: 25
condition:
  all:
    - request.headers.x-signature: exists
    - not request.signature: valid
action:
  type: block
  status: 403
  body: "Request signature verification failed"
```

## A09: Security Logging and Monitoring Failures

See [Audit Logging](../configuration.md#audit-logging-configuration) for details.

## A10: Server-Side Request Forgery (SSRF)

```yaml
name: SSRF Protection
description: Block requests to internal networks
priority: 10
condition:
  any:
    # Localhost access
    - request.query: regex "(?i)(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)"
    - request.query: contains "::1"

    # Cloud metadata endpoints
    - request.query: contains "169.254.169.254"
    - request.query: contains "metadata.google.internal"

    # Private IP ranges
    - request.query: regex "10\\.[0-9]+\\.[0-9]+\\.[0-9]+"
    - request.query: regex "172\\.(1[6-9]|2[0-9]|3[0-1])\\.[0-9]+"
    - request.query: regex "192\\.168\\.[0-9]+\\.[0-9]+"

    # Internal hostnames
    - request.query: regex "(?i)(internal|intranet|local|private)"
action:
  type: block
  status: 403
  body: "Access to internal resources denied"
```

## Attack Surface Reduction

### Disable Unnecessary HTTP Methods

```yaml
name: Block Dangerous HTTP Methods
description: Only allow necessary HTTP methods
priority: 1
condition:
  not request.method: in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
action:
  type: block
  status: 405
```

### Block Trace Requests

```yaml
name: Block TRACE Method
description: TRACE can be used for XST attacks
priority: 1
condition:
  request.method: equals "TRACE"
action:
  type: block
  status: 405
```

## Comprehensive Protection Example

```yaml
# Comprehensive OWASP protection configuration
rules:
  owasp_enabled: true

  # SQL Injection
  sql_injection:
    enabled: true
    threshold: 0.75
    block_on_match: true

  # XSS
  xss:
    enabled: true
    threshold: 0.8
    block_on_match: true

  # Command Injection
  command_injection:
    enabled: true
    threshold: 0.7
    block_on_match: true

  # LFI/RFI
  lfi:
    enabled: true
    threshold: 0.7
    block_on_match: true

  # XXE
  xxe:
    enabled: true
    block_on_match: true

  # SSRF
  ssrf:
    enabled: true
    block_internal_requests: true
    block_cloud_metadata: true

  # Path Traversal
  path_traversal:
    enabled: true
    threshold: 0.7
    block_on_match: true
```
