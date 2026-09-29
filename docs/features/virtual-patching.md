# Virtual Patching

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

Virtual patching provides a way to protect applications from vulnerabilities without modifying application code. This is essential for addressing newly discovered CVEs, legacy systems, and third-party applications.

## Virtual Patch Overview

A virtual patch is a WAF rule or configuration that blocks exploitation of a known vulnerability. Unlike traditional patches, virtual patches:

- Don't require code changes
- Take effect immediately
- Can be deployed in minutes
- Work with any application
- Are reversible

## Patch Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VIRTUAL PATCH LIFECYCLE                               │
└─────────────────────────────────────────────────────────────────────────────┘

  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
  │ Discover│───▶│ Create  │───▶│  Test   │───▶│ Deploy  │───▶│ Monitor │
  │   CVE  │    │  Patch  │    │         │    │         │    │         │
  └─────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────┘
      │              │              │              │              │
      │              │              │              │              │
      ▼              ▼              ▼              ▼              ▼
  ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
  │ Monitor │    │ Write   │    │ Staging │    │ Active  │    │ Expiry  │
  │ Security│    │ Rules   │    │  Test   │    │Protect  │    │ Review  │
  │ Feeds   │    │         │    │         │    │         │    │         │
  └─────────┘    └─────────┘    └─────────┘    └─────────┘    └─────────┘
```

## Creating Virtual Patches

### From CVE Description

When a new CVE is announced, create a patch based on the vulnerability description:

```yaml
# CVE-2024-1234: SQL Injection in /api/users endpoint
name: "CVE-2024-1234 SQL Injection Patch"
description: |
  Virtual patch for CVE-2024-1234
  SQL Injection vulnerability in /api/users endpoint
  CVSS: 9.1 CRITICAL
  Affects: Application Server v1.0-v2.3
priority: 1  # Critical vulnerabilities get highest priority
enabled: true
tags:
  - cve
  - cve-2024-1234
  - sql-injection
  - critical
condition:
  all:
    - request.path: prefix "/api/users"
    - request.method: in ["GET", "POST", "PUT", "DELETE"]
    - any:
        - request.query.sql_injection_score: "> 0.8"
        - request.body.sql_injection_score: "> 0.8"
        - request.query: regex "(?i)union.*select"
        - request.query: regex "(?i)select.*from.*users"
action:
  type: block
  status: 403
  body: |
    {"error": "security_block", "code": "CVE-2024-1234", "message": "Request blocked by security policy"}
  headers:
    X-Block-Reason: "CVE-2024-1234-detected"
    X-Security-Policy: "virtual-patch-active"
```

### Manual Patch Creation

Create patches based on application-specific knowledge:

```yaml
# Patch for a custom authentication bypass vulnerability
name: "Auth Bypass in /admin/login"
description: |
  Authentication bypass via SQL injection in login endpoint
  The application doesn't properly sanitize the username field
priority: 5
enabled: true
tags:
  - authentication
  - sql-injection
  - auth-bypass
condition:
  all:
    - request.path: equals "/admin/login"
    - request.method: equals "POST"
    - any:
        # Known bypass patterns
        - request.body.username: equals "admin'--"
        - request.body.username: contains "' OR '1'='1"
        - request.body.username: contains "' OR 1=1"
        # Generic SQL injection detection
        - request.body.sql_injection_score: "> 0.85"
action:
  type: block
  status: 403
  body: |
    {"error": "access_denied", "message": "Invalid credentials"}
```

### Patch for XXE Vulnerability

```yaml
# XXE vulnerability in XML document upload
name: "XXE in Document Upload CVE-2024-5678"
description: |
  XXE vulnerability in document upload functionality
  Allows reading internal files via XML external entity
  CVSS: 8.2 HIGH
priority: 3
enabled: true
tags:
  - cve
  - cve-2024-5678
  - xxe
  - xml-injection
condition:
  all:
    - request.path: prefix "/api/documents/upload"
    - request.headers.content-type: contains "xml"
    - any:
        - request.body: regex "(?i)<!ENTITY"
        - request.body: regex "(?i)SYSTEM\\s+['\"]"
        - request.body: contains "file://"
        - request.body: contains "php://"
action:
  type: block
  status: 403
  body: |
    {"error": "invalid_document", "message": "Document contains potentially dangerous content"}
```

### Patch for Remote Code Execution

```yaml
# RCE via template injection in /api/templates endpoint
name: "Template Injection RCE Patch CVE-2024-9012"
description: |
  Remote code execution via template injection
  Vulnerability in template rendering engine
  CVSS: 10.0 CRITICAL
priority: 1
enabled: true
tags:
  - cve
  - cve-2024-9012
  - rce
  - template-injection
condition:
  all:
    - request.path: prefix "/api/templates"
    - any:
        # Template injection patterns
        - request.body: regex "\\{\\{.*\\}\\}"
        - request.body: regex "\\{%.*%\\}"
        - request.body: regex "\\$\\{.*\\}"
        - request.body: contains "{{"
        - request.body: contains "{%"
        # Command injection patterns
        - request.body: regex "[;&|`$]"
        - request.body: regex "\\|\\s*\\w+"
action:
  type: block
  status: 403
  body: |
    {"error": "invalid_template", "message": "Template contains invalid syntax"}
```

## One-Click Patching from Scanner Results

Import vulnerability scan results to automatically create patches:

### Supported Scanner Formats

- Nessus
- Qualys
- OWASP ZAP
- Burp Suite
- Rapid7 Nexpose
- Custom JSON format

### Import Process

```bash
# Import from OWASP ZAP
fortressctl virtual-patch import \
  --scanner zap \
  --input zap-report.xml \
  --site-id <site-uuid>

# Import from Burp Suite
fortressctl virtual-patch import \
  --scanner burp \
  --input burp-report.xml \
  --site-id <site-uuid>

# Import from Nessus
fortressctl virtual-patch import \
  --scanner nessus \
  --input nessus-report.nessus \
  --site-id <site-uuid>

# Import from custom JSON
fortressctl virtual-patch import \
  --scanner custom \
  --input vulnerabilities.json \
  --site-id <site-uuid> \
  --format '{"cve": "%cve%", "path": "%path%", "severity": "%severity%"}'
```

### Import Configuration

```yaml
virtual_patching:
  import:
    # Auto-enable patches for critical/high severity
    auto_enable_critical: true
    auto_enable_high: true
    auto_enable_medium: false
    # Set patch priority based on severity
    priority_mapping:
      critical: 1
      high: 5
      medium: 20
      low: 50
    # Default expiration (30 days for scanner-based patches)
    default_expiry_days: 30
    # Add scanner source to tags
    include_scanner_tag: true
```

## Patch Testing Workflow

Before deploying patches to production, test them in a staging environment:

### Testing Process

```
1. Create patch in test mode
2. Send test requests (positive and negative)
3. Verify patch blocks exploit attempts
4. Verify patch doesn't block legitimate traffic
5. Deploy to production
```

### Test Mode

```bash
# Create patch in test mode (logs but doesn't block)
fortressctl virtual-patch create \
  --name "Test Patch for CVE-2024-1234" \
  --cve CVE-2024-1234 \
  --condition 'request.path prefix "/api/vulnerable"' \
  --action block \
  --test-mode true

# View test results
fortressctl virtual-patch test-results --patch-id <patch-uuid>

# Promote to production
fortressctl virtual-patch promote --patch-id <patch-uuid>

# Or discard if false positives
fortressctl virtual-patch discard --patch-id <patch-uuid>
```

### Automated Testing

```bash
# Run attack simulation
fortressctl virtual-patch test \
  --patch-id <patch-uuid> \
  --test-suite "OWASP-_TOP10"

# Test with specific payloads
fortressctl virtual-patch test \
  --patch-id <patch-uuid> \
  --payloads /path/to/payloads.txt

# View test report
fortressctl virtual-patch test-report --patch-id <patch-uuid>
```

### Test Payload Examples

```bash
# SQL Injection test payloads
"1' OR '1'='1"
"1\" OR \"1\"=\"1"
"1; DROP TABLE users--"
"1 UNION SELECT NULL--
"' OR 1=1 --"

# XSS test payloads
"<script>alert('XSS')</script>"
"<img src=x onerror=alert('XSS')>"
"javascript:alert('XSS')"
"<svg onload=alert('XSS')>"

# Command injection test payloads
"; ls -la"
"| cat /etc/passwd"
"& whoami"
"$(whoami)"
"`id`"
```

## Patch Coverage Reporting

Track which vulnerabilities are protected:

```bash
# Generate coverage report
fortressctl virtual-patch report \
  --site-id <site-uuid> \
  --format html \
  --output coverage-report.html

# List all active patches
fortressctl virtual-patch list --site-id <site-uuid>

# View patch statistics
fortressctl virtual-patch stats --patch-id <patch-uuid>
```

### Coverage Report Format

```markdown
# Virtual Patch Coverage Report
Site: example.com
Generated: 2024-01-15 10:30:00 UTC

## Protected Vulnerabilities

| CVE | Severity | Protected | Blocked Attempts | Status |
|-----|----------|-----------|------------------|--------|
| CVE-2024-1234 | CRITICAL | Yes | 1,234 | Active |
| CVE-2024-5678 | HIGH | Yes | 567 | Active |
| CVE-2023-9999 | MEDIUM | Yes | 89 | Active |

## Unprotected Vulnerabilities

| CVE | Severity | Reason | Recommended Action |
|-----|----------|--------|-------------------|
| CVE-2023-8888 | HIGH | No matching route | Review application routing |
| CVE-2023-7777 | MEDIUM | Existing patch | Update existing patch |

## Statistics

- Total Patches: 45
- Critical Patches: 5
- Total Blocked Attempts: 15,678
- Blocked Today: 234
```

## Managing Patch Expiry

Patches should have an expiry date to ensure they're reviewed:

### Expiry Configuration

```yaml
virtual_patching:
  expiry:
    # Default patch lifetime (days)
    default_ttl_days: 30
    # Critical patches get longer TTL
    critical_ttl_days: 90
    # Warning before expiry (days)
    warning_days: 7
    # Auto-renewal for stable patches
    auto_renew: true
    # Maximum TTL
    max_ttl_days: 365
```

### Patch Expiry Management

```bash
# View expiring patches
fortressctl virtual-patch list-expiring --days 7

# Renew a patch
fortressctl virtual-patch renew --patch-id <patch-uuid> --days 30

# View patch history
fortressctl virtual-patch history --patch-id <patch-uuid>

# Archive old patches (remove but keep history)
fortressctl virtual-patch archive --patch-id <patch-uuid>
```

### Expiry Notification

```yaml
notifications:
  patch_expiry:
    enabled: true
    # Send notification 7 days before expiry
    warning_days: [7, 3, 1]
    channels:
      - email
      - slack
    recipients:
      - security-team@example.com
```

## Patch Templates

Common vulnerability patterns have reusable templates:

### SQL Injection Template

```yaml
# Template for SQL injection patches
name: "SQL Injection Patch Template"
description: Generic SQL injection protection for specific endpoint
variables:
  - name: endpoint
    required: true
    description: "Endpoint path to protect"
  - name: severity
    required: false
    default: "high"
condition:
  all:
    - request.path: prefix "${endpoint}"
    - any:
        - request.query.sql_injection_score: "> 0.8"
        - request.body.sql_injection_score: "> 0.8"
action:
  type: block
  status: 403
```

### XSS Template

```yaml
# Template for XSS patches
name: "XSS Patch Template"
description: Generic XSS protection for specific endpoint
variables:
  - name: endpoint
    required: true
condition:
  all:
    - request.path: prefix "${endpoint}"
    - any:
        - request.query.xss_score: "> 0.8"
        - request.body.xss_score: "> 0.8"
action:
  type: block
  status: 403
```

### Use Template to Create Patch

```bash
fortressctl virtual-patch create-from-template \
  --template sql-injection \
  --variables "endpoint=/api/users,severity=critical"
```

## Integration with Vulnerability Management

### CI/CD Integration

```yaml
# In your CI/CD pipeline
- name: Create virtual patches
  run: |
    fortressctl virtual-patch import \
      --scanner arachni \
      --input vulnerability-report.json \
      --site-id ${{ SITE_ID }} \
      --auto-enable
```

### Integration with SIEM

```yaml
# Send patch events to SIEM
notifications:
  patch_events:
    enabled: true
    channels:
      - splunk
      - elastic
    events:
      - patch_created
      - patch_activated
      - patch_blocked_attack
      - patch_expired
```

## Best Practices

1. **Prioritize Critical Vulnerabilities**: Create patches for CRITICAL and HIGH severity CVEs first
2. **Use Test Mode**: Always test patches before enabling blocking
3. **Set Expiry Dates**: Patches should have expiration dates to force review
4. **Monitor False Positives**: Watch for legitimate traffic being blocked
5. **Keep Patch Rules Simple**: Complex rules are harder to debug
6. **Document Your Patches**: Include CVE references and vulnerability descriptions
7. **Review Patch Coverage Regularly**: Ensure all known vulnerabilities are protected
8. **Automate Patch Creation**: Integrate with vulnerability scanners for automatic protection
