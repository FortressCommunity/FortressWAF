# Compliance Reference

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF includes security controls that may help satisfy certain compliance requirements. This document maps available features to common compliance frameworks for reference.

**Important:** Compliance requires organization-wide policies, processes, and controls. A WAF alone cannot make you compliant with any framework. This document is a reference for auditors and security teams evaluating FortressWAF.

---

## PCI DSS v4.0

The following WAF features may help with PCI DSS requirements:

| Requirement | Relevant WAF Feature |
|-------------|---------------------|
| **6.4.2** Automated technical solution for public-facing web apps | WAF rule engine blocks common web attacks |
| **6.5.1** Injection attacks | Rules for SQLi, XSS, RCE detection |
| **11.5.1.1** Intrusion detection/prevention | Real-time attack detection and blocking |

### Relevant Configuration

```yaml
# Enable audit logging for rule changes
audit:
  enabled: true
  log_all_rule_changes: true

# Enable TLS enforcement
tls:
  min_version: "1.2"
```

---

## GDPR

FortressWAF includes data protection features that may assist with GDPR requirements:

- Configurable log fields (mask/truncate sensitive data)
- Log retention configuration with auto-purge
- TLS encryption in transit

### Relevant Configuration

```yaml
logging:
  mask_fields:
    - email
    - phone
  retention_days: 90
```

---

## SOC 2

FortressWAF security controls relevant to SOC 2 Trust Services Criteria:

| Criteria | Relevant WAF Feature |
|----------|---------------------|
| **CC6.1** Logical and physical access | API token authentication, IP allowlisting |
| **CC7.1** Detect security events | Attack detection and alerting |

FortressWAF has not undergone a SOC 2 audit. No attestation report is available.

---

## What FortressWAF Does NOT Provide

- Compliance certification or attestation reports
- FIPS 140-2 validated cryptographic modules
- Built-in compliance monitoring or scoring
- Automated compliance remediation
- Organization-wide policy enforcement beyond HTTP traffic

For compliance-specific questions, consult a qualified security professional.
