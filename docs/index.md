# FortressWAF Documentation

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF is a Go-based Web Application Firewall with rule-based detection, rate limiting, IP reputation, and an optional ML sidecar.

## Quick Start

```bash
docker compose -f deploy/docker-compose.yml up -d
curl http://localhost:8080/api/v1/health
```

## Feature Overview

| Feature | Description | Community | Enterprise |
|---------|-------------|-----------|------------|
| **OWASP Detection** | Pattern-based rules for SQLi, XSS, RCE, API attacks | ✅ | ✅ |
| **Rate Limiting** | Per-IP and global token/leaky bucket | ✅ | ✅ |
| **IP Reputation** | Allow/block lists, TOR/VPN/proxy detection | ✅ | ✅ |
| **Virtual Patching** | Deploy rules without app changes | ✅ | ✅ |
| **Dashboard** | Live metrics via WebSocket | ✅ | ✅ |
| **REST API** | Full configuration via API | ✅ | ✅ |
| **Bot Detection** | Signature-based bot detection | ✅ | ✅ |
| **ML Anomaly Detection** | Optional sidecar for anomaly scoring | ❌ | ✅ |
| **Multi-Tenancy** | Isolated site configurations | ❌ | ✅ |
| **Compliance Docs** | Reference documentation for PCI/GDPR | ❌ | ✅ |

## Documentation Sections

- [Getting Started](getting-started.md)
- [Architecture](architecture.md)
- [Configuration](configuration.md)
- [Rule Language](rule-language.md)
- [API Reference](api-reference.md)
- [Deployment](deployment.md)
- [Compliance](compliance.md)
- [Troubleshooting](troubleshooting.md)

## Project Status

FortressWAF is under active development. Core features are functional; some OWASP categories (LFI, SSRF, XXE) are on the roadmap. See the [CHANGELOG](../CHANGELOG.md) for release notes.
