# Getting Started with FortressWAF

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

Install and configure FortressWAF in under 5 minutes.

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker | 24.0+ | 25.0+ |
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8+ GB |
| Disk | 10 GB | 50 GB+ (SSD) |
| OS | Linux kernel 5.x+ | Ubuntu 22.04+ / Rocky Linux 9+ |

## Installation

### Option 1: One-line Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/FortressWAF/FortressWAF/main/install.sh | bash
```

This command:

1. Detects your OS and architecture
2. Downloads the latest FortressWAF release
3. Sets up the configuration directory at `/etc/fortresswaf/`
4. Installs the `fortressctl` CLI tool
5. Starts the proxy service via systemd

### Option 2: Docker Compose

```bash
# Clone the repository
git clone https://github.com/fortresswaf/fortresswaf.git
cd fortresswaf

# Start the full stack
docker compose -f deploy/docker-compose.yml up -d

# Check logs
docker compose logs -f proxy
```

### Option 3: Manual Binary Install

```bash
# Download the latest release
wget https://github.com/fortresswaf/fortresswaf/releases/latest/download/fortresswaf-linux-amd64.tar.gz

# Extract and install
tar -xzf fortresswaf-linux-amd64.tar.gz
sudo mv fortresswaf fortressctl /usr/local/bin/

# Create config directory
sudo mkdir -p /etc/fortresswaf/{rules,certs}

# Run
fortresswaf --config /etc/fortresswaf/config.yaml
```

## First Site Setup

### 1. Create a configuration file

```yaml
# /etc/fortresswaf/config.yaml
listen_addr: ":8080"
upstream_url: "http://your-app:3000"

rules:
  enabled: true
  path: "/etc/fortresswaf/rules/*.yaml"

rate_limiting:
  enabled: true
  default_limit: 100
  default_window: 60s

ip_reputation:
  enabled: true
  threat_intel_feeds:
    - "https://feeds.fortresswaf.io/malicious-ips.txt"

logging:
  level: info
  format: json
```

### 2. Start the proxy

```bash
fortresswaf --config /etc/fortresswaf/config.yaml
```

### 3. Apply default OWASP rules

```bash
fortressctl rules apply --profile owasp-top-10
fortressctl rules apply --profile api-security
```

## Verification Steps

### Health Check

```bash
curl http://localhost:8080/api/v1/health

# Expected response:
# {"status":"ok","version":"1.0.0","uptime":"5m23s"}
```

### Test an Attack Block

```bash
# SQL injection should be blocked
curl -v "http://localhost:8080/search?q=1%27%20OR%20%271%27%3D%271"

# Expected: 403 Forbidden with block page
```

### Dashboard

Open http://localhost:8080/dashboard in your browser.

Default credentials:

- Username: `admin`
- Password: `fortresswaf123` (change immediately)

### Metrics Endpoint

```bash
curl http://localhost:8080/api/v1/metrics

# Shows request counts, blocked counts, latency percentiles
```

## Configuration Directory Structure

```
/etc/fortresswaf/
├── config.yaml              # Main configuration
├── rules/                   # Custom rules (YAML)
│   ├── 01-owasp-sqli.yaml
│   ├── 02-owasp-xss.yaml
│   └── custom-rules.yaml
├── certs/                   # TLS certificates
│   ├── server.crt
│   └── server.key
├── logs/                    # Log files
│   └── access.log
└── plugins/                 # Plugin hooks (Enterprise; not implemented)
    └── custom-auth.lua
```

## Troubleshooting

| Symptom | Solution |
|---------|----------|
| Proxy won't start | Check `config.yaml` syntax: `fortressctl config validate` |
| Rules not applying | Verify rule files in `rules/` directory, run `fortressctl rules reload` |
| High latency | Check upstream health, reduce rule count, or disable ML engine |
| False positives | Add IP to whitelist: `fortressctl whitelist add 192.168.1.0/24` |
| WebSocket drops | Ensure websocket support is enabled in config |
| Memory high | Adjust `max_connections` and `buffer_size` settings |

## Next Steps

- [Architecture Overview](architecture.md)
- [Writing Custom Rules](rule-language.md)
- [Production Deployment](deployment.md)
- [Troubleshooting Guide](troubleshooting.md)
