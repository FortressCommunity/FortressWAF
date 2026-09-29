# Quick Start Guide

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

This guide will walk you through deploying FortressWAF using Docker Compose in under 5 minutes. By the end of this guide, you'll have a fully functional WAF protecting a sample application.

## Prerequisites

Before starting, ensure you have the following installed:

| Requirement | Minimum | Recommended |
|---|---|---|
| Docker | 20.10+ | 24+ |
| Docker Compose | v2 | v2 |
| RAM | 4 GB | 8 GB |
| CPU | 2 cores | 4+ cores |
| Disk | 20 GB | SSD recommended |

!!! warning "Hardware Requirements"
    The minimum requirements are for evaluation purposes. Production deployments require significantly more resources. See the [Production Docker Deployment](deploy/docker.md) guide for full requirements.

### Supported Platforms

- **Linux**: Ubuntu 20.04+, Debian 11+, CentOS 8+
- **macOS**: macOS 12+ (Intel and Apple Silicon)
- **Windows**: Windows 10/11 with WSL2 and Docker Desktop

## Installation Methods

### Method 1: One-Command Installer (Recommended)

The easiest way to get started is using our official installer script:

```bash
curl -sSL https://raw.githubusercontent.com/FortressWAF/FortressWAF/refs/heads/main/install.sh | bash
```

This script will:

1. Check system requirements (Docker, Docker Compose)
2. Create necessary directories
3. Generate secure passwords and API keys
4. Download the latest `docker-compose.yml`
5. Start all services
6. Display access credentials and URLs

The installer creates the following directory structure:

```
~/.fortresswaf/
├── config/
│   └── config.yaml          # Main configuration file
├── logs/                    # FortressWAF logs
├── data/                    # Persistent data (Redis, PostgreSQL)
├── docker-compose.yml       # Docker Compose configuration
└── .env                     # Environment variables (secrets)
```

### Method 2: Manual Docker Compose Setup

If you prefer to set up manually or customize the installation:

#### Step 1: Clone the Repository

```bash
git clone https://github.com/fortresswaf/fortresswaf.git
cd fortresswaf/deploy/docker-compose
```

#### Step 2: Create the Docker Compose File

Create a `docker-compose.yml` with the following content:

```yaml
version: '3.8'

services:
  fortresswaf:
    image: fortresswaf/fortresswaf:latest
    container_name: fortresswaf
    restart: unless-stopped
    ports:
      - "8443:8443"      # Dashboard HTTPS
      - "8444:8444"      # API HTTPS
      - "8080:8080"      # HTTP proxy (for testing)
    environment:
      - FW_ADMIN_USER=admin
      - FW_ADMIN_PASSWORD=${ADMIN_PASSWORD}
      - FW_API_KEY=${API_KEY}
      - FW_REDIS_HOST=redis
      - FW_REDIS_PORT=6379
      - FW_POSTGRES_HOST=postgres
      - FW_POSTGRES_PORT=5432
      - FW_POSTGRES_DB=fortresswaf
      - FW_POSTGRES_USER=fortresswaf
      - FW_POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - FW_TLS_ENABLED=true
      - FW_TLS_CERT=/certs/server.crt
      - FW_TLS_KEY=/certs/server.key
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
      - ./certs:/certs:ro
      - /var/run/docker.sock:/var/run/docker.sock
    depends_on:
      - redis
      - postgres
    networks:
      - fortresswaf-network
    healthcheck:
      test: ["CMD", "curl", "-kf", "https://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  redis:
    image: redis:7-alpine
    container_name: fortresswaf-redis
    restart: unless-stopped
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - redis-data:/data
    networks:
      - fortresswaf-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3

  postgres:
    image: postgres:15-alpine
    container_name: fortresswaf-postgres
    restart: unless-stopped
    environment:
      - POSTGRES_DB=fortresswaf
      - POSTGRES_USER=fortresswaf
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - fortresswaf-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fortresswaf -d fortresswaf"]
      interval: 10s
      timeout: 5s
      retries: 3

  # Optional: Prometheus metrics exporter
  prometheus:
    image: prom/prometheus:latest
    container_name: fortresswaf-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    networks:
      - fortresswaf-network
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  # Optional: Grafana dashboard
  grafana:
    image: grafana/grafana:latest
    container_name: fortresswaf-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    networks:
      - fortresswaf-network
    depends_on:
      - prometheus

volumes:
  redis-data:
  postgres-data:
  prometheus-data:
  grafana-data:

networks:
  fortresswaf-network:
    driver: bridge
```

#### Step 3: Create Environment File

Create a `.env` file with secure passwords:

```bash
# Generate secure passwords
export ADMIN_PASSWORD=$(openssl rand -base64 32)
export API_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
export GRAFANA_PASSWORD=$(openssl rand -base64 32)

# Save to .env file
cat > .env << EOF
ADMIN_PASSWORD=${ADMIN_PASSWORD}
API_KEY=${API_KEY}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
GRAFANA_PASSWORD=${GRAFANA_PASSWORD}
EOF
```

#### Step 4: Create Configuration Directory

```bash
mkdir -p config certs logs
```

Create the main `config/config.yaml`:

```yaml
# FortressWAF Configuration
server:
  host: 0.0.0.0
  port: 8443
  api_port: 8444
  tls:
    enabled: true
    cert_path: /certs/server.crt
    key_path: /certs/server.key
    min_version: "1.2"

logging:
  level: info
  format: json
  outputs:
    - type: stdout
    - type: file
      path: /app/logs/fortresswaf.log
    - type: syslog
      host: localhost
      port: 514

redis:
  host: redis
  port: 6379
  password: ""
  db: 0
  pool_size: 10
  ssl: false

database:
  host: postgres
  port: 5432
  name: fortresswaf
  user: fortresswaf
  password: ""
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: 5m

engine:
  workers: auto  # Number of worker threads (auto = CPU cores)
  max_request_size: 10MB
  request_timeout: 60s
  keep_alive_timeout: 30s
  disable_internal_errors: false

# Default rule set (will be loaded on startup)
rules:
  owasp_enabled: true
  community_rules_enabled: true
  custom_rules_path: /app/config/rules
  reload_interval: 30s

# ML Engine configuration
ml:
  enabled: true
  model_path: /app/config/models
  anomaly_threshold: 0.75
  fallback_enabled: true

# Rate limiting defaults
rate_limiting:
  enabled: true
  global:
    requests_per_minute: 1000
    burst: 100
  per_ip:
    requests_per_minute: 100
    burst: 20

# Bot detection
bot_detection:
  enabled: true
  fingerprint_enabled: true
  headless_browser_detection: true
  captcha_threshold: 0.8

# DDOS protection
ddos:
  enabled: true
  http_flood_threshold: 500
  slowloris_timeout: 30s
  slow_post_timeout: 60s

# Audit logging
audit:
  enabled: true
  log_all_requests: false
  log_blocked_requests: true
  log_suspicious_requests: true
  retention_days: 90
```

#### Step 5: Generate Self-Signed Certificates (for testing)

For production, use Let's Encrypt or your own CA:

```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -subj "/CN=localhost/O=FortressWAF/C=US" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

#### Step 6: Start the Services

```bash
# Pull images
docker-compose pull

# Start services in detached mode
docker-compose up -d

# Follow logs
docker-compose logs -f fortresswaf
```

Wait for the services to start (approximately 30-60 seconds):

```bash
# Check service status
docker-compose ps

# Expected output:
# NAME                STATUS          PORTS
# fortresswaf         Up (healthy)    0.0.0.0:8443->8443/tcp
# postgres            Up (healthy)    5432/tcp
# redis               Up (healthy)    6379/tcp
```

#### Step 7: Access the Dashboard

Once all services are healthy, access the FortressWAF dashboard:

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| **Dashboard** | https://localhost:8443 | `admin` / (from .env) |
| **API** | https://localhost:8444 | `api_key` / (from .env) |
| **Grafana** | http://localhost:3000 | `admin` / (from .env) |
| **Prometheus** | http://localhost:9090 | No auth |

### Step 8: Initial Configuration

After first login, you'll be guided through the setup wizard:

#### 1. Change Default Password

Immediately change the default admin password to a secure value.

#### 2. Add Your First Application

Navigate to **Applications > Add Application** and fill in:

```yaml
Name: my-web-app
Domain: app.example.com
Backend Origin: http://10.0.0.100:8080
TLS:
  mode: terminate  # or pass-through
  cert: uploaded cert
Health Check:
  path: /health
  interval: 10s
```

#### 3. Configure DNS

Point your domain DNS to the FortressWAF instance:

```
# DNS A record
app.example.com -> <FORTRESSWAF_IP>
```

#### 4. Import SSL Certificate

For production, upload your SSL certificate:

```bash
# Using the CLI
fortressctl cert import \
  --name production-cert \
  --cert /path/to/cert.pem \
  --key /path/to/key.pem
```

### Step 9: Verify Protection

Test that FortressWAF is properly blocking attacks:

```bash
# Test SQL injection (should be blocked)
curl -i "https://localhost:8443/?id=1' OR '1'='1"

# Expected response: HTTP/1.1 403 Forbidden
# Body: Attack detected: SQL Injection attempt

# Test XSS (should be blocked)
curl -i "https://localhost:8443/?name=<script>alert('XSS')</script>"

# Expected response: HTTP/1.1 403 Forbidden
# Body: Attack detected: Cross-Site Scripting attempt

# Test legitimate request (should pass)
curl -i "https://localhost:8443/?name=John"

# Expected response: HTTP/1.1 200 OK
# Body: Hello, John!
```

### Dashboard Tour

The FortressWAF dashboard provides:

| Section | Description |
|---------|-------------|
| **Overview** | Real-time traffic stats, attack map, top threats |
| **Applications** | Manage protected applications and domains |
| **Rules** | View, create, and manage WAF rules |
| **Traffic** | Live request log with filtering |
| **Attacks** | Detailed attack analytics and trends |
| **Bots** | Bot traffic analysis and management |
| **Rate Limits** | Rate limiting configuration and stats |
| **Reports** | Compliance and security reports |
| **Settings** | System configuration and users |

### Adding Your First Rule

Navigate to **Rules > Add Rule** and create a custom rule:

```yaml
name: Block Admin Path
description: Block access to admin paths from non-admin IPs
priority: 10
condition:
  all:
    - request.path prefix "/admin"
    - not ip.match subnet "10.0.0.0/8"
action: block
response:
  status: 403
  body: "Access denied"
```

### Testing Rate Limiting

```bash
# Rapid requests should trigger rate limiting
for i in {1..50}; do
  curl -i "https://localhost:8443/" -H "X-Client-ID: test-client"
done

# After 20 requests, you should receive 429 Too Many Requests
```

## Next Steps

Now that FortressWAF is running, explore these guides:

- **[Configuration Reference](configuration.md)** - Complete configuration options
- **[Architecture Deep Dive](concepts/architecture.md)** - Understand the internal architecture
- **[Rule Engine](concepts/rules.md)** - Write custom detection rules
- **[Kubernetes Deployment](kubernetes.md)** - Deploy at scale with Kubernetes
- **[API Reference](api-reference.md)** - Integrate with your CI/CD pipeline
- **[CLI Reference](cli-reference.md)** - Automate with fortressctl

## Common Issues

### Port Already in Use

If port 8443 is already in use:

```yaml
# Edit docker-compose.yml
services:
  fortresswaf:
    ports:
      - "8445:8443"  # Map to different host port
```

### Docker Socket Permission Denied

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER
newgrp docker
```

### Database Connection Failed

```bash
# Check if postgres is ready
docker-compose logs postgres

# Wait for postgres to be ready and retry
docker-compose up -d postgres
docker-compose up -d fortresswaf
```

### Out of Memory

If containers are being OOM killed:

```yaml
# Add memory limits in docker-compose.yml
services:
  fortresswaf:
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G
```

## Uninstall

To completely remove FortressWAF:

```bash
# Stop all services
docker-compose down

# Remove volumes (deletes all data)
docker-compose down -v

# Remove configuration files
rm -rf ~/.fortresswaf

# Remove docker images
docker rmi $(docker images | grep fortresswaf | awk '{print $3}')
```

## Getting Help

- **Documentation**: https://docs.fortresswaf.io
- **GitHub Issues**: https://github.com/fortresswaf/fortresswaf/issues
- **Community Forum**: https://community.fortresswaf.io
- **Slack**: https://slack.fortresswaf.io
- **Enterprise Support**: support@fortresswaf.io
