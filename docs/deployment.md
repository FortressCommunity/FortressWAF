# Deploying FortressWAF

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

## Docker Compose

### Development

```yaml
# deploy/docker-compose.dev.yml
version: "3.9"

services:
  proxy:
    image: fortresswaf/proxy:latest-dev
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./config:/etc/fortresswaf:ro
      - ./rules:/etc/fortresswaf/rules:ro
    environment:
      FORTRESS_LOG_LEVEL: debug
      FORTRESS_UPSTREAM: http://app:3000
    depends_on:
      - redis
      - app

  ml-engine:
    image: fortresswaf/ml-engine:latest-dev
    ports:
      - "50051:50051"
    volumes:
      - ./ml-engine/models:/models:ro
    environment:
      ML_MODEL_PATH: /models/ensemble_v2.pkl
    depends_on:
      - redis

  app:
    image: your-app:latest
    ports:
      - "3000:3000"

  dashboard:
    image: fortresswaf/dashboard:latest-dev
    ports:
      - "3001:3001"
    depends_on:
      - proxy

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: fortresswaf
      POSTGRES_USER: fortresswaf
      POSTGRES_PASSWORD: changeme
    volumes:
      - postgres-data:/var/lib/postgresql/data

volumes:
  redis-data:
  postgres-data:
```

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
```

### Staging

```yaml
# deploy/docker-compose.staging.yml
version: "3.9"

services:
  proxy:
    image: fortresswaf/proxy:${TAG:-latest}
    restart: always
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: "2"
          memory: "2G"
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/fortresswaf:ro
    environment:
      FORTRESS_LOG_LEVEL: info
      FORTRESS_REDIS_URL: redis://redis:6379
      FORTRESS_DB_URL: postgres://fortresswaf:changeme@postgres:5432/fortresswaf?sslmode=disable

  ml-engine:
    image: fortresswaf/ml-engine:${TAG:-latest}
    restart: always
    deploy:
      resources:
        limits:
          cpus: "4"
          memory: "4G"

  dashboard:
    image: fortresswaf/dashboard:${TAG:-latest}
    ports:
      - "3001:3001"

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

  postgres:
    image: postgres:16-alpine
    volumes:
      - postgres-data:/var/lib/postgresql/data

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
```

```bash
TAG=v1.0.0 docker compose -f deploy/docker-compose.staging.yml up -d
```

### Production

```yaml
# deploy/docker-compose.prod.yml
version: "3.9"

x-logging: &default-logging
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"

services:
  proxy:
    image: fortresswaf/proxy:${TAG:-latest}
    restart: always
    logging: *default-logging
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "4"
          memory: "4G"
        reservations:
          cpus: "2"
          memory: "2G"
    ports:
      - "8080:8080"
    volumes:
      - /etc/fortresswaf:/etc/fortresswaf:ro
      - /var/log/fortresswaf:/var/log/fortresswaf
    environment:
      FORTRESS_LOG_LEVEL: warn
      FORTRESS_REDIS_URL: redis://redis:6379
      FORTRESS_DB_URL: postgres://fortresswaf@postgres:5432/fortresswaf?sslmode=verify-full
      FORTRESS_SSL_CERT: /etc/fortresswaf/certs/server.crt
      FORTRESS_SSL_KEY: /etc/fortresswaf/certs/server.key
    depends_on:
      - redis
      - postgres
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    networks:
      - proxy
      - internal

  ml-engine:
    image: fortresswaf/ml-engine:${TAG:-latest}
    restart: always
    logging: *default-logging
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: "8"
          memory: "8G"
    volumes:
      - /data/models:/models:ro
    environment:
      ML_MODEL_PATH: /models/ensemble_v2.pkl
      ML_THRESHOLD: "0.7"
      ML_GPU_ENABLED: "false"
    networks:
      - internal

  dashboard:
    image: fortresswaf/dashboard:${TAG:-latest}
    restart: always
    logging: *default-logging
    ports:
      - "3001:3001"
    environment:
      DASHBOARD_PROXY_URL: http://proxy:8080
      DASHBOARD_REDIS_URL: redis://redis:6379
    networks:
      - internal
      - monitoring

  redis:
    image: redis:7-alpine
    restart: always
    logging: *default-logging
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    networks:
      - internal

  postgres:
    image: postgres:16-alpine
    restart: always
    logging: *default-logging
    volumes:
      - postgres-data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: fortresswaf
      POSTGRES_USER: fortresswaf
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    networks:
      - internal

networks:
  proxy:
    external: true
  internal:
    internal: true
  monitoring:
    external: true

volumes:
  redis-data:
    driver: local
  postgres-data:
    driver: local
```

## Kubernetes with Helm

```bash
# Add Helm repository
helm repo add fortresswaf https://helm.fortresswaf.io
helm repo update

# Install
helm install fortresswaf fortresswaf/fortresswaf \
  --namespace fortresswaf --create-namespace \
  --values values-prod.yaml
```

### values-prod.yaml

```yaml
# Sample values-prod.yaml
replicaCount: 3

image:
  repository: fortresswaf/proxy
  tag: latest
  pullPolicy: Always

config:
  upstreamURL: "http://my-app.prod.svc.cluster.local:8080"
  logLevel: info
  mlEnabled: true
  mlThreshold: 0.7
  rateLimitEnabled: true
  defaultRateLimit: 100
  defaultRateWindow: 60s

resources:
  proxy:
    requests:
      cpu: "2"
      memory: "2Gi"
    limits:
      cpu: "4"
      memory: "4Gi"
  mlEngine:
    requests:
      cpu: "4"
      memory: "4Gi"
    limits:
      cpu: "8"
      memory: "8Gi"

redis:
  enabled: true
  architecture: replication
  auth:
    enabled: true
    password: changeme

postgresql:
  enabled: true
  auth:
    database: fortresswaf
    username: fortresswaf
    password: changeme

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts:
        - api.example.com
      secretName: fortresswaf-tls

serviceMonitor:
  enabled: true
  interval: 15s

persistence:
  enabled: true
  size: 50Gi

rules:
  profiles:
    - owasp-top-10
    - api-security
  customRules:
    - id: "BLOCK_ENV"
      name: "Block .env access"
      pattern: "/.env"
      action: block
```

## Bare Metal with Ansible

```yaml
# deploy/ansible/playbook.yml
---
- name: Deploy FortressWAF
  hosts: waf_nodes
  become: yes
  vars:
    fortress_version: "1.0.0"
    fortress_upstream: "http://app-server:3000"

  tasks:
    - name: Download FortressWAF binary
      get_url:
        url: "https://github.com/fortresswaf/fortresswaf/releases/download/v{{ fortress_version }}/fortresswaf-linux-amd64.tar.gz"
        dest: /tmp/fortresswaf.tar.gz

    - name: Extract archive
      unarchive:
        src: /tmp/fortresswaf.tar.gz
        dest: /usr/local/bin/
        remote_src: yes

    - name: Create directories
      file:
        path: "{{ item }}"
        state: directory
        mode: 0755
      loop:
        - /etc/fortresswaf
        - /etc/fortresswaf/rules
        - /etc/fortresswaf/certs
        - /var/log/fortresswaf
        - /var/lib/fortresswaf

    - name: Copy configuration
      template:
        src: config.yaml.j2
        dest: /etc/fortresswaf/config.yaml
        mode: 0640

    - name: Copy systemd service
      template:
        src: fortresswaf.service.j2
        dest: /etc/systemd/system/fortresswaf.service
        mode: 0644

    - name: Enable and start service
      systemd:
        name: fortresswaf
        enabled: yes
        state: started
        daemon_reload: yes
```

## Terraform

```hcl
# deploy/terraform/main.tf
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

module "fortresswaf" {
  source = "github.com/fortresswaf/terraform-modules//aws"

  environment       = var.environment
  vpc_id            = var.vpc_id
  subnet_ids        = var.subnet_ids
  instance_count    = var.environment == "prod" ? 3 : 2
  instance_type     = var.environment == "prod" ? "m6i.xlarge" : "t3.medium"

  upstream_url      = var.upstream_url
  enable_ml         = var.environment == "prod"
  enable_dashboard  = true

  rules_profiles    = ["owasp-top-10", "api-security"]

  ssl_cert_arn      = var.ssl_cert_arn

  tags = {
    Environment = var.environment
    Project     = "FortressWAF"
  }
}
```

## Cloud Marketplace

### AWS Marketplace

```bash
# Subscribe via AWS Marketplace Console or AWS CLI
aws marketplace subscribe --product-code fwaf-xxxxxxxx

# Launch with CloudFormation
aws cloudformation create-stack \
  --stack-name fortresswaf \
  --template-url https://s3.amazonaws.com/fortresswaf-cfn/templates/fwaf-single.yaml \
  --parameters ParameterKey=UpstreamURL,ParameterValue=http://my-app:3000
```

### Azure Marketplace

```bash
# Via Azure CLI
az vm image terms accept \
  --offer fortresswaf-proxy \
  --publisher fortresswaf \
  --plan enterprise

# Deploy with ARM template
az deployment group create \
  --resource-group my-rg \
  --template-uri https://arm.fortresswaf.io/templates/proxy.json \
  --parameters upstreamURL=http://my-app:3000
```

### GCP Marketplace

```bash
# Via gcloud CLI
gcloud compute instances create fortresswaf-proxy \
  --image-project fortresswaf-cloud \
  --image-family fortresswaf-proxy-1 \
  --tags fortresswaf \
  --metadata upstream-url=http://my-app:3000
```

## Ingress Controller Mode

### NGINX Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fortresswaf-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/server-snippet: |
      location / {
        proxy_pass http://fortresswaf-proxy:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      }
spec:
  tls:
    - hosts:
        - api.example.com
      secretName: tls-secret
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: fortresswaf-proxy
                port:
                  number: 8080
```

### Traefik

```yaml
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: fortresswaf
spec:
  forwardAuth:
    address: http://fortresswaf-proxy:8080/api/v1/auth
    trustForwardHeader: true
```

## Service Mesh Integration

### Istio

```yaml
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: fortresswaf
spec:
  hosts:
    - fortresswaf.prod.svc.cluster.local
  ports:
    - number: 8080
      name: http
      protocol: HTTP
  resolution: DNS
  location: MESH_INTERNAL
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: fortresswaf-require
spec:
  selector:
    matchLabels:
      app: my-app
  action: CUSTOM
  provider:
    name: fortresswaf
  rules:
    - to:
        - operation:
            ports: ["8080"]
```

### Linkerd

```yaml
apiVersion: policy.linkerd.io/v1alpha1
kind: HTTPRoute
metadata:
  name: fortresswaf
spec:
  parentRefs:
    - name: my-app
      group: policy.linkerd.io
      kind: Service
  rules:
    - filters:
        - type: RequestRedirect
          requestRedirect:
            authority: fortresswaf-proxy:8080
```

## Health Checks

```yaml
# Kubernetes liveness/readiness probes
livenessProbe:
  httpGet:
    path: /api/v1/health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /api/v1/health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Monitoring with Prometheus

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: fortresswaf
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: fortresswaf-proxy
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
```

## Backup and Restore

```bash
# Backup rules and config
tar -czf fortresswaf-backup-$(date +%Y%m%d).tar.gz /etc/fortresswaf/

# Backup PostgreSQL
pg_dump -h localhost -U fortresswaf fortresswaf > fortresswaf-db-$(date +%Y%m%d).sql

# Backup Redis
redis-cli -a $REDIS_PASSWORD SAVE
cp /data/dump.rdb redis-backup-$(date +%Y%m%d).rdb

# Restore config
tar -xzf fortresswaf-backup-20240315.tar.gz -C /

# Restore database
psql -h localhost -U fortresswaf fortresswaf < fortresswaf-db-20240315.sql
```

## Upgrade Procedure

```bash
# 1. Backup current state
tar -czf pre-upgrade-backup.tar.gz /etc/fortresswaf/
pg_dump fortresswaf > pre-upgrade-db.sql

# 2. Pull new images
docker compose pull

# 3. Rolling update (Docker Compose)
docker compose up -d --no-deps --scale proxy=2 proxy

# 4. Verify health
for i in $(seq 1 10); do
  if curl -sf http://localhost:8080/api/v1/health; then
    echo "Upgrade successful"
    break
  fi
  sleep 2
done

# 5. Scale down old (if using blue/green)
docker compose up -d --no-deps --scale proxy=3 proxy
```

## Security Hardening

```bash
# Run as non-root user
useradd -r -s /bin/false fortresswaf
chown -R fortresswaf:fortresswaf /etc/fortresswaf /var/log/fortresswaf

# SELinux (RHEL/CentOS)
semanage port -a -t http_port_t -p tcp 8080
setsebool -P httpd_can_network_connect on

# AppArmor (Ubuntu/Debian)
apt install apparmor-utils
aa-enforce /etc/apparmor.d/usr.local.bin.fortresswaf

# Kernel hardening
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.somaxconn=65535
```
