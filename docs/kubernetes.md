# Kubernetes Deployment

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF includes a Helm chart for Kubernetes deployments. This guide covers deployment scenarios including high availability, auto-scaling, and integration with service meshes.

## Prerequisites

Before deploying FortressWAF on Kubernetes, ensure you have:

| Requirement | Version | Notes |
|-------------|---------|-------|
| Kubernetes | 1.24+ | EKS, GKE, AKS, K3s supported |
| Helm | 3.10+ | Required for chart installation |
| Ingress Controller | Any | nginx-ingress, Traefik, Istio Gateway |
| cert-manager | 1.11+ | For TLS certificate management |
| Metrics Server | Latest | For HPA autoscaling |

### Kubernetes Cluster Requirements

| Component | Requirement |
|-----------|-------------|
| Worker Nodes | 3+ nodes recommended for HA |
| Node Type | m5.large or equivalent |
| Storage | 50Gi per node for log persistence |
| Network | CNI plugin required (Calico, Cilium, Weave) |

## Helm Chart Installation

### Step 1: Add the FortressWAF Helm Repository

```bash
# Add the repository
helm repo add fortresswaf https://charts.fortresswaf.io
helm repo update

# Verify the chart is available
helm search repo fortresswaf
# NAME                    CHART VERSION   APP VERSION
# fortresswaf/fortresswaf 2.0.0           2.0.0
```

### Step 2: Create a Namespace

```bash
kubectl create namespace fortresswaf
kubectl label namespace fortresswaf istio-injection=enabled
```

### Step 3: Create Kubernetes Secrets

```bash
# Create a secret for admin credentials
kubectl create secret generic fortresswaf-credentials \
  --from-literal=admin-password=$(openssl rand -base64 32) \
  --from-literal=api-key=$(openssl rand -hex 32) \
  --namespace=fortresswaf

# Create a TLS secret for the dashboard
kubectl create secret tls fortresswaf-tls \
  --cert=/path/to/tls.crt \
  --key=/path/to/tls.key \
  --namespace=fortresswaf

# Create a secret for PostgreSQL
kubectl create secret generic fortresswaf-postgres \
  --from-literal=password=$(openssl rand -base64 32) \
  --namespace=fortresswaf

# Create a secret for Redis
kubectl create secret generic fortresswaf-redis \
  --from-literal=password=$(openssl rand -base64 32) \
  --namespace=fortresswaf
```

### Step 4: Create Values File

Create a `values.yaml` with your configuration:

```yaml
# values.yaml - Production Configuration

replicaCount: 3

image:
  repository: fortresswaf/fortresswaf
  tag: "2.0.0"
  pullPolicy: IfNotPresent
  pullSecrets:
    - name: fortresswaf-registry

service:
  type: ClusterIP
  ports:
    dashboard: 8443
    api: 8444
    proxy: 8080
    metrics: 9090

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "60"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "60"
  hosts:
    - host: waf.example.com
      paths:
        - path: /
          pathType: Prefix
          service: dashboard
          port: 8443
    - host: api.example.com
      paths:
        - path: /
          pathType: Prefix
          service: api
          port: 8444
  tls:
    - secretName: fortresswaf-tls
      hosts:
        - waf.example.com
        - api.example.com

resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 1000m
    memory: 2Gi

persistence:
  enabled: true
  storageClass: "gp3"
  size: 50Gi
  accessMode: ReadWriteOnce

# High Availability Configuration
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80

podDisruptionBudget:
  enabled: true
  minAvailable: 2
  # maxUnavailable: 1

podAntiAffinity:
  enabled: true
  topologyKey: kubernetes.io/hostname
  weightedPodAffinityTerm:
    weight: 100
    podAffinityTerm:
      labelSelector:
        matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
              - fortresswaf
      topologyKey: kubernetes.io/hostname

podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"
  prometheus.io/path: "/metrics"

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
    add:
      - NET_ADMIN
      - NET_BIND_SERVICE

config:
  # Logging configuration
  logging:
    level: info
    format: json
    outputs:
      - type: file
        path: /app/logs/fortresswaf.log
      - type: stdout

  # Worker configuration
  engine:
    workers: auto
    max_request_size: 10MB
    request_timeout: 60s

  # Redis configuration
  redis:
    host: fortresswaf-redis
    port: 6379
    passwordSecretRef:
      name: fortresswaf-redis
      key: password
    ssl: true
    cluster_mode: true
    max_retries: 3
    pool_size: 20

  # PostgreSQL configuration
  database:
    host: fortresswaf-postgres
    port: 5432
    name: fortresswaf
    user: fortresswaf
    passwordSecretRef:
      name: fortresswaf-postgres
      key: password
    ssl_mode: require
    max_open_conns: 25
    max_idle_conns: 10

  # ML Engine configuration
  ml:
    enabled: true
    anomaly_threshold: 0.75
    fallback_enabled: true
    model_update_interval: 1h

  # Rate limiting
  rate_limiting:
    enabled: true
    global:
      rpm: 10000
      burst: 500
    per_ip:
      rpm: 100
      burst: 20

  # Bot detection
  bot_detection:
    enabled: true
    fingerprint_enabled: true
    headless_browser_detection: true
    captcha_threshold: 0.8

  # DDoS protection
  ddos:
    enabled: true
    http_flood_threshold: 1000
    slowloris_timeout: 30s
    slow_post_timeout: 120s

  # Audit logging
  audit:
    enabled: true
    log_blocked_requests: true
    log_suspicious_requests: true
    retention_days: 90

# External Redis (if using managed Redis)
externalRedis:
  enabled: false
  host: ""
  port: 6379
  passwordSecretRef:
    name: ""
    key: ""

# External PostgreSQL (if using managed DB)
externalPostgres:
  enabled: false
  host: ""
  port: 5432
  database: ""
  username: ""
  passwordSecretRef:
    name: ""
    key: ""

# Postgresql sub-chart configuration
postgresql:
  enabled: true
  image:
    repository: postgres
    tag: "15-alpine"
  primary:
    persistence:
      enabled: true
      storageClass: "gp3"
      size: 100Gi
    resources:
      limits:
        cpu: 1000m
        memory: 2Gi
      requests:
        cpu: 500m
        memory: 1Gi
    podSecurityContext:
      enabled: true
      runAsUser: 999
      runAsGroup: 999
    containerSecurityContext:
      enabled: true
      readOnlyRootFilesystem: true
    serviceAccount:
      create: true
    service:
      type: ClusterIP
  auth:
    database: fortresswaf
    username: fortresswaf
    passwordSecretRef:
      name: fortresswaf-postgres
      key: password
  metrics:
    enabled: true
    serviceMonitor:
      enabled: true

# Redis sub-chart configuration
redis:
  enabled: true
  image:
    repository: redis
    tag: "7-alpine"
  architecture: replication
  auth:
    enabled: true
    passwordSecretRef:
      name: fortresswaf-redis
      key: password
  primary:
    persistence:
      enabled: true
      storageClass: "gp3"
      size: 10Gi
    resources:
      limits:
        cpu: 500m
        memory: 1Gi
      requests:
        cpu: 250m
        memory: 512Mi
    podSecurityContext:
      enabled: true
      runAsUser: 999
      runAsGroup: 999
    containerSecurityContext:
      enabled: true
      readOnlyRootFilesystem: true
    serviceAccount:
      create: true
    service:
      type: ClusterIP
  replica:
    replicaCount: 2
    persistence:
      enabled: true
      storageClass: "gp3"
      size: 10Gi
    resources:
      limits:
        cpu: 500m
        memory: 1Gi
      requests:
        cpu: 250m
        memory: 512Mi
  sentinel:
    enabled: true
    quorum: 2
    masterSet: mymaster
    service:
      type: ClusterIP

# ServiceMonitor for Prometheus
serviceMonitor:
  enabled: true
  namespace: monitoring
  interval: 30s
  scrapeTimeout: 10s
  targetPort: 9090
  path: /metrics

# PodDisruptionBudget
podDisruptionBudget:
  enabled: true
  minAvailable: 2

# NetworkPolicies
networkPolicy:
  enabled: true
  allowIngress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - port: 8443
        - port: 8444
  allowEgress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: postgresql
          podSelector:
            matchLabels:
              app.kubernetes.io/name: postgresql
      ports:
        - port: 5432
    - to:
        - namespaceSelector:
            matchLabels:
              name: redis
          podSelector:
            matchLabels:
              app.kubernetes.io/name: redis
      ports:
        - port: 6379
    - to:
        - namespaceSelector: {}
      ports:
        - port: 53
        - port: 443
        - port: 80

# RBAC Configuration
rbac:
  create: true
  rules:
    - apiGroups: [""]
      resources: ["configmaps", "secrets", "services", "pods"]
      verbs: ["get", "list", "watch"]
    - apiGroups: ["networking.k8s.io"]
      resources: ["ingresses"]
      verbs: ["get", "list", "watch", "update"]
    - apiGroups: ["policy"]
      resources: ["poddisruptionbudgets"]
      verbs: ["get", "list", "watch", "create", "update"]
    - apiGroups: ["autoscaling"]
      resources: ["horizontalpodautoscalers"]
      verbs: ["get", "list", "watch", "update"]

# ServiceAccount
serviceAccount:
  create: true
  name: fortresswaf
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/fortresswaf-role
```

### Step 5: Install the Chart

```bash
# Install with the values file
helm install fortresswaf fortresswaf/fortresswaf \
  --namespace fortresswaf \
  --values values.yaml \
  --timeout 10m \
  --wait

# Install with additional CLI overrides
helm install fortresswaf fortresswaf/fortresswaf \
  --namespace fortresswaf \
  --set image.tag=2.0.0 \
  --set replicaCount=3 \
  --set resources.limits.memory=4Gi \
  --timeout 10m \
  --wait
```

### Step 6: Verify Installation

```bash
# Check pod status
kubectl get pods -n fortresswaf

# Expected output:
# NAME                                READY   STATUS    RESTARTS   AGE
# fortresswaf-0                       1/1     Running   0          5m
# fortresswaf-1                       1/1     Running   0          5m
# fortresswaf-2                       1/1     Running   0          5m
# fortresswaf-postgresql-primary-0    1/1     Running   0          5m
# fortresswaf-redis-master-0          1/1     Running   0          5m
# fortresswaf-redis-replicas-0        1/1     Running   0          5m

# Check service status
kubectl get svc -n fortresswaf

# Check ingress
kubectl get ingress -n fortresswaf

# View logs
kubectl logs -n fortresswaf deployment/fortresswaf -f
```

## High Availability Setup

### Understanding HA Architecture

FortressWAF uses a multi-tenant architecture where multiple WAF instances share state through Redis:

```
                    ┌─────────────────────────────────────────────┐
                    │              Kubernetes Cluster             │
                    │                                             │
  Internet ───────▶ │  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
                    │  │Ingress  │  │Ingress  │  │Ingress  │    │
                    │  │Controller│  │Controller│  │Controller│   │
                    │  └────┬────┘  └────┬────┘  └────┬────┘    │
                    │       │            │            │         │
                    │       └────────────┼────────────┘         │
                    │                    │                      │
                    │            ┌───────▼───────┐              │
                    │            │  FortressWAF   │              │
                    │            │   Service      │              │
                    │            └───────┬───────┘              │
                    │         ┌──────────┼──────────┐           │
                    │    ┌─────▼────┐ ┌──▼───┐ ┌────▼────┐      │
                    │    │  Pod 0   │ │Pod 1  │ │ Pod 2  │      │
                    │    └─────┬────┘ └──┬───┘ └───┬────┘      │
                    │          │         │         │            │
                    └──────────┼─────────┼─────────┼────────────┘
                               │         │         │
                    ┌──────────┼─────────┼─────────┼────────────┐
                    │          ▼         ▼         ▼             │
                    │    ┌───────────────────────────────────┐   │
                    │    │         Redis Cluster             │   │
                    │    │  ( Sentinel for Failover )        │   │
                    │    └───────────────────────────────────┘   │
                    │                                           │
                    │    ┌───────────────────────────────────┐   │
                    │    │       PostgreSQL Primary         │   │
                    │    │    (with read replicas)          │   │
                    │    └───────────────────────────────────┘   │
                    └───────────────────────────────────────────┘
```

### Pod Disruption Budget

Configure a PodDisruptionBudget to ensure availability during node maintenance:

```yaml
# Ensure at least 2 pods are always available
podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

### Horizontal Pod Autoscaler

The Helm chart includes built-in HPA configuration:

```bash
# Check HPA status
kubectl get hpa -n fortresswaf

# Manual scale test
kubectl scale deployment fortresswaf --replicas=5 -n fortresswaf

# Auto-scaling behavior
# HPA will scale between 3-10 replicas based on CPU/memory utilization
```

### Configuring Topology Spread Constraints

For even better distribution across availability zones:

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: fortresswaf
        app.kubernetes.io/component: waf
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: fortresswaf
        app.kubernetes.io/component: waf
```

## NetworkPolicy Configuration

FortressWAF includes a comprehensive NetworkPolicy to restrict traffic flow:

```yaml
# NetworkPolicy allows:
# - Ingress: Only from Ingress Controllers (nginx-ingress)
# - Egress: To PostgreSQL, Redis, DNS, HTTPS

networkPolicy:
  enabled: true
  allowIngress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
          podSelector:
            matchLabels:
              app.kubernetes.io/component: controller
      ports:
        - protocol: TCP
          port: 8443
        - protocol: TCP
          port: 8444
    - from:
        - namespaceSelector:
            matchLabels:
              name: istio-system
          podSelector:
            matchLabels:
              app.kubernetes.io/component: ingressgateway
      ports:
        - protocol: TCP
          port: 8443
        - protocol: TCP
          port: 8444
  allowEgress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: fortresswaf
          podSelector:
            matchLabels:
              app.kubernetes.io/name: postgresql
        - namespaceSelector:
            matchLabels:
              name: fortresswaf
          podSelector:
            matchLabels:
              app.kubernetes.io/name: redis
      ports:
        - protocol: TCP
          port: 5432
        - protocol: TCP
          port: 6379
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 80
```

## Service Mesh Integration

### Istio Integration

To integrate FortressWAF with Istio service mesh:

```bash
# Enable Istio injection on the namespace
kubectl label namespace fortresswaf istio-injection=enabled

# Add Istio sidecar to pods
kubectl patch deployment fortresswaf \
  -n fortresswaf \
  --type=merge \
  -p '{"spec":{"template":{"metadata":{"annotations":{"traffic.sidecar.istio.io/includeInboundPorts":"8443,8444,8080"}}}}'
```

Create an Istio Gateway and VirtualService:

```yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: fortresswaf-gateway
  namespace: fortresswaf
spec:
  selector:
    istio: ingressgateway
  servers:
    - port:
        number: 443
        name: https
        protocol: HTTPS
      tls:
        mode: ISTIO_MUTUAL
      hosts:
        - "waf.example.com"
        - "api.example.com"
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: fortresswaf-dashboard
  namespace: fortresswaf
spec:
  hosts:
    - "waf.example.com"
  gateways:
    - fortresswaf/fortresswaf-gateway
  http:
    - match:
        - uri:
            prefix: "/"
      route:
        - destination:
            host: fortresswaf.fortresswaf.svc.cluster.local
            port:
              number: 8443
---
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: fortresswaf-destination
  namespace: fortresswaf
spec:
  host: fortresswaf.fortresswaf.svc.cluster.local
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 1000
      http:
        h2UpgradePolicy: UPGRADE
        http1MaxPendingRequests: 1000
        http2MaxRequests: 1000
    loadBalancer:
      simple: LEAST_REQUEST
    tls:
      mode: ISTIO_MUTUAL
```

### Linkerd Integration

For Linkerd service mesh:

```yaml
# Add Linkerd annotations to the deployment
podAnnotations:
  linkerd.io/inject: enabled
```

## Ingress Controller Setup

### NGINX Ingress Controller

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: fortresswaf-ingress
  namespace: fortresswaf
  annotations:
    kubernetes.io/ingress.class: "nginx"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "60"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "60"
    nginx.ingress.kubernetes.io/upstream-hash-by: "$request_uri"
    nginx.ingress.kubernetes.io/affinity: "cookie"
    nginx.ingress.kubernetes.io/session-cookie-name: "fw_session"
    nginx.ingress.kubernetes.io/session-cookie-expires: "3600"
    nginx.ingress.kubernetes.io/session-cookie-hash: "sha1"
spec:
  tls:
    - hosts:
        - waf.example.com
        - api.example.com
      secretName: fortresswaf-tls
  rules:
    - host: waf.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: fortresswaf-dashboard
                port:
                  number: 8443
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: fortresswaf-api
                port:
                  number: 8444
```

## Upgrading the Helm Chart

```bash
# Check current version
helm list -n fortresswaf

# Update Helm repository
helm repo update

# List available versions
helm search repo fortresswaf/fortresswaf --versions

# Upgrade to a new version
helm upgrade fortresswaf fortresswaf/fortresswaf \
  --namespace fortresswaf \
  --values values.yaml \
  --timeout 10m \
  --wait

# Rollback to a previous version
helm rollback fortresswaf 1 -n fortresswaf

# View release history
helm history fortresswaf -n fortresswaf
```

### Upgrading from v1.x to v2.x

Version 2.0 includes breaking changes:

1. **Configuration Structure**: The `config` section has been reorganized
2. **Secret Names**: Some secret references have changed
3. **API Changes**: The REST API has been updated

Please refer to the [migration guide](https://docs.fortresswaf.io/migration/v1-to-v2/) for detailed instructions.

## Backup and Restore

### Backup

```bash
# Create a backup script
cat > /tmp/backup-fortresswaf.sh << 'EOF'
#!/bin/bash
NAMESPACE=fortresswaf
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR=/tmp/fortresswaf-backup-${BACKUP_DATE}

mkdir -p ${BACKUP_DIR}

# Backup PostgreSQL data
kubectl exec -n ${NAMESPACE} fortresswaf-postgresql-primary-0 -- \
  pg_dump -U fortresswaf -d fortresswaf > ${BACKUP_DIR}/postgres.sql

# Backup Redis data
kubectl exec -n ${NAMESPACE} fortresswaf-redis-master-0 -- \
  redis-cli -a $(kubectl get secret -n ${NAMESPACE} fortresswaf-redis -o jsonpath='{.data.password}' | base64 -d) \
  --rdb /tmp/redis.rdb
kubectl cp -n ${NAMESPACE} fortresswaf-redis-master-0:/tmp/redis.rdb ${BACKUP_DIR}/redis.rdb

# Backup configuration
kubectl get configmap -n ${NAMESPACE} fortresswaf-config -o yaml > ${BACKUP_DIR}/configmap.yaml
kubectl get secret -n ${NAMESPACE} fortresswaf-credentials -o yaml > ${BACKUP_DIR}/credentials.yaml

# Create tarball
tar -czf /tmp/fortresswaf-backup-${BACKUP_DATE}.tar.gz -C ${BACKUP_DIR} .

# Upload to S3 (optional)
# aws s3 cp /tmp/fortresswaf-backup-${BACKUP_DATE}.tar.gz s3://my-bucket/backups/

echo "Backup completed: /tmp/fortresswaf-backup-${BACKUP_DATE}.tar.gz"
EOF

chmod +x /tmp/backup-fortresswaf.sh
./tmp/backup-fortresswaf.sh
```

### Restore

```bash
# Extract backup
tar -xzf /tmp/fortresswaf-backup-YYYYMMDD_HHMMSS.tar.gz -C /tmp/fortresswaf-backup/

# Restore PostgreSQL
kubectl exec -i -n fortresswaf fortresswaf-postgresql-primary-0 -- \
  psql -U fortresswaf -d fortresswaf < /tmp/fortresswaf-backup/postgres.sql

# Restore Redis
kubectl cp /tmp/fortresswaf-backup/redis.rdb -n fortresswaf fortresswaf-redis-master-0:/tmp/redis.rdb
kubectl exec -n fortresswaf fortresswaf-redis-master-0 -- \
  redis-cli -a $(kubectl get secret -n fortresswaf fortresswaf-redis -o jsonpath='{.data.password}' | base64 -d) \
  CONFIG SET dir /data
kubectl exec -n fortresswaf fortresswaf-redis-master-0 -- \
  redis-cli -a $(kubectl get secret -n fortresswaf fortresswaf-redis -o jsonpath='{.data.password}' | base64 -d) \
  CONFIG SET dbfilename dump.rdb
kubectl exec -n fortresswaf fortresswaf-redis-master-0 -- \
  redis-cli -a $(kubectl get secret -n fortresswaf fortresswaf-redis -o jsonpath='{.data.password}' | base64 -d) \
  DEBUG RELOAD
```

## Monitoring and Alerting

### Prometheus Metrics

FortressWAF exposes the following Prometheus metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `fortresswaf_requests_total` | Counter | Total requests processed |
| `fortresswaf_requests_blocked_total` | Counter | Total blocked requests |
| `fortresswaf_latency_seconds` | Histogram | Request latency |
| `fortresswaf_active_connections` | Gauge | Current active connections |
| `fortresswaf_ml_score` | Histogram | ML anomaly scores |
| `fortresswaf_rules_evaluated` | Counter | Rules evaluated |
| `fortresswaf_bot_score` | Histogram | Bot detection scores |

### Grafana Dashboard

Import the official Grafana dashboard from `deploy/grafana/dashboards/fortresswaf.json`:

```bash
kubectl create configmap fortresswaf-grafana-dashboard \
  --from-file=fortresswaf.json=deploy/grafana/dashboards/fortresswaf.json \
  -n monitoring

# Enable dashboard provisioning in values.yaml:
grafana:
  dashboards:
    default:
      fortresswaf:
        gnetId: 12345
        revision: 1
        datasource: Prometheus
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod events
kubectl describe pod -n fortresswaf fortresswaf-0

# Check resource quotas
kubectl describe resourcequota -n fortresswaf

# Check limit ranges
kubectl describe limitrange -n fortresswaf

# Common issues:
# 1. Out of memory - increase memory limits
# 2. PVC not bound - check StorageClass
# 3. Image pull errors - check imagePullSecrets
```

### High Memory Usage

```bash
# Check actual memory usage
kubectl top pods -n fortresswaf

# If memory usage is high:
# 1. Enable compression in Redis
# 2. Reduce log verbosity
# 3. Increase worker memory allocation
```

### Connection Issues

```bash
# Test connectivity from pod
kubectl exec -it -n fortresswaf fortresswaf-0 -- /bin/bash
nc -zv fortresswaf-postgresql 5432
nc -zv fortresswaf-redis 6379

# Check DNS resolution
nslookup fortresswaf-postgresql.fortresswaf.svc.cluster.local
```
