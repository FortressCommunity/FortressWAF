# Ansible Deployment

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF can be deployed and managed using Ansible for configuration management and automation.

## Ansible Role: fortresswaf.fortresswaf

### Role Structure

```
roles/fortresswaf/
├── defaults/
│   └── main.yml
├── tasks/
│   ├── main.yml
│   ├── install.yml
│   ├── configure.yml
│   └── service.yml
├── handlers/
│   └── main.yml
├── templates/
│   └── config.yaml.j2
├── vars/
│   └── main.yml
└── molecule/
    └── default/
```

### Installation

```bash
# Install via Ansible Galaxy
ansible-galaxy collection install fortresswaf.fortresswaf

# Or install role directly
ansible-galaxy role install fortresswaf.fortresswaf
```

## Quick Start

### Inventory

```ini
# inventory.ini
[fortresswaf]
waf-server-01 ansible_host=10.0.0.10
waf-server-02 ansible_host=10.0.0.11
waf-server-03 ansible_host=10.0.0.12

[fortresswaf:vars]
ansible_user=ubuntu
ansible_python_interpreter=/usr/bin/python3
```

### Playbook

```yaml
# site.yml
- name: Deploy FortressWAF
  hosts: fortresswaf
  become: yes
  vars:
    fortresswaf_version: "2.0.0"
    fortresswaf_admin_password: "{{ vault_fw_admin_password }}"

  roles:
    - fortresswaf.fortresswaf

  tasks:
    - name: Create sites
      fortresswaf_site:
        name: "{{ item.name }}"
        domain: "{{ item.domain }}"
        backend_url: "{{ item.backend }}"
        state: present
      loop:
        - { name: "webapp", domain: "app.example.com", backend: "http://10.0.1.10:8080" }
        - { name: "api", domain: "api.example.com", backend: "http://10.0.1.11:8080" }
```

## Role Variables

### Default Variables

```yaml
# defaults/main.yml

# Installation
fortresswaf_version: "2.0.0"
fortresswaf_install_dir: "/opt/fortresswaf"
fortresswaf_user: fortresswaf
fortresswaf_group: fortresswaf

# Service configuration
fortresswaf_service_name: fortresswaf
fortresswaf_service_state: started
fortresswaf_service_enabled: yes

# Ports
fortresswaf_dashboard_port: 8443
fortresswaf_api_port: 8444
fortresswaf_proxy_port: 8080

# Database
fortresswaf_postgres_host: localhost
fortresswaf_postgres_port: 5432
fortresswaf_postgres_db: fortresswaf
fortresswaf_postgres_user: fortresswaf
fortresswaf_postgres_password: ""

# Redis
fortresswaf_redis_host: localhost
fortresswaf_redis_port: 6379
fortresswaf_redis_password: ""

# TLS
fortresswaf_tls_enabled: true
fortresswaf_tls_cert_path: ""
fortresswaf_tls_key_path: ""

# ML Engine
fortresswaf_ml_enabled: true

# Logging
fortresswaf_log_level: info
fortresswaf_log_format: json
```

### Required Variables

```yaml
# Required for production
fortresswaf_admin_password: ""  # Must be set (use vault)
fortresswaf_api_key: ""  # Must be set (use vault)
fortresswaf_postgres_password: ""  # Must be set (use vault)
```

## Playbook Examples

### Basic Installation

```yaml
- name: Install FortressWAF
  hosts: fortresswaf_servers
  become: true
  vars:
    fortresswaf_version: "2.0.0"
    fortresswaf_admin_password: "{{ lookup('env', 'FW_ADMIN_PASSWORD') }}"

  roles:
    - fortresswaf.fortresswaf
```

### Full Production Setup

```yaml
- name: Production FortressWAF Deployment
  hosts: fortresswaf
  become: true
  vars:
    fortresswaf_version: "2.0.0"

    # Database configuration
    fortresswaf_postgres_host: "postgres.example.com"
    fortresswaf_postgres_port: 5432
    fortresswaf_postgres_db: fortresswaf
    fortresswaf_postgres_user: fortresswaf
    fortresswaf_postgres_password: "{{ vault_postgres_password }}"

    # Redis configuration
    fortresswaf_redis_host: "redis.example.com"
    fortresswaf_redis_port: 6379
    fortresswaf_redis_password: "{{ vault_redis_password }}"

    # TLS configuration
    fortresswaf_tls_enabled: true
    fortresswaf_tls_cert_path: "/etc/ssl/certs/fortresswaf.crt"
    fortresswaf_tls_key_path: "/etc/ssl/private/fortresswaf.key"

    # Rate limiting
    fortresswaf_rate_limit_global_rpm: 10000
    fortresswaf_rate_limit_per_ip_rpm: 100

    # ML Engine
    fortresswaf_ml_enabled: true

  roles:
    - fortresswaf.fortresswaf

  post_tasks:
    - name: Verify installation
      uri:
        url: "https://{{ inventory_hostname }}:{{ fortresswaf_dashboard_port }}/health"
        validate_certs: no
      register: health_check
      failed_when: health_check.status != 200
```

### Multi-Node Cluster

```yaml
- name: Deploy FortressWAF Cluster
  hosts: fortresswaf_cluster
  become: true
  vars:
    fortresswaf_version: "2.0.0"
    fortresswaf_cluster_enabled: true
    fortresswaf_cluster_nodes:
      - "10.0.0.10"
      - "10.0.0.11"
      - "10.0.0.12"
    fortresswaf_cluster_vip: "10.0.0.100"

  roles:
    - fortresswaf.fortresswaf
```

### With External Database

```yaml
- name: FortressWAF with External Services
  hosts: fortresswaf
  become: true
  vars:
    # Use existing PostgreSQL
    fortresswaf_postgres_host: "aws-rds-endpoint.rds.amazonaws.com"
    fortresswaf_postgres_port: 5432
    fortresswaf_postgres_db: fortresswaf
    fortresswaf_postgres_user: fortresswaf
    fortresswaf_postgres_password: "{{ vault_rds_password }}"
    fortresswaf_postgres_ssl_mode: require

    # Use existing Redis
    fortresswaf_redis_host: "redis.cache.amazonaws.com"
    fortresswaf_redis_port: 6379
    fortresswaf_redis_password: "{{ vault_elasticache_password }}"
    fortresswaf_redis_ssl: true

    # Configure connection pools
    fortresswaf_postgres_pool_size: 25
    fortresswaf_redis_pool_size: 20

  roles:
    - fortresswaf.fortresswaf
```

## Tasks

### Main Tasks File

```yaml
# tasks/main.yml
- name: Include install tasks
  include_tasks: install.yml

- name: Include configure tasks
  include_tasks: configure.yml

- name: Include service tasks
  include_tasks: service.yml
```

### Install Tasks

```yaml
# tasks/install.yml
- name: Install system dependencies
  apt:
    name:
      - curl
      - gnupg2
      - ca-certificates
      - lsb-release
    state: present
    update_cache: yes

- name: Add FortressWAF GPG key
  apt_key:
    url: "https://apt.fortresswaf.io/gpg.key"
    state: present

- name: Add FortressWAF repository
  apt_repository:
    repo: "deb https://apt.fortresswaf.io {{ ansible_distribution_release }} main"
    state: present

- name: Update apt cache
  apt:
    update_cache: yes

- name: Install FortressWAF
  apt:
    name: "fortresswaf={{ fortresswaf_version }}"
    state: present

- name: Create fortresswaf user
  user:
    name: "{{ fortresswaf_user }}"
    system: yes
    shell: /bin/false
    create_home: no

- name: Create directories
  file:
    path: "{{ item }}"
    state: directory
    owner: "{{ fortresswaf_user }}"
    group: "{{ fortresswaf_group }}"
    mode: '0750'
  loop:
    - /etc/fortresswaf
    - /var/log/fortresswaf
    - /var/lib/fortresswaf
```

### Configure Tasks

```yaml
# tasks/configure.yml
- name: Create config.yaml from template
  template:
    src: config.yaml.j2
    dest: /etc/fortresswaf/config.yaml
    owner: root
    group: "{{ fortresswaf_group }}"
    mode: '0640'
  notify: reload fortresswaf

- name: Create TLS certificates directory
  file:
    path: /etc/fortresswaf/certs
    state: directory
    owner: root
    group: root
    mode: '0755'

- name: Install TLS certificate
  copy:
    src: "{{ fortresswaf_tls_cert_path }}"
    dest: /etc/fortresswaf/certs/server.crt
    owner: root
    group: root
    mode: '0600'
  when: fortresswaf_tls_enabled|bool

- name: Install TLS private key
  copy:
    src: "{{ fortresswaf_tls_key_path }}"
    dest: /etc/fortresswaf/certs/server.key
    owner: root
    group: root
    mode: '0600'
  when: fortresswaf_tls_enabled|bool
```

### Service Tasks

```yaml
# tasks/service.yml
- name: Enable and start FortressWAF service
  systemd:
    name: "{{ fortresswaf_service_name }}"
    state: "{{ fortresswaf_service_state }}"
    enabled: "{{ fortresswaf_service_enabled }}"
    daemon_reload: yes

- name: Wait for service to be ready
  uri:
    url: "http://localhost:{{ fortresswaf_proxy_port }}/health"
    status_code: 200
  register: result
  retries: 30
  delay: 2
  until: result.status == 200
  when: fortresswaf_service_state == "started"
```

## Handlers

```yaml
# handlers/main.yml
- name: reload fortresswaf
  systemd:
    name: "{{ fortresswaf_service_name }}"
    state: reloaded

- name: restart fortresswaf
  systemd:
    name: "{{ fortresswaf_service_name }}"
    state: restarted

- name: stop fortresswaf
  systemd:
    name: "{{ fortresswaf_service_name }}"
    state: stopped
```

## Configuration Template

```yaml
# templates/config.yaml.j2
server:
  host: 0.0.0.0
  port: {{ fortresswaf_dashboard_port }}
  api_port: {{ fortresswaf_api_port }}
  tls:
    enabled: {{ fortresswaf_tls_enabled }}
    cert_path: /etc/fortresswaf/certs/server.crt
    key_path: /etc/fortresswaf/certs/server.key
    min_version: "1.2"

logging:
  level: {{ fortresswaf_log_level }}
  format: {{ fortresswaf_log_format }}

redis:
  host: {{ fortresswaf_redis_host }}
  port: {{ fortresswaf_redis_port }}
  password: {{ fortresswaf_redis_password }}
  ssl: {{ fortresswaf_redis_ssl | default(false) }}

database:
  host: {{ fortresswaf_postgres_host }}
  port: {{ fortresswaf_postgres_port }}
  name: {{ fortresswaf_postgres_db }}
  user: {{ fortresswaf_postgres_user }}
  password: {{ fortresswaf_postgres_password }}
  ssl_mode: {{ fortresswaf_postgres_ssl_mode | default('prefer') }}

ml:
  enabled: {{ fortresswaf_ml_enabled }}

rate_limiting:
  enabled: true
  global:
    requests_per_minute: {{ fortresswaf_rate_limit_global_rpm | default(10000) }}
  per_ip:
    requests_per_minute: {{ fortresswaf_rate_limit_per_ip_rpm | default(100) }}
```

## Idempotence

The role is designed to be idempotent:

- Package installation is idempotent (apt handles this)
- Configuration changes only happen if needed
- Service restart only happens on config changes (via handlers)
- User/group creation is idempotent

### Verification

```bash
# Run playbook multiple times - second run should show "changed": 0 for most tasks
ansible-playbook -i inventory site.yml
```

## Vault Integration

```yaml
# vault.yml (encrypted)
$ANSIBLE_VAULT;1.1;AES256
616263313233...  # Encrypted content

# playbook.yml
- name: Deploy with vault
  hosts: fortresswaf
  vars_files:
    - vault.yml
  roles:
    - fortresswaf.fortresswaf
```

```bash
# Run with vault password
ansible-playbook -i inventory site.yml --vault-id @prompt
```

## Complete Example

```yaml
# production.yml
- name: Production FortressWAF Deployment
  hosts: production_fortresswaf
  become: true
  environment:
    http_proxy: "{{ proxy_env.http_proxy | default('') }}"
    https_proxy: "{{ proxy_env.https_proxy | default('') }}"
    no_proxy: "{{ proxy_env.no_proxy | default('') }}"

  vars:
    fortresswaf_version: "2.0.0"
    fortresswaf_dashboard_port: 8443
    fortresswaf_api_port: 8444

    # From vault
    fortresswaf_admin_password: "{{ vault_fw_admin_password }}"
    fortresswaf_api_key: "{{ vault_fw_api_key }}"
    fortresswaf_postgres_password: "{{ vault_postgres_password }}"
    fortresswaf_redis_password: "{{ vault_redis_password }}"

    # Database
    fortresswaf_postgres_host: "postgres.internal"
    fortresswaf_postgres_port: 5432
    fortresswaf_postgres_db: fortresswaf
    fortresswaf_postgres_user: fortresswaf
    fortresswaf_postgres_ssl_mode: require

    # Redis
    fortresswaf_redis_host: "redis.internal"
    fortresswaf_redis_port: 6379
    fortresswaf_redis_ssl: true

    # TLS
    fortresswaf_tls_enabled: true
    fortresswaf_tls_cert_path: "/etc/ssl/certs/fortresswaf.crt"
    fortresswaf_tls_key_path: "/etc/ssl/private/fortresswaf.key"

    # ML
    fortresswaf_ml_enabled: true

    # Rate limiting
    fortresswaf_rate_limit_global_rpm: 10000
    fortresswaf_rate_limit_per_ip_rpm: 100

  roles:
    - fortresswaf.fortresswaf

  post_tasks:
    - name: Verify health
      uri:
        url: "https://{{ inventory_hostname }}:{{ fortresswaf_dashboard_port }}/health"
        validate_certs: no
        method: GET
      register: health
      failed_when: health.status != 200

    - name: Get admin token
      uri:
        url: "https://{{ inventory_hostname }}:{{ fortresswaf_api_port }}/api/v1/auth/login"
        validate_certs: no
        method: POST
        body_format: json
        body:
          username: admin
          password: "{{ fortresswaf_admin_password }}"
      register: auth

    - name: Create first site
      fortresswaf_site:
        api_url: "https://{{ inventory_hostname }}:{{ fortresswaf_api_port }}"
        api_key: "{{ fortresswaf_api_key }}"
        name: "production-app"
        domain: "app.example.com"
        backend_url: "http://10.0.1.10:8080"
      delegate_to: localhost
```
