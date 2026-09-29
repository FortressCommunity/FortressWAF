# Terraform Deployment

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides a Terraform provider for infrastructure as code deployments.

## Provider Configuration

### Required Provider Setup

```hcl
terraform {
  required_providers {
    fortresswaf = {
      source  = "fortresswaf/fortresswaf"
      version = "~> 2.0"
    }
  }
}

provider "fortresswaf" {
  # API endpoint
  api_url = "https://api.fortresswaf.io"

  # API credentials (can also use environment variable FW_API_KEY)
  api_key = var.fortresswaf_api_key
}
```

### Provider Authentication

```hcl
# Using environment variable (recommended)
# export FW_API_KEY="your-api-key"

# Or directly in configuration (not recommended for production)
provider "fortresswaf" {
  api_url = "https://api.fortresswaf.io"
  api_key = "your-api-key"
}
```

## Resources

### fortresswaf_site

Create and manage protected sites:

```hcl
resource "fortresswaf_site" "example" {
  name        = "example-production"
  domain      = "app.example.com"
  description = "Production application"

  # Backend configuration
  backend_url      = "https://internal.example.com"
  backend_host_header = "app.example.com"

  # TLS configuration
  tls_mode = "terminate"

  # Health check
  health_check_url     = "/health"
  health_check_interval = 10
  health_check_timeout  = 5

  # Tags
  tags = {
    environment = "production"
    team        = "platform"
  }
}

# Upload TLS certificate
resource "fortresswaf_certificate" "example" {
  name     = "example-com-cert"
  cert_pem = file("/path/to/cert.pem")
  key_pem  = file("/path/to/key.pem")

  # Or reference from ACM
  # arn = "arn:aws:acm:us-east-1:123456789012:certificate/xxxxx"
}

# Associate certificate with site
resource "fortresswaf_site" "example_with_tls" {
  # ... other attributes ...

  tls_mode = "terminate"
  tls_cert_id = fortresswaf_certificate.example.id
}
```

### fortresswaf_rule

Create custom security rules:

```hcl
resource "fortresswaf_rule" "block_sql_injection" {
  site_id = fortresswaf_site.example.id
  name    = "Block SQL Injection"
  description = "Blocks common SQL injection patterns"
  priority = 10
  enabled = true

  # Condition (JSON-based rule DSL)
  condition = jsonencode({
    any = [
      {
        request_query_sql_injection_score = { gt = 0.75 }
      },
      {
        request_body_sql_injection_score = { gt = 0.75 }
      },
      {
        request_query = { regex = "(?i)(union.*select|select.*from)" }
      }
    ]
  })

  # Action
  action = jsonencode({
    type   = "block"
    status = 403
    body   = "SQL injection attempt detected"
  })

  tags = {
    category = "injection"
    owasp    = "A03"
  }
}

resource "fortresswaf_rule" "protect_admin_path" {
  site_id = fortresswaf_site.example.id
  name    = "Protect Admin Path"
  priority = 5
  enabled = true

  condition = jsonencode({
    all = [
      { request_path = { prefix = "/admin" } },
      { not = { ip_match_cidr = "10.0.0.0/8" } }
    ]
  })

  action = jsonencode({
    type   = "block"
    status = 403
    body   = "Access denied"
  })
}
```

### fortresswaf_rate_limit

Configure rate limiting:

```hcl
resource "fortresswaf_rate_limit" "api_limits" {
  site_id = fortresswaf_site.example.id
  name    = "API Rate Limits"

  # Global rate limit
  global_limit {
    requests_per_minute = 10000
    burst               = 500
  }

  # Per-IP limit
  per_ip_limit {
    requests_per_minute = 100
    burst               = 20
  }
}

resource "fortresswaf_rate_limit" "login_limits" {
  site_id = fortresswaf_site.example.id
  name    = "Login Rate Limits"

  # Endpoint-specific limit
  endpoint_limit {
    path               = "/api/auth/login"
    method             = "POST"
    requests_per_minute = 5
    burst              = 2
  }
}
```

### fortresswaf_ip_list

Manage IP blocklists and allowlists:

```hcl
resource "fortresswaf_ip_list" "blocklist" {
  name        = "blocked-ips"
  description = "Manually blocked IP addresses"
  type        = "block"

  # Add individual IPs
  ips = [
    "1.2.3.4/32",
    "5.6.7.0/24",
  ]
}

resource "fortresswaf_ip_list" "allowlist" {
  name        = "trusted-ips"
  description = "Trusted IP addresses"
  type        = "allow"

  ips = [
    "10.0.0.0/8",
    "192.168.0.0/16",
  ]
}
```

### fortresswaf_api_key

Manage API keys:

```hcl
resource "fortresswaf_api_key" "cicd_key" {
  site_id = fortresswaf_site.example.id
  name    = "CI/CD Pipeline Key"
  expires_at = "2025-12-31T23:59:59Z"

  permissions = ["read", "write"]

  tags = {
    purpose = "cicd"
    team    = "devops"
  }
}

# Access the API key (only shown once)
output "api_key" {
  value     = fortresswaf_api_key.cicd_key.key
  sensitive = true
}
```

### fortresswaf_virtual_patch

Manage virtual patches:

```hcl
resource "fortresswaf_virtual_patch" "cve_2024_1234" {
  site_id    = fortresswaf_site.example.id
  name       = "CVE-2024-1234 Patch"
  cve_id     = "CVE-2024-1234"
  priority   = 1
  enabled    = true
  expires_at = "2025-01-01T00:00:00Z"

  condition = jsonencode({
    all = [
      { request_path = { prefix = "/api/vulnerable" } },
      { request_method = { in = ["GET", "POST", "PUT", "DELETE"] } },
      { request_query_sql_injection_score = { gt = 0.8 } }
    ]
  })

  action = jsonencode({
    type   = "block"
    status = 403
    body   = "Blocked by security policy CVE-2024-1234"
  })
}
```

## Data Sources

### fortresswaf_site

```hcl
data "fortresswaf_site" "by_domain" {
  domain = "app.example.com"
}

# Use the data source
resource "fortresswaf_rule" "example" {
  site_id = data.fortresswaf_site.by_domain.id
  # ...
}
```

### fortresswaf_rules

```hcl
data "fortresswaf_rules" "owasp_rules" {
  site_id = fortresswaf_site.example.id
  filter = {
    tag = "owasp"
  }
}
```

### fortresswaf_stats

```hcl
data "fortresswaf_stats" "traffic" {
  site_id = fortresswaf_site.example.id
  period  = "24h"
}

output "requests_blocked" {
  value = data.fortresswaf_stats.traffic.requests_blocked
}
```

## State Management

### Local State (Default)

```hcl
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
```

### Remote State (Production)

```hcl
terraform {
  backend "s3" {
    bucket = "my-terraform-state"
    key    = "fortresswaf/prod/terraform.tfstate"
    region = "us-east-1"
  }
}
```

### State Locking

```hcl
terraform {
  backend "s3" {
    bucket         = "my-terraform-state"
    key            = "fortresswaf/prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}
```

## Import Existing Resources

Import existing FortressWAF resources into Terraform:

```bash
# Import a site
terraform import fortresswaf_site.example site-uuid

# Import a rule
terraform import fortresswaf_rule.example rule-uuid

# Import IP list
terraform import fortresswaf_ip_list.blocklist list-uuid
```

### Import Configuration

```hcl
# Import with existing resources
resource "fortresswaf_site" "imported" {
  # Leave empty for import
}

# Then run:
# terraform import fortresswaf_site.imported <site-id>
```

## Complete Example

```hcl
terraform {
  required_providers {
    fortresswaf = {
      source  = "fortresswaf/fortresswaf"
      version = "~> 2.0"
    }
  }
}

variable "fortresswaf_api_key" {
  sensitive = true
}

provider "fortresswaf" {
  api_url = "https://api.fortresswaf.io"
  api_key = var.fortresswaf_api_key
}

# Create site
resource "fortresswaf_site" "app" {
  name        = "my-app"
  domain      = "app.example.com"
  backend_url = "https://internal.example.com"
}

# Upload certificate
resource "fortresswaf_certificate" "app" {
  name     = "app-example-com"
  cert_pem = file("cert.pem")
  key_pem  = file("key.pem")
}

# Associate certificate
resource "fortresswaf_site" "app_with_tls" {
  name        = "my-app"
  domain      = "app.example.com"
  backend_url = "https://internal.example.com"
  tls_mode    = "terminate"
  tls_cert_id = fortresswaf_certificate.app.id
}

# Create OWASP rules
resource "fortresswaf_rule" "sql_injection" {
  site_id   = fortresswaf_site.app.id
  name      = "Block SQL Injection"
  priority  = 10
  enabled   = true
  condition = jsonencode({
    any = [
      { request_query_sql_injection_score = { gt = 0.75 } },
      { request_body_sql_injection_score = { gt = 0.75 } }
    ]
  })
  action = jsonencode({
    type   = "block"
    status = 403
  })
}

resource "fortresswaf_rule" "xss" {
  site_id   = fortresswaf_site.app.id
  name      = "Block XSS"
  priority  = 10
  enabled   = true
  condition = jsonencode({
    any = [
      { request_query_xss_score = { gt = 0.8 } },
      { request_body_xss_score = { gt = 0.8 } }
    ]
  })
  action = jsonencode({
    type   = "block"
    status = 403
  })
}

# Configure rate limiting
resource "fortresswaf_rate_limit" "global" {
  site_id = fortresswaf_site.app.id
  name    = "Global Rate Limit"

  global_limit {
    requests_per_minute = 10000
    burst               = 500
  }

  per_ip_limit {
    requests_per_minute = 100
    burst               = 20
  }
}

# Block known malicious IPs
resource "fortresswaf_ip_list" "blocked" {
  name = "Blocked IPs"
  type = "block"
  ips = [
    "192.0.2.0/24",  # Example block
    "198.51.100.0/24",
  ]
}

# Create API key for CI/CD
resource "fortresswaf_api_key" "cicd" {
  site_id    = fortresswaf_site.app.id
  name       = "CI/CD Key"
  expires_at = "2025-12-31T23:59:59Z"
  permissions = ["read", "write"]
}

# Outputs
output "site_id" {
  value = fortresswaf_site.app.id
}

output "dashboard_url" {
  value = "https://${fortresswaf_site.app.domain}:8443"
}
```

## Troubleshooting

### Debug Provider

```hcl
provider "fortresswaf" {
  api_url = "https://api.fortresswaf.io"
  api_key = var.fortresswaf_api_key

  # Enable debug logging
  debug = true
}
```

### Common Issues

```bash
# Error: Invalid API key
# Solution: Verify your API key has correct permissions

# Error: Site already exists
# Solution: Import existing site with terraform import

# Error: Rate limit exceeded
# Solution: Use TF_LOG=DEBUG to see request rate limits
```
