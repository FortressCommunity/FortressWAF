> **Note:** REST API, GraphQL, gRPC, and SOAP/XML features are implemented.

# API Security Features

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides security for REST, GraphQL, and WebSocket APIs. This document details the API security capabilities and configuration options.

## API Security Overview

| API Type | Protection Level | Key Features |
|----------|------------------|--------------|
| REST | Stable | Request validation, rate limiting, OWASP coverage |
| GraphQL | Stable | Query depth limiting, field authorization, alias detection |
| gRPC | Experimental | Content-type detection, method-level rate limiting |
| WebSocket | Stable | Message validation, connection limiting |
| SOAP | Experimental | XML validation, WS-Security |

## OWASP API Top 10 Coverage

| Vulnerability | Detection Method | Prevention |
|---------------|------------------|------------|
| API1: Broken Object Level Authorization | Rule engine + ML | IDOR detection |
| API2: Broken Authentication | Rate limiting + anomaly detection | Brute force protection |
| API3: Excessive Data Exposure | Response inspection | Automatic field filtering |
| API4: Lack of Resources & Rate Limiting | Rate limiting engine | Per-endpoint limits |
| API5: Broken Function Level Authorization | Path-based rules | Privilege escalation detection |
| API6: Mass Assignment | Schema validation | Field allowlisting |
| API7: Security Misconfiguration | Configuration checks | Hardening defaults |
| API8: Injection | Rule engine + ML | SQLi, NoSQL injection protection |
| API9: Improper Assets Management | Discovery + shadow API detection | Inventory tracking |
| API10: Insufficient Logging & Monitoring | Audit logging | Full request logging |

## REST API Protection

### Request Validation

#### Schema Validation

```yaml
name: Validate JSON Request Body
description: Ensure JSON body matches expected schema
priority: 10
condition:
  all:
    - request.path: prefix "/api/"
    - request.headers.content-type: contains "application/json"
    - request.method: in ["POST", "PUT", "PATCH"]
action:
  type: validate_schema
  schema:
    type: object
    required: ["email", "password"]
    properties:
      email:
        type: string
        format: email
        maxLength: 255
      password:
        type: string
        minLength: 8
        maxLength: 128
      name:
        type: string
        maxLength: 100
      age:
        type: integer
        minimum: 0
        maximum: 150
    additionalProperties: false
```

#### Query Parameter Validation

```yaml
name: Validate Query Parameters
description: Validate query parameter types and ranges
priority: 20
condition:
  request.path: prefix "/api/users"
action:
  type: validate_query
  rules:
    - param: page
      type: integer
      min: 1
      max: 1000
    - param: limit
      type: integer
      min: 1
      max: 100
    - param: sort
      type: string
      enum: ["name", "email", "created_at"]
    - param: order
      type: string
      enum: ["asc", "desc"]
```

### Endpoint-Specific Rate Limiting

```yaml
rate_limiting:
  per_endpoint:
    - path: "/api/users"
      method: GET
      rpm: 100
      burst: 20
    - path: "/api/users"
      method: POST
      rpm: 20
      burst: 5
    - path: "/api/auth/login"
      method: POST
      rpm: 10
      burst: 3
    - path: "/api/search"
      method: GET
      rpm: 30
      burst: 10
```

### Authentication Enforcement

```yaml
name: Require Authentication
description: Block unauthenticated access to protected endpoints
priority: 5
condition:
  all:
    - request.path: prefix "/api/"
    - not request.path: prefix "/api/public"
    - not request.path: prefix "/api/auth"
    - not request.headers.authorization: exists
action:
  type: block
  status: 401
  body: |
    {"error": "authentication_required", "message": "Valid authentication credentials required"}
  headers:
    WWW-Authenticate: Bearer
```

### JWT Token Validation

```yaml
name: Validate JWT Tokens
description: Validate JWT structure and signature
priority: 5
condition:
  request.headers.authorization: exists
action:
  type: validate_jwt
  jwt:
    algorithm: RS256
    public_key_source: jwks_uri  # or static_key, jwks_endpoint
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"
    issuer: "https://auth.example.com"
    audience: "api://fortresswaf"
    validate_exp: true
    validate_nbf: true
    validate_iat: true
    leeway: 60  # seconds
```

### API Key Validation

```yaml
name: Validate API Keys
description: Validate API key format and check against database
priority: 5
condition:
  request.headers.x-api-key: exists
action:
  type: validate_api_key
  api_key:
    header_name: X-API-Key
    validate_format: true
    min_length: 32
    max_length: 64
    prefix: "fw_"  # Optional prefix requirement
    check_revoked: true
    cache_ttl: 300
```

## GraphQL Protection

GraphQL requires special handling due to its unique query structure.

### Query Depth Limiting

```yaml
name: GraphQL Query Depth Limit
description: Prevent deeply nested GraphQL queries
priority: 10
condition:
  all:
    - request.headers.content-type: contains "application/graphql"
    - request.path: contains "graphql"
action:
  type: graphql_validate
  graphql:
    max_query_depth: 10
    max_aliases: 15
    max_root_fields: 20
    max_batch_size: 10
    reject_introspection: false  # true in production
```

### Field Authorization

```yaml
name: GraphQL Field Authorization
description: Enforce field-level authorization
priority: 20
condition:
  request.path: contains "graphql"
action:
  type: graphql_validate
  field_authorization:
    # Role-based field access
    admin_only_fields:
      - users.delete
      - settings.credentials
      - audit.logs
    authenticated_fields:
      - users.profile
      - orders.history
    public_fields:
      - users.publicProfile
      - products.list
      - products.detail
```

### Query Cost Analysis

```yaml
name: GraphQL Query Cost Limit
description: Limit query complexity based on cost analysis
priority: 15
condition:
  request.path: contains "graphql"
action:
  type: graphql_validate
  cost_analysis:
    enabled: true
    max_cost: 1000
    default_field_cost: 1
    list_field_cost: 3
    nested_field_cost: 2
    multiplier: 1.5  # For lists with arguments
    depth_cost_factor: 1.2
```

### GraphQL Injection Protection

```yaml
name: GraphQL Injection Protection
description: Protect against injection attacks in GraphQL queries
priority: 10
condition:
  all:
    - request.headers.content-type: contains "application/graphql"
    - request.body: contains "query"
action:
  type: graphql_validate
  injection_protection:
    enabled: true
    # Block queries containing potentially dangerous operations
    block_dangerous_fields:
      - __schema
      - __type
      - __typename  # Only when combined with other risks
    warn_suspicious:
      - __directives
      - __苗条
```

### Batch Query Limiting

```yaml
name: GraphQL Batch Query Limit
description: Limit the number of queries in a batch
priority: 15
condition:
  request.path: contains "graphql"
action:
  type: graphql_validate
  batch:
    max_batch_size: 10
    rate_limit:
      requests_per_minute: 30
      burst: 5
```

### Mutation Rate Limiting

```yaml
name: GraphQL Mutation Rate Limit
description: Strict rate limiting for mutations
priority: 10
condition:
  all:
    - request.path: contains "graphql"
    - request.body: contains "mutation"
action:
  type: rate_limit
  rate_limit:
    requests_per_minute: 20
    burst: 5
```

## gRPC Protection

> **Status: Experimental** — Basic content-type detection and method rate limiting work, but full gRPC protocol validation (service/method resolution, message parsing, streaming control) is on the roadmap.

### Protocol Validation

```yaml
name: gRPC Protocol Validation
description: Validate gRPC requests
priority: 10
condition:
  all:
    - request.headers.content-type: contains "application/grpc"
    - request.path: prefix "/"
action:
  type: grpc_validate
  grpc:
    # Validate service and method exist
    validate_service_method: true
    allowed_services:
      - user.v1.UserService
      - order.v1.OrderService
      - payment.v1.PaymentService
    # Validate message format
    validate_message: true
    max_message_size: 4MB
    # Validate compression
    allowed_compressions:
      - gzip
      - identity
```

### gRPC Method Rate Limiting

```yaml
name: gRPC Method Rate Limiting
description: Rate limit specific gRPC methods
priority: 20
condition:
  all:
    - request.headers.content-type: contains "application/grpc"
    - request.path: ends_with "CreateUser"
action:
  type: rate_limit
  rate_limit:
    requests_per_minute: 10
    burst: 3
```

### gRPC Streaming Limits

```yaml
name: gRPC Streaming Limits
description: Limit gRPC streaming connections
priority: 15
condition:
  request.headers.content-type: contains "application/grpc"
action:
  type: grpc_validate
  streaming:
    max_concurrent_streams: 100
    max_message_size: 4MB
    connection_timeout: 30m
```

## WebSocket Protection

### Connection Limiting

```yaml
name: WebSocket Connection Limit
description: Limit WebSocket connections per IP
priority: 10
condition:
  request.headers.upgrade: contains "websocket"
action:
  type: rate_limit
  rate_limit:
    connections_per_ip: 10
    connections_per_user: 5
    connection_rate: 5  # per minute
```

### WebSocket Message Validation

```yaml
name: WebSocket Message Validation
description: Validate WebSocket message format and content
priority: 20
condition:
  request.headers.upgrade: contains "websocket"
action:
  type: websocket_validate
  message:
    max_size: 64KB
    max_messages_per_minute: 1000
    allowed_types:
      - text
      - json
    schema_validation:
      enabled: true
      message_type_field: "type"
      schemas:
        - type: "chat"
          fields:
            - name: "message"
              type: "string"
              maxLength: 1000
            - name: "room"
              type: "string"
```

### WebSocket Frame Inspection

```yaml
name: WebSocket Frame Inspection
description: Inspect WebSocket frames for attacks
priority: 15
condition:
  request.headers.upgrade: contains "websocket"
action:
  type: websocket_validate
  frame_inspection:
    enabled: true
    # Block fragmented frames that could be used for evasion
    allow_fragmented: false
    # Block ping/pong floods
    max_ping_pong_per_minute: 60
```

## Shadow API Discovery

Shadow APIs (undocumented endpoints being used) pose significant security risks.

### Shadow API Detection

```yaml
name: Shadow API Discovery
description: Detect access to undocumented APIs
priority: 30
condition:
  request.path: prefix "/api/"
action:
  type: monitor
  log_level: warning
  shadow_api:
    enabled: true
    # Compare against known OpenAPI spec
    openapi_validation: true
    # Flag new endpoints
    detect_new_endpoints: true
    # Alert on shadow usage
    alert_on_shadow: true
    # Block if strict mode enabled
    block_shadow_apis: false
```

### OpenAPI Specification Validation

```yaml
name: OpenAPI Validation
description: Validate requests against OpenAPI spec
priority: 10
condition:
  request.path: prefix "/api/"
action:
  type: openapi_validate
  openapi:
    spec_url: "https://api.example.com/openapi.json"
    validate_request: true
    validate_response: false
    strict_mode: false  # true blocks non-matching requests
    # Ignore paths not in spec
    allow_undefined_paths: true
```

## Mass Assignment Protection

Mass assignment vulnerabilities occur when client-provided data is bound to data models without proper filtering.

### Field Allowlisting

```yaml
name: Prevent Mass Assignment
description: Only allow explicitly permitted fields
priority: 25
condition:
  all:
    - request.path: prefix "/api/"
    - request.method: in ["POST", "PUT", "PATCH"]
action:
  type: validate_input
  mass_assignment:
    mode: allowlist  # "allowlist" or "blocklist"
    # Fields allowed for each endpoint
    allowlists:
      /api/users:
        POST:
          - name
          - email
          - password
        PUT:
          - name
          - email
        PATCH:
          - name
      /api/settings:
        PUT:
          - theme
          - language
          - notifications
```

### Block Dangerous Fields

```yaml
name: Block Dangerous Fields
description: Block fields that should never be user-settable
priority: 5
condition:
  all:
    - request.path: prefix "/api/"
    - request.method: in ["POST", "PUT", "PATCH"]
action:
  type: validate_input
  mass_assignment:
    mode: blocklist
    blocklists:
      - is_admin
      - is_superuser
      - role
      - permissions
      - _id
      - created_at
      - updated_at
      - deleted_at
      - password_hash
      - api_key
```

## API Fuzzing Protection

```yaml
name: Detect API Fuzzing
description: Block rapid requests with varying parameters
priority: 35
condition:
  all:
    - request.path: prefix "/api/"
    - session.api_fuzz_score: "> 0.7"
action:
  type: block
  status: 429
  body: |
    {"error": "too_many_requests", "message": "Unusual request pattern detected"}
```

### Fuzzing Pattern Detection

```python
def calculate_fuzz_score(request, session) -> float:
    features = {
        # Rapid parameter variation
        'param_variation_count': session.unique_param_combinations_recent,
        # Common fuzzing values
        'has_fuzz_value': any(v in request.query for v in [
            '<script>', ' OR 1=1', '{{7*7}}', '${jndi:',
            '<%25', '%s%s%s', '../..', 'NULL'
        ]),
        # Request rate
        'request_rate': session.requests_last_minute,
        # Error response rate
        'error_rate': session.error_responses_recent / session.total_requests_recent,
    }

    return fuzz_model.predict_proba([features])[0]
```

## API Key Management

### API Key Generation

```bash
# Generate API key via CLI
fortressctl api-keys create \
  --name "Production API Key" \
  --site-id <site-uuid> \
  --permissions "read,write" \
  --expires-at 2025-12-31

# Output:
# API Key: fw_prod_abc123...xyz789
# Secret: sk_prod_xyz789...abc123
```

### API Key Permissions

```yaml
api_key_permissions:
  read:
    - GET requests
    - HEAD requests
  write:
    - POST requests
    - PUT requests
    - PATCH requests
    - DELETE requests
  admin:
    - All operations
    - Configuration changes
    - User management
```

### API Key Rotation

```bash
# Rotate API key
fortressctl api-keys rotate \
  --key-id <key-uuid> \
  --grace-period 24h  # Old key valid for 24 hours during rotation

# Revoke API key
fortressctl api-keys revoke \
  --key-id <key-uuid>
```

## Response Data Protection

### Sensitive Data Detection

```yaml
name: Detect Sensitive Data in Responses
description: Monitor for sensitive data exposure
priority: 50
condition:
  request.path: prefix "/api/"
action:
  type: response_inspect
  sensitive_data:
    enabled: true
    detect:
      - credit_card
      - ssn
      - password
      - api_key
      - private_key
    actions:
      log: true
      mask: true
      alert: true
      block: false
```

### Response Filtering

```yaml
name: Filter Sensitive Fields
description: Remove sensitive fields from responses
priority: 100
condition:
  request.path: prefix "/api/"
action:
  type: response_filter
  filters:
    - path: "/api/users/*"
      remove_fields: ["password", "salt", "apiKey"]
    - path: "/api/settings"
      remove_fields: ["internalNotes"]
```
