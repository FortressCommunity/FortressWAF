> **Note:** HTTP/2 detection is implemented in TLS mode when `http2_enabled: true` is set. HTTP/3 detection is not implemented. HTTP/1.x is fully supported.

# Protocol Compliance

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF validates HTTP/1.x protocol compliance, detecting and blocking malformed requests, HTTP smuggling, and protocol-level attacks.

## Configuration

```yaml
rules:
  - id: PROTO-001
    name: HTTP Protocol Validation
    enabled: true
    severity: medium
    action: block
    phase: access
    field: request.protocol
    operator: regex
    value: "HTTP/(1\\.[01]|2)"
    params:
      strict_mode: true             # Block all non-compliant requests
      max_header_count: 100         # Maximum HTTP headers
      max_header_size: 8192         # Maximum bytes per header
      max_header_line_size: 4096    # Maximum header line length
      max_uri_length: 8192          # Maximum URI length
      allow_http10: false           # Reject HTTP/1.0
      require_host_header: true     # Require Host header
      allowed_methods:              # Strict HTTP methods
        - GET
        - HEAD
        - POST
        - PUT
        - DELETE
        - PATCH
        - OPTIONS
        - CONNECT    # Block CONNECT by default
        - TRACE      # Block TRACE by default
```

## HTTP Smuggling Detection

Detects and blocks HTTP request smuggling attacks (CL.TE, TE.CL, TE.TE):

```yaml
- id: PROTO-002
  name: HTTP Smuggling Detection
  enabled: true
  severity: critical
  action: block
  field: request.headers.content-length
  operator: regex
  value: ".*"
  params:
    check_transfer_encoding: true
    check_content_length: true
    block_malformed: true
```

### CL.TE Attack

Detects when Content-Length and Transfer-Encoding headers conflict:

```http
POST / HTTP/1.1
Host: example.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

### TE.CL Attack

Detects when front-end uses Transfer-Encoding but back-end uses Content-Length.

## HTTP Method Validation

```yaml
- id: PROTO-003
  name: HTTP Method Enforcement
  enabled: true
  severity: high
  action: block
  field: request.method
  operator: not_in
  value: "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS"
```

## Header Validation

### Header Size Limits

```yaml
params:
  max_header_count: 100         # Maximum headers
  max_header_size: 8192         # Max bytes per header value
  max_header_line_size: 4096    # Max header line (name+value)
```

### Required Headers

```yaml
- id: PROTO-004
  name: Require Host Header
  enabled: true
  severity: medium
  action: block
  field: request.headers.host
  operator: not_exists
```

## URI Validation

```yaml
params:
  max_uri_length: 8192          # Maximum URI length
  allow_encoded_slashes: false  # Block %2F in path
  allow_null_bytes: false       # Block null bytes
  allowed_schemes:              # Allowed URI schemes
    - http
    - https
```

## HTTP Version Enforcement

```yaml
- id: PROTO-005
  name: HTTP Version Check
  enabled: true
  severity: low
  action: block
  field: request.protocol
  operator: not_in
  value: "HTTP/1.1"
  params:
    allow_http10: false
```

## Compliance Checks

### HTTP/1.1 Compliance

- Request must have Host header
- Content-Length must match actual body size
- Transfer-Encoding takes precedence over Content-Length
- Chunked encoding must use valid format

### HTTP/2 Compliance

- Pseudo-headers (:method, :path, :scheme, :authority) required
- HEADERS frame must precede CONTINUATION
- Stream ID validation
- Flow control window adherence

## Example: Strict Compliance

```yaml
rules:
  - id: PROTO-001
    name: Strict HTTP Compliance
    enabled: true
    severity: high
    action: block
    field: request.protocol
    operator: regex
    value: "HTTP/.*"
    params:
      strict_mode: true
      max_header_count: 50
      max_uri_length: 4096
      require_host_header: true
      allowed_methods:
        - GET
        - POST
        - PUT
        - DELETE
        - PATCH
```

## Best Practices

- Enable strict mode in production for maximum security
- Monitor protocol errors for signs of scanning or attacks
- Allow CONNECT and TRACE methods only if specifically needed
- Set realistic header/URI limits based on your application
- Test custom limits with your application before enforcing
- Log protocol violations for security auditing
