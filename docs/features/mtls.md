# mTLS Client Certificate Authentication

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF supports mutual TLS (mTLS) authentication to verify client identity using X.509 certificates.

## Configuration

```yaml
mtls:
  enabled: true
  ca_file: "/etc/fortresswaf/ca.pem"
  client_auth: "require-and-verify-client-cert"  # or "require-any-client-cert", "no-client-certs"
  skip_verify: false            # Skip certificate chain verification
  policy_oid: ""                 # Required certificate policy OID
  verify_depth: 5               # Maximum certificate chain depth
  fail_on_error: true           # Block if connection info unavailable
  early_auth: true              # Authenticate before processing request
  username_header: "X-Client-Cert-User"  # Header injected with cert subject
```

## Client Auth Modes

| Mode | Description |
|------|-------------|
| `no-client-certs` | mTLS disabled, only server TLS |
| `require-any-client-cert` | Accept any valid client cert |
| `require-and-verify-client-cert` | Require + verify against CA |

## Certificate Validation

### Chain Verification

Validates the certificate chain up to `verify_depth` levels against the configured CA certificate.

### Policy OID Checking

When `policy_oid` is set, FortressWAF validates that the client certificate contains the required policy extension (OID `2.5.29.32`).

### Certificate Information

Extracted client certificate info is available for logging and inspection:

| Field | Description |
|-------|-------------|
| Subject | Distinguished name (e.g. `CN=client.example.com`) |
| Issuer | CA distinguished name |
| NotBefore | Certificate validity start |
| NotAfter | Certificate validity end |
| SerialNumber | Certificate serial number |

## Header Injection

When `username_header` is configured, FortressWAF injects the certificate subject into the upstream request headers:

```http
X-Client-Cert-User: CN=client.example.com,O=Example Corp,C=US
```

## Inspection Pipeline

mTLS inspection runs early in the pipeline (before other security checks):

1. Extract TLS connection from request context
2. Validate peer certificates against CA
3. Check policy OID (if configured)
4. Inject certificate info into headers (if configured)
5. Block or allow based on validation result

## Example: Production Configuration

```yaml
mtls:
  enabled: true
  ca_file: "/etc/fortresswaf/ca/ca-cert.pem"
  client_auth: "require-and-verify-client-cert"
  skip_verify: false
  verify_depth: 3
  fail_on_error: true
  username_header: "X-Client-Cert-DN"
```

## Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `MTLS-001` | No connection info | Ensure request reaches FortressWaf via TLS |
| `MTLS-002` | Connection not TLS | Configure TLS listener |
| `MTLS-003` | No client cert | Configure client to present cert |
| `MTLS-004` | Policy violation | Update cert with required policy OID |
