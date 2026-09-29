# Authentication & Authorization

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](../README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

FortressWAF provides built-in JWT validation and OAuth 2.0 token introspection to protect APIs from unauthorized access.

## JWT Validation

### Configuration

Enable JWT validation in the global config:

```yaml
jwt:
  enabled: true
  jwks_url: "https://auth.example.com/.well-known/jwks.json"
  issuers:
    - "https://auth.example.com"
  audiences:
    - "api://fortresswaf"
  algorithms:
    - RS256
    - ES256
  secret: ""               # HMAC secret (for HS256)
```

### How It Works

1. Extracts the `Authorization: Bearer <token>` header
2. Decodes the JWT header to identify the algorithm and key ID (`kid`)
3. Validates standard claims (exp, nbf, iat, iss, aud)
4. Fetches JWKS keys from the configured endpoint (cached with 1h TTL)
5. Verifies the token signature against the matching JWK
6. Sets `ctx.UserID = claims.Subject` for downstream inspectors

### Claim Validation

| Claim | Validation | Configurable |
|-------|-----------|--------------|
| `exp` | Token must not be expired | Always |
| `nbf` | Token must be valid if present | Always |
| `iss` | Must match one of configured issuers | Optional |
| `aud` | Must include one configured audience | Optional |
| `alg`| Only allowed algorithms accepted | Required |

### Scope & Role Check

```rust
validator.has_scope(&claims, "admin:write");
validator.has_role(&claims, "admin");
```

## OAuth 2.0 Token Introspection

### Configuration

```yaml
oauth:
  enabled: true
  introspection_url: "https://auth.example.com/oauth/introspect"
  client_id: "fortresswaf"
  client_secret: "your-client-secret"
  token_type_hint: "access_token"
```

### How It Works

1. Extracts `Authorization: Bearer <token>` header
2. Sends token to the introspection endpoint (RFC 7662)
3. Caches results with 5-minute TTL to reduce latency
4. Blocks inactive or invalid tokens
5. Sets `ctx.UserID = info.Subject` for downstream inspectors

### Example: Protecting API Routes

When enabled, both JWT and OAuth validators run before other security checks. If a token is invalid or expired, the request is blocked immediately with score 80-90.

### Best Practices

- Use JWKS URL for production instead of static secrets
- Rotate signing keys regularly
- Combine with rate limiting for login endpoints
- Use short token lifetimes (15-60 minutes)
- Always validate `aud` claim to prevent token reuse across services
