# Development Setup Guide

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

## Prerequisites

- Go 1.25+
- Node.js 20+ (for dashboard)
- Python 3.12+ (for ML engine)
- Docker 24+ (optional, for containerized development)
- Make

## Repository Structure

```
fortresswaf/
├── cmd/
│   ├── proxy/          # Main WAF proxy binary
│   └── ctl/            # CLI management tool (fortressctl)
├── internal/
│   ├── api/            # REST API server and handlers
│   ├── config/         # YAML configuration loading and hot-reload
│   ├── engine/         # Detection engine (18 inspectors)
│   ├── geo/            # GeoIP lookups (MaxMind)
│   ├── ml/             # ML sidecar client
│   ├── ratelimit/      # Rate limiting algorithms
│   ├── reputation/     # IP reputation checks
│   ├── rules/          # Rule DSL engine
│   ├── session/        # Session management
│   ├── siem/           # SIEM event export
│   └── tenant/         # Multi-tenant support
├── dashboard/          # Next.js management UI
├── ml-engine/          # Python ML sidecar
├── deploy/             # Deployment configurations
├── docs/               # Documentation (MkDocs)
├── tests/              # Test suites
└── rules/              # Default rule sets
```

## Local Development

### 1. Clone and Build

```bash
git clone https://github.com/FortressWAF/FortressWAF.git
cd FortressWAF

# Build all Go binaries
make build

# Verify compilation
go vet ./...
```

### 2. Run Unit Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests
make test-integration

# With race detection
go test ./... -race -count=1
```

### 3. Dashboard Development

```bash
cd dashboard
npm install
npm run dev  # Starts Next.js dev server on :3000
```

The dashboard proxies API requests to the proxy admin server (`:8443` by default).

### 4. ML Engine Development

```bash
cd ml-engine
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

### 5. Documentation

```bash
cd docs
mkdocs serve  # Serves on http://localhost:8000
```

## Development Workflow

### Branch Strategy

- `main` — stable, release-ready
- `fix/*` — bug fixes
- `feature/*` — new features

### Commit Messages

Follow conventional commits:
```
feat: add new inspector
fix: correct SQLi false positive
docs: update configuration reference
test: add e2e coverage for pipeline
chore: update dependencies
```

### Code Style

- **Go**: `go fmt ./...` before committing. The project uses `.golangci.yml` for linting rules.
- **TypeScript**: ESLint + Prettier (via Next.js config).
- **Python**: Ruff for linting and formatting.

### Pre-commit Hooks

```bash
make install-hooks
```

Runs: trailing whitespace, YAML/JSON/TOML validation, golangci-lint, ruff, prettier, markdownlint, detect-secrets.

## Testing Guidelines

### Unit Tests

- Package: `tests/unit/`
- Table-driven tests preferred
- Each inspector should have initialization + no-panic tests
- Use `newTestRequest()` and `newTestContext()` helpers

### Integration Tests

- Package: `tests/integration/`
- Test real HTTP interactions with `httptest`
- Cover TLS, ACME, OCSP scenarios

### E2E Tests

- Package: `tests/e2e/`
- Tagged with `//go:build e2e`
- Test full detection pipeline with attack corpus
- Verify scoring and decision outputs

### Attack Corpus

Located in `tests/attack-corpus/`, these files contain known attack payloads:

| File | Attack Type | Payloads |
|------|-------------|----------|
| `sqli.txt` | SQL Injection | 65 |
| `sqli-advanced.txt` | Advanced SQLi | 1572 |
| `xss.txt` | Cross-Site Scripting | 61 |
| `rce.txt` | Remote Code Execution | 38 |
| `lfi.txt` | Local File Inclusion | 30 |
| `ssrf.txt` | Server-Side Request Forgery | 21 |
| `bots.txt` | Malicious Bot User-Agents | 37 |
| `scanners.txt` | Security Scanner User-Agents | 27 |
| `valid.txt` | Benign Requests | Various |

## Adding a New Inspector

1. Create a new file in `internal/engine/` implementing the `Inspector` interface:

```go
type MyInspector struct {}

func (m *MyInspector) Name() string { return "my_inspector" }

func (m *MyInspector) Inspect(ctx *engine.RequestContext) (*engine.Decision, error) {
    // Inspection logic
    return &engine.Decision{
        Action:   engine.ActionBlock,
        RuleID:   "MY-001",
        Severity: "high",
        Score:    90,
    }, nil
}
```

2. Add the inspector to `EngineConfig` and `Engine` struct in `engine.go`
3. Wire it in `cmd/proxy/main.go` `buildEngineConfig()`
4. Add unit tests in `tests/unit/`
5. Add attack corpus payloads if applicable

## Configuration

See [Configuration Reference](configuration.md) for all YAML fields.

The config file supports environment variable expansion:
```yaml
db:
  dsn: "${DB_DSN:-postgres://localhost:5432/fortresswaf}"
```
