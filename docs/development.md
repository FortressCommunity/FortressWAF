# Development Setup Guide

> **Design notes — not the source of truth.** This document describes the
> intended design. For what the code actually does today, read the
> [README](README.md) and `deploy/config.yaml`. Where they disagree, the
> README and the code win.

## Prerequisites

- Rust (stable toolchain via `rustup`)
- Node.js 20+ (for the dashboard)
- Python 3.12+ (for the ML engine)
- Docker 24+ (optional, for containerized development)
- Make

## Repository Structure

```
fortresswaf/
├── rust/
│   └── crates/
│       ├── proxy/      # WAF server: flags, admin router, TLS, hyper servers, binary
│       ├── core/       # Detection engine (all inspectors) + request model
│       ├── config/     # YAML configuration loading and hot-reload
│       ├── services/   # blocklist, compliance, geo, ml, ratelimit, reputation,
│       │               #   session, siem, sites, tenant, traincorpus, uaparse,
│       │               #   billing
│       └── ctl/        # fortressctl CLI + healthcheck probe
├── dashboard/          # Next.js management UI
├── ml-engine/          # Python ML sidecar
├── deploy/             # Deployment configurations
├── docs/               # Documentation (MkDocs)
├── tests/
│   └── attack-corpus/  # Attack payloads replayed by the parity test
└── rules/              # Default rule sets (not loaded at runtime; see README)
```

`services/` contains `billing`, `tenant`, `geo`, `ratelimit`, `reputation`, and
`session`, which compile but are **not wired into the proxy** — leftover
scaffolding, not working features.

## Local Development

### 1. Clone and Build

```bash
git clone https://github.com/FortressWAF/FortressWAF.git
cd FortressWAF

# Build all crates and the three binaries (cargo workspace under rust/)
make build          # equivalent to: cd rust && cargo build --release --locked
```

The binaries land in `rust/target/release/`: `fortresswaf` (proxy + admin API +
metrics), `fortressctl` (CLI), and `healthcheck`.

### 2. Run Tests

```bash
# All tests (unit + the attack-corpus parity test)
make test           # cd rust && cargo test --workspace --locked

# Unit tests only
make test-unit

# Integration tests (the attack-corpus parity test)
make test-integration
```

The attack-corpus test replays `ml-engine/training/data/` and
`tests/attack-corpus/valid.txt` through the engine and fails the build if any
category drops below its documented detection floor. See
[`rust/DEVIATIONS.md`](../rust/DEVIATIONS.md) for what the port wires up.

### 3. Lint and Format

```bash
make lint-rust      # cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --check
make format         # cargo fmt
```

Both `clippy` and `fmt --check` are expected to be clean; CI fails otherwise.

### 4. Run the proxy locally

```bash
./rust/target/release/fortresswaf \
    --config deploy/config.yaml --proxy-port 8080 --admin-port 8443
```

Enable TLS by setting `tls.enabled: true` with `tls.cert_file` / `tls.key_file`
(rustls). There is **no** built-in ACME path; supply certificates out of band.

### 5. Dashboard Development

```bash
cd dashboard
npm install
npm run dev  # Starts Next.js dev server on :3000
```

The dashboard proxies API requests to the proxy admin server (`:8443` by default).

### 6. ML Engine Development

```bash
cd ml-engine
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

### 7. Documentation

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

- **Rust**: `cargo fmt` before committing. Clippy must pass with `-D warnings`.
- **TypeScript**: ESLint + Prettier (via Next.js config).
- **Python**: Ruff for linting and formatting.

### Pre-commit Hooks

```bash
make install-hooks
```

Runs: trailing whitespace, YAML/JSON/TOML validation, `cargo fmt`, `cargo clippy`,
ruff, prettier, markdownlint, detect-secrets.

## Testing Guidelines

### Unit Tests

- Live in each crate under `#[cfg(test)]` modules (e.g.
  `rust/crates/core/src/inspectors/`).
- Each inspector has an initialization and no-false-positive test where relevant.
- Build a request with `RequestContext::new(HttpRequest::new(method, path))` and
  set `raw_query` / headers as needed.

### Integration Tests

- `rust/crates/proxy/tests/attack_corpus.rs` replays the real corpus.
- The corpus lives in `tests/attack-corpus/` (benign values) and
  `ml-engine/training/data/` (attack categories).

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

The detection-rate categories are read from `ml-engine/training/data/`.

## Adding a New Inspector

1. Create a file under `rust/crates/core/src/inspectors/` implementing the
   `Inspector` trait:

```rust
use crate::action::{Action, Decision};
use crate::context::RequestContext;
use crate::engine::{EngineError, Inspector};

pub struct MyInspector;

impl Inspector for MyInspector {
    fn name(&self) -> &str {
        "my_inspector"
    }

    fn inspect(&self, ctx: &mut RequestContext) -> Result<Option<Decision>, EngineError> {
        if ctx.path.contains("bad") {
            return Ok(Some(
                Decision::new(Action::Block, 90.0)
                    .with_rule_id("MY-001")
                    .with_severity("high"),
            ));
        }
        Ok(None)
    }
}
```

2. Add a field to `EngineConfig` (and to the ordered `inspectors` list in
   `Engine::new`) in `rust/crates/core/src/engine.rs`.
3. Wire it in `rust/crates/proxy/src/engine_factory.rs` `build_engine_config()`.
4. Add unit tests in the inspector's `#[cfg(test)]` module.
5. Add attack corpus payloads if applicable.

## Configuration

See [Configuration Reference](configuration.md) for all YAML fields.

The config file supports environment variable expansion:
```yaml
db:
  dsn: "${DB_DSN:-postgres://localhost:5432/fortresswaf}"
```
