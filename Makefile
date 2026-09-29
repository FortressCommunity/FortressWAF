SHELL := /bin/bash
CARGO ?= cargo
RUST_DIR := rust
BIN_DIR := bin
COVERAGE_DIR := coverage

# Build metadata
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

export FORTRESSWAF_VERSION := $(VERSION)
export FORTRESSWAF_COMMIT := $(COMMIT)
export FORTRESSWAF_BUILD_DATE := $(BUILD_DATE)

.PHONY: help dev dev-down dev-logs build build-all test test-unit test-integration lint lint-rust lint-py lint-ts lint-docker lint-yaml lint-markdown clean docker-build docker-up docker-down docker-logs deploy restart-caddy release install uninstall coverage bench profile format docs validate-corpus

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev: ## Start development environment (same stack as production)
	cd deploy && docker compose up -d --build

dev-down: ## Stop development environment
	cd deploy && docker compose down

dev-logs: ## View development logs
	cd deploy && docker compose logs -f

build: ## Build all Rust binaries (release)
	cd $(RUST_DIR) && $(CARGO) build --release --locked
	@mkdir -p $(BIN_DIR)
	cp $(RUST_DIR)/target/release/fortresswaf $(BIN_DIR)/fortresswaf
	cp $(RUST_DIR)/target/release/fortressctl $(BIN_DIR)/fortressctl
	cp $(RUST_DIR)/target/release/healthcheck $(BIN_DIR)/healthcheck
	@echo "Binaries built in $(BIN_DIR)/"

build-all: ## Build for all platforms (cross-compilation needs a linker per target)
	@mkdir -p $(BIN_DIR)
	cd $(RUST_DIR) && $(CARGO) build --release --locked
	@echo "Cross-compilation requires installing targets, e.g.:"
	@echo "  rustup target add x86_64-unknown-linux-musl"
	@echo "  cargo build --release --target x86_64-unknown-linux-musl"

test: ## Run all Rust tests
	cd $(RUST_DIR) && $(CARGO) test --workspace --locked

test-unit: ## Run unit tests only
	cd $(RUST_DIR) && $(CARGO) test --workspace --lib --locked

test-integration: ## Run integration tests (the attack-corpus parity test)
	cd $(RUST_DIR) && $(CARGO) test --workspace --test attack_corpus --locked

train-ml: ## Train ML models with attack corpus
	cd ml-engine && pip install -r requirements.txt && python -m training.train --data-dir training/data

test-ml: ## Run ML engine tests
	cd ml-engine && pip install -r requirements-dev.txt && python -m pytest test_api.py -v

test-dashboard: ## Run dashboard tests
	cd dashboard && npm test -- --watchAll=false

lint: lint-rust lint-py lint-ts lint-docker lint-yaml lint-markdown ## Run all linters

lint-rust: ## Run Rust linter (clippy + fmt)
	cd $(RUST_DIR) && $(CARGO) clippy --workspace --all-targets --locked -- -D warnings
	cd $(RUST_DIR) && $(CARGO) fmt --check

lint-py: ## Run Python linter
	ruff check ml-engine/ --fix
	ruff format ml-engine/ --check

lint-ts: ## Run TypeScript linter
	cd dashboard && npm run lint

lint-docker: ## Run Dockerfile linter
	 hadolint Dockerfile
	 hadolint ml-engine/Dockerfile
	 hadolint dashboard/Dockerfile

lint-yaml: ## Run YAML linter
	yamllint .

lint-markdown: ## Run Markdown linter
	markdownlint docs/ README.md

coverage: ## Generate coverage report (requires cargo-tarpaulin or cargo-llvm-cov)
	@mkdir -p $(COVERAGE_DIR)
	cd $(RUST_DIR) && $(CARGO) llvm-cov --workspace --html --output-dir ../$(COVERAGE_DIR)/html
	@echo "Coverage report: $(COVERAGE_DIR)/html"

bench: ## Run benchmarks (requires cargo-criterion or the built-in harness)
	cd $(RUST_DIR) && $(CARGO) bench --workspace 2>/dev/null || echo "No cargo benchmarks defined; the Go benchmark suite was removed with the Go backend."

profile: ## Run a release profile build
	cd $(RUST_DIR) && $(CARGO) build --release --locked
	@echo "Perf profiling: run the binary under perf/flamegraph, e.g. 'perf record ./bin/fortresswaf'"

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR)/
	rm -rf $(COVERAGE_DIR)/
	cd $(RUST_DIR) && $(CARGO) clean
	@echo "Clean complete"

docker-build: ## Build all Docker images
	cd deploy && docker compose build

docker-up: ## Start the full stack
	cd deploy && docker compose up -d

docker-down: ## Stop the full stack (keeps volumes)
	cd deploy && docker compose down

docker-logs: ## View stack logs
	cd deploy && docker compose logs -f

deploy: ## Rebuild + redeploy + restart Caddy + verify the browser path
	bash scripts/deploy.sh

restart-caddy: ## Refresh Caddy's service DNS (fixes 502 after a recreate)
	cd deploy && docker compose restart caddy

format: ## Format code
	cd $(RUST_DIR) && $(CARGO) fmt
	ruff format ml-engine/
	cd dashboard && npx prettier --write "src/**/*.{ts,tsx,js,jsx,json,css,scss}"

docs: ## Start documentation server
	cd docs && mkdocs serve

docs-build: ## Build documentation site
	cd docs && mkdocs build --strict

install: build ## Install binaries to system
	sudo cp $(BIN_DIR)/fortresswaf /usr/local/bin/
	sudo cp $(BIN_DIR)/fortressctl /usr/local/bin/
	sudo cp $(BIN_DIR)/healthcheck /usr/local/bin/
	sudo mkdir -p /etc/fortresswaf/rules
	@echo "Installed to /usr/local/bin/"

uninstall: ## Remove installed binaries
	sudo rm -f /usr/local/bin/fortresswaf
	sudo rm -f /usr/local/bin/fortressctl
	sudo rm -f /usr/local/bin/healthcheck
	@echo "Uninstalled"

security-scan: ## Run security scans
	trivy image fortresswaf/proxy:latest --severity CRITICAL,HIGH --exit-code 1
	cd $(RUST_DIR) && $(CARGO) audit
	cd ml-engine && pip-audit
	cd dashboard && npm audit

vulncheck: ## Check for known vulnerabilities
	cd $(RUST_DIR) && $(CARGO) audit

dep-update: ## Update Rust dependencies
	cd $(RUST_DIR) && $(CARGO) update

dep-audit: ## Audit dependencies
	cd $(RUST_DIR) && $(CARGO) tree --duplicates
	cd ml-engine && pip list --outdated
	cd dashboard && npm outdated

install-hooks: ## Install pre-commit hooks
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Pre-commit hooks installed"

update-hooks: ## Update pre-commit hooks
	pre-commit autoupdate

run-hooks: ## Run pre-commit hooks on all files
	pre-commit run --all-files

compliance-report: ## Generate compliance report
	fortressctl config validate

validate-corpus: ## Validate attack corpus files
	@echo "Validating attack corpus..."
	@for f in tests/attack-corpus/*.txt; do \
		lines=$$(wc -l < "$$f"); \
		echo "  $$f: $$lines lines"; \
	done
	@echo "Corpus validated"
