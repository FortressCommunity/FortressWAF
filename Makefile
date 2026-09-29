SHELL := /bin/bash
GO ?= go
GOFLAGS ?= -ldflags="-s -w"
BIN_DIR := bin
COVERAGE_DIR := coverage

# Build metadata
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags="-s -w -X 'github.com/FortressWAF/FortressWAF/internal/version.Version=$(VERSION)' -X 'github.com/FortressWAF/FortressWAF/internal/version.Commit=$(COMMIT)' -X 'github.com/FortressWAF/FortressWAF/internal/version.BuildDate=$(BUILD_DATE)'"

.PHONY: help dev dev-down dev-logs build build-all test lint lint-go lint-py lint-ts clean docker-build docker-up docker-down docker-logs deploy restart-caddy release install uninstall coverage bench profile format generate docs

help: ## Display this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

dev: ## Start development environment (same stack as production)
	cd deploy && docker compose up -d --build

dev-down: ## Stop development environment
	cd deploy && docker compose down

dev-logs: ## View development logs
	cd deploy && docker compose logs -f

build: ## Build all Go binaries
	@mkdir -p $(BIN_DIR)
	$(GO) build $(LDFLAGS) -o $(BIN_DIR)/fortresswaf ./cmd/proxy
	$(GO) build $(LDFLAGS) -o $(BIN_DIR)/fortressctl ./cmd/ctl
	@echo "Binaries built in $(BIN_DIR)/"

build-all: build ## Build for all platforms
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/fortresswaf-linux-amd64 ./cmd/proxy
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/fortresswaf-linux-arm64 ./cmd/proxy
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/fortresswaf-darwin-amd64 ./cmd/proxy
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/fortresswaf-darwin-arm64 ./cmd/proxy
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BIN_DIR)/fortresswaf-windows-amd64.exe ./cmd/proxy
	@echo "Cross-compiled binaries in $(BIN_DIR)/"

test: ## Run all tests
	$(GO) test ./... -v -race -count=1 -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic
	$(GO) tool cover -func=$(COVERAGE_DIR)/coverage.out | tail -1

test-unit: ## Run unit tests only
	$(GO) test ./internal/... -v -race -count=1 -coverprofile=$(COVERAGE_DIR)/unit.out

test-integration: ## Run integration tests
	$(GO) test -tags=integration ./tests/... -v -count=1 -coverprofile=$(COVERAGE_DIR)/integration.out

train-ml: ## Train ML models with attack corpus
	cd ml-engine && pip install -r requirements.txt && python -m training.train --data-dir training/data

test-ml: ## Run ML engine tests
	cd ml-engine && pip install -r requirements-dev.txt && python -m pytest test_api.py -v

test-dashboard: ## Run dashboard tests
	cd dashboard && npm test -- --watchAll=false

test-e2e: ## Run end-to-end tests
	$(GO) test -tags=e2e ./tests/e2e/... -v -count=1

lint: lint-go lint-py lint-ts lint-docker lint-yaml lint-markdown ## Run all linters

lint-go: ## Run Go linter
	golangci-lint run ./... --timeout=5m --out-format=colored-line-number

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

coverage: ## Generate coverage report
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test ./... -coverprofile=$(COVERAGE_DIR)/coverage.out -covermode=atomic
	$(GO) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(GO) tool cover -func=$(COVERAGE_DIR)/coverage.out
	@echo "Coverage report: $(COVERAGE_DIR)/coverage.html"

bench: ## Run benchmarks
	$(GO) test ./... -bench=. -benchmem -run=^$$ -count=3 | tee $(COVERAGE_DIR)/benchmark.txt

profile: ## Run CPU profile
	@mkdir -p $(COVERAGE_DIR)
	$(GO) test ./internal/engine -bench=BenchmarkRuleEngine -cpuprofile=$(COVERAGE_DIR)/cpu.prof -memprofile=$(COVERAGE_DIR)/mem.prof
	@echo "Profiles saved to $(COVERAGE_DIR)/"

clean: ## Clean build artifacts
	rm -rf $(BIN_DIR)/
	rm -rf $(COVERAGE_DIR)/
	rm -f *.out *.test *.prof
	$(GO) clean -cache -testcache
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
	$(GO) fmt ./...
	ruff format ml-engine/
	cd dashboard && npx prettier --write "src/**/*.{ts,tsx,js,jsx,json,css,scss}"

generate: ## Generate code
	$(GO) generate ./...

docs: ## Start documentation server
	cd docs && mkdocs serve

docs-build: ## Build documentation site
	cd docs && mkdocs build --strict

install: build ## Install binaries to system
	sudo cp $(BIN_DIR)/fortresswaf /usr/local/bin/
	sudo cp $(BIN_DIR)/fortressctl /usr/local/bin/
	sudo mkdir -p /etc/fortresswaf/rules
	@echo "Installed to /usr/local/bin/"

uninstall: ## Remove installed binaries
	sudo rm -f /usr/local/bin/fortresswaf
	sudo rm -f /usr/local/bin/fortressctl
	@echo "Uninstalled"

dist: build-all ## Create release archives
	@mkdir -p dist
	@for os in linux darwin windows; do \
		for arch in amd64 arm64; do \
			ext=""; \
			[ "$$os" = "windows" ] && ext=".exe"; \
			bin="fortresswaf-$$os-$$arch$$ext"; \
			dir="fortresswaf-$$VERSION-$$os-$$arch"; \
			mkdir -p dist/$$dir; \
			cp $(BIN_DIR)/$$bin dist/$$dir/fortresswaf$$ext; \
			cp deploy/config.yaml dist/$$dir/; \
			cp LICENSE dist/$$dir/; \
			cd dist && tar czf $$dir.tar.gz $$dir && rm -rf $$dir && cd ..; \
		done; \
	done
	cp $(BIN_DIR)/fortresswaf-linux-amd64 dist/fortresswaf-linux-amd64
	@echo "Release archives in dist/"

release: lint test docker-build ## Prepare release
	@echo "Release checks passed for v$(VERSION)"

security-scan: ## Run security scans
	trivy image fortresswaf/proxy:latest --severity CRITICAL,HIGH --exit-code 1
	govulncheck ./...
	cd ml-engine && pip-audit
	cd dashboard && npm audit

vulncheck: ## Check for known vulnerabilities
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

# Dependency management
dep-update: ## Update Go dependencies
	$(GO) get -u ./...
	$(GO) mod tidy

dep-audit: ## Audit dependencies
	$(GO) list -m -u all 2>/dev/null | grep '\['
	cd ml-engine && pip list --outdated
	cd dashboard && npm outdated

# Git hooks
install-hooks: ## Install pre-commit hooks
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Pre-commit hooks installed"

update-hooks: ## Update pre-commit hooks
	pre-commit autoupdate

run-hooks: ## Run pre-commit hooks on all files
	pre-commit run --all-files

# Compliance
compliance-report: ## Generate compliance report
	fortressctl compliance report --all --period 90d --output ./reports/

# Attack corpus validation
validate-corpus: ## Validate attack corpus files
	@echo "Validating attack corpus..."
	@for f in tests/attack-corpus/*.txt; do \
		lines=$$(wc -l < "$$f"); \
		echo "  $$f: $$lines lines"; \
	done
	@echo "Corpus validated"
