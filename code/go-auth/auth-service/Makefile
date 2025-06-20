# Makefile for Go Authentication Service
# Provides common development tasks and deployment commands

# =============================================================================
# Versioning System
# =============================================================================

# Version sources (in priority order)
SEMANTIC_VERSION := $(shell test -f VERSION && cat VERSION || echo "1.0.0")
BUILD_NUMBER := $(shell test -f BUILD_NUMBER && cat BUILD_NUMBER || echo "0")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY := $(shell test -z "`git status --porcelain`" || echo "-dirty")

# Build metadata
BUILD_TIME := $(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILD_USER := $(shell whoami)
BUILD_HOST := $(shell hostname)

# Version calculation
ifeq ($(GIT_TAG),)
    # No exact tag match - use semantic version + build number + commit
    VERSION := v$(SEMANTIC_VERSION)-build.$(BUILD_NUMBER)+$(GIT_COMMIT)$(GIT_DIRTY)
else
    # Exact tag match - use git tag
    VERSION := $(GIT_TAG)$(GIT_DIRTY)
endif

# Docker and binary variables
BINARY_NAME=auth-service
DOCKER_IMAGE=auth-service
DOCKER_TAG := $(VERSION)

# Go build flags with comprehensive version info
LDFLAGS := -ldflags "\
    -X main.Version=$(VERSION) \
    -X main.BuildTime=$(BUILD_TIME) \
    -X main.GitCommit=$(GIT_COMMIT) \
    -X main.GitBranch=$(GIT_BRANCH) \
    -X main.BuildUser=$(BUILD_USER) \
    -X main.BuildHost=$(BUILD_HOST) \
    -X main.SemanticVersion=$(SEMANTIC_VERSION) \
    -X main.BuildNumber=$(BUILD_NUMBER)"

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
BLUE=\033[0;34m
PURPLE=\033[0;35m
CYAN=\033[0;36m
NC=\033[0m # No Color

.PHONY: help
help: ## Display this help message
	@echo "$(BLUE)Go Authentication Service$(NC)"
	@echo "Available commands:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# =============================================================================
# Development Commands
# =============================================================================

.PHONY: setup
setup: ## Install development dependencies
	@echo "$(YELLOW)Installing development dependencies...$(NC)"
	go mod download
	go mod verify
	@echo "$(GREEN)Dependencies installed successfully$(NC)"

.PHONY: tidy
tidy: ## Clean up go.mod and go.sum
	@echo "$(YELLOW)Tidying Go modules...$(NC)"
	go mod tidy
	@echo "$(GREEN)Go modules tidied$(NC)"

.PHONY: vendor
vendor: ## Create vendor directory
	@echo "$(YELLOW)Creating vendor directory...$(NC)"
	go mod vendor
	@echo "$(GREEN)Vendor directory created$(NC)"

.PHONY: run
run: ## Run the service locally
	@echo "$(YELLOW)Starting authentication service...$(NC)"
	go run cmd/server/main.go

.PHONY: run-dev
run-dev: ## Run the service in development mode with live reload
	@echo "$(YELLOW)Starting development server with live reload...$(NC)"
	@which air > /dev/null || (echo "$(RED)air not found. Install with: go install github.com/cosmtrek/air@latest$(NC)" && exit 1)
	air

.PHONY: build
build: ## Build the binary
	@echo "$(YELLOW)Building $(BINARY_NAME)...$(NC)"
	CGO_ENABLED=0 GOOS=linux go build ${LDFLAGS} -a -installsuffix cgo -o bin/$(BINARY_NAME) cmd/server/main.go
	@echo "$(GREEN)Binary built: bin/$(BINARY_NAME)$(NC)"

.PHONY: build-local
build-local: ## Build the binary for local OS
	@echo "$(YELLOW)Building $(BINARY_NAME) for local OS...$(NC)"
	go build ${LDFLAGS} -o bin/$(BINARY_NAME) cmd/server/main.go
	@echo "$(GREEN)Binary built: bin/$(BINARY_NAME)$(NC)"

# =============================================================================
# Versioning Commands
# =============================================================================

.PHONY: version
version: ## Show current version information
	@echo "$(CYAN)Version Information:$(NC)"
	@echo "  $(PURPLE)Full Version:$(NC)     $(VERSION)"
	@echo "  $(PURPLE)Semantic Version:$(NC) $(SEMANTIC_VERSION)"
	@echo "  $(PURPLE)Build Number:$(NC)     $(BUILD_NUMBER)"
	@echo "  $(PURPLE)Git Commit:$(NC)       $(GIT_COMMIT)"
	@echo "  $(PURPLE)Git Branch:$(NC)       $(GIT_BRANCH)"
	@echo "  $(PURPLE)Git Tag:$(NC)          $(GIT_TAG)"
	@echo "  $(PURPLE)Build Time:$(NC)       $(BUILD_TIME)"
	@echo "  $(PURPLE)Build User:$(NC)       $(BUILD_USER)"
	@echo "  $(PURPLE)Build Host:$(NC)       $(BUILD_HOST)"

.PHONY: version-bump-build
version-bump-build: ## Increment build number
	@echo "$(YELLOW)Incrementing build number...$(NC)"
	@CURRENT=$$(cat BUILD_NUMBER 2>/dev/null || echo 0); \
	NEW=$$((CURRENT + 1)); \
	echo $$NEW > BUILD_NUMBER; \
	echo "$(GREEN)Build number incremented: $$CURRENT -> $$NEW$(NC)"

.PHONY: version-bump-patch
version-bump-patch: version-bump-build ## Bump patch version (1.0.0 -> 1.0.1)
	@echo "$(YELLOW)Bumping patch version...$(NC)"
	@CURRENT=$(SEMANTIC_VERSION); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	PATCH=$$(echo $$CURRENT | cut -d. -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo $$NEW_VERSION > VERSION; \
	echo "$(GREEN)Version bumped: $$CURRENT -> $$NEW_VERSION$(NC)"

.PHONY: version-bump-minor
version-bump-minor: version-bump-build ## Bump minor version (1.0.1 -> 1.1.0)
	@echo "$(YELLOW)Bumping minor version...$(NC)"
	@CURRENT=$(SEMANTIC_VERSION); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	MINOR=$$(echo $$CURRENT | cut -d. -f2); \
	NEW_MINOR=$$((MINOR + 1)); \
	NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	echo $$NEW_VERSION > VERSION; \
	echo "$(GREEN)Version bumped: $$CURRENT -> $$NEW_VERSION$(NC)"

.PHONY: version-bump-major
version-bump-major: version-bump-build ## Bump major version (1.1.0 -> 2.0.0)
	@echo "$(YELLOW)Bumping major version...$(NC)"
	@CURRENT=$(SEMANTIC_VERSION); \
	MAJOR=$$(echo $$CURRENT | cut -d. -f1); \
	NEW_MAJOR=$$((MAJOR + 1)); \
	NEW_VERSION="$$NEW_MAJOR.0.0"; \
	echo $$NEW_VERSION > VERSION; \
	echo "$(GREEN)Version bumped: $$CURRENT -> $$NEW_VERSION$(NC)"

.PHONY: version-tag
version-tag: ## Create a Git tag for the current version
	@echo "$(YELLOW)Creating Git tag for version $(VERSION)...$(NC)"
	@if git rev-parse "v$(SEMANTIC_VERSION)" >/dev/null 2>&1; then \
		echo "$(RED)Tag v$(SEMANTIC_VERSION) already exists$(NC)"; \
		exit 1; \
	fi
	git tag -a "v$(SEMANTIC_VERSION)" -m "Release version $(SEMANTIC_VERSION)"
	@echo "$(GREEN)Git tag v$(SEMANTIC_VERSION) created$(NC)"
	@echo "$(CYAN)Push tags with: git push origin --tags$(NC)"

.PHONY: version-release
version-release: version-bump-patch version-tag ## Bump patch version and create Git tag
	@echo "$(GREEN)Release $(SEMANTIC_VERSION) ready!$(NC)"

.PHONY: version-release-minor
version-release-minor: version-bump-minor version-tag ## Bump minor version and create Git tag
	@echo "$(GREEN)Minor release $(SEMANTIC_VERSION) ready!$(NC)"

.PHONY: version-release-major
version-release-major: version-bump-major version-tag ## Bump major version and create Git tag
	@echo "$(GREEN)Major release $(SEMANTIC_VERSION) ready!$(NC)"

.PHONY: build-versioned
build-versioned: version-bump-build build ## Increment build number and build binary
	@echo "$(GREEN)Build completed with version: $(VERSION)$(NC)"

# =============================================================================
# Testing Commands
# =============================================================================

.PHONY: test
test: ## Run all tests
	@echo "$(YELLOW)Running tests...$(NC)"
	go test -v -race -coverprofile=coverage.out ./...
	@echo "$(GREEN)Tests completed$(NC)"

.PHONY: test-short
test-short: ## Run tests without integration tests
	@echo "$(YELLOW)Running unit tests...$(NC)"
	go test -v -race -short ./...
	@echo "$(GREEN)Unit tests completed$(NC)"

.PHONY: test-integration
test-integration: ## Run integration tests only
	@echo "$(YELLOW)Running integration tests...$(NC)"
	go test -v -race -run Integration ./...
	@echo "$(GREEN)Integration tests completed$(NC)"

.PHONY: test-coverage
test-coverage: test ## Generate and display test coverage
	@echo "$(YELLOW)Generating coverage report...$(NC)"
	go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)Coverage report generated: coverage.html$(NC)"

.PHONY: benchmark
benchmark: ## Run benchmarks
	@echo "$(YELLOW)Running benchmarks...$(NC)"
	go test -bench=. -benchmem ./...

# =============================================================================
# Code Quality Commands
# =============================================================================

.PHONY: lint
lint: ## Run linter
	@echo "$(YELLOW)Running linter...$(NC)"
	@which golangci-lint > /dev/null || (echo "$(RED)golangci-lint not found. Install from: https://golangci-lint.run/usage/install/$(NC)" && exit 1)
	golangci-lint run
	@echo "$(GREEN)Linting completed$(NC)"

.PHONY: fmt
fmt: ## Format code
	@echo "$(YELLOW)Formatting code...$(NC)"
	go fmt ./...
	@echo "$(GREEN)Code formatted$(NC)"

.PHONY: vet
vet: ## Run go vet
	@echo "$(YELLOW)Running go vet...$(NC)"
	go vet ./...
	@echo "$(GREEN)Vet completed$(NC)"

.PHONY: check
check: fmt vet lint test ## Run all quality checks

# =============================================================================
# Database Commands
# =============================================================================

.PHONY: db-up
db-up: ## Start PostgreSQL database using Docker
	@echo "$(YELLOW)Starting PostgreSQL database...$(NC)"
	docker run --name auth-postgres -e POSTGRES_DB=authdb -e POSTGRES_USER=authuser -e POSTGRES_PASSWORD=authpass -p 5432:5432 -d postgres:15-alpine
	@echo "$(GREEN)Database started on localhost:5432$(NC)"

.PHONY: db-down
db-down: ## Stop and remove PostgreSQL database
	@echo "$(YELLOW)Stopping PostgreSQL database...$(NC)"
	docker stop auth-postgres || true
	docker rm auth-postgres || true
	@echo "$(GREEN)Database stopped and removed$(NC)"

.PHONY: db-migrate-up
db-migrate-up: ## Run database migrations up
	@echo "$(YELLOW)Running database migrations...$(NC)"
	@which migrate > /dev/null || (echo "$(RED)migrate not found. Install from: https://github.com/golang-migrate/migrate$(NC)" && exit 1)
	migrate -path migrations -database "postgres://authuser:authpass@localhost:5432/authdb?sslmode=disable" up
	@echo "$(GREEN)Migrations completed$(NC)"

.PHONY: db-migrate-down
db-migrate-down: ## Run database migrations down
	@echo "$(YELLOW)Rolling back database migrations...$(NC)"
	migrate -path migrations -database "postgres://authuser:authpass@localhost:5432/authdb?sslmode=disable" down
	@echo "$(GREEN)Migrations rolled back$(NC)"

.PHONY: db-reset
db-reset: db-down db-up ## Reset database (stop, start, migrate)
	@echo "$(YELLOW)Waiting for database to be ready...$(NC)"
	sleep 5
	$(MAKE) db-migrate-up

# =============================================================================
# Docker Commands
# =============================================================================

.PHONY: docker-build
docker-build: version-bump-build ## Build Docker image with version information
	@echo "$(YELLOW)Building Docker image with version $(VERSION)...$(NC)"
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg GIT_BRANCH=$(GIT_BRANCH) \
		--build-arg BUILD_USER=$(BUILD_USER) \
		--build-arg BUILD_HOST=$(BUILD_HOST) \
		--build-arg SEMANTIC_VERSION=$(SEMANTIC_VERSION) \
		--build-arg BUILD_NUMBER=$(BUILD_NUMBER) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		.
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(VERSION)$(NC)"
	@echo "$(CYAN)Image also tagged as: $(DOCKER_IMAGE):latest$(NC)"

.PHONY: docker-run
docker-run: ## Run Docker container
	@echo "$(YELLOW)Running Docker container...$(NC)"
	docker run --rm -p 6910:6910 --env-file .env $(DOCKER_IMAGE):latest

.PHONY: docker-push
docker-push: docker-build ## Push Docker image to registry
	@echo "$(YELLOW)Pushing Docker image...$(NC)"
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker image pushed$(NC)"

# =============================================================================
# Docker Compose Commands
# =============================================================================

.PHONY: compose-up
compose-up: ## Start all services with docker-compose
	@echo "$(YELLOW)Starting services with docker-compose...$(NC)"
	@export VERSION=$(VERSION) BUILD_TIME="$(BUILD_TIME)" && docker compose up -d
	@echo "$(GREEN)Services started. Check status with 'make compose-status'$(NC)"

.PHONY: compose-build
compose-build: ## Build services with docker-compose
	@echo "$(YELLOW)Building services with docker-compose...$(NC)"
	@export VERSION=$(VERSION) BUILD_TIME="$(BUILD_TIME)" && docker compose build
	@echo "$(GREEN)Services built successfully$(NC)"

.PHONY: compose-up-build
compose-up-build: ## Build and start all services with docker-compose
	@echo "$(YELLOW)Building and starting services with docker-compose...$(NC)"
	@export VERSION=$(VERSION) BUILD_TIME="$(BUILD_TIME)" && docker compose up -d --build
	@echo "$(GREEN)Services built and started$(NC)"

.PHONY: compose-down
compose-down: ## Stop and remove all services
	@echo "$(YELLOW)Stopping services...$(NC)"
	@docker compose down
	@echo "$(GREEN)Services stopped$(NC)"

.PHONY: compose-down-volumes
compose-down-volumes: ## Stop services and remove volumes
	@echo "$(YELLOW)Stopping services and removing volumes...$(NC)"
	@docker compose down -v
	@echo "$(GREEN)Services stopped and volumes removed$(NC)"

.PHONY: compose-status
compose-status: ## Show status of all services
	@echo "$(BLUE)Service Status:$(NC)"
	@docker compose ps

.PHONY: compose-logs
compose-logs: ## Show logs from all services
	@docker compose logs -f

.PHONY: compose-logs-app
compose-logs-app: ## Show logs from auth-service only
	@docker compose logs -f auth-service

.PHONY: compose-restart
compose-restart: ## Restart the auth-service
	@echo "$(YELLOW)Restarting auth-service...$(NC)"
	@docker compose restart auth-service
	@echo "$(GREEN)Auth service restarted$(NC)"

.PHONY: compose-shell
compose-shell: ## Open shell in auth-service container
	@docker compose exec auth-service sh

.PHONY: compose-test
compose-test: ## Run tests in docker-compose environment
	@echo "$(YELLOW)Running tests in docker-compose environment...$(NC)"
	@export VERSION=$(VERSION) BUILD_TIME="$(BUILD_TIME)" && docker compose -f docker-compose.yml -f docker-compose.test.yml up --build --abort-on-container-exit test-runner

# =============================================================================
# Cleanup Commands
# =============================================================================

.PHONY: clean
clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	rm -rf bin/
	rm -rf vendor/
	rm -f coverage.out coverage.html
	@echo "$(GREEN)Cleanup completed$(NC)"

.PHONY: clean-docker
clean-docker: ## Clean Docker images and containers
	@echo "$(YELLOW)Cleaning Docker artifacts...$(NC)"
	docker system prune -f
	@echo "$(GREEN)Docker cleanup completed$(NC)"

# =============================================================================
# Security Commands
# =============================================================================

.PHONY: security-scan
security-scan: ## Run security vulnerability scan
	@echo "$(YELLOW)Running security scan...$(NC)"
	@which gosec > /dev/null || (echo "$(RED)gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest$(NC)" && exit 1)
	gosec ./...
	@echo "$(GREEN)Security scan completed$(NC)"

.PHONY: deps-check
deps-check: ## Check for dependency vulnerabilities
	@echo "$(YELLOW)Checking dependencies for vulnerabilities...$(NC)"
	@which govulncheck > /dev/null || (echo "$(RED)govulncheck not found. Install with: go install golang.org/x/vuln/cmd/govulncheck@latest$(NC)" && exit 1)
	govulncheck ./...
	@echo "$(GREEN)Dependency check completed$(NC)"

# =============================================================================
# Documentation Commands
# =============================================================================

.PHONY: docs
docs: ## Generate API documentation using Swagger/OpenAPI
	@echo "$(YELLOW)Generating API documentation...$(NC)"
	@which swag > /dev/null || (which ~/go/bin/swag > /dev/null) || (echo "$(RED)swag not found. Install with: go install github.com/swaggo/swag/cmd/swag@latest$(NC)" && exit 1)
	@if which swag > /dev/null; then \
		swag init -g cmd/server/main.go -o docs/ --parseInternal --parseDependency; \
	else \
		~/go/bin/swag init -g cmd/server/main.go -o docs/ --parseInternal --parseDependency; \
	fi
	@echo "$(GREEN)Swagger documentation generated in docs/$(NC)"
	@echo "$(BLUE)Files generated:$(NC)"
	@echo "  - docs/docs.go (Go definitions)"
	@echo "  - docs/swagger.json (JSON format)"
	@echo "  - docs/swagger.yaml (YAML format)"

.PHONY: docs-serve
docs-serve: docs ## Serve documentation locally with static HTTP server
	@echo "$(YELLOW)Serving documentation on http://localhost:8081$(NC)"
	@which python3 > /dev/null || (echo "$(RED)python3 not found$(NC)" && exit 1)
	cd docs && python3 -m http.server 8081

.PHONY: docs-validate
docs-validate: docs ## Validate generated OpenAPI specification
	@echo "$(YELLOW)Validating OpenAPI specification...$(NC)"
	@which swagger > /dev/null || (echo "$(YELLOW)swagger CLI not found. Install with: go install github.com/go-swagger/go-swagger/cmd/swagger@latest$(NC)" && echo "$(YELLOW)Skipping validation...$(NC)" && exit 0)
	swagger validate docs/swagger.yaml
	@echo "$(GREEN)OpenAPI specification is valid$(NC)"

# =============================================================================
# Installation Commands
# =============================================================================

.PHONY: install
install: build ## Install binary to $GOPATH/bin
	@echo "$(YELLOW)Installing $(BINARY_NAME)...$(NC)"
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "$(GREEN)$(BINARY_NAME) installed to $(GOPATH)/bin/$(NC)"

.PHONY: install-tools
install-tools: ## Install development tools
	@echo "$(YELLOW)Installing development tools...$(NC)"
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/swaggo/swag/cmd/swag@latest
	@echo "$(BLUE)Optional: Install swagger CLI for validation with:$(NC)"
	@echo "  go install github.com/go-swagger/go-swagger/cmd/swagger@latest"
	@echo "$(GREEN)Development tools installed$(NC)"

# =============================================================================
# Environment Commands
# =============================================================================

.PHONY: env-example
env-example: ## Copy environment example file
	@echo "$(YELLOW)Creating .env from .env.example...$(NC)"
	cp .env.example .env
	@echo "$(GREEN).env file created. Please update with your values.$(NC)"

.PHONY: env-check
env-check: ## Check required environment variables
	@echo "$(YELLOW)Checking environment variables...$(NC)"
	@./scripts/check-env.sh || echo "$(RED)Some environment variables are missing$(NC)"

# =============================================================================
# Information Commands
# =============================================================================

.PHONY: status
status: ## Show service status and health
	@echo "$(YELLOW)Checking service status...$(NC)"
	@curl -s http://localhost:6910/health | jq '.' || echo "$(RED)Service not running or not responding$(NC)"
