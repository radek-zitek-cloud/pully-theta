# Makefile for Go Authentication Service
# Provides common development tasks and deployment commands

# Variables
BINARY_NAME=auth-service
DOCKER_IMAGE=auth-service
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "v1.0.0-dev")
BUILD_TIME=$(shell date +%Y-%m-%dT%H:%M:%S%z)
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

# Colors for output
RED=\033[0;31m
GREEN=\033[0;32m
YELLOW=\033[1;33m
BLUE=\033[0;34m
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
docker-build: ## Build Docker image
	@echo "$(YELLOW)Building Docker image...$(NC)"
	docker build -t $(DOCKER_IMAGE):$(VERSION) -t $(DOCKER_IMAGE):latest .
	@echo "$(GREEN)Docker image built: $(DOCKER_IMAGE):$(VERSION)$(NC)"

.PHONY: docker-run
docker-run: ## Run Docker container
	@echo "$(YELLOW)Running Docker container...$(NC)"
	docker run --rm -p 8080:8080 --env-file .env $(DOCKER_IMAGE):latest

.PHONY: docker-push
docker-push: docker-build ## Push Docker image to registry
	@echo "$(YELLOW)Pushing Docker image...$(NC)"
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest
	@echo "$(GREEN)Docker image pushed$(NC)"

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
docs: ## Generate API documentation
	@echo "$(YELLOW)Generating API documentation...$(NC)"
	@which swag > /dev/null || (echo "$(RED)swag not found. Install with: go install github.com/swaggo/swag/cmd/swag@latest$(NC)" && exit 1)
	swag init -g cmd/server/main.go -o docs/
	@echo "$(GREEN)Documentation generated in docs/$(NC)"

.PHONY: docs-serve
docs-serve: docs ## Serve documentation locally
	@echo "$(YELLOW)Serving documentation on http://localhost:8081$(NC)"
	@which python3 > /dev/null || (echo "$(RED)python3 not found$(NC)" && exit 1)
	cd docs && python3 -m http.server 8081

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

.PHONY: version
version: ## Show version information
	@echo "$(BLUE)Authentication Service$(NC)"
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(shell go version)"

.PHONY: status
status: ## Show service status and health
	@echo "$(YELLOW)Checking service status...$(NC)"
	@curl -s http://localhost:8080/health | jq '.' || echo "$(RED)Service not running or not responding$(NC)"
