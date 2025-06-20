# Makefile Targets Documentation

This document provides a comprehensive description of all Makefile targets available in the Go Authentication Service project.

## Quick Reference

To see all available targets, run:
```bash
make help
```

## Target Categories

### 🆘 Help Commands

| Target | Description |
|--------|-------------|
| `help` | Display help message with all available targets and their descriptions |

### 🚀 Development Commands

| Target | Description |
|--------|-------------|
| `setup` | Install development dependencies using `go mod download` and `go mod verify` |
| `tidy` | Clean up go.mod and go.sum files using `go mod tidy` |
| `vendor` | Create vendor directory with all dependencies |
| `run` | Run the service locally using `go run cmd/server/main.go` |
| `run-dev` | Run the service in development mode with live reload using Air (requires Air to be installed) |
| `build` | Build the binary for Linux with CGO disabled and version information embedded |
| `build-local` | Build the binary for the local operating system |

### 📋 Versioning Commands

| Target | Description |
|--------|-------------|
| `version` | Display current version information including semantic version, build number, Git metadata, and build details |
| `version-bump-build` | Increment the build number in the BUILD_NUMBER file |
| `version-bump-patch` | Bump patch version (e.g., 1.0.0 → 1.0.1) and increment build number |
| `version-bump-minor` | Bump minor version (e.g., 1.0.1 → 1.1.0) and increment build number |
| `version-bump-major` | Bump major version (e.g., 1.1.0 → 2.0.0) and increment build number |
| `version-tag` | Create a Git tag for the current semantic version |
| `version-release` | Bump patch version and create Git tag (combines version-bump-patch + version-tag) |
| `version-release-minor` | Bump minor version and create Git tag (combines version-bump-minor + version-tag) |
| `version-release-major` | Bump major version and create Git tag (combines version-bump-major + version-tag) |
| `build-versioned` | Increment build number and build binary with version information |

### 🧪 Testing Commands

| Target | Description |
|--------|-------------|
| `test` | Run all tests with race detection and generate coverage report |
| `test-short` | Run unit tests only (excludes integration tests) |
| `test-integration` | Run integration tests only |
| `test-coverage` | Generate and display test coverage report in HTML format |
| `benchmark` | Run benchmark tests with memory profiling |

### ✅ Code Quality Commands

| Target | Description |
|--------|-------------|
| `lint` | Run golangci-lint for code linting (requires golangci-lint to be installed) |
| `fmt` | Format code using `go fmt` |
| `vet` | Run `go vet` for static analysis |
| `check` | Run all quality checks: format, vet, lint, and test |

### 🗄️ Database Commands

| Target | Description |
|--------|-------------|
| `db-up` | Start PostgreSQL database using Docker with predefined credentials |
| `db-down` | Stop and remove PostgreSQL database container |
| `db-migrate-up` | Run database migrations up (requires migrate tool) |
| `db-migrate-down` | Run database migrations down (rollback) |
| `db-reset` | Reset database: stop, start, wait, and migrate |

### 🐳 Docker Commands

| Target | Description |
|--------|-------------|
| `docker-build` | Build Docker image with version information and build arguments |
| `docker-run` | Run Docker container with environment file |
| `docker-push` | Build and push Docker image to registry |

### 🐳 Docker Compose Commands

| Target | Description |
|--------|-------------|
| `compose-up` | Start all services with docker-compose in detached mode |
| `compose-build` | Build services with docker-compose |
| `compose-up-build` | Build and start all services with docker-compose |
| `compose-down` | Stop and remove all services |
| `compose-down-volumes` | Stop services and remove volumes |
| `compose-status` | Show status of all services |
| `compose-logs` | Show logs from all services (follows logs) |
| `compose-logs-app` | Show logs from auth-service only |
| `compose-restart` | Restart the auth-service container |
| `compose-shell` | Open shell in auth-service container |
| `compose-test` | Run tests in docker-compose environment |

### 🧹 Cleanup Commands

| Target | Description |
|--------|-------------|
| `clean` | Clean build artifacts (bin/, vendor/, coverage files) |
| `clean-docker` | Clean Docker images and containers using `docker system prune` |

### 🔒 Security Commands

| Target | Description |
|--------|-------------|
| `security-scan` | Run security vulnerability scan using gosec (requires gosec to be installed) |
| `deps-check` | Check for dependency vulnerabilities using govulncheck (requires govulncheck) |

### 📚 Documentation Commands

| Target | Description |
|--------|-------------|
| `docs` | Generate API documentation using Swagger/OpenAPI (requires swag) |
| `docs-serve` | Serve documentation locally on port 8081 using Python HTTP server |
| `docs-validate` | Validate generated OpenAPI specification using swagger CLI |

### 📦 Installation Commands

| Target | Description |
|--------|-------------|
| `install` | Install binary to $GOPATH/bin |
| `install-tools` | Install all development tools (air, golangci-lint, gosec, govulncheck, swag, migrate) |

### 🌍 Environment Commands

| Target | Description |
|--------|-------------|
| `env-example` | Copy .env.example to .env file |
| `env-check` | Check required environment variables using scripts/check-env.sh |

### ℹ️ Information Commands

| Target | Description |
|--------|-------------|
| `status` | Check service status and health by calling the /health endpoint |

## Variable Information

The Makefile uses several variables that are automatically computed:

- `VERSION`: Full version string combining semantic version, build number, and Git metadata
- `SEMANTIC_VERSION`: Version from VERSION file (e.g., "1.0.0")
- `BUILD_NUMBER`: Build number from BUILD_NUMBER file
- `GIT_COMMIT`: Current Git commit hash
- `GIT_BRANCH`: Current Git branch
- `GIT_TAG`: Current Git tag (if any)
- `BUILD_TIME`: Build timestamp
- `BUILD_USER`: User who ran the build
- `BUILD_HOST`: Host where build was executed
- `DOCKER_TAG`: Docker tag (sanitized version for Docker compatibility)

## Common Workflows

### Development Workflow
```bash
make setup          # Install dependencies
make run-dev         # Start development server with live reload
make test            # Run tests
make check           # Run quality checks
```

### Build and Release Workflow
```bash
make version-bump-patch    # Bump version
make build-versioned       # Build with version info
make docker-build          # Build Docker image
make docker-push           # Push to registry
```

### Database Setup Workflow
```bash
make db-up           # Start database
make db-migrate-up   # Run migrations
```

### Quality Assurance Workflow
```bash
make check           # Run all quality checks
make security-scan   # Security vulnerability scan
make deps-check      # Dependency vulnerability check
make test-coverage   # Generate coverage report
```

## Tool Dependencies

Some targets require additional tools to be installed:

- **Air**: For live reload (`run-dev`)
- **golangci-lint**: For linting (`lint`)
- **gosec**: For security scanning (`security-scan`)
- **govulncheck**: For vulnerability checking (`deps-check`)
- **swag**: For API documentation generation (`docs`)
- **migrate**: For database migrations (`db-migrate-*`)
- **swagger**: For OpenAPI validation (`docs-validate`)
- **Python 3**: For serving documentation (`docs-serve`)

Use `make install-tools` to install most of these tools automatically.
