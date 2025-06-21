# Version Management for Go Authentication Service

This document explains the automatic versioning system for the authentication service.

## Version Format

The service uses semantic versioning (SemVer) format: `MAJOR.MINOR.PATCH-BUILD`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)  
- **BUILD**: Automatic build number (incremented on each build)

## Automatic Version Sources

### 1. Git Tags (Primary)
- Uses `git describe --tags --always --dirty`
- Format: `v1.2.3-4-g1234567` (tag-commits-hash)
- Fallback to `v1.0.0-dev` if no tags exist

### 2. Version File (Secondary)
- `VERSION` file in project root
- Manual control over semantic version
- Build number auto-incremented

### 3. Build Metadata
- Build timestamp: `2025-06-20T14:30:00+0200`
- Git commit hash: `g1234567`
- Build environment: `development|staging|production`

## Usage

### Makefile Commands
```bash
# Build with automatic versioning
make build

# Show current version
make version

# Create new version tag
make tag VERSION=v1.2.3

# Build with specific version
make build VERSION=v1.2.3

# Increment version automatically
make version-bump-patch    # 1.0.0 -> 1.0.1
make version-bump-minor    # 1.0.1 -> 1.1.0
make version-bump-major    # 1.1.0 -> 2.0.0
```

### Version Information in Code
```go
// Injected at build time via ldflags
var (
    Version   = "dev"
    BuildTime = "unknown"
    GitCommit = "unknown"
)
```

### Health Endpoint
Version information is available in health checks:
```json
{
  "status": "healthy",
  "version": "v1.2.3-build.42",
  "build_time": "2025-06-20T14:30:00+0200",
  "git_commit": "1234567"
}
```

## Implementation Details

### Build-time Injection
Version information is injected using Go's `-ldflags`:
```bash
go build -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GitCommit=${GIT_COMMIT}"
```

### Docker Image Tagging
Docker images are tagged with the same version:
```bash
docker build -t auth-service:v1.2.3 .
docker build -t auth-service:latest .
```

### Documentation Updates
Swagger documentation version is automatically updated during build.

## Version History

Versions are tracked in:
- Git tags: `git tag -l`
- CHANGELOG.md: Manual change tracking
- Docker registry: Image tag history
- Health endpoint: Runtime version info

## Best Practices

1. **Use Git Tags**: Create annotated tags for releases
2. **Semantic Versioning**: Follow SemVer strictly
3. **Build Numbers**: Let build system auto-increment
4. **Change Tracking**: Update CHANGELOG.md manually
5. **Release Notes**: Document changes for each version
