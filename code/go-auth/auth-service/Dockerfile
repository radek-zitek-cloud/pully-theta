# Dockerfile for Go Authentication Service
# Multi-stage build for production-ready, minimal container

# =============================================================================
# Build Stage
# =============================================================================
FROM golang:1.24-alpine AS builder

# Set build metadata
ARG VERSION=dev
ARG BUILD_TIME
ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy dependency files first (for better layer caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with optimizations
RUN go build \
    -a \
    -installsuffix cgo \
    -ldflags="-w -s -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
    -o auth-service \
    cmd/server/main.go

# =============================================================================
# Runtime Stage
# =============================================================================
FROM alpine:3.18 AS runtime

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    && update-ca-certificates

# Create non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy binary from build stage
COPY --from=builder /build/auth-service ./auth-service

# Copy migrations directory
COPY --from=builder /build/migrations ./migrations

# Create necessary directories and set permissions
RUN mkdir -p /app/logs && \
    chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose application port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Set runtime metadata
LABEL maintainer="your-email@example.com" \
      version="${VERSION}" \
      description="Go Authentication Service" \
      org.opencontainers.image.title="auth-service" \
      org.opencontainers.image.description="Production-ready JWT authentication microservice" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_TIME}" \
      org.opencontainers.image.source="https://github.com/your-org/auth-service" \
      org.opencontainers.image.licenses="MIT"

# Start the application
ENTRYPOINT ["./auth-service"]

# =============================================================================
# Development Stage (Optional)
# =============================================================================
FROM golang:1.24-alpine AS development

# Install development tools
RUN apk add --no-cache git make bash curl

# Install air for live reloading (using the new module path)
RUN go install github.com/air-verse/air@latest

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Download dependencies as root first to avoid permission issues
RUN go mod download

# Create non-root user and set up proper permissions
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup && \
    chown -R appuser:appgroup /app && \
    chown -R appuser:appgroup /go/pkg/mod && \
    chmod -R 755 /go/pkg/mod

USER appuser

# Expose development port
EXPOSE 8080

# Start with air for live reloading
CMD ["air", "-c", ".air.toml"]
