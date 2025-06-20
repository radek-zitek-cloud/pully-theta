package api

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"auth-service/internal/domain"
)

// HealthHandler handles health check and monitoring endpoints.
// This handler provides comprehensive health information for the authentication service
// including database connectivity, dependency status, and system readiness.
//
// The handler separates different types of health checks:
// - Basic health: Simple alive check for load balancers
// - Ready check: Detailed readiness with dependency validation
// - Live check: Liveness probe for container orchestration
//
// Health checks follow industry standards and provide actionable information
// for monitoring systems, load balancers, and operational teams.
//
// Dependencies:
// - Database connection for connectivity checks
// - Logger for health check logging and debugging
// - Version information for build metadata
//
// Security considerations:
// - Health endpoints are typically public but may expose system information
// - Consider rate limiting in production environments
// - Sensitive dependency details should not be exposed
type HealthHandler struct {
	db          *sql.DB
	logger      *logrus.Logger
	versionInfo *VersionInfo
}

// VersionInfo contains build and version metadata for health responses.
// This information helps with debugging, monitoring, and operational tracking.
type VersionInfo struct {
	Version         string `json:"version"`          // Full version string (e.g., "v1.2.3-build.42+abcd123")
	SemanticVersion string `json:"semantic_version"` // Semantic version (e.g., "1.2.3")
	BuildNumber     string `json:"build_number"`     // Incremental build number
	BuildTime       string `json:"build_time"`       // RFC3339 build timestamp
	GitCommit       string `json:"git_commit"`       // Short git commit hash
	GitBranch       string `json:"git_branch"`       // Git branch name
	BuildUser       string `json:"build_user"`       // Username who built the binary
	BuildHost       string `json:"build_host"`       // Hostname where binary was built
}

// NewHealthHandler creates a new health handler instance.
// This constructor validates dependencies and returns a configured handler
// ready to serve health check endpoints.
//
// Parameters:
//   - db: Database connection for health checks (can be nil for basic checks)
//   - logger: Structured logger for health check operations
//   - versionInfo: Build and version metadata for health responses
//
// Returns:
//   - Configured HealthHandler instance
//
// Example:
//
//	versionInfo := &VersionInfo{
//	    Version: "v1.2.3",
//	    BuildTime: "2025-06-20T14:30:00Z",
//	    GitCommit: "abcd123",
//	}
//	healthHandler := NewHealthHandler(dbConnection, logger, versionInfo)
//	router.GET("/health", healthHandler.HealthCheck)
//	router.GET("/health/ready", healthHandler.ReadinessCheck)
//	router.GET("/health/live", healthHandler.LivenessCheck)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func NewHealthHandler(db *sql.DB, logger *logrus.Logger, versionInfo *VersionInfo) *HealthHandler {
	return &HealthHandler{
		db:          db,
		logger:      logger,
		versionInfo: versionInfo,
	}
}

// HealthCheck handles basic health check requests.
// This endpoint provides essential health information including service status,
// version, and basic dependency checks. It's designed for load balancers and
// monitoring systems that need fast, reliable health status.
//
// HTTP Method: GET
// Path: /health
//
// Success Response (200 OK):
//
//	{
//	  "status": "healthy",
//	  "timestamp": "2025-06-20T14:30:00Z",
//	  "version": "1.0.0",
//	  "checks": {
//	    "database": {
//	      "status": "healthy",
//	      "response_time_ms": 25,
//	      "last_checked": "2025-06-20T14:30:00Z"
//	    }
//	  }
//	}
//
// Error Responses:
//   - 503 Service Unavailable: Service or critical dependencies unhealthy
//
// Usage:
// - Load balancers for routing decisions
// - Monitoring systems for alerting
// - Operations teams for service status
// - Container orchestration health checks
//
// @Summary      Basic health check
// @Description  Get service health status with essential dependency checks
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200  {object}  domain.HealthCheckResponse  "Service is healthy"
// @Failure      503  {object}  domain.HealthCheckResponse  "Service or dependencies are unhealthy"
// @Router       /health [get]
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	requestID := h.getRequestID(c)
	startTime := time.Now()

	h.logger.WithField("request_id", requestID).Debug("Health check request received")

	// Initialize response with basic service info
	response := &domain.HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   h.getVersionString(),
		Checks:    make(map[string]domain.HealthCheck),
	}

	// Overall service health status
	overallHealthy := true

	// Check database connectivity if available
	if h.db != nil {
		dbHealth := h.checkDatabaseHealth(c.Request.Context())
		response.Checks["database"] = dbHealth

		if dbHealth.Status != "healthy" {
			overallHealthy = false
		}
	}

	// Set overall status based on all checks
	if !overallHealthy {
		response.Status = "unhealthy"
		h.logger.WithFields(logrus.Fields{
			"request_id": requestID,
			"status":     "unhealthy",
			"duration":   time.Since(startTime),
		}).Warn("Health check failed")

		c.JSON(http.StatusServiceUnavailable, response)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"request_id": requestID,
		"status":     "healthy",
		"duration":   time.Since(startTime),
	}).Debug("Health check completed successfully")

	c.JSON(http.StatusOK, response)
}

// ReadinessCheck handles detailed readiness probe requests.
// This endpoint performs comprehensive checks to determine if the service
// is ready to handle requests. It validates all critical dependencies
// and provides detailed status information.
//
// HTTP Method: GET
// Path: /health/ready
//
// Success Response (200 OK):
//
//	{
//	  "status": "ready",
//	  "timestamp": "2025-06-20T14:30:00Z",
//	  "version": "1.0.0",
//	  "checks": {
//	    "database": {
//	      "status": "healthy",
//	      "response_time_ms": 15,
//	      "last_checked": "2025-06-20T14:30:00Z"
//	    },
//	    "migrations": {
//	      "status": "healthy",
//	      "response_time_ms": 5,
//	      "last_checked": "2025-06-20T14:30:00Z"
//	    }
//	  }
//	}
//
// Error Responses:
//   - 503 Service Unavailable: Service not ready to handle requests
//
// Usage:
// - Kubernetes readiness probes
// - Load balancer backend registration
// - Deployment validation
// - Service mesh routing decisions
//
// @Summary      Readiness probe
// @Description  Comprehensive readiness check with all dependency validation
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200  {object}  domain.HealthCheckResponse  "Service is ready"
// @Failure      503  {object}  domain.HealthCheckResponse  "Service is not ready"
// @Router       /health/ready [get]
func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	requestID := h.getRequestID(c)
	startTime := time.Now()

	h.logger.WithField("request_id", requestID).Debug("Readiness check request received")

	// Initialize response with service info
	response := &domain.HealthCheckResponse{
		Status:    "ready",
		Timestamp: time.Now(),
		Version:   h.getVersionString(),
		Checks:    make(map[string]domain.HealthCheck),
	}

	// Overall readiness status
	overallReady := true

	// Check database connectivity and schema
	if h.db != nil {
		dbHealth := h.checkDatabaseHealth(c.Request.Context())
		response.Checks["database"] = dbHealth

		if dbHealth.Status != "healthy" {
			overallReady = false
		}

		// Check database migrations status
		migrationHealth := h.checkMigrationsHealth(c.Request.Context())
		response.Checks["migrations"] = migrationHealth

		if migrationHealth.Status != "healthy" {
			overallReady = false
		}
	}

	// Set overall status based on all checks
	if !overallReady {
		response.Status = "not_ready"
		h.logger.WithFields(logrus.Fields{
			"request_id": requestID,
			"status":     "not_ready",
			"duration":   time.Since(startTime),
		}).Warn("Readiness check failed")

		c.JSON(http.StatusServiceUnavailable, response)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"request_id": requestID,
		"status":     "ready",
		"duration":   time.Since(startTime),
	}).Debug("Readiness check completed successfully")

	c.JSON(http.StatusOK, response)
}

// LivenessCheck handles liveness probe requests.
// This endpoint provides a lightweight check to determine if the service
// is alive and functioning. It performs minimal checks to avoid impacting
// service performance during high load.
//
// HTTP Method: GET
// Path: /health/live
//
// Success Response (200 OK):
//
//	{
//	  "status": "alive",
//	  "timestamp": "2025-06-20T14:30:00Z",
//	  "version": "1.0.0"
//	}
//
// Error Responses:
//   - 503 Service Unavailable: Service is not functioning (should trigger restart)
//
// Usage:
// - Kubernetes liveness probes
// - Container restart decisions
// - Service monitoring for critical failures
// - Automated recovery systems
//
// @Summary      Liveness probe
// @Description  Lightweight liveness check for container orchestration
// @Tags         health
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]interface{}  "Service is alive"
// @Failure      503  {object}  map[string]interface{}  "Service is not functioning"
// @Router       /health/live [get]
func (h *HealthHandler) LivenessCheck(c *gin.Context) {
	requestID := h.getRequestID(c)

	h.logger.WithField("request_id", requestID).Debug("Liveness check request received")

	// Simple response indicating service is alive
	// This check should be very fast and not perform expensive operations
	response := map[string]interface{}{
		"status":    "alive",
		"timestamp": time.Now(),
		"version":   h.getVersionString(),
	}

	h.logger.WithField("request_id", requestID).Debug("Liveness check completed")

	c.JSON(http.StatusOK, response)
}

// checkDatabaseHealth performs database connectivity and basic functionality checks.
// This method tests database connection, performs a simple query, and measures response time.
//
// Parameters:
//   - ctx: Request context for timeout and cancellation
//
// Returns:
//   - HealthCheck struct with status, response time, and last checked timestamp
//
// The check performs:
// 1. Database ping to verify connectivity
// 2. Simple query execution to validate functionality
// 3. Response time measurement for performance monitoring
//
// Time Complexity: O(1) - single database operation
// Space Complexity: O(1) - constant memory usage
func (h *HealthHandler) checkDatabaseHealth(ctx context.Context) domain.HealthCheck {
	startTime := time.Now()

	// Create context with timeout for database operations
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Test database connectivity
	if err := h.db.PingContext(checkCtx); err != nil {
		h.logger.WithError(err).Error("Database ping failed")
		return domain.HealthCheck{
			Status:       "unhealthy",
			ResponseTime: int64(time.Since(startTime).Milliseconds()),
			LastChecked:  time.Now(),
			Error:        "Database connection failed",
		}
	}

	// Test basic query execution
	var result int
	err := h.db.QueryRowContext(checkCtx, "SELECT 1").Scan(&result)
	if err != nil {
		h.logger.WithError(err).Error("Database query test failed")
		return domain.HealthCheck{
			Status:       "unhealthy",
			ResponseTime: int64(time.Since(startTime).Milliseconds()),
			LastChecked:  time.Now(),
			Error:        "Database query failed",
		}
	}

	responseTime := time.Since(startTime).Milliseconds()

	return domain.HealthCheck{
		Status:       "healthy",
		ResponseTime: int64(responseTime),
		LastChecked:  time.Now(),
	}
}

// checkMigrationsHealth verifies that database migrations are up to date.
// This method checks if the database schema matches the expected version
// by validating the presence of required tables and schema version.
//
// Parameters:
//   - ctx: Request context for timeout and cancellation
//
// Returns:
//   - HealthCheck struct with migration status and timing information
//
// The check performs:
// 1. Validation of core tables existence (users, refresh_tokens, etc.)
// 2. Schema version verification if migration tracking is implemented
// 3. Response time measurement
//
// Time Complexity: O(n) where n is the number of tables to check
// Space Complexity: O(1) - constant memory usage
func (h *HealthHandler) checkMigrationsHealth(ctx context.Context) domain.HealthCheck {
	startTime := time.Now()

	// Create context with timeout for database operations
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Check for existence of core tables
	requiredTables := []string{"users", "refresh_tokens", "password_reset_tokens", "audit_logs"}

	for _, table := range requiredTables {
		var exists bool
		query := `
			SELECT EXISTS (
				SELECT FROM information_schema.tables 
				WHERE table_schema = 'public' 
				AND table_name = $1
			)`

		err := h.db.QueryRowContext(checkCtx, query, table).Scan(&exists)
		if err != nil {
			h.logger.WithError(err).WithField("table", table).Error("Failed to check table existence")
			return domain.HealthCheck{
				Status:       "unhealthy",
				ResponseTime: int64(time.Since(startTime).Milliseconds()),
				LastChecked:  time.Now(),
				Error:        "Migration check failed",
			}
		}

		if !exists {
			h.logger.WithField("table", table).Error("Required table missing")
			return domain.HealthCheck{
				Status:       "unhealthy",
				ResponseTime: int64(time.Since(startTime).Milliseconds()),
				LastChecked:  time.Now(),
				Error:        "Database schema incomplete",
			}
		}
	}

	responseTime := time.Since(startTime).Milliseconds()

	return domain.HealthCheck{
		Status:       "healthy",
		ResponseTime: int64(responseTime),
		LastChecked:  time.Now(),
	}
}

// getRequestID extracts or generates a request ID for correlation.
// This method looks for an existing request ID in the context or generates
// a new one for request tracing and correlation.
//
// Parameters:
//   - c: Gin context containing request information
//
// Returns:
//   - String request ID for logging and correlation
//
// The method follows this priority:
// 1. Check for existing request ID in Gin context
// 2. Check for X-Request-ID header from client
// 3. Generate new UUID if none exists
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (h *HealthHandler) getRequestID(c *gin.Context) string {
	// Try to get request ID from context (set by middleware)
	if id, exists := c.Get("request_id"); exists {
		if requestID, ok := id.(string); ok {
			return requestID
		}
	}

	// Try to get from header
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		return requestID
	}

	// Generate new request ID
	return "health_" + time.Now().Format("20060102150405")
}

// getVersionString returns the appropriate version string for health responses.
// This method provides a consistent version format across all health endpoints.
//
// Version priority:
// 1. Full version from build info (if available)
// 2. Semantic version from build info (if available)
// 3. Default fallback version
//
// Returns:
//   - String version identifier for health responses
//
// Example outputs:
//   - "v1.2.3-build.42+abcd123" (full version with build info)
//   - "v1.2.3" (semantic version only)
//   - "dev" (development/unknown version)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (h *HealthHandler) getVersionString() string {
	if h.versionInfo == nil {
		return "dev"
	}

	// Use full version if available and non-empty
	if h.versionInfo.Version != "" && h.versionInfo.Version != "dev" {
		return h.versionInfo.Version
	}

	// Fall back to semantic version
	if h.versionInfo.SemanticVersion != "" {
		return "v" + h.versionInfo.SemanticVersion
	}

	// Final fallback
	return "dev"
}

// getVersionInfo returns detailed version information for enhanced health responses.
// This method provides comprehensive build metadata for debugging and monitoring.
//
// Returns:
//   - Map containing detailed version and build information
//   - Empty map if version info is not available
//
// Response includes:
//   - version: Full version string
//   - semantic_version: Semantic version number
//   - build_number: Incremental build number
//   - build_time: RFC3339 build timestamp
//   - git_commit: Short git commit hash
//   - git_branch: Git branch name
//   - build_user: Username who built the binary
//   - build_host: Hostname where binary was built
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (h *HealthHandler) getVersionInfo() map[string]interface{} {
	if h.versionInfo == nil {
		return map[string]interface{}{
			"version": "dev",
		}
	}

	return map[string]interface{}{
		"version":          h.versionInfo.Version,
		"semantic_version": h.versionInfo.SemanticVersion,
		"build_number":     h.versionInfo.BuildNumber,
		"build_time":       h.versionInfo.BuildTime,
		"git_commit":       h.versionInfo.GitCommit,
		"git_branch":       h.versionInfo.GitBranch,
		"build_user":       h.versionInfo.BuildUser,
		"build_host":       h.versionInfo.BuildHost,
	}
}
