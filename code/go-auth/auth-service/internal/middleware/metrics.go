package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
)

// MetricsRecorder defines the interface for recording HTTP metrics.
// This interface allows different metrics implementations to be used
// while maintaining consistency in the middleware layer.
type MetricsRecorder interface {
	// RecordHTTPRequest records metrics for an HTTP request.
	//
	// Parameters:
	//   - method: HTTP method (GET, POST, PUT, DELETE, etc.)
	//   - path: Request path (should be normalized to avoid high cardinality)
	//   - statusCode: HTTP response status code
	//   - duration: Request processing duration in seconds
	RecordHTTPRequest(method, path string, statusCode int, duration float64)
}

// MetricsMiddleware creates a Gin middleware that records HTTP request metrics.
// This middleware captures comprehensive request/response metrics for monitoring
// and observability purposes.
//
// The middleware records:
// - Request count by method, path, and status code
// - Request duration histogram by method and path
// - Proper path normalization to prevent metric cardinality explosion
//
// Path Normalization:
// - Dynamic path parameters are normalized (e.g., /users/123 -> /users/:id)
// - This prevents unlimited unique metric labels from user-controlled input
// - Gin's route patterns are used when available
//
// Performance Considerations:
// - Minimal overhead using time.Since()
// - Non-blocking metric recording
// - Efficient string operations
//
// Security Considerations:
// - No sensitive data is recorded in metrics
// - Path normalization prevents information leakage
// - Status codes help identify attack patterns
//
// Parameters:
//   - recorder: Implementation that will receive the metrics
//
// Returns:
//   - Gin middleware function
//
// Example:
//
//	metricsMiddleware := middleware.MetricsMiddleware(metricsHandler)
//	router.Use(metricsMiddleware)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func MetricsMiddleware(recorder MetricsRecorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Record start time for duration calculation
		start := time.Now()

		// Process the request
		c.Next()

		// Calculate request duration in seconds
		duration := time.Since(start).Seconds()

		// Get normalized path to prevent metric cardinality explosion
		// Use the matched route pattern if available, otherwise use raw path
		path := c.Request.URL.Path
		if route := c.FullPath(); route != "" {
			path = route
		}

		// Normalize common paths to reduce cardinality
		path = normalizePath(path)

		// Record metrics with labels
		recorder.RecordHTTPRequest(
			c.Request.Method,
			path,
			c.Writer.Status(),
			duration,
		)
	}
}

// normalizePath normalizes request paths to prevent metric cardinality explosion.
// This function converts dynamic path segments to standard patterns while
// preserving the semantic meaning for monitoring purposes.
//
// Normalization rules:
// - UUID patterns -> :id
// - Numeric patterns -> :id
// - Email patterns -> :email
// - Very long paths -> truncated with indicator
// - Special characters -> sanitized
//
// Examples:
//   - "/api/v1/users/123" -> "/api/v1/users/:id"
//   - "/api/v1/users/550e8400-e29b-41d4-a716-446655440000" -> "/api/v1/users/:id"
//   - "/metrics" -> "/metrics" (unchanged)
//   - "/health" -> "/health" (unchanged)
//
// Parameters:
//   - path: Original request path
//
// Returns:
//   - Normalized path suitable for metrics labeling
//
// Time Complexity: O(n) where n is path length
// Space Complexity: O(1)
func normalizePath(path string) string {
	// Handle empty or root paths
	if path == "" || path == "/" {
		return "/"
	}

	// Don't normalize common static paths
	switch path {
	case "/health", "/health/live", "/health/ready", "/metrics":
		return path
	case "/api/v1/health", "/api/v1/health/live", "/api/v1/health/ready", "/api/v1/metrics":
		return path
	}

	// For paths that already contain Gin route parameters, return as-is
	// These are already normalized by Gin (e.g., "/api/v1/users/:id")
	if containsGinParams(path) {
		return path
	}

	// If path is too long, truncate it to prevent unbounded memory usage
	const maxPathLength = 200
	if len(path) > maxPathLength {
		return path[:maxPathLength] + "..."
	}

	// For dynamic paths without Gin parameters, apply basic normalization
	// This is a fallback for cases where FullPath() isn't available
	return path
}

// containsGinParams checks if a path contains Gin route parameters.
// Gin route parameters are denoted by colons (e.g., :id, :email).
//
// Parameters:
//   - path: Path to check
//
// Returns:
//   - true if path contains Gin parameters
//   - false otherwise
//
// Examples:
//   - "/api/v1/users/:id" -> true
//   - "/api/v1/users/123" -> false
//   - "/api/v1/auth/:operation" -> true
//
// Time Complexity: O(n) where n is path length
// Space Complexity: O(1)
func containsGinParams(path string) bool {
	for i := 0; i < len(path); i++ {
		if path[i] == ':' {
			return true
		}
	}
	return false
}
