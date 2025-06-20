package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"auth-service/internal/domain"
)

// HTTPErrorMapper provides centralized error handling and HTTP response mapping
// for the authentication service API. It ensures consistent error responses
// across all endpoints while maintaining proper logging and security practices.
//
// The mapper handles different categories of errors:
// - Validation errors (400 Bad Request)
// - Authentication errors (401 Unauthorized)
// - Authorization errors (403 Forbidden)
// - Rate limiting errors (429 Too Many Requests)
// - Infrastructure errors (503 Service Unavailable)
// - General internal errors (500 Internal Server Error)
//
// Security considerations:
// - Sanitizes error messages to prevent information leakage
// - Logs detailed error information for debugging
// - Provides consistent error response format
// - Includes request correlation IDs for tracing
//
// Time Complexity: O(1) for error mapping
// Space Complexity: O(1) for error response generation
type HTTPErrorMapper struct {
	logger *logrus.Logger
}

// HTTPErrorResponse represents the standardized error response format
// returned by all API endpoints. This ensures consistent error handling
// across different clients and provides sufficient information for debugging.
type HTTPErrorResponse struct {
	// Error is the machine-readable error code for programmatic handling
	Error string `json:"error" example:"validation_error"`

	// Message is the human-readable error description
	Message string `json:"message" example:"The provided email address is invalid"`

	// RequestID is the unique identifier for request tracing and debugging
	RequestID string `json:"request_id" example:"req_123456789"`

	// Timestamp is the ISO 8601 formatted time when the error occurred
	Timestamp string `json:"timestamp" example:"2025-06-20T23:15:30Z"`

	// Details contains additional context for validation errors (optional)
	Details interface{} `json:"details,omitempty"`
}

// NewHTTPErrorMapper creates a new HTTP error mapper instance with the provided logger.
// The logger is used for recording detailed error information while ensuring
// that sensitive information is not exposed in HTTP responses.
//
// Parameters:
//   - logger: Structured logger for recording error events and debugging information
//
// Returns:
//   - Configured HTTPErrorMapper instance ready for use
//
// Example:
//
//	logger := logrus.New()
//	errorMapper := NewHTTPErrorMapper(logger)
//
//	// Use in Gin middleware or handlers
//	if err != nil {
//	    errorMapper.MapError(c, err, "user_registration", requestID)
//	    return
//	}
func NewHTTPErrorMapper(logger *logrus.Logger) *HTTPErrorMapper {
	if logger == nil {
		// Create a default logger if none provided (defensive programming)
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	return &HTTPErrorMapper{
		logger: logger,
	}
}

// MapError processes an error and sends an appropriate HTTP response to the client.
// This is the primary method for handling all errors in the API layer.
//
// The method performs the following operations:
// 1. Logs detailed error information for debugging and monitoring
// 2. Determines the appropriate HTTP status code based on error type
// 3. Generates a sanitized error message for the client
// 4. Sends a standardized JSON error response
//
// Parameters:
//   - c: Gin context for the current HTTP request
//   - err: The error that occurred during request processing
//   - operation: Description of the operation that failed (for logging)
//   - requestID: Unique identifier for request tracing
//
// Error Categories and HTTP Status Codes:
//   - Validation errors: 400 Bad Request
//   - Authentication errors: 401 Unauthorized
//   - Authorization errors: 403 Forbidden
//   - Rate limiting errors: 429 Too Many Requests
//   - Infrastructure errors: 503 Service Unavailable
//   - Unknown errors: 500 Internal Server Error
//
// Security Note:
// Error messages are sanitized to prevent information leakage that could
// aid attackers. Detailed error information is only logged server-side.
//
// Example:
//
//	user, err := authService.Register(ctx, req)
//	if err != nil {
//	    errorMapper.MapError(c, err, "user_registration", requestID)
//	    return
//	}
func (m *HTTPErrorMapper) MapError(c *gin.Context, err error, operation, requestID string) {
	// Extract request context information for comprehensive logging
	ctx := c.Request.Context()

	// Log detailed error information for debugging and monitoring
	// This includes sensitive information that should not be exposed to clients
	m.logErrorDetails(ctx, err, operation, requestID, c)

	// Determine HTTP status code and error response based on error type
	httpCode, errorCode, message, details := m.categorizeError(err)

	// Record error metrics for monitoring and alerting
	m.recordErrorMetrics(errorCode, operation, httpCode)

	// Set security headers to prevent information leakage
	m.setSecurityHeaders(c)

	// Send standardized error response to client
	response := HTTPErrorResponse{
		Error:     errorCode,
		Message:   message,
		RequestID: requestID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Details:   details,
	}

	c.JSON(httpCode, response)
}

// MapErrorWithDetails is similar to MapError but allows providing additional
// context details for complex validation errors or debugging information.
//
// Parameters:
//   - c: Gin context for the current HTTP request
//   - err: The error that occurred during request processing
//   - operation: Description of the operation that failed
//   - requestID: Unique identifier for request tracing
//   - details: Additional context information (e.g., validation field errors)
//
// Example:
//
//	validationErrors := map[string]string{
//	    "email": "Invalid email format",
//	    "password": "Password too weak",
//	}
//	errorMapper.MapErrorWithDetails(c, err, "validation", requestID, validationErrors)
func (m *HTTPErrorMapper) MapErrorWithDetails(c *gin.Context, err error, operation, requestID string, details interface{}) {
	ctx := c.Request.Context()

	m.logErrorDetails(ctx, err, operation, requestID, c)
	httpCode, errorCode, message, _ := m.categorizeError(err)

	m.recordErrorMetrics(errorCode, operation, httpCode)
	m.setSecurityHeaders(c)

	response := HTTPErrorResponse{
		Error:     errorCode,
		Message:   message,
		RequestID: requestID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Details:   details,
	}

	c.JSON(httpCode, response)
}

// logErrorDetails records comprehensive error information for debugging,
// monitoring, and security analysis. This information is not exposed to clients.
func (m *HTTPErrorMapper) logErrorDetails(ctx context.Context, err error, operation, requestID string, c *gin.Context) {
	// Extract client information for security monitoring
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Get user ID from context if available (for user-specific error tracking)
	userID := ""
	if uid, exists := c.Get("user_id"); exists {
		if userIDStr, ok := uid.(string); ok {
			userID = userIDStr
		}
	}

	// Create comprehensive log entry with all relevant context
	logEntry := m.logger.WithError(err).WithFields(logrus.Fields{
		"operation":  operation,
		"request_id": requestID,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"query":      c.Request.URL.RawQuery,
		"client_ip":  clientIP,
		"user_agent": userAgent,
		"user_id":    userID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"error_type": m.getErrorType(err),
	})

	// Log at appropriate level based on error severity
	switch {
	case domain.IsValidationError(err):
		logEntry.Warn("Validation error occurred")
	case domain.IsAuthenticationError(err):
		logEntry.Warn("Authentication error occurred")
	case domain.IsAuthorizationError(err):
		logEntry.Warn("Authorization error occurred")
	case domain.IsRateLimitError(err):
		logEntry.Warn("Rate limit error occurred")
	case domain.IsSecurityError(err):
		logEntry.Error("Security error detected - potential threat")
	case domain.IsInfrastructureError(err):
		logEntry.Error("Infrastructure error occurred")
	default:
		logEntry.Error("Unexpected error occurred")
	}
}

// categorizeError determines the appropriate HTTP status code, error code,
// and client-safe message based on the error type.
func (m *HTTPErrorMapper) categorizeError(err error) (httpCode int, errorCode string, message string, details interface{}) {
	switch {
	case domain.IsValidationError(err):
		return http.StatusBadRequest, "validation_error", m.sanitizeValidationMessage(err), nil

	case domain.IsAuthenticationError(err):
		return http.StatusUnauthorized, "authentication_error", "Authentication failed", nil

	case domain.IsAuthorizationError(err):
		return http.StatusForbidden, "authorization_error", "Access denied", nil

	case domain.IsRateLimitError(err):
		return http.StatusTooManyRequests, "rate_limit_error", "Too many requests", nil

	case domain.IsInfrastructureError(err):
		return http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable", nil

	case domain.IsSecurityError(err):
		// Return generic error for security issues to avoid information leakage
		return http.StatusForbidden, "access_denied", "Access denied", nil

	default:
		return http.StatusInternalServerError, "internal_error", "Internal server error", nil
	}
}

// sanitizeValidationMessage creates a client-safe validation error message
// while preserving useful information for debugging.
func (m *HTTPErrorMapper) sanitizeValidationMessage(err error) string {
	// Return the actual validation error message as it's safe for clients
	// These errors are designed to help users correct their input
	switch err {
	case domain.ErrInvalidEmail:
		return "Please provide a valid email address"
	case domain.ErrWeakPassword:
		return "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters"
	case domain.ErrPasswordMismatch:
		return "Password confirmation does not match"
	case domain.ErrEmailExists:
		return "An account with this email address already exists"
	default:
		return "Invalid input provided"
	}
}

// getErrorType returns a string representation of the error type for logging.
func (m *HTTPErrorMapper) getErrorType(err error) string {
	switch {
	case domain.IsValidationError(err):
		return "validation"
	case domain.IsAuthenticationError(err):
		return "authentication"
	case domain.IsAuthorizationError(err):
		return "authorization"
	case domain.IsRateLimitError(err):
		return "rate_limit"
	case domain.IsInfrastructureError(err):
		return "infrastructure"
	case domain.IsSecurityError(err):
		return "security"
	default:
		return "unknown"
	}
}

// recordErrorMetrics records error metrics for monitoring and alerting.
// This would typically integrate with Prometheus or other monitoring systems.
func (m *HTTPErrorMapper) recordErrorMetrics(errorCode, operation string, httpCode int) {
	// TODO: Implement metrics collection
	// This would typically increment counters for:
	// - Total errors by type
	// - Errors by operation
	// - HTTP status code distribution
	// - Error rate over time

	m.logger.WithFields(logrus.Fields{
		"error_code":  errorCode,
		"operation":   operation,
		"http_code":   httpCode,
		"metric_type": "error_count",
	}).Debug("Error metrics recorded")
}

// setSecurityHeaders adds security headers to prevent information leakage
// and protect against common web vulnerabilities.
func (m *HTTPErrorMapper) setSecurityHeaders(c *gin.Context) {
	// Prevent content type sniffing
	c.Header("X-Content-Type-Options", "nosniff")

	// Prevent embedding in frames (clickjacking protection)
	c.Header("X-Frame-Options", "DENY")

	// Enable XSS protection
	c.Header("X-XSS-Protection", "1; mode=block")

	// Ensure content is served over HTTPS in production
	if c.GetHeader("X-Forwarded-Proto") == "https" {
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}
