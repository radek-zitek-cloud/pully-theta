package test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"auth-service/internal/api"
	"auth-service/internal/domain"
)

// TestHTTPErrorMapper_NewHTTPErrorMapper tests the constructor for the error mapper.
func TestHTTPErrorMapper_NewHTTPErrorMapper(t *testing.T) {
	tests := []struct {
		name        string
		logger      *logrus.Logger
		expectNil   bool
		description string
	}{
		{
			name:        "with_valid_logger",
			logger:      logrus.New(),
			expectNil:   false,
			description: "Should create error mapper with provided logger",
		},
		{
			name:        "with_nil_logger",
			logger:      nil,
			expectNil:   false,
			description: "Should create error mapper with default logger when nil provided",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := api.NewHTTPErrorMapper(tt.logger)

			// Test that mapper was created successfully
			assert.NotNil(t, mapper, "Error mapper should not be nil")

			// Test functionality by using the mapper (since logger is private)
			// This ensures the constructor worked properly regardless of logger parameter
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest("POST", "/test", nil)
			c.Request = req

			// This should not panic and should work properly
			mapper.MapError(c, domain.ErrInvalidInput, "test_operation", "test_req_id")
			assert.Equal(t, http.StatusBadRequest, w.Code, "Mapper should be functional")
		})
	}
}

// TestHTTPErrorMapper_MapError tests the main error mapping functionality.
func TestHTTPErrorMapper_MapError(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress log output during tests
	mapper := api.NewHTTPErrorMapper(logger)

	tests := []struct {
		name          string
		error         error
		operation     string
		requestID     string
		expectedCode  int
		expectedError string
		expectedMsg   string
		description   string
	}{
		{
			name:          "validation_error_invalid_email",
			error:         domain.ErrInvalidEmail,
			operation:     "user_registration",
			requestID:     "req_123",
			expectedCode:  http.StatusBadRequest,
			expectedError: "validation_error",
			expectedMsg:   "Please provide a valid email address",
			description:   "Should map invalid email to 400 with user-friendly message",
		},
		{
			name:          "validation_error_weak_password",
			error:         domain.ErrWeakPassword,
			operation:     "user_registration",
			requestID:     "req_124",
			expectedCode:  http.StatusBadRequest,
			expectedError: "validation_error",
			expectedMsg:   "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters",
			description:   "Should map weak password to 400 with security requirements",
		},
		{
			name:          "validation_error_email_exists",
			error:         domain.ErrEmailExists,
			operation:     "user_registration",
			requestID:     "req_125",
			expectedCode:  http.StatusBadRequest,
			expectedError: "validation_error",
			expectedMsg:   "An account with this email address already exists",
			description:   "Should map existing email to 400 with clear message",
		},
		{
			name:          "authentication_error_invalid_credentials",
			error:         domain.ErrInvalidCredentials,
			operation:     "user_login",
			requestID:     "req_126",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "authentication_error",
			expectedMsg:   "Authentication failed",
			description:   "Should map invalid credentials to 401 with generic message",
		},
		{
			name:          "authentication_error_token_expired",
			error:         domain.ErrTokenExpired,
			operation:     "token_validation",
			requestID:     "req_127",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "authentication_error",
			expectedMsg:   "Authentication failed",
			description:   "Should map expired token to 401 with generic message",
		},
		{
			name:          "authorization_error_forbidden",
			error:         domain.ErrForbidden,
			operation:     "admin_access",
			requestID:     "req_128",
			expectedCode:  http.StatusForbidden,
			expectedError: "authorization_error",
			expectedMsg:   "Access denied",
			description:   "Should map forbidden error to 403",
		},
		{
			name:          "authorization_error_insufficient_permissions",
			error:         domain.ErrInsufficientPermissions,
			operation:     "user_management",
			requestID:     "req_129",
			expectedCode:  http.StatusForbidden,
			expectedError: "authorization_error",
			expectedMsg:   "Access denied",
			description:   "Should map insufficient permissions to 403",
		},
		{
			name:          "rate_limit_error_exceeded",
			error:         domain.ErrRateLimitExceeded,
			operation:     "api_request",
			requestID:     "req_130",
			expectedCode:  http.StatusTooManyRequests,
			expectedError: "rate_limit_error",
			expectedMsg:   "Too many requests",
			description:   "Should map rate limit exceeded to 429",
		},
		{
			name:          "rate_limit_error_too_many_login_attempts",
			error:         domain.ErrTooManyLoginAttempts,
			operation:     "user_login",
			requestID:     "req_131",
			expectedCode:  http.StatusTooManyRequests,
			expectedError: "rate_limit_error",
			expectedMsg:   "Too many requests",
			description:   "Should map too many login attempts to 429",
		},
		{
			name:          "infrastructure_error_database",
			error:         domain.ErrDatabase,
			operation:     "user_query",
			requestID:     "req_132",
			expectedCode:  http.StatusServiceUnavailable,
			expectedError: "service_unavailable",
			expectedMsg:   "Service temporarily unavailable",
			description:   "Should map database error to 503",
		},
		{
			name:          "infrastructure_error_email_service",
			error:         domain.ErrEmailService,
			operation:     "password_reset",
			requestID:     "req_133",
			expectedCode:  http.StatusServiceUnavailable,
			expectedError: "service_unavailable",
			expectedMsg:   "Service temporarily unavailable",
			description:   "Should map email service error to 503",
		},
		{
			name:          "security_error_suspicious_activity",
			error:         domain.ErrSuspiciousActivity,
			operation:     "user_login",
			requestID:     "req_134",
			expectedCode:  http.StatusForbidden,
			expectedError: "access_denied",
			expectedMsg:   "Access denied",
			description:   "Should map security error to 403 with generic message",
		},
		{
			name:          "unknown_error",
			error:         errors.New("unknown error"),
			operation:     "unknown_operation",
			requestID:     "req_135",
			expectedCode:  http.StatusInternalServerError,
			expectedError: "internal_error",
			expectedMsg:   "Internal server error",
			description:   "Should map unknown error to 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test context
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Set up request
			req := httptest.NewRequest("POST", "/test", nil)
			req.Header.Set("User-Agent", "Test-Agent/1.0")
			c.Request = req

			// Call MapError
			mapper.MapError(c, tt.error, tt.operation, tt.requestID)

			// Verify HTTP status code
			assert.Equal(t, tt.expectedCode, w.Code, tt.description)

			// Verify Content-Type
			assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

			// Verify security headers
			assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
			assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))

			// Parse response body
			var response api.HTTPErrorResponse
			require.NotEmpty(t, w.Body.Bytes(), "Should have response body")

			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err, "Should be able to parse JSON response")

			// Verify response structure
			assert.Equal(t, tt.expectedError, response.Error, "Error code should match")
			assert.Equal(t, tt.expectedMsg, response.Message, "Error message should match")
			assert.Equal(t, tt.requestID, response.RequestID, "Request ID should match")
			assert.NotEmpty(t, response.Timestamp, "Timestamp should be present")

			// Verify timestamp format
			_, err = time.Parse(time.RFC3339, response.Timestamp)
			assert.NoError(t, err, "Timestamp should be in RFC3339 format")
		})
	}
}

// TestHTTPErrorMapper_MapErrorWithDetails tests error mapping with additional details.
func TestHTTPErrorMapper_MapErrorWithDetails(t *testing.T) {
	// Setup
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress log output during tests
	mapper := api.NewHTTPErrorMapper(logger)

	// Test data
	validationDetails := map[string]string{
		"email":    "Invalid email format",
		"password": "Password too weak",
	}

	// Create test context
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	req := httptest.NewRequest("POST", "/test", nil)
	c.Request = req

	// Call MapErrorWithDetails
	mapper.MapErrorWithDetails(c, domain.ErrValidationFailed, "form_validation", "req_999", validationDetails)

	// Verify response
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response api.HTTPErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "validation_error", response.Error)
	assert.Equal(t, "Invalid input provided", response.Message)
	assert.Equal(t, "req_999", response.RequestID)
	assert.NotNil(t, response.Details)

	// Convert details back to compare (JSON unmarshaling creates interface{})
	detailsMap, ok := response.Details.(map[string]interface{})
	require.True(t, ok, "Details should be a map")
	assert.Equal(t, "Invalid email format", detailsMap["email"])
	assert.Equal(t, "Password too weak", detailsMap["password"])
}

// TestHTTPErrorMapper_SecurityHeaders tests that security headers are properly set.
func TestHTTPErrorMapper_SecurityHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	mapper := api.NewHTTPErrorMapper(logger)

	tests := []struct {
		name           string
		forwardedProto string
		expectHSTS     bool
		description    string
	}{
		{
			name:           "https_request",
			forwardedProto: "https",
			expectHSTS:     true,
			description:    "Should set HSTS header for HTTPS requests",
		},
		{
			name:           "http_request",
			forwardedProto: "http",
			expectHSTS:     false,
			description:    "Should not set HSTS header for HTTP requests",
		},
		{
			name:           "no_forwarded_proto",
			forwardedProto: "",
			expectHSTS:     false,
			description:    "Should not set HSTS header when no forwarded proto",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			req := httptest.NewRequest("POST", "/test", nil)
			if tt.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			c.Request = req

			mapper.MapError(c, domain.ErrInvalidInput, "test", "req_123")

			// Check standard security headers
			assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
			assert.Equal(t, "1; mode=block", w.Header().Get("X-XSS-Protection"))

			// Check HSTS header
			hstsHeader := w.Header().Get("Strict-Transport-Security")
			if tt.expectHSTS {
				assert.Equal(t, "max-age=31536000; includeSubDomains", hstsHeader)
			} else {
				assert.Empty(t, hstsHeader)
			}
		})
	}
}

// TestHTTPErrorMapper_UserContextLogging tests that user context is properly logged.
func TestHTTPErrorMapper_UserContextLogging(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress log output during tests
	mapper := api.NewHTTPErrorMapper(logger)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Set user context
	c.Set("user_id", "user_123")

	req := httptest.NewRequest("POST", "/test?param=value", nil)
	req.Header.Set("User-Agent", "Test-Browser/1.0")
	c.Request = req

	// This test mainly ensures no panics occur when user context is present
	// In a real implementation, you would use a test logger to verify log content
	mapper.MapError(c, domain.ErrInvalidCredentials, "user_login", "req_456")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// BenchmarkHTTPErrorMapper_MapError benchmarks the error mapping performance.
func BenchmarkHTTPErrorMapper_MapError(b *testing.B) {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress log output during benchmarks
	mapper := api.NewHTTPErrorMapper(logger)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		req := httptest.NewRequest("POST", "/test", nil)
		c.Request = req

		mapper.MapError(c, domain.ErrInvalidCredentials, "benchmark_test", "req_bench")
	}
}

// TestHTTPErrorMapper_CategorizeError tests error categorization through public MapError method.
// Since categorizeError is internal, we test it indirectly through the public API.
func TestHTTPErrorMapper_CategorizeError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress log output during tests
	mapper := api.NewHTTPErrorMapper(logger)

	tests := []struct {
		name         string
		error        error
		expectedCode int
		expectedType string
	}{
		{"validation", domain.ErrInvalidEmail, http.StatusBadRequest, "validation_error"},
		{"authentication", domain.ErrInvalidCredentials, http.StatusUnauthorized, "authentication_error"},
		{"authorization", domain.ErrForbidden, http.StatusForbidden, "authorization_error"},
		{"rate_limit", domain.ErrRateLimitExceeded, http.StatusTooManyRequests, "rate_limit_error"},
		{"infrastructure", domain.ErrDatabase, http.StatusServiceUnavailable, "service_unavailable"},
		{"security", domain.ErrSuspiciousActivity, http.StatusForbidden, "access_denied"},
		{"unknown", errors.New("unknown"), http.StatusInternalServerError, "internal_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test through public MapError method
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			req := httptest.NewRequest("POST", "/test", nil)
			c.Request = req

			mapper.MapError(c, tt.error, "test_operation", "test_req_id")

			// Verify HTTP status code
			assert.Equal(t, tt.expectedCode, w.Code, "HTTP status code should match expected")

			// Parse response to verify error type
			var response api.HTTPErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err, "Should be able to parse JSON response")

			assert.Equal(t, tt.expectedType, response.Error, "Error type should match expected")
		})
	}
}
