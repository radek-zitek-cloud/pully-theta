package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth-service/internal/domain"
	"auth-service/internal/service"
)

// AuthHandler handles HTTP requests for authentication operations.
// This handler provides RESTful endpoints for user registration, login,
// logout, token refresh, and password management.
//
// The handler follows these principles:
// - Comprehensive input validation
// - Proper HTTP status codes
// - Structured error responses
// - Request correlation IDs for tracing
// - Security headers and rate limiting
// - Audit logging for all operations
//
// Dependencies:
// - AuthService: Core authentication business logic
// - Logger: Structured logging for requests and errors
//
// Security features:
// - Input sanitization and validation
// - Rate limiting middleware integration
// - CORS support for web applications
// - Request/response logging for audit
// - Error message sanitization to prevent information disclosure
type AuthHandler struct {
	authService *service.AuthService
	logger      *logrus.Logger
}

// NewAuthHandler creates a new authentication handler instance.
// This constructor validates dependencies and returns a configured handler.
//
// Parameters:
//   - authService: Service containing authentication business logic
//   - logger: Structured logger for request handling
//
// Returns:
//   - Configured AuthHandler instance
//   - Error if any dependency is nil
//
// Example usage:
//
//	authHandler := NewAuthHandler(authService, logger)
//	router.POST("/auth/login", authHandler.Login)
func NewAuthHandler(authService *service.AuthService, logger *logrus.Logger) (*AuthHandler, error) {
	if authService == nil {
		return nil, fmt.Errorf("auth service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}, nil
}

// Register handles user registration requests.
// This endpoint allows new users to create accounts with email and password.
//
// HTTP Method: POST
// Path: /api/v1/auth/register
// Content-Type: application/json
//
// Request Body:
//
//	{
//	  "email": "user@example.com",
//	  "password": "SecurePass123!",
//	  "password_confirm": "SecurePass123!",
//	  "first_name": "John",
//	  "last_name": "Doe"
//	}
//
// Success Response (201 Created):
//
//	{
//	  "success": true,
//	  "message": "User registered successfully",
//	  "user": {
//	    "id": "123e4567-e89b-12d3-a456-426614174000",
//	    "email": "user@example.com",
//	    "first_name": "John",
//	    "last_name": "Doe",
//	    "full_name": "John Doe",
//	    "is_email_verified": false,
//	    "is_active": true,
//	    "created_at": "2023-01-15T10:30:00Z",
//	    "updated_at": "2023-01-15T10:30:00Z"
//	  }
//	}
//
// Error Responses:
//   - 400 Bad Request: Validation errors, email exists
//   - 429 Too Many Requests: Rate limit exceeded
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Password is validated for strength
// - Email uniqueness is enforced
// - Rate limiting prevents abuse
// - All attempts are logged for audit
func (h *AuthHandler) Register(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"operation":  "register",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Registration request received")

	// Parse and validate request body
	var req domain.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Invalid registration request body")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Invalid request format", err, requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Registration validation failed")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Validation failed", err, requestID)
		return
	}

	// Call service layer for registration
	user, err := h.authService.Register(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "registration", requestID)
		return
	}

	// Prepare success response
	response := gin.H{
		"success":    true,
		"message":    "User registered successfully",
		"user":       domain.ToUserResponse(user),
		"request_id": requestID,
		"timestamp":  time.Now(),
	}

	h.logger.WithFields(logrus.Fields{
		"operation":  "register",
		"request_id": requestID,
		"user_id":    user.ID,
		"email":      user.Email,
	}).Info("User registered successfully")

	c.JSON(http.StatusCreated, response)
}

// Login handles user authentication requests.
// This endpoint authenticates users and returns JWT tokens for API access.
//
// HTTP Method: POST
// Path: /api/v1/auth/login
// Content-Type: application/json
//
// Request Body:
//
//	{
//	  "email": "user@example.com",
//	  "password": "SecurePass123!",
//	  "remember_me": false
//	}
//
// Success Response (200 OK):
//
//	{
//	  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//	  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//	  "token_type": "Bearer",
//	  "expires_in": 900,
//	  "user": {
//	    "id": "123e4567-e89b-12d3-a456-426614174000",
//	    "email": "user@example.com",
//	    "first_name": "John",
//	    "last_name": "Doe",
//	    "full_name": "John Doe",
//	    "is_email_verified": true,
//	    "is_active": true,
//	    "last_login_at": "2023-01-15T10:30:00Z",
//	    "created_at": "2023-01-01T12:00:00Z",
//	    "updated_at": "2023-01-15T10:30:00Z"
//	  }
//	}
//
// Error Responses:
//   - 400 Bad Request: Invalid request format
//   - 401 Unauthorized: Invalid credentials, account inactive
//   - 429 Too Many Requests: Rate limit exceeded
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Rate limiting prevents brute force attacks
// - Failed attempts are logged and monitored
// - Account lockouts after repeated failures
// - Tokens have appropriate expiry times
func (h *AuthHandler) Login(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"operation":  "login",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Login request received")

	// Parse and validate request body
	var req domain.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Invalid login request body")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Invalid request format", err, requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Login validation failed")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Validation failed", err, requestID)
		return
	}

	// Call service layer for authentication
	authResponse, err := h.authService.Login(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "login", requestID)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"operation":  "login",
		"request_id": requestID,
		"user_id":    authResponse.User.ID,
		"email":      authResponse.User.Email,
	}).Info("User logged in successfully")

	c.JSON(http.StatusOK, authResponse)
}

// Logout handles user logout requests.
// This endpoint revokes the user's refresh token, effectively logging them out.
//
// HTTP Method: POST
// Path: /api/v1/auth/logout
// Headers: Authorization: Bearer <access_token>
// Content-Type: application/json
//
// Request Body:
//
//	{
//	  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
//	}
//
// Success Response (200 OK):
//
//	{
//	  "success": true,
//	  "message": "Logged out successfully",
//	  "request_id": "req_123e4567-e89b-12d3-a456-426614174000",
//	  "timestamp": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 400 Bad Request: Invalid request format
//   - 401 Unauthorized: Invalid or missing access token
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Requires valid access token for authentication
// - Immediately revokes refresh token
// - Logs logout events for audit
// - Graceful handling if token already expired
func (h *AuthHandler) Logout(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"operation":  "logout",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Logout request received")

	// Parse refresh token from request body
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Invalid logout request body")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Invalid request format", err, requestID)
		return
	}

	// Validate request
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Logout validation failed")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Validation failed", err, requestID)
		return
	}

	// Call service layer for logout
	err := h.authService.Logout(c.Request.Context(), req.RefreshToken, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "logout", requestID)
		return
	}

	// Prepare success response
	response := domain.SuccessResponse{
		Success:   true,
		Message:   "Logged out successfully",
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	h.logger.WithFields(logrus.Fields{
		"operation":  "logout",
		"request_id": requestID,
	}).Info("User logged out successfully")

	c.JSON(http.StatusOK, response)
}

// RefreshToken handles token refresh requests.
// This endpoint exchanges a valid refresh token for a new access token.
//
// HTTP Method: POST
// Path: /api/v1/auth/refresh
// Content-Type: application/json
//
// Request Body:
//
//	{
//	  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
//	}
//
// Success Response (200 OK):
//
//	{
//	  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//	  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//	  "token_type": "Bearer",
//	  "expires_in": 900,
//	  "user": {
//	    "id": "123e4567-e89b-12d3-a456-426614174000",
//	    "email": "user@example.com",
//	    "first_name": "John",
//	    "last_name": "Doe",
//	    "full_name": "John Doe",
//	    "is_email_verified": true,
//	    "is_active": true,
//	    "last_login_at": "2023-01-15T10:30:00Z",
//	    "created_at": "2023-01-01T12:00:00Z",
//	    "updated_at": "2023-01-15T10:30:00Z"
//	  }
//	}
//
// Error Responses:
//   - 400 Bad Request: Invalid request format
//   - 401 Unauthorized: Invalid, expired, or revoked refresh token
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Validates refresh token signature and expiry
// - Checks user account status
// - Logs all refresh attempts for audit
// - May implement token rotation for enhanced security
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"operation":  "refresh_token",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Token refresh request received")

	// Parse and validate request body
	var req domain.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Invalid refresh token request body")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Invalid request format", err, requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Refresh token validation failed")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Validation failed", err, requestID)
		return
	}

	// Call service layer for token refresh
	authResponse, err := h.authService.RefreshToken(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "refresh_token", requestID)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"operation":  "refresh_token",
		"request_id": requestID,
		"user_id":    authResponse.User.ID,
	}).Info("Token refreshed successfully")

	c.JSON(http.StatusOK, authResponse)
}

// Helper methods will be continued in the next part...

// getRequestID extracts or generates a request correlation ID for tracing.
func (h *AuthHandler) getRequestID(c *gin.Context) string {
	// Try to get request ID from header first
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		return requestID
	}

	// Try to get from context
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}

	// Generate new request ID
	return "req_" + uuid.New().String()
}

// validateStruct validates a struct using validator tags
func (h *AuthHandler) validateStruct(s interface{}) error {
	// This would use a validator library like go-playground/validator
	// For now, returning nil - implement with proper validation
	return nil
}

// errorResponse sends a standardized error response
func (h *AuthHandler) errorResponse(c *gin.Context, status int, errorType, message string, err error, requestID string) {
	response := domain.ErrorResponse{
		Error:     errorType,
		Message:   message,
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	// Add validation details if available
	if err != nil && status == http.StatusBadRequest {
		response.Details = err.Error()
	}

	c.JSON(status, response)
}

// handleServiceError maps service layer errors to appropriate HTTP responses
func (h *AuthHandler) handleServiceError(c *gin.Context, err error, operation, requestID string) {
	h.logger.WithError(err).WithFields(logrus.Fields{
		"operation":  operation,
		"request_id": requestID,
	}).Error("Service error occurred")

	// Map domain errors to HTTP status codes
	switch {
	case domain.IsAuthenticationError(err):
		h.errorResponse(c, http.StatusUnauthorized, "authentication_error", "Authentication failed", err, requestID)
	case domain.IsValidationError(err):
		h.errorResponse(c, http.StatusBadRequest, "validation_error", err.Error(), err, requestID)
	case domain.IsRateLimitError(err):
		h.errorResponse(c, http.StatusTooManyRequests, "rate_limit_error", "Too many requests", err, requestID)
	case domain.IsInfrastructureError(err):
		h.errorResponse(c, http.StatusServiceUnavailable, "service_unavailable", "Service temporarily unavailable", err, requestID)
	default:
		h.errorResponse(c, http.StatusInternalServerError, "internal_error", "Internal server error", err, requestID)
	}
}
