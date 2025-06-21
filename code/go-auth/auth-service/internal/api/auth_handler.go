package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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
// - HTTPErrorMapper: Centralized error handling and response mapping
// - Logger: Structured logging for requests and errors
//
// Security features:
// - Input sanitization and validation
// - Rate limiting middleware integration
// - CORS support for web applications
// - Request/response logging for audit
// - Error message sanitization to prevent information disclosure
// - Consistent error response format via centralized error mapper
//
// Architecture:
// The handler uses the HTTPErrorMapper for all error responses, ensuring
// consistent error handling, proper logging, and security considerations
// across all authentication endpoints.
type AuthHandler struct {
	authService *service.AuthService
	errorMapper *HTTPErrorMapper
	logger      *logrus.Logger
}

// NewAuthHandler creates a new authentication handler instance.
// This constructor validates dependencies and returns a configured handler
// with centralized error mapping for consistent error responses.
//
// Parameters:
//   - authService: Service containing authentication business logic
//   - logger: Structured logger for request handling
//
// Returns:
//   - Configured AuthHandler instance with HTTPErrorMapper
//   - Error if any dependency is nil
//
// Example usage:
//
//	authHandler, err := NewAuthHandler(authService, logger)
//	if err != nil {
//	    log.Fatal("Failed to create auth handler:", err)
//	}
//	router.POST("/auth/login", authHandler.Login)
//
// Architecture:
// The constructor automatically initializes the HTTPErrorMapper using the
// provided logger, ensuring all error responses follow the same format
// and security practices defined in the refactoring plan.
func NewAuthHandler(authService *service.AuthService, logger *logrus.Logger) (*AuthHandler, error) {
	if authService == nil {
		return nil, fmt.Errorf("auth service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	return &AuthHandler{
		authService: authService,
		errorMapper: NewHTTPErrorMapper(logger),
		logger:      logger,
	}, nil
}

// Register handles user registration requests.
// This endpoint allows new users to create accounts with email and password.
//
// @Summary      Register a new user
// @Description  Create a new user account with email, password, and profile information
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        user  body      domain.RegisterRequest  true  "User registration data"
// @Success      201   {object}  domain.RegisterResponse "User successfully registered"
// @Failure      400   {object}  domain.ErrorResponse    "Bad request - validation errors"
// @Failure      409   {object}  domain.ErrorResponse    "Conflict - email already exists"
// @Failure      429   {object}  domain.ErrorResponse    "Too many requests - rate limit exceeded"
// @Failure      500   {object}  domain.ErrorResponse    "Internal server error"
// @Router       /auth/register [post]
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
		h.errorMapper.MapError(c, err, "register_request_parsing", requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Registration validation failed")
		h.errorMapper.MapError(c, err, "register_validation", requestID)
		return
	}

	// Call service layer for registration
	user, err := h.authService.Register(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.errorMapper.MapError(c, err, "user_registration", requestID)
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
// @Summary      Authenticate user
// @Description  Authenticate user with email and password, returns JWT tokens
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        credentials  body      domain.LoginRequest   true  "User login credentials"
// @Success      200          {object}  domain.LoginResponse  "Authentication successful"
// @Failure      400          {object}  domain.ErrorResponse  "Bad request - validation errors"
// @Failure      401          {object}  domain.ErrorResponse  "Unauthorized - invalid credentials"
// @Failure      429          {object}  domain.ErrorResponse  "Too many requests - rate limit exceeded"
// @Failure      500          {object}  domain.ErrorResponse  "Internal server error"
// @Router       /auth/login [post]
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
		h.errorMapper.MapError(c, err, "login_request_parsing", requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Login validation failed")
		h.errorMapper.MapError(c, err, "login_validation", requestID)
		return
	}

	// Call service layer for authentication
	authResponse, err := h.authService.Login(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.errorMapper.MapError(c, err, "user_authentication", requestID)
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
//
// @Summary      Logout user
// @Description  Logout user and revoke refresh tokens to invalidate session. No request body required - only Authorization header with Bearer token.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200   {object}  domain.SuccessResponse  "Successfully logged out"
// @Failure      401   {object}  domain.ErrorResponse    "Unauthorized - invalid token"
// @Failure      500   {object}  domain.ErrorResponse    "Internal server error"
// @Router       /auth/logout [post]
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

	// Get user ID from JWT token in Authorization header (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorMapper.MapError(c, err, "logout_authentication", requestID)
		return
	}

	// Call service layer for logout (revoke all refresh tokens for user)
	err = h.authService.LogoutAll(c.Request.Context(), userID, clientIP, userAgent)
	if err != nil {
		h.errorMapper.MapError(c, err, "user_logout", requestID)
		return
	}

	// Prepare success response
	response := map[string]interface{}{
		"success":    true,
		"message":    "Logged out successfully",
		"request_id": requestID,
		"timestamp":  time.Now(),
	}

	h.logger.WithFields(logrus.Fields{
		"operation":  "logout",
		"request_id": requestID,
		"user_id":    userID,
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
//
// @Summary      Refresh access token
// @Description  Refresh access token using a valid refresh token
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        request  body      domain.RefreshTokenRequest  true  "Refresh token data"
// @Success      200      {object}  domain.LoginResponse        "New access token generated"
// @Failure      400      {object}  domain.ErrorResponse        "Bad request - invalid format"
// @Failure      401      {object}  domain.ErrorResponse        "Unauthorized - invalid or expired refresh token"
// @Failure      500      {object}  domain.ErrorResponse        "Internal server error"
// @Router       /auth/refresh [post]
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
		h.errorMapper.MapError(c, err, "refresh_token_request_parsing", requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Refresh token validation failed")
		h.errorMapper.MapError(c, err, "refresh_token_validation", requestID)
		return
	}

	// Call service layer for token refresh
	authResponse, err := h.authService.RefreshToken(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.errorMapper.MapError(c, err, "token_refresh", requestID)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"operation":  "refresh_token",
		"request_id": requestID,
		"user_id":    authResponse.User.ID,
	}).Info("Token refreshed successfully")

	c.JSON(http.StatusOK, authResponse)
}

// LogoutAll logs out the user from all devices by revoking all refresh tokens.
// This endpoint provides a way to terminate all active sessions for security purposes.
//
// @Summary      Logout from all devices
// @Description  Revoke all refresh tokens for the authenticated user, logging them out from all devices
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{} "Logout successful"
// @Failure      401  {object}  domain.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure      404  {object}  domain.ErrorResponse "User not found"
// @Failure      500  {object}  domain.ErrorResponse "Internal server error"
// @Router       /auth/logout-all [post]
//
// HTTP Method: POST
// Path: /api/v1/auth/logout-all
// Headers: Authorization: Bearer <access_token>
//
// Success Response (200 OK):
//
//	{
//	  "success": true,
//	  "message": "Successfully logged out from all devices",
//	  "request_id": "req_123e4567-e89b-12d3-a456-426614174000",
//	  "timestamp": "2023-01-15T10:30:00Z"
//	}
//
// Security considerations:
// - Requires valid JWT access token
// - Revokes all refresh tokens for the user
// - All existing sessions become invalid
// - Operation is logged for audit purposes
// - Cannot be undone - user must login again on all devices
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	// Generate request ID for tracking
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"operation":  "logout_all",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Logout-all request received")

	// Get user ID from JWT token in Authorization header (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorMapper.MapError(c, err, "logout_all_authentication", requestID)
		return
	}

	// Call service layer for logout-all (revoke all refresh tokens for user)
	err = h.authService.LogoutAll(c.Request.Context(), userID, clientIP, userAgent)
	if err != nil {
		h.errorMapper.MapError(c, err, "logout_all_execution", requestID)
		return
	}

	// Prepare success response
	response := map[string]interface{}{
		"success":    true,
		"message":    "Successfully logged out from all devices",
		"request_id": requestID,
		"timestamp":  time.Now().UTC(),
	}

	h.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"request_id": requestID,
	}).Info("User logged out from all devices successfully")

	c.JSON(http.StatusOK, response)
}
