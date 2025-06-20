package api

import (
	"fmt"
	"net/http"
	"strings"
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
		h.errorResponse(c, http.StatusUnauthorized, "unauthorized", "Invalid or missing authentication token", err, requestID)
		return
	}

	// Call service layer for logout (revoke all refresh tokens for user)
	err = h.authService.LogoutAll(c.Request.Context(), userID, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "logout", requestID)
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

// UpdateProfile godoc
//
// @Summary      Update user profile
// @Description  Updates the authenticated user's profile information. Supports partial updates.
// @Description  Only provided fields will be updated. Email changes trigger re-verification.
// @Description  All updates are logged for audit purposes.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        profile  body      domain.UpdateProfileRequest  true  "Profile update data"
// @Success      200      {object}  domain.UserResponse         "Profile updated successfully"
// @Failure      400      {object}  domain.ErrorResponse        "Invalid input data"
// @Failure      401      {object}  domain.ErrorResponse        "Unauthorized - invalid or missing token"
// @Failure      409      {object}  domain.ErrorResponse        "Email already exists"
// @Failure      500      {object}  domain.ErrorResponse        "Internal server error"
// @Router       /auth/me [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	// Generate request ID for logging and tracking
	requestID := h.getRequestID(c)
	h.logger.WithField("request_id", requestID).Info("Profile update request received")

	// Extract user ID from JWT token (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorResponse(c, http.StatusUnauthorized, "unauthorized", "Invalid authentication token", err, requestID)
		return
	}

	// Parse and validate request body
	var req domain.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to parse request body")
		h.errorResponse(c, http.StatusBadRequest, "invalid_input", "Failed to parse request body: "+err.Error(), err, requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.errorResponse(c, http.StatusBadRequest, "validation_error", err.Error(), err, requestID)
		return
	}

	// Check if at least one field is provided for update
	if req.Email == nil && req.FirstName == nil && req.LastName == nil {
		h.errorResponse(c, http.StatusBadRequest, "invalid_input", "At least one field must be provided for update", nil, requestID)
		return
	}

	// Get current user details
	existingUser, err := h.authService.GetUserByID(c.Request.Context(), userID.String())
	if err != nil {
		if err == domain.ErrUserNotFound {
			h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("User not found")
			h.errorResponse(c, http.StatusUnauthorized, "unauthorized", "User not found", err, requestID)
			return
		}
		h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("Failed to retrieve user details")
		h.errorResponse(c, http.StatusInternalServerError, "internal_error", "Failed to retrieve user details", err, requestID)
		return
	}

	// If email is being updated, check for uniqueness
	if req.Email != nil && *req.Email != existingUser.Email {
		_, err := h.authService.GetUserByEmail(c.Request.Context(), *req.Email)
		if err == nil {
			// Email already exists
			h.logger.WithField("request_id", requestID).WithField("email", *req.Email).Warn("Email already in use")
			h.errorResponse(c, http.StatusConflict, "email_conflict", "Email address is already in use", nil, requestID)
			return
		}
		if err != domain.ErrUserNotFound {
			// Database error
			h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to validate email uniqueness")
			h.errorResponse(c, http.StatusInternalServerError, "internal_error", "Failed to validate email uniqueness", err, requestID)
			return
		}
	}

	// Prepare update data - only include fields that are provided
	updateData := make(map[string]interface{})
	changedFields := []string{}

	if req.Email != nil && *req.Email != existingUser.Email {
		updateData["email"] = *req.Email
		updateData["is_email_verified"] = false // Email changes require re-verification
		changedFields = append(changedFields, "email")
	}

	if req.FirstName != nil && *req.FirstName != existingUser.FirstName {
		updateData["first_name"] = *req.FirstName
		changedFields = append(changedFields, "first_name")
	}

	if req.LastName != nil && *req.LastName != existingUser.LastName {
		updateData["last_name"] = *req.LastName
		changedFields = append(changedFields, "last_name")
	}

	// If no actual changes detected, return current user data
	if len(changedFields) == 0 {
		h.logger.WithField("request_id", requestID).WithField("user_id", userID).Info("No changes detected, returning current user data")
		response := domain.UserResponse{
			ID:              existingUser.ID,
			Email:           existingUser.Email,
			FirstName:       existingUser.FirstName,
			LastName:        existingUser.LastName,
			FullName:        existingUser.GetFullName(),
			IsEmailVerified: existingUser.IsEmailVerified,
			IsActive:        existingUser.IsActive,
			LastLoginAt:     existingUser.LastLoginAt,
			CreatedAt:       existingUser.CreatedAt,
			UpdatedAt:       existingUser.UpdatedAt,
		}
		c.JSON(http.StatusOK, response)
		return
	}

	// Update timestamp
	updateData["updated_at"] = time.Now()

	// Perform the update
	err = h.authService.UpdateProfile(c.Request.Context(), userID.String(), updateData)
	if err != nil {
		if err == domain.ErrEmailExists {
			h.errorResponse(c, http.StatusConflict, "email_conflict", "Email address is already in use", err, requestID)
			return
		}
		h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("Failed to update user profile")
		h.errorResponse(c, http.StatusInternalServerError, "internal_error", "Failed to update user profile", err, requestID)
		return
	}

	// Get updated user data
	updatedUser, err := h.authService.GetUserByID(c.Request.Context(), userID.String())
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("Failed to retrieve updated user details")
		h.errorResponse(c, http.StatusInternalServerError, "internal_error", "Failed to retrieve updated user details", err, requestID)
		return
	}

	// Log the profile update for audit purposes
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	auditLog := &domain.AuditLog{
		UserID:           &userID,
		EventType:        "profile_update",
		EventDescription: fmt.Sprintf("Updated fields: %s", strings.Join(changedFields, ", ")),
		IPAddress:        clientIP,
		UserAgent:        userAgent,
		Success:          true,
		CreatedAt:        time.Now(),
	}

	// Log audit event (non-blocking - don't fail request if audit logging fails)
	if err := h.authService.LogAuditEvent(c.Request.Context(), auditLog); err != nil {
		// Log error but don't fail the request
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to create audit log")
	}

	// Return updated user data
	response := domain.UserResponse{
		ID:              updatedUser.ID,
		Email:           updatedUser.Email,
		FirstName:       updatedUser.FirstName,
		LastName:        updatedUser.LastName,
		FullName:        updatedUser.GetFullName(),
		IsEmailVerified: updatedUser.IsEmailVerified,
		IsActive:        updatedUser.IsActive,
		LastLoginAt:     updatedUser.LastLoginAt,
		CreatedAt:       updatedUser.CreatedAt,
		UpdatedAt:       updatedUser.UpdatedAt,
	}

	h.logger.WithField("request_id", requestID).WithField("user_id", userID).WithField("changed_fields", changedFields).Info("Profile updated successfully")
	c.JSON(http.StatusOK, response)
}

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

// validateStruct validates a struct using validator tags.
// This function performs comprehensive validation of request DTOs
// using the go-playground/validator library to ensure data integrity
// before processing business logic.
//
// Validation features:
// - Required field validation
// - Format validation (email, etc.)
// - Length constraints (min/max)
// - Custom validation rules
// - Field cross-validation (password confirmation)
//
// Parameters:
//   - s: Interface containing the struct to validate
//
// Returns:
//   - Error with detailed validation messages if validation fails
//   - nil if validation passes
//
// Example validation tags supported:
//   - required: Field must not be empty
//   - email: Must be valid email format
//   - min=8: Minimum length of 8 characters
//   - max=255: Maximum length of 255 characters
//   - eqfield=Password: Must equal the Password field
func (h *AuthHandler) validateStruct(s interface{}) error {
	// For now, implement basic validation manually
	// TODO: Integrate go-playground/validator for comprehensive validation

	switch v := s.(type) {
	case *domain.RegisterRequest:
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}
		if v.Password == "" {
			return fmt.Errorf("password is required")
		}
		if len(v.Password) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}
		if v.PasswordConfirm == "" {
			return fmt.Errorf("password_confirm is required")
		}
		if v.Password != v.PasswordConfirm {
			return fmt.Errorf("password and password_confirm must match")
		}
		if v.FirstName == "" {
			return fmt.Errorf("first_name is required")
		}
		if len(v.FirstName) > 100 {
			return fmt.Errorf("first_name must be no more than 100 characters")
		}
		if v.LastName == "" {
			return fmt.Errorf("last_name is required")
		}
		if len(v.LastName) > 100 {
			return fmt.Errorf("last_name must be no more than 100 characters")
		}
		// Basic email format check
		if !strings.Contains(v.Email, "@") || !strings.Contains(v.Email, ".") {
			return fmt.Errorf("email must be a valid email address")
		}
		if len(v.Email) > 255 {
			return fmt.Errorf("email must be no more than 255 characters")
		}

	case *domain.LoginRequest:
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}
		if v.Password == "" {
			return fmt.Errorf("password is required")
		}
		// Basic email format check
		if !strings.Contains(v.Email, "@") || !strings.Contains(v.Email, ".") {
			return fmt.Errorf("email must be a valid email address")
		}

	case *domain.ResetPasswordRequest:
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}
		// Basic email format check
		if !strings.Contains(v.Email, "@") || !strings.Contains(v.Email, ".") {
			return fmt.Errorf("email must be a valid email address")
		}

	case *domain.ConfirmResetPasswordRequest:
		if v.Token == "" {
			return fmt.Errorf("token is required")
		}
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}
		if v.NewPassword == "" {
			return fmt.Errorf("new_password is required")
		}
		if len(v.NewPassword) < 8 {
			return fmt.Errorf("new_password must be at least 8 characters")
		}
		if v.NewPasswordConfirm == "" {
			return fmt.Errorf("new_password_confirm is required")
		}
		if v.NewPassword != v.NewPasswordConfirm {
			return fmt.Errorf("new_password and new_password_confirm must match")
		}
	}

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

// getUserIDFromContext extracts the user ID from the Gin context.
// This function retrieves the user ID that was set by the authentication middleware
// after validating the JWT token in the Authorization header.
//
// The user ID can be stored in different formats in the context:
// - As a uuid.UUID type directly
// - As a string that needs to be parsed into UUID
//
// Parameters:
//   - c: Gin context containing the request and middleware data
//
// Returns:
//   - User UUID if found in context
//   - Error if user ID is missing or invalid format
//
// Security considerations:
// - Only works after authentication middleware has validated the JWT
// - Returns error if no valid user session is found
// - Ensures user ID format consistency across the application
func (h *AuthHandler) getUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	// Try to get user ID from context (set by auth middleware)
	userIDValue, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, fmt.Errorf("user ID not found in context")
	}

	// Convert to UUID
	switch v := userIDValue.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(v)
	default:
		return uuid.Nil, fmt.Errorf("invalid user ID format in context")
	}
}
