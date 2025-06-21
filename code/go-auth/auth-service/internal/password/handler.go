package password

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// Handler provides HTTP endpoints for password management operations.
// This handler exposes RESTful APIs for password changes, resets, and validation
// with comprehensive input validation, error handling, and security measures.
//
// Endpoints provided:
// - POST /api/v1/password/change - Change user password (authenticated)
// - POST /api/v1/password/reset/request - Request password reset (public)
// - POST /api/v1/password/reset/complete - Complete password reset (public)
// - POST /api/v1/password/validate - Validate password strength (public)
// - GET /api/v1/password/requirements - Get password requirements (public)
//
// Security features:
// - JWT authentication for password changes
// - Rate limiting protection (via middleware)
// - Input validation and sanitization
// - Structured error responses
// - Comprehensive audit logging
// - CORS and security headers support
//
// Error handling:
// - Consistent JSON error responses
// - Appropriate HTTP status codes
// - Security-conscious error messages
// - Detailed logging for debugging
//
// Dependencies:
// - Service: Password business logic service
// - Logger: Structured logging for requests and errors
// - Config: Service configuration
type Handler struct {
	service *Service
	logger  *logrus.Logger
	config  *config.Config
}

// NewHandler creates a new password HTTP handler with the specified dependencies.
// This constructor validates all dependencies and initializes the handler
// for secure HTTP request processing.
//
// Parameters:
//   - service: Password service for business logic
//   - logger: Structured logger for HTTP requests and errors
//   - config: Service configuration
//
// Returns:
//   - Configured password handler
//   - Error if any dependency is invalid
//
// Example usage:
//
//	passwordHandler, err := password.NewHandler(passwordService, logger, config)
//	if err != nil {
//	    log.Fatal("Failed to create password handler:", err)
//	}
//
//	router := mux.NewRouter()
//	passwordHandler.RegisterRoutes(router)
func NewHandler(service *Service, logger *logrus.Logger, config *config.Config) (*Handler, error) {
	if service == nil {
		return nil, fmt.Errorf("password service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	return &Handler{
		service: service,
		logger:  logger,
		config:  config,
	}, nil
}

// RegisterRoutes registers all password-related HTTP routes with the router.
// This method sets up all endpoints with proper middleware and handlers.
//
// Parameters:
//   - router: Gin router group to register routes with
//
// Routes registered:
//   - POST /password/change (requires authentication)
//   - POST /password/reset/request (public)
//   - POST /password/reset/complete (public)
//   - POST /password/validate (public)
//   - GET /password/requirements (public)
//
// Example usage:
//
//	v1 := router.Group("/api/v1")
//	passwordHandler.RegisterRoutes(v1)
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	// Password change endpoint (requires authentication)
	router.PUT("/password/change", h.ChangePassword)

	// Password reset endpoints (public)
	router.POST("/password/forgot", h.RequestPasswordReset)
	router.POST("/password/reset", h.CompletePasswordReset)

	// Password validation endpoints (public)
	router.POST("/password/validate", h.ValidatePassword)
	router.GET("/password/requirements", h.GetPasswordRequirements)
}

// ChangePasswordRequest represents the request payload for password changes.
// This struct defines the expected JSON structure for password change operations.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,min=1,max=256"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// RequestPasswordResetRequest represents the request payload for password reset requests.
// This struct defines the expected JSON structure for initiating password resets.
type RequestPasswordResetRequest struct {
	Email string `json:"email" validate:"required,email,max=256"`
}

// CompletePasswordResetRequest represents the request payload for completing password resets.
// This struct defines the expected JSON structure for password reset completion.
type CompletePasswordResetRequest struct {
	Token       string `json:"token" validate:"required,min=1,max=256"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
}

// ValidatePasswordRequest represents the request payload for password validation.
// This struct defines the expected JSON structure for password strength validation.
type ValidatePasswordRequest struct {
	Password  string `json:"password" validate:"required,min=1,max=128"`
	UserEmail string `json:"user_email,omitempty" validate:"omitempty,email,max=256"`
	UserName  string `json:"user_name,omitempty" validate:"omitempty,max=256"`
}

// PasswordValidationResponse represents the response for password validation.
// This struct provides detailed feedback about password strength and requirements.
type PasswordValidationResponse struct {
	Valid           bool     `json:"valid"`
	Score           int      `json:"score"`
	Errors          []string `json:"errors,omitempty"`
	Suggestions     []string `json:"suggestions,omitempty"`
	Requirements    []string `json:"requirements"`
	MetRequirements []string `json:"met_requirements"`
}

// ChangePassword handles password change requests for authenticated users.
// This endpoint requires current password verification and implements
// comprehensive security measures.
//
// HTTP Method: POST
// Path: /password/change
// Authentication: Required (JWT token)
// Content-Type: application/json
//
// Request Body:
//
//	{
//	    "current_password": "currentPassword123",
//	    "new_password": "newSecurePassword456!"
//	}
//
// Response (200 OK):
//
//	{
//	    "success": true,
//	    "message": "Password changed successfully"
//	}
//
// Response (400 Bad Request):
//
//	{
//	    "success": false,
//	    "message": "Invalid request",
//	    "error": {
//	        "code": "VALIDATION_ERROR",
//	        "message": "Request validation failed",
//	        "details": "New password must be at least 8 characters"
//	    }
//	}
//
// Response (401 Unauthorized):
//
//	{
//	    "success": false,
//	    "message": "Invalid credentials",
//	    "error": {
//	        "code": "INVALID_CREDENTIALS",
//	        "message": "Current password is incorrect"
//	    }
//	}
//
// Security considerations:
// - Requires valid JWT authentication
// - Current password verification prevents unauthorized changes
// - All refresh tokens are revoked after successful change
// - Comprehensive audit logging
// - Rate limiting protection (via middleware)
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (h *Handler) ChangePassword(c *gin.Context) {
	// Extract client information for audit logging
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"endpoint":   "/password/change",
		"method":     c.Request.Method,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password change request received")

	// Get authenticated user ID from context (set by auth middleware)
	userIDStr, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in request context")
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "Authentication required",
			"error": gin.H{
				"code":    "AUTHENTICATION_REQUIRED",
				"message": "Authentication required",
			},
		})
		return
	}

	userID, ok := userIDStr.(uuid.UUID)
	if !ok {
		h.logger.Error("Invalid user ID format in context")
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "Authentication required",
			"error": gin.H{
				"code":    "AUTHENTICATION_REQUIRED",
				"message": "Authentication required",
			},
		})
		return
	}

	// Parse and validate request body
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Failed to parse password change request")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid JSON in request body",
			"error": gin.H{
				"code":    "INVALID_JSON",
				"message": "Invalid JSON in request body",
				"details": err.Error(),
			},
		})
		return
	}

	// Validate input fields
	if err := h.validateChangePasswordRequest(&req); err != nil {
		h.logger.WithError(err).Warn("Password change request validation failed")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Request validation failed",
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Request validation failed",
				"details": err.Error(),
			},
		})
		return
	}

	// Perform password change
	if err := h.service.ChangePassword(c.Request.Context(), userID, req.CurrentPassword, req.NewPassword, clientIP, userAgent); err != nil {
		h.handlePasswordError(c, err, "password change")
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Password changed successfully",
	})
}

// RequestPasswordReset handles password reset requests.
// This endpoint initiates the password reset flow by sending a reset email.
//
// HTTP Method: POST
// Path: /password/reset/request
// Authentication: Not required
// Content-Type: application/json
//
// Request Body:
//
//	{
//	    "email": "user@example.com"
//	}
//
// Response (200 OK):
//
//	{
//	    "success": true,
//	    "message": "If the email address is registered, a password reset link will be sent"
//	}
//
// Security considerations:
// - Always returns success to prevent email enumeration
// - Rate limiting protection (via middleware)
// - Input validation and sanitization
// - Comprehensive audit logging
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (h *Handler) RequestPasswordReset(c *gin.Context) {
	// Extract client information for audit logging
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"endpoint":   "/password/reset/request",
		"method":     c.Request.Method,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset request received")

	// Parse and validate request body
	var req RequestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Failed to parse password reset request")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid JSON in request body",
			"error": gin.H{
				"code":    "INVALID_JSON",
				"message": "Invalid JSON in request body",
				"details": err.Error(),
			},
		})
		return
	}

	// Validate input fields
	if err := h.validateResetRequestRequest(&req); err != nil {
		h.logger.WithError(err).Warn("Password reset request validation failed")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Request validation failed",
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Request validation failed",
				"details": err.Error(),
			},
		})
		return
	}

	// Process password reset request
	if err := h.service.RequestPasswordReset(c.Request.Context(), req.Email, clientIP, userAgent); err != nil {
		h.logger.WithError(err).Error("Password reset request failed")
		// Always return success to prevent enumeration attacks
	}

	// Always return success response
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "If the email address is registered, a password reset link will be sent",
	})
}

// CompletePasswordReset handles password reset completion.
// This endpoint completes the password reset flow using a reset token.
//
// HTTP Method: POST
// Path: /password/reset/complete
// Authentication: Not required
// Content-Type: application/json
//
// Request Body:
//
//	{
//	    "token": "secure_reset_token",
//	    "new_password": "newSecurePassword123!"
//	}
//
// Response (200 OK):
//
//	{
//	    "success": true,
//	    "message": "Password reset completed successfully"
//	}
//
// Response (400 Bad Request):
//
//	{
//	    "success": false,
//	    "message": "Invalid or expired token",
//	    "error": {
//	        "code": "INVALID_TOKEN",
//	        "message": "Reset token is invalid or expired"
//	    }
//	}
//
// Security considerations:
// - Token validation with expiration checking
// - Password strength validation
// - All user tokens revoked after successful reset
// - Comprehensive audit logging
// - Rate limiting protection (via middleware)
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (h *Handler) CompletePasswordReset(c *gin.Context) {
	// Extract client information for audit logging
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"endpoint":   "/password/reset/complete",
		"method":     c.Request.Method,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset completion request received")

	// Parse and validate request body
	var req CompletePasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Failed to parse password reset completion request")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid JSON in request body",
			"error": gin.H{
				"code":    "INVALID_JSON",
				"message": "Invalid JSON in request body",
				"details": err.Error(),
			},
		})
		return
	}

	// Validate input fields
	if err := h.validateResetCompleteRequest(&req); err != nil {
		h.logger.WithError(err).Warn("Password reset completion request validation failed")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Request validation failed",
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Request validation failed",
				"details": err.Error(),
			},
		})
		return
	}

	// Complete password reset
	if err := h.service.CompletePasswordReset(c.Request.Context(), req.Token, req.NewPassword, clientIP, userAgent); err != nil {
		h.handlePasswordError(c, err, "password reset completion")
		return
	}

	// Return success response
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Password reset completed successfully",
	})
}

// ValidatePassword handles password validation requests.
// This endpoint provides password strength validation and feedback.
//
// HTTP Method: POST
// Path: /password/validate
// Authentication: Not required
// Content-Type: application/json
//
// Request Body:
//
//	{
//	    "password": "MyPassword123!",
//	    "user_email": "user@example.com",
//	    "user_name": "John Doe"
//	}
//
// Response (200 OK):
//
//	{
//	    "success": true,
//	    "message": "Password validation completed",
//	    "data": {
//	        "valid": true,
//	        "score": 85,
//	        "requirements": ["At least 8 characters", "Contains uppercase", "Contains lowercase", "Contains numbers", "Contains special characters"],
//	        "met_requirements": ["At least 8 characters", "Contains uppercase", "Contains lowercase", "Contains numbers", "Contains special characters"]
//	    }
//	}
//
// Response (200 OK - Invalid Password):
//
//	{
//	    "success": true,
//	    "message": "Password validation completed",
//	    "data": {
//	        "valid": false,
//	        "score": 40,
//	        "errors": ["Password must contain at least one special character"],
//	        "suggestions": ["Add special characters like !@#$%^&*", "Consider using a longer password"],
//	        "requirements": ["At least 8 characters", "Contains uppercase", "Contains lowercase", "Contains numbers", "Contains special characters"],
//	        "met_requirements": ["At least 8 characters", "Contains uppercase", "Contains lowercase", "Contains numbers"]
//	    }
//	}
//
// Security considerations:
// - Does not store or log the actual password
// - Provides helpful feedback without exposing internals
// - Context-aware validation to prevent personal info in passwords
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
func (h *Handler) ValidatePassword(c *gin.Context) {
	// Extract client information for logging (don't log password)
	clientIP := c.ClientIP()

	h.logger.WithFields(logrus.Fields{
		"endpoint":  "/password/validate",
		"method":    c.Request.Method,
		"client_ip": clientIP,
	}).Info("Password validation request received")

	// Parse and validate request body
	var req ValidatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).Warn("Failed to parse password validation request")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid JSON in request body",
			"error": gin.H{
				"code":    "INVALID_JSON",
				"message": "Invalid JSON in request body",
				"details": err.Error(),
			},
		})
		return
	}

	// Validate input fields (but don't log the password)
	if err := h.validatePasswordValidationRequest(&req); err != nil {
		h.logger.WithError(err).Warn("Password validation request validation failed")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Request validation failed",
			"error": gin.H{
				"code":    "VALIDATION_ERROR",
				"message": "Request validation failed",
				"details": err.Error(),
			},
		})
		return
	}

	// Perform password validation
	var validationErr error
	if req.UserEmail != "" || req.UserName != "" {
		validationErr = h.service.ValidatePasswordWithContext(req.Password, req.UserEmail, req.UserName)
	} else {
		validationErr = h.service.ValidatePassword(req.Password)
	}

	// Calculate password strength score
	score := h.service.GetPasswordStrengthScore(req.Password)

	// Build response
	response := PasswordValidationResponse{
		Valid:           validationErr == nil,
		Score:           score,
		Requirements:    h.getPasswordRequirements(),
		MetRequirements: h.getMetRequirements(req.Password),
	}

	if validationErr != nil {
		response.Errors = []string{validationErr.Error()}
		response.Suggestions = h.getPasswordSuggestions(req.Password, score)
	}

	// Return validation response
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Password validation completed",
		"data":    response,
	})
}

// GetPasswordRequirements returns the current password requirements.
// This endpoint provides clients with the dynamic password policy to
// build user-friendly password creation interfaces.
//
// HTTP Method: GET
// Path: /password/requirements
// Authentication: Not required (public endpoint)
// Content-Type: application/json
//
// Response (200 OK):
//
//	{
//	    "success": true,
//	    "message": "Password requirements retrieved",
//	    "data": {
//	        "min_length": 8,
//	        "max_length": 128,
//	        "require_uppercase": true,
//	        "require_lowercase": true,
//	        "require_digits": true,
//	        "require_special_chars": true,
//	        "special_char_set": "!@#$%^&*()_+-=[]{}|;:,.<>?",
//	        "requirements": [
//	            "At least 8 characters long",
//	            "At least one uppercase letter",
//	            "At least one lowercase letter",
//	            "At least one digit",
//	            "At least one special character"
//	        ]
//	    }
//	}
//
// Use cases:
// - Frontend password strength indicators
// - Dynamic validation messages
// - User onboarding and help systems
// - Third-party integration requirements
//
// Security considerations:
// - Public endpoint, no authentication required
// - No sensitive information disclosed
// - Helps users create stronger passwords
// - Can be cached by clients for performance
//
// Example usage:
//
//	fetch('/api/v1/auth/password/requirements')
//	  .then(response => response.json())
//	  .then(data => {
//	    // Build password requirements UI
//	    displayPasswordRequirements(data.data.requirements);
//	  });
func (h *Handler) GetPasswordRequirements(c *gin.Context) {
	h.logger.WithFields(logrus.Fields{
		"endpoint": "/password/requirements",
		"method":   c.Request.Method,
	}).Info("Password requirements request received")

	// Get password requirements from service
	requirements := h.service.GetPasswordRequirements()

	// Return requirements response
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Password requirements retrieved",
		"data":    requirements,
	})
}

// Helper methods for request validation

// validateChangePasswordRequest validates the password change request structure.
func (h *Handler) validateChangePasswordRequest(req *ChangePasswordRequest) error {
	if strings.TrimSpace(req.CurrentPassword) == "" {
		return fmt.Errorf("current password is required")
	}
	if len(req.CurrentPassword) > 256 {
		return fmt.Errorf("current password is too long")
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		return fmt.Errorf("new password is required")
	}
	if len(req.NewPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}
	if len(req.NewPassword) > 128 {
		return fmt.Errorf("new password is too long")
	}
	return nil
}

// validateResetRequestRequest validates the password reset request structure.
func (h *Handler) validateResetRequestRequest(req *RequestPasswordResetRequest) error {
	if strings.TrimSpace(req.Email) == "" {
		return fmt.Errorf("email address is required")
	}
	if len(req.Email) > 256 {
		return fmt.Errorf("email address is too long")
	}
	if !strings.Contains(req.Email, "@") {
		return fmt.Errorf("email address is invalid")
	}
	return nil
}

// validateResetCompleteRequest validates the password reset completion request structure.
func (h *Handler) validateResetCompleteRequest(req *CompletePasswordResetRequest) error {
	if strings.TrimSpace(req.Token) == "" {
		return fmt.Errorf("reset token is required")
	}
	if len(req.Token) > 256 {
		return fmt.Errorf("reset token is too long")
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		return fmt.Errorf("new password is required")
	}
	if len(req.NewPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}
	if len(req.NewPassword) > 128 {
		return fmt.Errorf("new password is too long")
	}
	return nil
}

// validatePasswordValidationRequest validates the password validation request structure.
func (h *Handler) validatePasswordValidationRequest(req *ValidatePasswordRequest) error {
	if strings.TrimSpace(req.Password) == "" {
		return fmt.Errorf("password is required")
	}
	if len(req.Password) > 128 {
		return fmt.Errorf("password is too long")
	}
	if req.UserEmail != "" && len(req.UserEmail) > 256 {
		return fmt.Errorf("user email is too long")
	}
	if req.UserName != "" && len(req.UserName) > 256 {
		return fmt.Errorf("user name is too long")
	}
	return nil
}

// Helper methods for response handling

// handlePasswordError converts service errors to appropriate HTTP responses.
// This method uses errors.Is() to properly handle wrapped errors from the
// password validation system, ensuring detailed error messages reach the client.
//
// Parameters:
//   - c: Gin context for HTTP response
//   - err: Error from password service operations
//   - operation: Description of the operation for logging
//
// HTTP Response Mapping:
//   - ErrUserNotFound: 404 Not Found
//   - ErrInvalidCredentials: 401 Unauthorized
//   - ErrWeakPassword: 400 Bad Request (with detailed validation errors)
//   - ErrAccountInactive: 403 Forbidden
//   - ErrTokenExpired: 400 Bad Request
//   - ErrInvalidToken/ErrTokenNotFound: 400 Bad Request
//   - Other errors: 500 Internal Server Error
//
// Security considerations:
// - Password validation errors include detailed requirements to help users
// - Authentication errors are generic to prevent information disclosure
// - All errors are logged for security monitoring
//
// Example password validation error response:
//
//	{
//	  "success": false,
//	  "message": "Password does not meet requirements",
//	  "error": {
//	    "code": "WEAK_PASSWORD",
//	    "message": "Password does not meet requirements",
//	    "details": "password must contain at least one uppercase letter"
//	  }
//	}
func (h *Handler) handlePasswordError(c *gin.Context, err error, operation string) {
	// Use errors.Is() to properly handle wrapped errors from password validation
	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "User not found",
			"error": gin.H{
				"code":    "USER_NOT_FOUND",
				"message": "User not found",
			},
		})
	case errors.Is(err, domain.ErrInvalidCredentials):
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "Invalid credentials",
			"error": gin.H{
				"code":    "INVALID_CREDENTIALS",
				"message": "Invalid credentials",
			},
		})
	case errors.Is(err, domain.ErrWeakPassword):
		// Extract the detailed error message for password validation feedback
		var errorDetails string
		if err.Error() != domain.ErrWeakPassword.Error() {
			// Remove the base error prefix to get the specific validation message
			errorDetails = strings.TrimPrefix(err.Error(), domain.ErrWeakPassword.Error()+": ")
		} else {
			errorDetails = "Password does not meet security requirements"
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Password does not meet requirements",
			"error": gin.H{
				"code":    "WEAK_PASSWORD",
				"message": "Password does not meet requirements",
				"details": errorDetails,
			},
		})
	case errors.Is(err, domain.ErrAccountInactive):
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "Account is inactive",
			"error": gin.H{
				"code":    "ACCOUNT_INACTIVE",
				"message": "Account is inactive",
			},
		})
	case errors.Is(err, domain.ErrTokenExpired):
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Reset token has expired",
			"error": gin.H{
				"code":    "TOKEN_EXPIRED",
				"message": "Reset token has expired",
			},
		})
	case errors.Is(err, domain.ErrInvalidToken), errors.Is(err, domain.ErrTokenNotFound):
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Reset token is invalid",
			"error": gin.H{
				"code":    "INVALID_TOKEN",
				"message": "Reset token is invalid",
			},
		})
	default:
		h.logger.WithError(err).Errorf("Unexpected error during %s", operation)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "An internal error occurred",
			"error": gin.H{
				"code":    "INTERNAL_ERROR",
				"message": "An internal error occurred",
			},
		})
	}
}

// getPasswordRequirements returns a list of password requirements for display.
func (h *Handler) getPasswordRequirements() []string {
	return []string{
		"At least 8 characters long",
		"Contains at least one uppercase letter",
		"Contains at least one lowercase letter",
		"Contains at least one number",
		"Contains at least one special character",
		"Does not contain personal information",
	}
}

// getMetRequirements returns which requirements the password meets.
func (h *Handler) getMetRequirements(password string) []string {
	var met []string

	if len(password) >= 8 {
		met = append(met, "At least 8 characters long")
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		if char >= 'A' && char <= 'Z' {
			hasUpper = true
		} else if char >= 'a' && char <= 'z' {
			hasLower = true
		} else if char >= '0' && char <= '9' {
			hasDigit = true
		} else if strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char) {
			hasSpecial = true
		}
	}

	if hasUpper {
		met = append(met, "Contains at least one uppercase letter")
	}
	if hasLower {
		met = append(met, "Contains at least one lowercase letter")
	}
	if hasDigit {
		met = append(met, "Contains at least one number")
	}
	if hasSpecial {
		met = append(met, "Contains at least one special character")
	}

	return met
}

// getPasswordSuggestions returns suggestions for improving password strength.
func (h *Handler) getPasswordSuggestions(password string, score int) []string {
	var suggestions []string

	if len(password) < 12 {
		suggestions = append(suggestions, "Consider using a longer password (12+ characters)")
	}

	if score < 60 {
		suggestions = append(suggestions, "Add more character variety (uppercase, lowercase, numbers, symbols)")
	}

	if !strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
		suggestions = append(suggestions, "Add special characters like !@#$%^&*")
	}

	if score < 40 {
		suggestions = append(suggestions, "Avoid common patterns and dictionary words")
		suggestions = append(suggestions, "Consider using a passphrase with multiple words")
	}

	return suggestions
}
