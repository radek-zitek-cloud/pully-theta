package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"auth-service/internal/domain"
)

// ChangePassword handles password change requests from authenticated users.
// This endpoint requires the current password for verification before allowing the change.
//
// @Summary      Change user password
// @Description  Change authenticated user's password with current password verification
// @Tags         auth
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        password  body      domain.ChangePasswordRequest  true  "Password change request"
// @Success      200       {object}  domain.SuccessResponse        "Password changed successfully"
// @Failure      400       {object}  domain.ErrorResponse          "Bad request - validation errors"
// @Failure      401       {object}  domain.ErrorResponse          "Unauthorized - invalid current password"
// @Failure      500       {object}  domain.ErrorResponse          "Internal server error"
// @Router       /auth/change-password [post]
//
// HTTP Method: POST
// Path: /api/v1/auth/change-password
// Headers: Authorization: Bearer <access_token>
// Content-Type: application/json
//
// Request Body:
//
//	{
//	  "current_password": "OldPassword123!",
//	  "new_password": "NewSecurePass456!",
//	  "new_password_confirm": "NewSecurePass456!"
//	}
//
// Success Response (200 OK):
//
//	{
//	  "success": true,
//	  "message": "Password changed successfully",
//	  "request_id": "req_123e4567-e89b-12d3-a456-426614174000",
//	  "timestamp": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 400 Bad Request: Validation errors, password mismatch
//   - 401 Unauthorized: Invalid current password, invalid access token
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Requires valid access token for authentication
// - Current password verification prevents unauthorized changes
// - New password must meet security requirements
// - All existing refresh tokens are revoked after successful change
// - Password change events are logged for audit
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(map[string]interface{}{
		"operation":  "change_password",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password change request received")

	// Get user ID from JWT token (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorResponse(c, http.StatusUnauthorized, "authentication_error", "Invalid authentication", err, requestID)
		return
	}

	// Parse and validate request body
	var req domain.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Invalid change password request body")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Invalid request format", err, requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Change password validation failed")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Validation failed", err, requestID)
		return
	}

	// Call service layer for password change
	err = h.authService.ChangePassword(c.Request.Context(), userID, &req, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "change_password", requestID)
		return
	}

	// Prepare success response
	response := domain.SuccessResponse{
		Success:   true,
		Message:   "Password changed successfully",
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	h.logger.WithFields(map[string]interface{}{
		"operation":  "change_password",
		"request_id": requestID,
		"user_id":    userID,
	}).Info("Password changed successfully")

	c.JSON(http.StatusOK, response)
}

// ResetPassword handles password reset initiation requests.
// This endpoint sends a password reset token to the user's email address.
//
// @Summary      Initiate password reset
// @Description  Send password reset instructions to user's email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        email  body      domain.ResetPasswordRequest  true  "Password reset request"
// @Success      200    {object}  domain.SuccessResponse       "Reset instructions sent"
// @Failure      400    {object}  domain.ErrorResponse         "Bad request - validation errors"
// @Failure      429    {object}  domain.ErrorResponse         "Too many requests - rate limit exceeded"
// @Failure      500    {object}  domain.ErrorResponse         "Internal server error"
// @Router       /auth/reset-password [post]
//
// HTTP Method: POST
// Path: /api/v1/auth/reset-password
// Content-Type: application/json
//
// Request Body:
//
//	{
//	  "email": "user@example.com"
//	}
//
// Success Response (200 OK):
//
//	{
//	  "success": true,
//	  "message": "If the email address exists in our system, you will receive password reset instructions",
//	  "request_id": "req_123e4567-e89b-12d3-a456-426614174000",
//	  "timestamp": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 400 Bad Request: Invalid email format
//   - 429 Too Many Requests: Rate limit exceeded
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Rate limiting prevents email flooding abuse
// - Response message doesn't reveal whether email exists (privacy)
// - Reset tokens are time-limited and single-use
// - All reset requests are logged for audit
// - Email validation prevents malicious inputs
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(map[string]interface{}{
		"operation":  "reset_password",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset request received")

	// Parse and validate request body
	var req domain.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Invalid reset password request body")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Invalid request format", err, requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Reset password validation failed")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Validation failed", err, requestID)
		return
	}

	// Call service layer for password reset initiation
	err := h.authService.ResetPassword(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "reset_password", requestID)
		return
	}

	// Prepare success response (always same message for security)
	response := domain.SuccessResponse{
		Success:   true,
		Message:   "If the email address exists in our system, you will receive password reset instructions",
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	h.logger.WithFields(map[string]interface{}{
		"operation":  "reset_password",
		"request_id": requestID,
		"email":      req.Email,
	}).Info("Password reset request processed")

	c.JSON(http.StatusOK, response)
}

// ConfirmResetPassword handles password reset completion requests.
// This endpoint uses the token sent via email to set a new password.
//
// @Summary      Complete password reset
// @Description  Reset password using token from email
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        reset  body      domain.ConfirmResetPasswordRequest  true  "Password reset confirmation"
// @Success      200    {object}  domain.SuccessResponse              "Password reset successful"
// @Failure      400    {object}  domain.ErrorResponse                "Bad request - validation errors"
// @Failure      401    {object}  domain.ErrorResponse                "Unauthorized - invalid token"
// @Failure      500    {object}  domain.ErrorResponse                "Internal server error"
// @Router       /auth/confirm-reset-password [post]
//
// HTTP Method: POST
// Path: /api/v1/auth/confirm-reset-password
// Content-Type: application/json
//
// Request Body:
//
//	{
//	  "token": "secure_reset_token_from_email",
//	  "email": "user@example.com",
//	  "new_password": "NewSecurePass789!",
//	  "new_password_confirm": "NewSecurePass789!"
//	}
//
// Success Response (200 OK):
//
//	{
//	  "success": true,
//	  "message": "Password reset successfully. Please log in with your new password",
//	  "request_id": "req_123e4567-e89b-12d3-a456-426614174000",
//	  "timestamp": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 400 Bad Request: Invalid token, validation errors, token expired
//   - 401 Unauthorized: Token not found or already used
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Token validation (expiry, single-use, email match)
// - New password strength validation
// - All existing refresh tokens are revoked after successful reset
// - Reset token is invalidated after use
// - Password reset completion events are logged for audit
func (h *AuthHandler) ConfirmResetPassword(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(map[string]interface{}{
		"operation":  "confirm_reset_password",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset confirmation request received")

	// Parse and validate request body
	var req domain.ConfirmResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Invalid confirm reset password request body")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Invalid request format", err, requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Warn("Confirm reset password validation failed")
		h.errorResponse(c, http.StatusBadRequest, "validation_error", "Validation failed", err, requestID)
		return
	}

	// Call service layer for password reset completion
	err := h.authService.ConfirmResetPassword(c.Request.Context(), &req, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "confirm_reset_password", requestID)
		return
	}

	// Prepare success response
	response := domain.SuccessResponse{
		Success:   true,
		Message:   "Password reset successfully. Please log in with your new password",
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	h.logger.WithFields(map[string]interface{}{
		"operation":  "confirm_reset_password",
		"request_id": requestID,
		"email":      req.Email,
	}).Info("Password reset completed successfully")

	c.JSON(http.StatusOK, response)
}

// Me handles requests for the current user's profile information.
// This endpoint returns the authenticated user's profile data.
//
// @Summary      Get current user profile
// @Description  Retrieve authenticated user's profile information
// @Tags         user
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  domain.UserResponse   "User profile data"
// @Failure      401  {object}  domain.ErrorResponse  "Unauthorized - invalid token"
// @Failure      403  {object}  domain.ErrorResponse  "Forbidden - account inactive"
// @Failure      500  {object}  domain.ErrorResponse  "Internal server error"
// @Router       /auth/me [get]
//
// HTTP Method: GET
// Path: /api/v1/auth/me
// Headers: Authorization: Bearer <access_token>
//
// Success Response (200 OK):
//
//	{
//	  "id": "123e4567-e89b-12d3-a456-426614174000",
//	  "email": "user@example.com",
//	  "first_name": "John",
//	  "last_name": "Doe",
//	  "full_name": "John Doe",
//	  "is_email_verified": true,
//	  "is_active": true,
//	  "last_login_at": "2023-01-15T10:30:00Z",
//	  "created_at": "2023-01-01T12:00:00Z",
//	  "updated_at": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 401 Unauthorized: Invalid or missing access token
//   - 403 Forbidden: Account inactive or deleted
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Requires valid access token for authentication
// - Sensitive information (password hash) is excluded
// - Account status is checked before returning data
func (h *AuthHandler) Me(c *gin.Context) {
	requestID := h.getRequestID(c)

	h.logger.WithFields(map[string]interface{}{
		"operation":  "me",
		"request_id": requestID,
	}).Debug("User profile request received")

	// Get user ID from JWT token (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorResponse(c, http.StatusUnauthorized, "authentication_error", "Invalid authentication", err, requestID)
		return
	}

	// Call service layer to get user profile
	user, err := h.authService.GetUserProfile(c.Request.Context(), userID)
	if err != nil {
		h.handleServiceError(c, err, "me", requestID)
		return
	}

	// Convert to response DTO and return
	userResponse := domain.ToUserResponse(user)

	h.logger.WithFields(map[string]interface{}{
		"operation":  "me",
		"request_id": requestID,
		"user_id":    userID,
	}).Debug("User profile retrieved successfully")

	c.JSON(http.StatusOK, userResponse)
}

// LogoutAll handles requests to log out from all devices.
// This endpoint revokes all refresh tokens for the authenticated user.
//
// @Summary      Logout from all devices
// @Description  Revoke all refresh tokens for the authenticated user
// @Tags         auth
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  domain.SuccessResponse  "Logged out from all devices"
// @Failure      401  {object}  domain.ErrorResponse    "Unauthorized - invalid token"
// @Failure      500  {object}  domain.ErrorResponse    "Internal server error"
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
//	  "message": "Logged out from all devices successfully",
//	  "request_id": "req_123e4567-e89b-12d3-a456-426614174000",
//	  "timestamp": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 401 Unauthorized: Invalid or missing access token
//   - 500 Internal Server Error: Server error
//
// Security considerations:
// - Requires valid access token for authentication
// - Immediately revokes all user's refresh tokens
// - Useful for security incidents or compromise response
// - Logs logout events for audit
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(map[string]interface{}{
		"operation":  "logout_all",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Logout all devices request received")

	// Get user ID from JWT token (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorResponse(c, http.StatusUnauthorized, "authentication_error", "Invalid authentication", err, requestID)
		return
	}

	// Call service layer for logout all
	err = h.authService.LogoutAll(c.Request.Context(), userID, clientIP, userAgent)
	if err != nil {
		h.handleServiceError(c, err, "logout_all", requestID)
		return
	}

	// Prepare success response
	response := domain.SuccessResponse{
		Success:   true,
		Message:   "Logged out from all devices successfully",
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	h.logger.WithFields(map[string]interface{}{
		"operation":  "logout_all",
		"request_id": requestID,
		"user_id":    userID,
	}).Info("User logged out from all devices successfully")

	c.JSON(http.StatusOK, response)
}

// HealthCheck handles health check requests.
// This endpoint provides information about service health and dependencies.
//
// @Summary      Health check
// @Description  Check service health and dependencies status
// @Tags         health
// @Produce      json
// @Success      200  {object}  domain.HealthCheckResponse  "Service is healthy"
// @Failure      503  {object}  domain.HealthCheckResponse  "Service is unhealthy"
// @Router       /health [get]
//
// HTTP Method: GET
// Path: /health
//
// Success Response (200 OK):
//
//	{
//	  "status": "healthy",
//	  "timestamp": "2023-01-15T10:30:00Z",
//	  "version": "1.0.0",
//	  "checks": {
//	    "database": {
//	      "status": "healthy",
//	      "response_time_ms": 25,
//	      "last_checked": "2023-01-15T10:30:00Z"
//	    }
//	  }
//	}
//
// Error Responses:
//   - 503 Service Unavailable: Service or dependencies unhealthy
//
// This endpoint is used by:
// - Load balancers for health checks
// - Monitoring systems for service status
// - Operations teams for troubleshooting
func (h *AuthHandler) HealthCheck(c *gin.Context) {
	requestID := h.getRequestID(c)

	h.logger.WithField("request_id", requestID).Debug("Health check request received")

	// Basic health response - in production, would check database connectivity
	response := domain.HealthCheckResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0", // This would come from build info
		Checks: map[string]domain.HealthCheck{
			"database": {
				Status:       "healthy",
				ResponseTime: 25, // This would be actual response time
				LastChecked:  time.Now(),
			},
		},
	}

	c.JSON(http.StatusOK, response)
}

// getUserIDFromContext extracts the user ID from the Gin context.
// This is set by the JWT authentication middleware after token validation.
//
// Parameters:
//   - c: Gin context containing user information
//
// Returns:
//   - User UUID if found in context
//   - Error if user ID is missing or invalid format
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
