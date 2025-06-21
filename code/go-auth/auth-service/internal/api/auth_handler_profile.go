package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"auth-service/internal/domain"
)

// ProfileHandlers contains all user profile-related HTTP handlers.
// This file is separated from the main authentication handlers to improve
// code organization and maintainability by grouping related functionality.
//
// Profile handlers include:
// - UpdateProfile: Update user profile information
// - Me: Retrieve current user profile
//
// All profile handlers require authentication and use the same error mapping
// and logging patterns established in the main AuthHandler.
//
// Security considerations:
// - All endpoints require valid JWT authentication
// - Profile updates include audit logging
// - Email changes require re-verification
// - Sensitive information is excluded from responses
// - Input validation prevents injection attacks
//
// Design patterns:
// - Consistent error handling via HTTPErrorMapper
// - Structured logging with request correlation
// - Comprehensive input validation
// - Audit trail for all profile changes
// - Idempotent operations where possible

// UpdateProfile godoc
//
// @Summary      Update user profile
// @Description  Updates the authenticated user's profile information. Supports partial updates.
// @Description  Only provided fields will be updated. Email changes trigger re-verification.
// @Description  All updates are logged for audit purposes.
// @Tags         user
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
//
// HTTP Method: PUT
// Path: /api/v1/auth/me
// Headers: Authorization: Bearer <access_token>
// Content-Type: application/json
//
// Request Body (partial update supported):
//
//	{
//	  "email": "newemail@example.com",     // optional
//	  "first_name": "John",                // optional
//	  "last_name": "Doe"                   // optional
//	}
//
// Success Response (200 OK):
//
//	{
//	  "id": "123e4567-e89b-12d3-a456-426614174000",
//	  "email": "newemail@example.com",
//	  "first_name": "John",
//	  "last_name": "Doe",
//	  "full_name": "John Doe",
//	  "is_email_verified": false,          // false if email was changed
//	  "is_active": true,
//	  "last_login_at": "2023-01-15T09:30:00Z",
//	  "created_at": "2023-01-01T12:00:00Z",
//	  "updated_at": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 400 Bad Request: Invalid input data or validation errors
//   - 401 Unauthorized: Invalid or missing authentication token
//   - 409 Conflict: Email address already exists
//   - 500 Internal Server Error: Database or server error
//
// Security considerations:
// - Requires valid JWT access token in Authorization header
// - Email changes require re-verification for security
// - All profile changes are logged for audit purposes
// - Input validation prevents injection and malformed data
// - Partial updates supported - only specified fields are changed
// - Email uniqueness is enforced across all users
//
// Business rules:
// - At least one field must be provided for update
// - Email changes reset email verification status
// - Profile updates are immediately visible
// - No changes return current profile without database update
// - Failed updates don't affect existing profile data
//
// Time Complexity: O(1) for single user operations
// Space Complexity: O(1) - minimal memory usage for profile data
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	// Generate request ID for logging and tracking
	requestID := h.getRequestID(c)
	h.logger.WithField("request_id", requestID).Info("Profile update request received")

	// Extract user ID from JWT token (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorMapper.MapError(c, err, "profile_update_authentication", requestID)
		return
	}

	// Parse and validate request body
	var req domain.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to parse request body")
		h.errorMapper.MapError(c, err, "profile_update_request_parsing", requestID)
		return
	}

	// Validate request using struct tags
	if err := h.validateStruct(&req); err != nil {
		h.errorMapper.MapError(c, err, "profile_update_validation", requestID)
		return
	}

	// Check if at least one field is provided for update
	if req.Email == nil && req.FirstName == nil && req.LastName == nil {
		h.errorMapper.MapError(c, domain.ErrValidationFailed, "profile_update_empty_fields", requestID)
		return
	}

	// Get current user details for comparison and validation
	existingUser, err := h.authService.GetUserByID(c.Request.Context(), userID.String())
	if err != nil {
		if err == domain.ErrUserNotFound {
			h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("User not found")
			h.errorMapper.MapError(c, err, "profile_update_user_lookup", requestID)
			return
		}
		h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("Failed to retrieve user details")
		h.errorMapper.MapError(c, err, "profile_update_user_lookup", requestID)
		return
	}

	// If email is being updated, check for uniqueness across all users
	if req.Email != nil && *req.Email != existingUser.Email {
		_, err := h.authService.GetUserByEmail(c.Request.Context(), *req.Email)
		if err == nil {
			// Email already exists - return conflict error
			h.logger.WithField("request_id", requestID).WithField("email", *req.Email).Warn("Email already in use")
			h.errorMapper.MapError(c, domain.ErrEmailExists, "profile_update_email_conflict", requestID)
			return
		}
		if err != domain.ErrUserNotFound {
			// Database error during email validation
			h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to validate email uniqueness")
			h.errorMapper.MapError(c, err, "profile_update_email_validation", requestID)
			return
		}
	}

	// Prepare update data - only include fields that are provided and changed
	updateData := make(map[string]interface{})
	changedFields := []string{}

	// Check and prepare email update
	if req.Email != nil && *req.Email != existingUser.Email {
		updateData["email"] = *req.Email
		updateData["is_email_verified"] = false // Email changes require re-verification
		changedFields = append(changedFields, "email")
	}

	// Check and prepare first name update
	if req.FirstName != nil && *req.FirstName != existingUser.FirstName {
		updateData["first_name"] = *req.FirstName
		changedFields = append(changedFields, "first_name")
	}

	// Check and prepare last name update
	if req.LastName != nil && *req.LastName != existingUser.LastName {
		updateData["last_name"] = *req.LastName
		changedFields = append(changedFields, "last_name")
	}

	// If no actual changes detected, return current user data without database update
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

	// Update timestamp for changed fields
	updateData["updated_at"] = time.Now()

	// Perform the profile update in database
	err = h.authService.UpdateProfile(c.Request.Context(), userID.String(), updateData)
	if err != nil {
		if err == domain.ErrEmailExists {
			// Handle race condition where email was taken between validation and update
			h.errorMapper.MapError(c, err, "profile_update_email_conflict", requestID)
			return
		}
		h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("Failed to update user profile")
		h.errorMapper.MapError(c, err, "profile_update_execution", requestID)
		return
	}

	// Get updated user data to return in response
	updatedUser, err := h.authService.GetUserByID(c.Request.Context(), userID.String())
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).WithField("user_id", userID).Error("Failed to retrieve updated user details")
		h.errorMapper.MapError(c, err, "profile_update_retrieval", requestID)
		return
	}

	// Create audit log for profile update (non-blocking)
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
		// Log error but don't fail the request - audit logging is supplementary
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to create audit log")
	}

	// Prepare and return success response with updated user data
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

// Me retrieves the current user's profile information.
// This endpoint returns the authenticated user's profile data excluding sensitive information
// such as password hashes and internal system fields.
//
// @Summary      Get current user profile
// @Description  Retrieve the authenticated user's profile information
// @Tags         user
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  domain.User "User profile data"
// @Failure      401  {object}  domain.ErrorResponse "Unauthorized - invalid or missing token"
// @Failure      404  {object}  domain.ErrorResponse "User not found"
// @Failure      500  {object}  domain.ErrorResponse "Internal server error"
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
//	  "last_login_at": "2023-01-15T09:30:00Z",
//	  "created_at": "2023-01-01T12:00:00Z",
//	  "updated_at": "2023-01-15T10:30:00Z",
//	  "request_id": "req_123e4567-e89b-12d3-a456-426614174000",
//	  "timestamp": "2023-01-15T10:30:00Z"
//	}
//
// Error Responses:
//   - 401 Unauthorized: Invalid or missing authentication token
//   - 404 Not Found: User not found (should not happen with valid token)
//   - 500 Internal Server Error: Database or server error
//
// Security considerations:
// - Requires valid JWT access token in Authorization header
// - Password hash is excluded from response for security
// - User ID is validated before lookup to prevent unauthorized access
// - Access is logged for audit purposes and security monitoring
// - No sensitive internal fields are exposed in the response
//
// Performance considerations:
// - Single database query for user profile retrieval
// - Minimal data transfer with only necessary fields
// - Fast response time for frequently accessed endpoint
// - No complex joins or aggregations required
//
// Usage patterns:
// - Called by frontend applications after login
// - Used to display user information in profile sections
// - Can be called frequently without performance concerns
// - Often used to verify current user context
//
// Time Complexity: O(1) - single user lookup by ID
// Space Complexity: O(1) - fixed size user profile data
func (h *AuthHandler) Me(c *gin.Context) {
	// Generate request ID for tracking and correlation
	requestID := h.getRequestID(c)
	clientIP := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	h.logger.WithFields(logrus.Fields{
		"operation":  "get_profile",
		"request_id": requestID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Get user profile request received")

	// Get user ID from JWT token in Authorization header (set by auth middleware)
	userID, err := h.getUserIDFromContext(c)
	if err != nil {
		h.logger.WithError(err).WithField("request_id", requestID).Error("Failed to get user ID from context")
		h.errorMapper.MapError(c, err, "profile_get_authentication", requestID)
		return
	}

	// Get user profile from service layer
	user, err := h.authService.GetUserByID(c.Request.Context(), userID.String())
	if err != nil {
		h.errorMapper.MapError(c, err, "profile_get_retrieval", requestID)
		return
	}

	// Prepare success response (exclude sensitive fields like password hash)
	response := map[string]interface{}{
		"id":                user.ID,
		"email":             user.Email,
		"first_name":        user.FirstName,
		"last_name":         user.LastName,
		"full_name":         user.GetFullName(),
		"is_email_verified": user.IsEmailVerified,
		"is_active":         user.IsActive,
		"last_login_at":     user.LastLoginAt,
		"created_at":        user.CreatedAt,
		"updated_at":        user.UpdatedAt,
		"request_id":        requestID,
		"timestamp":         time.Now().UTC(),
	}

	h.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"request_id": requestID,
	}).Info("User profile retrieved successfully")

	c.JSON(http.StatusOK, response)
}
