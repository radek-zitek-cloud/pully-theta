package domain

import (
	"time"

	"github.com/google/uuid"
)

// RegisterRequest represents the data required for user registration.
// This DTO validates input and ensures all required fields are provided
// with appropriate constraints and formats.
//
// @Description User registration request payload
// Validation rules:
// - Email: Required, valid format, max 255 characters
// - Password: Required, minimum 8 characters, complexity requirements
// - Names: Required, non-empty, max 100 characters each
type RegisterRequest struct {
	// Email is the user's email address, must be unique in the system
	Email string `json:"email" validate:"required,email,max=255" example:"user@example.com"`

	// Password is the plain text password, will be hashed before storage
	// Must meet security requirements: min 8 chars, complexity rules
	Password string `json:"password" validate:"required,min=8,max=128" example:"SecurePass123!"`

	// PasswordConfirm must match the password field exactly
	PasswordConfirm string `json:"password_confirm" validate:"required,eqfield=Password" example:"SecurePass123!"`

	// FirstName is the user's given name
	FirstName string `json:"first_name" validate:"required,min=1,max=100" example:"John"`

	// LastName is the user's family name
	LastName string `json:"last_name" validate:"required,min=1,max=100" example:"Doe"`
}

// LoginRequest represents the data required for user authentication.
// Uses email and password combination for login.
//
// @Description User login request payload
// Security considerations:
// - Email lookup should be case-insensitive
// - Failed attempts should be rate-limited
// - Log all login attempts for audit purposes
type LoginRequest struct {
	// Email is the user's registered email address
	Email string `json:"email" validate:"required,email" example:"user@example.com"`

	// Password is the user's plain text password for verification
	Password string `json:"password" validate:"required" example:"SecurePass123!"`

	// RememberMe indicates if the user wants extended session duration
	// This affects the refresh token expiry time
	RememberMe bool `json:"remember_me" example:"false"`
}

// ChangePasswordRequest represents the data required for password changes.
// Requires the current password for verification before allowing the change.
//
// Security features:
// - Current password verification prevents unauthorized changes
// - New password must meet security requirements
// - Password confirmation prevents typos
type ChangePasswordRequest struct {
	// CurrentPassword is required to verify the user's identity
	CurrentPassword string `json:"current_password" validate:"required" example:"OldPassword123!"`

	// NewPassword is the desired new password
	NewPassword string `json:"new_password" validate:"required,min=8,max=128" example:"NewSecurePass456!"`

	// NewPasswordConfirm must match the new password exactly
	NewPasswordConfirm string `json:"new_password_confirm" validate:"required,eqfield=NewPassword" example:"NewSecurePass456!"`
}

// ResetPasswordRequest represents the initial request to reset a password.
// This triggers sending a reset token to the user's email address.
//
// Rate limiting should be applied to prevent abuse of this endpoint.
type ResetPasswordRequest struct {
	// Email is the address to send the reset token to
	Email string `json:"email" validate:"required,email" example:"user@example.com"`
}

// ConfirmResetPasswordRequest represents the data to complete password reset.
// Uses the token sent via email along with the new password.
//
// Security considerations:
// - Token should be single-use and time-limited
// - New password must meet security requirements
// - Email should match the original reset request
type ConfirmResetPasswordRequest struct {
	// Token is the secure token sent via email
	Token string `json:"token" validate:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// Email is the user's email address for verification
	Email string `json:"email" validate:"required,email" example:"user@example.com"`

	// NewPassword is the desired new password
	NewPassword string `json:"new_password" validate:"required,min=8,max=128" example:"NewSecurePass789!"`

	// NewPasswordConfirm must match the new password exactly
	NewPasswordConfirm string `json:"new_password_confirm" validate:"required,eqfield=NewPassword" example:"NewSecurePass789!"`
}

// RefreshTokenRequest represents the data required for token refresh.
// Uses the refresh token to obtain a new access token.
type RefreshTokenRequest struct {
	// RefreshToken is the JWT refresh token issued during login
	RefreshToken string `json:"refresh_token" validate:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// AuthResponse represents the response returned after successful authentication.
// Contains both access and refresh tokens along with user information.
//
// @Description Authentication response with JWT tokens and user info
// Token types:
// - AccessToken: Short-lived (15 minutes), used for API authentication
// - RefreshToken: Long-lived (7 days), used to obtain new access tokens
type AuthResponse struct {
	// AccessToken is the JWT token for API authentication
	AccessToken string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// RefreshToken is used to obtain new access tokens
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// TokenType indicates the type of token (typically "Bearer")
	TokenType string `json:"token_type" example:"Bearer"`

	// ExpiresIn indicates access token lifetime in seconds
	ExpiresIn int64 `json:"expires_in" example:"900"`

	// User contains the authenticated user's information
	User UserResponse `json:"user"`
}

// UserResponse represents user data returned in API responses.
// Excludes sensitive information like password hashes.
//
// @Description User information in API responses
// This DTO is used in various endpoints:
// - Authentication responses
// - User profile endpoints
// - User listing endpoints (admin)
type UserResponse struct {
	// ID is the user's unique identifier
	ID uuid.UUID `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`

	// Email is the user's email address
	Email string `json:"email" example:"user@example.com"`

	// FirstName is the user's given name
	FirstName string `json:"first_name" example:"John"`

	// LastName is the user's family name
	LastName string `json:"last_name" example:"Doe"`

	// FullName is a computed field combining first and last names
	FullName string `json:"full_name" example:"John Doe"`

	// IsEmailVerified indicates if the user has verified their email
	IsEmailVerified bool `json:"is_email_verified" example:"true"`

	// IsActive indicates if the user account is active
	IsActive bool `json:"is_active" example:"true"`

	// LastLoginAt is the timestamp of the user's last login
	LastLoginAt *time.Time `json:"last_login_at,omitempty" example:"2023-01-15T10:30:00Z"`

	// CreatedAt is when the user account was created
	CreatedAt time.Time `json:"created_at" example:"2023-01-01T12:00:00Z"`

	// UpdatedAt is when the user account was last modified
	UpdatedAt time.Time `json:"updated_at" example:"2023-01-15T10:30:00Z"`
}

// ErrorResponse represents the standard error response format.
// Provides consistent error messaging across all API endpoints.
//
// @Description Standard error response format
// HTTP status codes:
// - 400: Validation errors, malformed requests
// - 401: Authentication required or failed
// - 403: Insufficient permissions
// - 404: Resource not found
// - 429: Rate limit exceeded
// - 500: Internal server error
type ErrorResponse struct {
	// Error is a brief error code or type
	Error string `json:"error" example:"validation_error"`

	// Message is a human-readable error description
	Message string `json:"message" example:"The provided email address is invalid"`

	// Details contains additional error information (validation errors, etc.)
	Details interface{} `json:"details,omitempty"`

	// RequestID is a unique identifier for this request (for debugging)
	RequestID string `json:"request_id,omitempty" example:"req_123e4567-e89b-12d3-a456-426614174000"`

	// Timestamp is when the error occurred
	Timestamp time.Time `json:"timestamp" example:"2023-01-15T10:30:00Z"`
}

// SuccessResponse represents the standard success response format.
// Used for operations that don't return specific data.
type SuccessResponse struct {
	// Success indicates the operation completed successfully
	Success bool `json:"success" example:"true"`

	// Message provides additional context about the operation
	Message string `json:"message" example:"Password changed successfully"`

	// RequestID is a unique identifier for this request
	RequestID string `json:"request_id,omitempty" example:"req_123e4567-e89b-12d3-a456-426614174000"`

	// Timestamp is when the operation completed
	Timestamp time.Time `json:"timestamp" example:"2023-01-15T10:30:00Z"`
}

// PaginatedResponse represents a paginated list of items.
// Used for endpoints that return lists of data with pagination.
type PaginatedResponse struct {
	// Data contains the actual items for this page
	Data interface{} `json:"data"`

	// Pagination contains metadata about the pagination
	Pagination PaginationMeta `json:"pagination"`
}

// PaginationMeta contains metadata about paginated results.
// Helps clients understand the pagination state and navigate pages.
type PaginationMeta struct {
	// CurrentPage is the current page number (1-based)
	CurrentPage int `json:"current_page" example:"1"`

	// PerPage is the number of items per page
	PerPage int `json:"per_page" example:"20"`

	// TotalPages is the total number of pages available
	TotalPages int `json:"total_pages" example:"5"`

	// TotalItems is the total number of items across all pages
	TotalItems int64 `json:"total_items" example:"95"`

	// HasNext indicates if there are more pages after this one
	HasNext bool `json:"has_next" example:"true"`

	// HasPrev indicates if there are pages before this one
	HasPrev bool `json:"has_prev" example:"false"`
}

// HealthCheckResponse represents the health check endpoint response.
// Provides information about service health and dependencies.
type HealthCheckResponse struct {
	// Status indicates overall service health ("healthy", "unhealthy", "degraded")
	Status string `json:"status" example:"healthy"`

	// Timestamp is when the health check was performed
	Timestamp time.Time `json:"timestamp" example:"2023-01-15T10:30:00Z"`

	// Version is the service version
	Version string `json:"version" example:"1.0.0"`

	// Checks contains detailed health information for dependencies
	Checks map[string]HealthCheck `json:"checks"`
}

// HealthCheck represents the health status of a specific dependency.
// Each external dependency (database, cache, etc.) has its own health check.
type HealthCheck struct {
	// Status indicates this dependency's health
	Status string `json:"status" example:"healthy"`

	// ResponseTime is how long this check took (in milliseconds)
	ResponseTime int64 `json:"response_time_ms" example:"25"`

	// Error contains error details if the check failed
	Error string `json:"error,omitempty"`

	// LastChecked is when this dependency was last checked
	LastChecked time.Time `json:"last_checked" example:"2023-01-15T10:30:00Z"`
}

// RegisterResponse represents the response returned after successful user registration.
// Contains the newly created user information.
//
// @Description User registration success response
type RegisterResponse struct {
	// Success indicates if the operation was successful
	Success bool `json:"success" example:"true"`

	// Message provides a human-readable success message
	Message string `json:"message" example:"User registered successfully"`

	// User contains the newly registered user's information
	User UserResponse `json:"user"`

	// RequestID is a unique identifier for this request
	RequestID string `json:"request_id" example:"req_123e4567-e89b-12d3-a456-426614174000"`

	// Timestamp is when the registration was completed
	Timestamp time.Time `json:"timestamp" example:"2023-01-15T10:30:00Z"`
}

// LoginResponse represents the response returned after successful authentication.
// Contains JWT tokens and user information.
//
// @Description User login success response with JWT tokens
type LoginResponse struct {
	// AccessToken is the JWT token for API authentication
	AccessToken string `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// RefreshToken is used to obtain new access tokens
	RefreshToken string `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// TokenType indicates the type of token (typically "Bearer")
	TokenType string `json:"token_type" example:"Bearer"`

	// ExpiresIn indicates access token lifetime in seconds
	ExpiresIn int64 `json:"expires_in" example:"900"`

	// User contains the authenticated user's information
	User UserResponse `json:"user"`

	// RequestID is a unique identifier for this request
	RequestID string `json:"request_id" example:"req_123e4567-e89b-12d3-a456-426614174000"`

	// Timestamp is when the login was completed
	Timestamp time.Time `json:"timestamp" example:"2023-01-15T10:30:00Z"`
}

// ToUserResponse converts a User entity to a UserResponse DTO.
// This method excludes sensitive information and computes derived fields.
//
// Parameters:
//   - user: The User entity to convert
//
// Returns:
//   - UserResponse DTO suitable for API responses
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func ToUserResponse(user *User) UserResponse {
	return UserResponse{
		ID:              user.ID,
		Email:           user.Email,
		FirstName:       user.FirstName,
		LastName:        user.LastName,
		FullName:        user.GetFullName(),
		IsEmailVerified: user.IsEmailVerified,
		IsActive:        user.IsActive,
		LastLoginAt:     user.LastLoginAt,
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
	}
}

// ToUserResponseList converts a slice of User entities to UserResponse DTOs.
// This is a convenience method for list endpoints.
//
// Parameters:
//   - users: Slice of User entities to convert
//
// Returns:
//   - Slice of UserResponse DTOs
//
// Time Complexity: O(n) where n is the number of users
// Space Complexity: O(n)
func ToUserResponseList(users []*User) []UserResponse {
	responses := make([]UserResponse, len(users))
	for i, user := range users {
		responses[i] = ToUserResponse(user)
	}
	return responses
}
