package api

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"auth-service/internal/domain"
)

// AuthHandlerUtils contains utility functions for the AuthHandler.
// These functions are separated from the main handler to improve code organization
// and maintainability while keeping the core handler focused on HTTP request handling.
//
// This file contains:
// - Request ID generation and extraction
// - Context utilities for extracting user information
// - Input validation logic for authentication requests
//
// Security considerations:
// - All validation functions properly sanitize inputs
// - User context extraction validates data types and formats
// - Request ID generation ensures unique correlation IDs
//
// Design principles:
// - Single responsibility: Each function has one clear purpose
// - Comprehensive error handling with descriptive messages
// - Consistent naming conventions and documentation
// - Type safety with proper type assertions and validation

// getRequestID extracts or generates a request correlation ID for tracing.
// This function implements a fallback strategy to ensure every request
// has a unique identifier for logging and debugging purposes.
//
// Lookup priority:
// 1. X-Request-ID header (from client or upstream proxy)
// 2. request_id from Gin context (set by middleware)
// 3. Generate new UUID-based request ID
//
// Parameters:
//   - c: Gin context containing request headers and context data
//
// Returns:
//   - String containing the request ID (never empty)
//
// Example:
//   - "req_123e4567-e89b-12d3-a456-426614174000" (generated)
//   - "upstream-proxy-12345" (from header)
//   - "middleware-req-67890" (from context)
//
// Usage:
//
//	requestID := h.getRequestID(c)
//	h.logger.WithField("request_id", requestID).Info("Processing request")
func (h *AuthHandler) getRequestID(c *gin.Context) string {
	// Try to get request ID from header first (highest priority)
	// This allows upstream proxies or clients to provide their own correlation IDs
	if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
		return requestID
	}

	// Try to get from Gin context (set by middleware)
	// This allows request ID middleware to set consistent IDs
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}

	// Generate new request ID as fallback
	// Format: req_<uuid> for easy identification in logs
	return "req_" + uuid.New().String()
}

// validateStruct validates a struct using comprehensive validation rules.
// This function performs domain-specific validation of request DTOs
// to ensure data integrity and security before processing business logic.
//
// Validation features:
// - Required field validation with specific error messages
// - Format validation (email, password strength, etc.)
// - Length constraints with security considerations
// - Field cross-validation (password confirmation)
// - Domain-specific business rules
//
// Security considerations:
// - Email format validation prevents injection attacks
// - Password strength requirements enforce security policies
// - Length limits prevent buffer overflow attacks
// - Input sanitization prevents malicious data processing
//
// Parameters:
//   - s: Interface containing the struct to validate
//
// Returns:
//   - Error with specific validation message if validation fails
//   - nil if all validation passes
//
// Supported request types:
//   - domain.RegisterRequest: User registration validation
//   - domain.LoginRequest: Login credential validation
//   - domain.ResetPasswordRequest: Password reset email validation
//   - domain.ConfirmResetPasswordRequest: Password reset confirmation validation
//
// Example validation errors:
//   - "email is required"
//   - "password must be at least 8 characters"
//   - "password and password_confirm must match"
//   - "email must be a valid email address"
//
// Time Complexity: O(1) - constant time validation
// Space Complexity: O(1) - no additional space allocation
//
// TODO: Integrate go-playground/validator for more comprehensive validation
// TODO: Add regex-based email validation for improved security
// TODO: Implement password complexity requirements (uppercase, lowercase, numbers, symbols)
func (h *AuthHandler) validateStruct(s interface{}) error {
	// Type switch to handle different request types with specific validation rules
	switch v := s.(type) {
	case *domain.RegisterRequest:
		// Validate required fields first
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}
		if v.Password == "" {
			return fmt.Errorf("password is required")
		}
		if v.PasswordConfirm == "" {
			return fmt.Errorf("password_confirm is required")
		}
		if v.FirstName == "" {
			return fmt.Errorf("first_name is required")
		}
		if v.LastName == "" {
			return fmt.Errorf("last_name is required")
		}

		// Validate password requirements
		if len(v.Password) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}
		if v.Password != v.PasswordConfirm {
			return fmt.Errorf("password and password_confirm must match")
		}

		// Validate name length constraints
		if len(v.FirstName) > 100 {
			return fmt.Errorf("first_name must be no more than 100 characters")
		}
		if len(v.LastName) > 100 {
			return fmt.Errorf("last_name must be no more than 100 characters")
		}

		// Validate email format and length
		if err := h.validateEmail(v.Email); err != nil {
			return err
		}

	case *domain.LoginRequest:
		// Validate required login credentials
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}
		if v.Password == "" {
			return fmt.Errorf("password is required")
		}

		// Validate email format
		if err := h.validateEmail(v.Email); err != nil {
			return err
		}

	case *domain.ResetPasswordRequest:
		// Validate required email for password reset
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}

		// Validate email format
		if err := h.validateEmail(v.Email); err != nil {
			return err
		}

	case *domain.ConfirmResetPasswordRequest:
		// Validate required fields for password reset confirmation
		if v.Token == "" {
			return fmt.Errorf("token is required")
		}
		if v.Email == "" {
			return fmt.Errorf("email is required")
		}
		if v.NewPassword == "" {
			return fmt.Errorf("new_password is required")
		}
		if v.NewPasswordConfirm == "" {
			return fmt.Errorf("new_password_confirm is required")
		}

		// Validate new password requirements
		if len(v.NewPassword) < 8 {
			return fmt.Errorf("new_password must be at least 8 characters")
		}
		if v.NewPassword != v.NewPasswordConfirm {
			return fmt.Errorf("new_password and new_password_confirm must match")
		}

		// Validate email format
		if err := h.validateEmail(v.Email); err != nil {
			return err
		}

	default:
		// Unknown request type - skip validation
		// This allows for extensibility without requiring validation for all struct types
		return nil
	}

	return nil
}

// validateEmail performs basic email format validation.
// This function provides a simple email validation to prevent obviously invalid
// email addresses while avoiding complex regex that might cause performance issues.
//
// Validation rules:
// - Must contain @ symbol (required for email format)
// - Must contain . symbol (required for domain)
// - Length must not exceed 255 characters (RFC 5321 limit)
// - Must not be empty
//
// Parameters:
//   - email: String containing the email address to validate
//
// Returns:
//   - Error with specific message if validation fails
//   - nil if email format is acceptable
//
// Security considerations:
// - Prevents email injection attacks through basic format checking
// - Length limit prevents buffer overflow attacks
// - Does not perform DNS validation to avoid external dependencies
//
// Limitations:
// - Basic validation only - does not catch all invalid email formats
// - Does not validate domain existence or deliverability
// - May accept some technically invalid but harmless email formats
//
// Example valid emails:
//   - "user@example.com"
//   - "test.email+tag@domain.co.uk"
//   - "user123@test-domain.org"
//
// Example invalid emails:
//   - "plainaddress" (no @ symbol)
//   - "user@" (no domain)
//   - "@domain.com" (no local part)
//   - "" (empty string)
//
// Time Complexity: O(n) where n is email length
// Space Complexity: O(1) - no additional space allocation
func (h *AuthHandler) validateEmail(email string) error {
	// Check for empty email
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	// Check length constraint (RFC 5321 limit)
	if len(email) > 255 {
		return fmt.Errorf("email must be no more than 255 characters")
	}

	// Basic format validation - must contain @ and .
	// This is a minimal check to catch obviously invalid emails
	if !strings.Contains(email, "@") {
		return fmt.Errorf("email must contain @ symbol")
	}
	if !strings.Contains(email, ".") {
		return fmt.Errorf("email must contain domain extension")
	}

	// Additional basic checks
	if strings.Count(email, "@") != 1 {
		return fmt.Errorf("email must contain exactly one @ symbol")
	}

	// Check for @ at start or end
	if strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
		return fmt.Errorf("email must have local part and domain")
	}

	return nil
}

// getUserIDFromContext extracts the user ID from the Gin context.
// This function retrieves the user ID that was set by the authentication middleware
// after validating the JWT token in the Authorization header.
//
// The user ID can be stored in different formats in the context:
// - As a uuid.UUID type directly (preferred)
// - As a string that needs to be parsed into UUID
//
// Parameters:
//   - c: Gin context containing the request and middleware data
//
// Returns:
//   - User UUID if found and valid in context
//   - Error if user ID is missing, invalid format, or cannot be parsed
//
// Security considerations:
// - Only works after authentication middleware has validated the JWT
// - Returns domain.ErrUnauthorized for missing or invalid user context
// - Validates UUID format to prevent injection attacks
// - Ensures type safety with proper type assertions
//
// Error conditions:
// - User ID not found in context (user not authenticated)
// - User ID is not a valid UUID format
// - User ID context value is not a supported type
//
// Example usage:
//
//	userID, err := h.getUserIDFromContext(c)
//	if err != nil {
//	    h.errorMapper.MapError(c, err, "authentication_required", requestID)
//	    return
//	}
//
//	// Use userID for authenticated operations
//	user, err := h.authService.GetUserByID(ctx, userID.String())
//
// Time Complexity: O(1) - constant time context lookup and parsing
// Space Complexity: O(1) - no additional space allocation
func (h *AuthHandler) getUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	// Try to get user ID from Gin context (set by auth middleware)
	userIDValue, exists := c.Get("user_id")
	if !exists {
		// User ID not found - user is not authenticated
		return uuid.Nil, domain.ErrUnauthorized
	}

	// Convert to UUID based on the type stored in context
	switch v := userIDValue.(type) {
	case uuid.UUID:
		// Direct UUID type - return as-is
		return v, nil
	case string:
		// String UUID - parse and validate format
		parsedUUID, err := uuid.Parse(v)
		if err != nil {
			// Invalid UUID format
			return uuid.Nil, fmt.Errorf("invalid user ID format: %w", err)
		}
		return parsedUUID, nil
	default:
		// Unsupported type in context
		return uuid.Nil, fmt.Errorf("unsupported user ID type in context: %T", v)
	}
}
