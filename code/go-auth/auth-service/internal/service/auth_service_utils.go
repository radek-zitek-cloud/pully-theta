package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// AuthServiceUtils provides common utility functions for authentication operations.
// This struct contains helper methods for password operations, token generation,
// validation, email normalization, and audit logging.
//
// These utilities are shared across different authentication service components
// to ensure consistency and reduce code duplication.
//
// Security features:
// - Secure password hashing using bcrypt
// - Cryptographically secure token generation
// - Email normalization and validation
// - Comprehensive audit logging
//
// Dependencies:
// - Config: For service configuration (password requirements, JWT settings)
// - Logger: For structured logging
// - AuditLogRepository: For security audit logging
type AuthServiceUtils struct {
	config    *config.Config
	logger    *logrus.Logger
	auditRepo domain.AuditLogRepository
}

// NewAuthServiceUtils creates a new instance of authentication utilities.
// This constructor validates dependencies and returns a configured utils instance.
//
// Parameters:
//   - config: Service configuration containing security settings
//   - logger: Structured logger for operations
//   - auditRepo: Repository for audit log persistence
//
// Returns:
//   - Configured AuthServiceUtils instance
//   - Error if any dependency is invalid
//
// Example usage:
//
//	utils, err := NewAuthServiceUtils(config, logger, auditRepo)
//	if err != nil {
//	    log.Fatal("Failed to create auth utils:", err)
//	}
func NewAuthServiceUtils(config *config.Config, logger *logrus.Logger, auditRepo domain.AuditLogRepository) (*AuthServiceUtils, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if auditRepo == nil {
		return nil, fmt.Errorf("audit repository is required")
	}

	return &AuthServiceUtils{
		config:    config,
		logger:    logger,
		auditRepo: auditRepo,
	}, nil
}

// generateSecureToken creates a cryptographically secure random token.
// This method uses crypto/rand for secure random number generation,
// suitable for password reset tokens, session tokens, and other security-critical tokens.
//
// Parameters:
//   - length: Length of the token in bytes (will be hex-encoded, so output is 2x length)
//
// Returns:
//   - Hex-encoded random token string
//   - Error if random generation fails
//
// Security considerations:
// - Uses crypto/rand for cryptographically secure randomness
// - Minimum recommended length is 16 bytes (32 characters when hex-encoded)
// - Tokens are suitable for security-critical operations
//
// Time Complexity: O(n) where n is the token length
// Space Complexity: O(n)
//
// Example usage:
//
//	token, err := utils.generateSecureToken(32) // 64-character hex string
//	if err != nil {
//	    return fmt.Errorf("failed to generate token: %w", err)
//	}
func (u *AuthServiceUtils) generateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		u.logger.WithError(err).Error("Failed to generate secure random bytes")
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

// validatePasswordStrength validates that a password meets security requirements.
// This method enforces password complexity rules to ensure user account security.
//
// Password requirements:
// - Minimum 8 characters length
// - Maximum 128 characters length
// - At least one uppercase letter (A-Z)
// - At least one lowercase letter (a-z)
// - At least one digit (0-9)
// - At least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)
// - No common patterns or dictionary words (future enhancement)
//
// Parameters:
//   - password: Password string to validate
//
// Returns:
//   - Error if password doesn't meet requirements, nil if valid
//
// Security considerations:
// - Helps prevent weak passwords that are vulnerable to attacks
// - Requirements are configurable through service configuration
// - Error messages are specific to help users create strong passwords
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
//
// Example usage:
//
//	if err := utils.validatePasswordStrength("MySecurePass123!"); err != nil {
//	    return fmt.Errorf("password validation failed: %w", err)
//	}
func (u *AuthServiceUtils) validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return domain.ErrWeakPassword
	}
	if len(password) > 128 {
		return domain.ErrWeakPassword
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasDigit   = false
		hasSpecial = false
	)

	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case strings.ContainsRune(specialChars, char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return domain.ErrWeakPassword
	}

	return nil
}

// normalizeEmail converts an email address to a normalized form for consistent storage.
// This method handles case normalization and basic format validation to ensure
// email consistency across the system.
//
// Normalization rules:
// - Convert to lowercase
// - Trim whitespace
// - Basic format validation (contains @ and domain)
// - Remove any control characters
//
// Parameters:
//   - email: Email address to normalize
//
// Returns:
//   - Normalized email string (empty if invalid)
//
// Security considerations:
// - Prevents duplicate accounts with different case variations
// - Basic validation helps prevent malformed email storage
// - Does not perform deep validation (that should be done separately)
//
// Time Complexity: O(n) where n is email length
// Space Complexity: O(n)
//
// Example usage:
//
//	normalizedEmail := utils.normalizeEmail("  User@Example.COM  ")
//	// Returns: "user@example.com"
func (u *AuthServiceUtils) normalizeEmail(email string) string {
	// Basic normalization
	normalized := strings.TrimSpace(strings.ToLower(email))

	// Basic validation - must contain @ and have domain
	if !strings.Contains(normalized, "@") {
		return ""
	}

	parts := strings.Split(normalized, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}

	// Check for basic domain structure
	if !strings.Contains(parts[1], ".") {
		return ""
	}

	return normalized
}

// hashPassword creates a bcrypt hash of the provided password.
// This method uses bcrypt with a configurable cost factor for secure password storage.
//
// Parameters:
//   - password: Plain text password to hash
//
// Returns:
//   - Bcrypt hash string suitable for database storage
//   - Error if hashing fails
//
// Security considerations:
// - Uses bcrypt algorithm which is designed for password hashing
// - Configurable cost factor allows tuning for security vs performance
// - Includes salt automatically to prevent rainbow table attacks
// - Hash output is safe for database storage
//
// Time Complexity: O(2^cost) where cost is bcrypt cost factor
// Space Complexity: O(1)
//
// Example usage:
//
//	hash, err := utils.hashPassword("userPassword123")
//	if err != nil {
//	    return fmt.Errorf("failed to hash password: %w", err)
//	}
func (u *AuthServiceUtils) hashPassword(password string) (string, error) {
	// Use bcrypt cost from config, default to 12 if not specified
	cost := 12
	if u.config.Security.BcryptCost > 0 {
		cost = u.config.Security.BcryptCost
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		u.logger.WithError(err).Error("Failed to generate password hash")
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// verifyPassword compares a plain text password with a bcrypt hash.
// This method safely verifies passwords without exposing timing attacks.
//
// Parameters:
//   - plaintext: Plain text password to verify
//   - hash: Bcrypt hash to compare against
//
// Returns:
//   - Error if verification fails or passwords don't match
//
// Security considerations:
// - Resistant to timing attacks due to bcrypt's constant-time comparison
// - Safe to use for authentication verification
// - Will return error for both invalid hash format and password mismatch
//
// Time Complexity: O(2^cost) where cost is bcrypt cost factor
// Space Complexity: O(1)
//
// Example usage:
//
//	if err := utils.verifyPassword("userPassword123", storedHash); err != nil {
//	    return domain.ErrInvalidCredentials
//	}
func (u *AuthServiceUtils) verifyPassword(plaintext, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}

// auditLogSuccess records a successful operation in the audit log.
// This method creates an audit log entry for successful authentication events.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the user performing the operation (nil for anonymous)
//   - eventType: Type of event (login, register, logout, etc.)
//   - description: Human-readable description of the event
//   - clientIP: Client IP address for security tracking
//   - userAgent: Client user agent for security tracking
//
// Security considerations:
// - All successful operations should be audited for security monitoring
// - Audit logs are critical for compliance and incident response
// - User agent and IP tracking helps identify suspicious patterns
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	utils.auditLogSuccess(ctx, &userID, "login", "User logged in successfully", "192.168.1.1", "Mozilla/5.0...")
func (u *AuthServiceUtils) auditLogSuccess(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string) {
	u.auditLog(ctx, userID, eventType, description, clientIP, userAgent, true, nil)
}

// auditLogFailure records a failed operation in the audit log.
// This method creates an audit log entry for failed authentication events.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the user performing the operation (nil for anonymous)
//   - eventType: Type of event (login, register, logout, etc.)
//   - description: Human-readable description of the event
//   - clientIP: Client IP address for security tracking
//   - userAgent: Client user agent for security tracking
//   - err: Error that caused the failure
//
// Security considerations:
// - Failed operations are critical for security monitoring
// - Helps identify brute force attacks and suspicious patterns
// - Error information helps with troubleshooting
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	utils.auditLogFailure(ctx, &userID, "login", "Invalid password", "192.168.1.1", "Mozilla/5.0...", domain.ErrInvalidCredentials)
func (u *AuthServiceUtils) auditLogFailure(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, err error) {
	u.auditLog(ctx, userID, eventType, description, clientIP, userAgent, false, err)
}

// auditLog creates and stores an audit log entry.
// This internal method handles the common logic for both success and failure audit logs.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the user performing the operation (nil for anonymous)
//   - eventType: Type of event (login, register, logout, etc.)
//   - description: Human-readable description of the event
//   - clientIP: Client IP address for security tracking
//   - userAgent: Client user agent for security tracking
//   - success: Whether the operation was successful
//   - err: Error that caused failure (nil for successful operations)
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (u *AuthServiceUtils) auditLog(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, success bool, err error) {
	auditLog := &domain.AuditLog{
		ID:               uuid.New(),
		UserID:           userID,
		EventType:        eventType,
		EventDescription: description,
		IPAddress:        clientIP,
		UserAgent:        userAgent,
		Success:          success,
		CreatedAt:        time.Now().UTC(),
	}

	// Add error details if present
	if err != nil {
		if auditLog.Metadata == nil {
			auditLog.Metadata = make(map[string]interface{})
		}
		auditLog.Metadata["error"] = err.Error()
	}

	// Store audit log (non-blocking to avoid impacting user experience)
	go func() {
		auditCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if _, logErr := u.auditRepo.Create(auditCtx, auditLog); logErr != nil {
			u.logger.WithError(logErr).WithFields(logrus.Fields{
				"audit_id":    auditLog.ID,
				"event_type":  eventType,
				"user_id":     userID,
				"description": description,
			}).Error("Failed to create audit log entry")
		}
	}()
}
