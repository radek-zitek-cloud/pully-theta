package password

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// Service provides comprehensive password management operations including
// password changes, validation, reset flows, and security policies.
//
// This service consolidates all password-related business logic:
// - Password strength validation and policies
// - Secure password hashing and verification
// - Password change operations with verification
// - Password reset flows with time-limited tokens
// - Password history tracking (future enhancement)
// - Security event audit logging
//
// Security features:
// - Bcrypt hashing with configurable cost
// - Password strength validation
// - Current password verification for changes
// - Rate limiting for reset operations
// - Comprehensive audit logging
// - Token-based reset with expiration
//
// Dependencies:
// - UserRepository: For user data operations
// - RefreshTokenRepository: For token invalidation
// - PasswordResetTokenRepository: For reset token management
// - Validator: For password strength validation
// - ResetService: For password reset operations
// - Logger: For security audit logging
// - Config: For service configuration
type Service struct {
	userRepo         domain.UserRepository
	refreshTokenRepo domain.RefreshTokenRepository
	resetService     *ResetService
	validator        *Validator
	logger           *logrus.Logger
	config           *config.Config
}

// ServiceConfig contains configuration for password service operations.
// This allows customization of security policies and behavior.
type ServiceConfig struct {
	ValidationConfig ValidationConfig `json:"validation"`
	ResetConfig      ResetConfig      `json:"reset"`
	BcryptCost       int              `json:"bcrypt_cost" default:"12"`
	RevokeAllTokens  bool             `json:"revoke_all_tokens" default:"true"`
}

// NewService creates a new password service with the specified dependencies.
// This constructor validates all dependencies and initializes the service
// with secure default configurations.
//
// Parameters:
//   - userRepo: Repository for user operations
//   - refreshTokenRepo: Repository for refresh token operations
//   - resetTokenRepo: Repository for password reset tokens
//   - emailService: Service for sending reset emails
//   - logger: Structured logger for audit events
//   - config: Service configuration
//   - serviceConfig: Password service specific configuration
//
// Returns:
//   - Configured password service
//   - Error if any dependency is invalid
//
// Example usage:
//
//	passwordService, err := password.NewService(
//	    userRepo, refreshTokenRepo, resetTokenRepo, emailService,
//	    logger, config, password.ServiceConfig{
//	        ValidationConfig: password.ValidationConfig{
//	            MinLength: 12,
//	            RequireSpecialChars: true,
//	        },
//	        ResetConfig: password.ResetConfig{
//	            TokenTTL: time.Hour,
//	        },
//	        BcryptCost: 12,
//	    })
//	if err != nil {
//	    log.Fatal("Failed to create password service:", err)
//	}
func NewService(
	userRepo domain.UserRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	resetTokenRepo domain.PasswordResetTokenRepository,
	emailService EmailService,
	logger *logrus.Logger,
	config *config.Config,
	serviceConfig ServiceConfig,
) (*Service, error) {
	// Validate dependencies
	if userRepo == nil {
		return nil, fmt.Errorf("user repository is required")
	}
	if refreshTokenRepo == nil {
		return nil, fmt.Errorf("refresh token repository is required")
	}
	if resetTokenRepo == nil {
		return nil, fmt.Errorf("reset token repository is required")
	}
	if emailService == nil {
		return nil, fmt.Errorf("email service is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Create password validator
	validator, err := NewValidator(serviceConfig.ValidationConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create password validator: %w", err)
	}

	// Create reset service
	resetService, err := NewResetService(
		userRepo, resetTokenRepo, emailService, validator,
		logger, config, serviceConfig.ResetConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create reset service: %w", err)
	}

	return &Service{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		resetService:     resetService,
		validator:        validator,
		logger:           logger,
		config:           config,
	}, nil
}

// NewDefaultService creates a password service with secure default settings.
// This is a convenience constructor for standard security requirements.
//
// Parameters:
//   - userRepo: Repository for user operations
//   - refreshTokenRepo: Repository for refresh token operations
//   - resetTokenRepo: Repository for password reset tokens
//   - emailService: Service for sending reset emails
//   - logger: Structured logger for audit events
//   - config: Service configuration
//
// Returns:
//   - Password service with default secure configuration
//   - Error if any dependency is invalid
//
// Example usage:
//
//	passwordService, err := password.NewDefaultService(
//	    userRepo, refreshTokenRepo, resetTokenRepo, emailService, logger, config)
//	if err != nil {
//	    log.Fatal("Failed to create password service:", err)
//	}
func NewDefaultService(
	userRepo domain.UserRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	resetTokenRepo domain.PasswordResetTokenRepository,
	emailService EmailService,
	logger *logrus.Logger,
	config *config.Config,
) (*Service, error) {
	defaultConfig := ServiceConfig{
		ValidationConfig: ValidationConfig{
			MinLength:           8,
			MaxLength:           128,
			RequireUppercase:    true,
			RequireLowercase:    true,
			RequireDigits:       true,
			RequireSpecialChars: true,
			SpecialCharSet:      "!@#$%^&*()_+-=[]{}|;:,.<>?",
		},
		ResetConfig: ResetConfig{
			TokenTTL:             time.Hour,
			MaxAttemptsPerIP:     5,
			MaxAttemptsPerEmail:  3,
			TokenLength:          32,
			RequireEmailVerified: true,
		},
		BcryptCost:      12,
		RevokeAllTokens: true,
	}

	return NewService(userRepo, refreshTokenRepo, resetTokenRepo, emailService, logger, config, defaultConfig)
}

// ChangePassword allows an authenticated user to change their password.
// This method requires the current password for verification and implements
// comprehensive security measures including token revocation.
//
// Security features:
// - Current password verification prevents unauthorized changes
// - New password strength validation
// - All refresh tokens revoked after password change
// - Comprehensive audit logging
// - Rate limiting protection (future enhancement)
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the authenticated user changing password
//   - currentPassword: User's current password for verification
//   - newPassword: New password to set
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error if password change fails
//
// Possible errors:
//   - domain.ErrUserNotFound: User doesn't exist or is inactive
//   - domain.ErrInvalidCredentials: Current password is incorrect
//   - domain.ErrWeakPassword: New password doesn't meet requirements
//   - domain.ErrAccountInactive: Account is disabled or deleted
//   - domain.ErrInfrastructureError: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	err := passwordService.ChangePassword(ctx, userID, "currentPass123!", "newSecurePass456!", "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    return fmt.Errorf("password change failed: %w", err)
//	}
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword, clientIP, userAgent string) error {
	s.logger.WithFields(logrus.Fields{
		"operation":  "change_password",
		"user_id":    userID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password change attempt")

	// Get user from database
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.auditLogFailure(ctx, &userID, "password_change", "User not found", clientIP, userAgent, err)
			return domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user for password change")
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user account is active
	if !user.IsActive || user.DeletedAt != nil {
		s.auditLogFailure(ctx, &userID, "password_change", "Account inactive", clientIP, userAgent, domain.ErrAccountInactive)
		return domain.ErrAccountInactive
	}

	// Verify current password
	if err := s.verifyPassword(currentPassword, user.PasswordHash); err != nil {
		s.auditLogFailure(ctx, &userID, "password_change", "Invalid current password", clientIP, userAgent, domain.ErrInvalidCredentials)
		return domain.ErrInvalidCredentials
	}

	// Validate new password strength
	if err := s.validator.ValidateWithContext(newPassword, user.Email, user.GetFullName()); err != nil {
		s.auditLogFailure(ctx, &userID, "password_change", "New password validation failed", clientIP, userAgent, err)
		return err
	}

	// Check if new password is different from current
	if err := s.verifyPassword(newPassword, user.PasswordHash); err == nil {
		// New password is the same as current password
		s.auditLogFailure(ctx, &userID, "password_change", "New password same as current", clientIP, userAgent, domain.ErrWeakPassword)
		return fmt.Errorf("%w: new password must be different from current password", domain.ErrWeakPassword)
	}

	// Hash the new password
	passwordHash, err := s.hashPassword(newPassword)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash new password")
		s.auditLogFailure(ctx, &userID, "password_change", "Password hashing failed", clientIP, userAgent, err)
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	user.PasswordHash = passwordHash
	user.PasswordChangedAt = time.Now().UTC()
	user.UpdatedAt = time.Now().UTC()

	if _, err := s.userRepo.Update(ctx, user); err != nil {
		s.logger.WithError(err).Error("Failed to update user password")
		s.auditLogFailure(ctx, &userID, "password_change", "Database update failed", clientIP, userAgent, err)
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke all existing refresh tokens for security
	if err := s.revokeAllUserTokens(ctx, userID); err != nil {
		s.logger.WithError(err).Warn("Failed to revoke user tokens after password change")
		// Don't fail the operation - password was already changed
	}

	// Record successful audit log
	s.auditLogSuccess(ctx, &userID, "password_change", "Password changed successfully", clientIP, userAgent)

	s.logger.WithField("user_id", userID).Info("Password changed successfully")
	return nil
}

// RequestPasswordReset initiates a password reset process for a user.
// This delegates to the reset service for comprehensive reset handling.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - email: User's email address for reset
//   - clientIP: Client IP address for rate limiting and audit
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error only for infrastructure failures (silent for user errors)
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	err := passwordService.RequestPasswordReset(ctx, "user@example.com", "192.168.1.1", "Mozilla/5.0...")
//	// Always returns success to user to prevent enumeration
func (s *Service) RequestPasswordReset(ctx context.Context, email, clientIP, userAgent string) error {
	return s.resetService.RequestReset(ctx, email, clientIP, userAgent)
}

// CompletePasswordReset completes the password reset process using a reset token.
// This delegates to the reset service for comprehensive reset handling.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - token: Reset token from email
//   - newPassword: New password to set
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error if reset fails
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	err := passwordService.CompletePasswordReset(ctx, "secure_token", "NewPassword123!", "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    return fmt.Errorf("password reset failed: %w", err)
//	}
func (s *Service) CompletePasswordReset(ctx context.Context, token, newPassword, clientIP, userAgent string) error {
	return s.resetService.CompleteReset(ctx, token, newPassword, clientIP, userAgent)
}

// ValidatePassword validates a password against configured strength requirements.
// This method provides comprehensive password validation without user context.
//
// Parameters:
//   - password: Password string to validate
//
// Returns:
//   - Error if password doesn't meet requirements, nil if valid
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
//
// Example usage:
//
//	err := passwordService.ValidatePassword("MySecurePass123!")
//	if err != nil {
//	    return fmt.Errorf("password validation failed: %w", err)
//	}
func (s *Service) ValidatePassword(password string) error {
	return s.validator.Validate(password)
}

// ValidatePasswordWithContext validates password with user-specific context.
// This provides enhanced validation that prevents personal information in passwords.
//
// Parameters:
//   - password: Password string to validate
//   - userEmail: User's email address
//   - userName: User's full name
//
// Returns:
//   - Error if password doesn't meet requirements, nil if valid
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
//
// Example usage:
//
//	err := passwordService.ValidatePasswordWithContext("MySecurePass123!", "user@example.com", "John Doe")
//	if err != nil {
//	    return fmt.Errorf("password validation failed: %w", err)
//	}
func (s *Service) ValidatePasswordWithContext(password, userEmail, userName string) error {
	return s.validator.ValidateWithContext(password, userEmail, userName)
}

// GetPasswordRequirements returns the current password policy requirements.
// This method provides a structured representation of the password validation
// rules that can be used by clients to build dynamic user interfaces.
//
// Returns:
//   - PasswordRequirements: Structured password policy information
//
// The returned structure includes:
// - Minimum and maximum length requirements
// - Character class requirements (uppercase, lowercase, digits, special)
// - List of human-readable requirement descriptions
// - Valid special character set
//
// Time Complexity: O(1)
// Space Complexity: O(1)
//
// Example usage:
//
//	requirements := passwordService.GetPasswordRequirements()
//	for _, req := range requirements.Requirements {
//	    fmt.Printf("- %s\n", req)
//	}
//
// Example response structure:
//
//	{
//	  "min_length": 8,
//	  "max_length": 128,
//	  "require_uppercase": true,
//	  "require_lowercase": true,
//	  "require_digits": true,
//	  "require_special_chars": true,
//	  "special_char_set": "!@#$%^&*()_+-=[]{}|;:,.<>?",
//	  "requirements": [
//	    "At least 8 characters long",
//	    "At least one uppercase letter",
//	    "At least one lowercase letter",
//	    "At least one digit",
//	    "At least one special character"
//	  ]
//	}
func (s *Service) GetPasswordRequirements() PasswordRequirements {
	return s.validator.GetRequirements()
}

// GetPasswordStrengthScore calculates a password strength score from 0-100.
// This method provides quantitative feedback about password quality that
// can be used in user interfaces for real-time password strength indicators.
//
// Parameters:
//   - password: Password string to analyze
//
// Returns:
//   - Strength score from 0 (very weak) to 100 (very strong)
//
// Scoring factors:
// - Length (longer passwords score higher)
// - Character diversity (multiple character classes score higher)
// - Entropy calculation based on character set size
// - Pattern detection (repeated characters, sequences reduce score)
// - Common password detection (known weak passwords score very low)
//
// Time Complexity: O(n) where n is password length
// Space Complexity: O(1)
//
// Example usage:
//
//	score := passwordService.GetPasswordStrengthScore("MySecurePass123!")
//	if score < 60 {
//	    log.Warn("Password strength is below recommended threshold")
//	}
//
// Score interpretation:
// - 0-30: Very weak (unacceptable)
// - 31-50: Weak (discouraged)
// - 51-70: Fair (acceptable)
// - 71-85: Good (recommended)
// - 86-100: Excellent (ideal)
func (s *Service) GetPasswordStrengthScore(password string) int {
	return s.validator.GetStrengthScore(password)
}

// CleanupExpiredResetTokens removes expired password reset tokens.
// This method should be called periodically for database maintenance.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//
// Returns:
//   - Number of tokens cleaned up
//   - Error if cleanup fails
//
// Time Complexity: O(n) where n is number of expired tokens
// Space Complexity: O(1)
//
// Example usage:
//
//	count, err := passwordService.CleanupExpiredResetTokens(ctx)
//	if err != nil {
//	    log.Error("Failed to cleanup expired tokens:", err)
//	}
//	log.Info("Cleaned up", count, "expired tokens")
func (s *Service) CleanupExpiredResetTokens(ctx context.Context) (int64, error) {
	return s.resetService.CleanupExpiredTokens(ctx)
}

// hashPassword creates a bcrypt hash of the password.
// This method uses the configured bcrypt cost for secure hashing.
//
// Parameters:
//   - password: Plain text password to hash
//
// Returns:
//   - Bcrypt hash of the password
//   - Error if hashing fails
//
// Time Complexity: O(2^cost) where cost is bcrypt cost parameter
// Space Complexity: O(1)
func (s *Service) hashPassword(password string) (string, error) {
	cost := s.config.Security.BcryptCost
	if cost < 10 || cost > 15 {
		cost = 12 // Safe default
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedBytes), nil
}

// verifyPassword checks if a plain text password matches a bcrypt hash.
// This method provides constant-time comparison for security.
//
// Parameters:
//   - password: Plain text password to verify
//   - hash: Bcrypt hash to compare against
//
// Returns:
//   - Error if password doesn't match, nil if valid
//
// Time Complexity: O(2^cost) where cost is bcrypt cost parameter
// Space Complexity: O(1)
func (s *Service) verifyPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// revokeAllUserTokens invalidates all refresh tokens for a user.
// This method is called after password changes for security.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: User's unique identifier
//
// Returns:
//   - Error if revocation fails
//
// Time Complexity: O(n) where n is number of user tokens
// Space Complexity: O(1)
func (s *Service) revokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	return s.refreshTokenRepo.RevokeAllUserTokens(ctx, userID)
}

// auditLogSuccess logs successful password operations for security audit.
// This method records positive security events for compliance and monitoring.
//
// Parameters:
//   - ctx: Context for the operation
//   - userID: ID of the user
//   - eventType: Type of event (e.g., "password_change")
//   - description: Human-readable description of the event
//   - clientIP: Client IP address
//   - userAgent: Client user agent string
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (s *Service) auditLogSuccess(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string) {
	s.auditLog(ctx, userID, eventType, description, clientIP, userAgent, true, nil)
}

// auditLogFailure logs failed password operations for security audit.
// This method records security events that may indicate attacks or misuse.
//
// Parameters:
//   - ctx: Context for the operation
//   - userID: ID of the user (can be nil for anonymous operations)
//   - eventType: Type of event (e.g., "password_change")
//   - description: Human-readable description of the event
//   - clientIP: Client IP address
//   - userAgent: Client user agent string
//   - err: Error that occurred
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (s *Service) auditLogFailure(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, err error) {
	s.auditLog(ctx, userID, eventType, description, clientIP, userAgent, false, err)
}

// auditLog creates audit log entries for password operations.
// This method provides centralized audit logging for security monitoring.
//
// Parameters:
//   - ctx: Context for the operation
//   - userID: ID of the user (can be nil for anonymous operations)
//   - eventType: Type of event being logged
//   - description: Human-readable description
//   - clientIP: Client IP address
//   - userAgent: Client user agent string
//   - success: Whether the operation was successful
//   - err: Error if operation failed (can be nil)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (s *Service) auditLog(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, success bool, err error) {
	// Create structured log entry
	logFields := logrus.Fields{
		"event_type":  eventType,
		"success":     success,
		"client_ip":   clientIP,
		"user_agent":  userAgent,
		"description": description,
	}

	if userID != nil {
		logFields["user_id"] = userID.String()
	}

	if err != nil {
		logFields["error"] = err.Error()
		s.logger.WithFields(logFields).Warn("Password operation failed")
	} else {
		s.logger.WithFields(logFields).Info("Password operation completed")
	}

	// TODO: Store audit log in database
	// For now, just log to structured logger
}

// PasswordRequirements represents the password policy configuration
// that can be exposed to clients for dynamic UI generation.
type PasswordRequirements struct {
	MinLength           int      `json:"min_length"`
	MaxLength           int      `json:"max_length"`
	RequireUppercase    bool     `json:"require_uppercase"`
	RequireLowercase    bool     `json:"require_lowercase"`
	RequireDigits       bool     `json:"require_digits"`
	RequireSpecialChars bool     `json:"require_special_chars"`
	SpecialCharSet      string   `json:"special_char_set"`
	Requirements        []string `json:"requirements"`
}
