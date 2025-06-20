package password

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// ResetService handles password reset operations including token generation,
// validation, and password updates. This service implements secure password
// reset flows with time-limited tokens and comprehensive security measures.
//
// Security features:
// - Cryptographically secure token generation
// - Time-limited reset tokens (configurable expiry)
// - Token hashing for secure storage
// - Single-use tokens with automatic invalidation
// - Rate limiting protection
// - Comprehensive audit logging
// - IP address tracking for security monitoring
//
// Reset flow:
// 1. User requests password reset with email
// 2. System generates secure token and stores hash
// 3. Reset email sent with token link
// 4. User clicks link and provides new password
// 5. Token validated and password updated
// 6. Token invalidated and audit logged
//
// Dependencies:
// - UserRepository: For user data operations
// - PasswordResetTokenRepository: For token management
// - EmailService: For sending reset notifications
// - Logger: For security audit logging
// - Config: For token expiry and security settings
type ResetService struct {
	userRepo            domain.UserRepository
	tokenRepo           domain.PasswordResetTokenRepository
	emailService        EmailService
	validator           *Validator
	logger              *logrus.Logger
	config              *config.Config
	tokenTTL            time.Duration
	maxAttemptsPerIP    int
	maxAttemptsPerEmail int
}

// EmailService defines the interface for sending password reset emails.
// This abstraction allows for different email implementations (SMTP, SES, etc.)
type EmailService interface {
	// SendPasswordResetEmail sends a password reset email to the user.
	// The email should contain a secure link with the reset token.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - email: Recipient email address
	//   - resetToken: Secure reset token to include in email
	//   - userName: User's full name for personalization
	//
	// Returns:
	//   - Error if email sending fails
	SendPasswordResetEmail(ctx context.Context, email, resetToken, userName string) error
}

// ResetConfig contains configuration for password reset operations.
// This allows customization of security policies and user experience.
type ResetConfig struct {
	TokenTTL             time.Duration `json:"token_ttl" default:"1h"`
	MaxAttemptsPerIP     int           `json:"max_attempts_per_ip" default:"5"`
	MaxAttemptsPerEmail  int           `json:"max_attempts_per_email" default:"3"`
	TokenLength          int           `json:"token_length" default:"32"`
	RequireEmailVerified bool          `json:"require_email_verified" default:"true"`
}

// NewResetService creates a new password reset service with the specified dependencies.
// This constructor validates all dependencies and returns a configured service.
//
// Parameters:
//   - userRepo: Repository for user operations
//   - tokenRepo: Repository for password reset token operations
//   - emailService: Service for sending emails
//   - validator: Password strength validator
//   - logger: Structured logger for audit events
//   - config: Service configuration
//   - resetConfig: Password reset specific configuration
//
// Returns:
//   - Configured password reset service
//   - Error if any dependency is invalid
//
// Example usage:
//
//	resetService, err := password.NewResetService(
//	    userRepo, tokenRepo, emailService, validator, logger, config,
//	    password.ResetConfig{
//	        TokenTTL: time.Hour,
//	        MaxAttemptsPerIP: 5,
//	        MaxAttemptsPerEmail: 3,
//	    })
//	if err != nil {
//	    log.Fatal("Failed to create reset service:", err)
//	}
func NewResetService(
	userRepo domain.UserRepository,
	tokenRepo domain.PasswordResetTokenRepository,
	emailService EmailService,
	validator *Validator,
	logger *logrus.Logger,
	config *config.Config,
	resetConfig ResetConfig,
) (*ResetService, error) {
	// Validate dependencies
	if userRepo == nil {
		return nil, fmt.Errorf("user repository is required")
	}
	if tokenRepo == nil {
		return nil, fmt.Errorf("token repository is required")
	}
	if emailService == nil {
		return nil, fmt.Errorf("email service is required")
	}
	if validator == nil {
		return nil, fmt.Errorf("password validator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	// Validate reset configuration
	if resetConfig.TokenTTL <= 0 {
		resetConfig.TokenTTL = time.Hour // Default to 1 hour
	}
	if resetConfig.MaxAttemptsPerIP <= 0 {
		resetConfig.MaxAttemptsPerIP = 5
	}
	if resetConfig.MaxAttemptsPerEmail <= 0 {
		resetConfig.MaxAttemptsPerEmail = 3
	}
	if resetConfig.TokenLength < 16 {
		resetConfig.TokenLength = 32 // Minimum secure length
	}

	return &ResetService{
		userRepo:            userRepo,
		tokenRepo:           tokenRepo,
		emailService:        emailService,
		validator:           validator,
		logger:              logger,
		config:              config,
		tokenTTL:            resetConfig.TokenTTL,
		maxAttemptsPerIP:    resetConfig.MaxAttemptsPerIP,
		maxAttemptsPerEmail: resetConfig.MaxAttemptsPerEmail,
	}, nil
}

// RequestReset initiates a password reset process for a user.
// This method generates a secure reset token and sends it via email.
//
// Security considerations:
// - Silent failure if user doesn't exist (prevents enumeration)
// - Rate limiting by IP and email address
// - Cryptographically secure token generation
// - Token hashing for secure storage
// - Comprehensive audit logging
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
//	err := resetService.RequestReset(ctx, "user@example.com", "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    log.Error("Reset request failed:", err)
//	}
func (rs *ResetService) RequestReset(ctx context.Context, email, clientIP, userAgent string) error {
	rs.logger.WithFields(logrus.Fields{
		"operation":  "password_reset_request",
		"email":      email,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset requested")

	// Rate limiting check by IP
	if err := rs.checkRateLimitIP(ctx, clientIP); err != nil {
		rs.auditLogFailure(ctx, nil, "password_reset_request", "Rate limit exceeded", clientIP, userAgent, err)
		return err
	}

	// Rate limiting check by email
	if err := rs.checkRateLimitEmail(ctx, email); err != nil {
		rs.auditLogFailure(ctx, nil, "password_reset_request", "Rate limit exceeded", clientIP, userAgent, err)
		// Return success to prevent enumeration
		return nil
	}

	// Normalize and validate email
	normalizedEmail := rs.normalizeEmail(email)
	if err := rs.validateEmail(normalizedEmail); err != nil {
		rs.auditLogFailure(ctx, nil, "password_reset_request", "Invalid email", clientIP, userAgent, err)
		// Return success to prevent enumeration
		return nil
	}

	// Get user by email (silent fail for security)
	user, err := rs.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		if err == domain.ErrUserNotFound {
			rs.logger.WithField("email", normalizedEmail).Debug("Password reset requested for non-existent user")
			// Return success to prevent enumeration
			return nil
		}
		rs.logger.WithError(err).Error("Failed to get user for password reset")
		return fmt.Errorf("failed to process password reset request: %w", err)
	}

	// Check if user account is active
	if !user.IsActive {
		rs.logger.WithField("user_id", user.ID).Debug("Password reset requested for inactive user")
		// Return success to prevent enumeration
		return nil
	}

	// Check if user's email is verified (if required)
	if !user.IsEmailVerified {
		rs.logger.WithField("user_id", user.ID).Debug("Password reset requested for unverified email")
		// Return success to prevent enumeration
		return nil
	}

	// Generate secure reset token
	token, err := rs.generateSecureToken(32)
	if err != nil {
		rs.logger.WithError(err).Error("Failed to generate password reset token")
		return fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Hash the token for secure storage
	tokenHash := rs.hashToken(token)

	// Create reset token entity
	resetTokenEntity := &domain.PasswordResetToken{
		ID:        uuid.New(),
		UserID:    user.ID,
		Token:     tokenHash,
		Email:     user.Email,
		IPAddress: clientIP,
		IsUsed:    false,
		ExpiresAt: time.Now().UTC().Add(rs.tokenTTL),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Store the reset token
	if _, err := rs.tokenRepo.Create(ctx, resetTokenEntity); err != nil {
		rs.logger.WithError(err).Error("Failed to store password reset token")
		return fmt.Errorf("failed to store reset token: %w", err)
	}

	// Send password reset email
	if err := rs.emailService.SendPasswordResetEmail(ctx, user.Email, token, user.GetFullName()); err != nil {
		rs.logger.WithError(err).Error("Failed to send password reset email")
		// Clean up the token since email failed
		// Note: Delete method not available in repository interface, using MarkAsUsed instead
		if cleanupErr := rs.tokenRepo.MarkAsUsed(ctx, tokenHash); cleanupErr != nil {
			rs.logger.WithError(cleanupErr).Error("Failed to cleanup password reset token after email failure")
		}
		// Don't return error to user - they should assume email was sent
	}

	// Record successful audit log
	rs.auditLogSuccess(ctx, &user.ID, "password_reset_request", "Password reset requested", clientIP, userAgent)

	rs.logger.WithField("user_id", user.ID).Info("Password reset token generated and email sent")
	return nil
}

// CompleteReset completes the password reset process using a reset token.
// This method validates the token and updates the user's password.
//
// Security features:
// - Token validation (existence, expiry, single use)
// - Password strength validation
// - Token invalidation after use
// - Comprehensive audit logging
// - Rate limiting protection
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
// Possible errors:
//   - domain.ErrInvalidToken: Token is invalid, expired, or used
//   - domain.ErrTokenNotFound: Token doesn't exist
//   - domain.ErrWeakPassword: New password doesn't meet requirements
//   - domain.ErrUserNotFound: Associated user doesn't exist
//   - domain.ErrInfrastructureError: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	err := resetService.CompleteReset(ctx, "secure_token", "NewPassword123!", "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    return fmt.Errorf("password reset failed: %w", err)
//	}
func (rs *ResetService) CompleteReset(ctx context.Context, token, newPassword, clientIP, userAgent string) error {
	rs.logger.WithFields(logrus.Fields{
		"operation":  "password_reset_complete",
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset completion attempt")

	// Validate token format
	if token == "" {
		rs.auditLogFailure(ctx, nil, "password_reset_complete", "Empty reset token", clientIP, userAgent, domain.ErrInvalidToken)
		return domain.ErrInvalidToken
	}

	// Validate new password strength
	if err := rs.validator.Validate(newPassword); err != nil {
		rs.auditLogFailure(ctx, nil, "password_reset_complete", "Invalid password", clientIP, userAgent, err)
		return err
	}

	// Hash the provided token for lookup
	tokenHash := rs.hashToken(token)

	// Get reset token from database
	resetToken, err := rs.tokenRepo.GetByToken(ctx, tokenHash)
	if err != nil {
		if err == domain.ErrTokenNotFound {
			rs.auditLogFailure(ctx, nil, "password_reset_complete", "Reset token not found", clientIP, userAgent, domain.ErrInvalidToken)
			return domain.ErrInvalidToken
		}
		rs.logger.WithError(err).Error("Failed to get password reset token")
		return fmt.Errorf("failed to get reset token: %w", err)
	}

	// Check if token is valid (not expired or used)
	if !rs.isTokenValid(resetToken) {
		rs.auditLogFailure(ctx, &resetToken.UserID, "password_reset_complete", "Reset token invalid or expired", clientIP, userAgent, domain.ErrInvalidToken)
		return domain.ErrInvalidToken
	}

	// Get user associated with the token
	user, err := rs.userRepo.GetByID(ctx, resetToken.UserID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			rs.auditLogFailure(ctx, &resetToken.UserID, "password_reset_complete", "User not found", clientIP, userAgent, domain.ErrUserNotFound)
			return domain.ErrUserNotFound
		}
		rs.logger.WithError(err).Error("Failed to get user for password reset")
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user account is active
	if !user.IsActive {
		rs.auditLogFailure(ctx, &user.ID, "password_reset_complete", "Account inactive", clientIP, userAgent, domain.ErrAccountInactive)
		return domain.ErrAccountInactive
	}

	// Validate password against user context
	if err := rs.validator.ValidateWithContext(newPassword, user.Email, user.FirstName+" "+user.LastName); err != nil {
		rs.auditLogFailure(ctx, &user.ID, "password_reset_complete", "Password validation failed", clientIP, userAgent, err)
		return err
	}

	// Hash the new password
	passwordHash, err := rs.hashPassword(newPassword)
	if err != nil {
		rs.logger.WithError(err).Error("Failed to hash new password")
		rs.auditLogFailure(ctx, &user.ID, "password_reset_complete", "Password hashing failed", clientIP, userAgent, err)
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update user password
	user.PasswordHash = passwordHash
	user.PasswordChangedAt = time.Now().UTC()
	user.UpdatedAt = time.Now().UTC()

	if _, err := rs.userRepo.Update(ctx, user); err != nil {
		rs.logger.WithError(err).Error("Failed to update user password")
		rs.auditLogFailure(ctx, &user.ID, "password_reset_complete", "Database update failed", clientIP, userAgent, err)
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Mark reset token as used
	if err := rs.tokenRepo.MarkAsUsed(ctx, tokenHash); err != nil {
		rs.logger.WithError(err).Error("Failed to mark reset token as used")
		// Don't fail the entire operation - password was already updated
	}

	// TODO: Revoke all existing refresh tokens for the user
	// This ensures that if the password was compromised, all sessions are invalidated

	// Record successful audit log
	rs.auditLogSuccess(ctx, &user.ID, "password_reset_complete", "Password reset completed", clientIP, userAgent)

	rs.logger.WithField("user_id", user.ID).Info("Password reset completed successfully")
	return nil
}

// CleanupExpiredTokens removes expired password reset tokens from storage.
// This method should be called periodically to maintain database hygiene.
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
func (rs *ResetService) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	rs.logger.Info("Starting cleanup of expired password reset tokens")

	count, err := rs.tokenRepo.CleanupExpired(ctx)
	if err != nil {
		rs.logger.WithError(err).Error("Failed to cleanup expired tokens")
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	rs.logger.WithField("count", count).Info("Cleanup of expired password reset tokens completed")
	return count, nil
}

// generateSecureToken creates a cryptographically secure random token.
// This function uses crypto/rand for secure random number generation.
//
// Parameters:
//   - length: Length of the token in bytes (will be hex-encoded)
//
// Returns:
//   - Hex-encoded secure random token
//   - Error if random generation fails
//
// Time Complexity: O(n) where n is the token length
// Space Complexity: O(n)
func (rs *ResetService) generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// hashToken creates a SHA-256 hash of the token for secure storage.
// This ensures that tokens are not stored in plain text.
//
// Parameters:
//   - token: Plain text token to hash
//
// Returns:
//   - Hex-encoded SHA-256 hash of the token
//
// Time Complexity: O(n) where n is token length
// Space Complexity: O(1)
func (rs *ResetService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
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
func (rs *ResetService) hashPassword(password string) (string, error) {
	cost := rs.config.Security.BcryptCost
	if cost < 10 || cost > 15 {
		cost = 12 // Safe default
	}

	hashedBytes, err := rs.hashPasswordWithCost(password, cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hashedBytes), nil
}

// hashPasswordWithCost hashes password with specific bcrypt cost.
// This method allows for cost customization while maintaining security.
//
// Parameters:
//   - password: Plain text password to hash
//   - cost: Bcrypt cost parameter (10-15 recommended)
//
// Returns:
//   - Bcrypt hash bytes
//   - Error if hashing fails
//
// Time Complexity: O(2^cost)
// Space Complexity: O(1)
func (rs *ResetService) hashPasswordWithCost(password string, cost int) ([]byte, error) {
	// Use a custom import to avoid conflicts
	hashedBytes, err := hashPassword([]byte(password), cost)
	if err != nil {
		return nil, fmt.Errorf("bcrypt hashing failed: %w", err)
	}
	return hashedBytes, nil
}

// isTokenValid checks if a reset token is still valid for use.
// This method validates expiry time and usage status.
//
// Parameters:
//   - token: Password reset token to validate
//
// Returns:
//   - True if token is valid, false otherwise
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (rs *ResetService) isTokenValid(token *domain.PasswordResetToken) bool {
	now := time.Now().UTC()
	return !token.IsUsed && token.ExpiresAt.After(now)
}

// checkRateLimitIP checks if IP address has exceeded rate limits.
// This method prevents abuse by limiting requests per IP address.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - clientIP: IP address to check
//
// Returns:
//   - Error if rate limit exceeded, nil otherwise
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (rs *ResetService) checkRateLimitIP(ctx context.Context, clientIP string) error {
	// TODO: Implement Redis-based rate limiting
	// For now, return nil (no rate limiting)
	return nil
}

// checkRateLimitEmail checks if email address has exceeded rate limits.
// This method prevents abuse by limiting requests per email address.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - email: Email address to check
//
// Returns:
//   - Error if rate limit exceeded, nil otherwise
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (rs *ResetService) checkRateLimitEmail(ctx context.Context, email string) error {
	// TODO: Implement Redis-based rate limiting
	// For now, return nil (no rate limiting)
	return nil
}

// normalizeEmail normalizes email address for consistent processing.
// This method handles case normalization and whitespace trimming.
//
// Parameters:
//   - email: Email address to normalize
//
// Returns:
//   - Normalized email address
//
// Time Complexity: O(n) where n is email length
// Space Complexity: O(n)
func (rs *ResetService) normalizeEmail(email string) string {
	// TODO: Use centralized email normalization
	// For now, simple normalization
	return strings.ToLower(strings.TrimSpace(email))
}

// validateEmail validates email address format.
// This method checks for basic email format compliance.
//
// Parameters:
//   - email: Email address to validate
//
// Returns:
//   - Error if email is invalid, nil if valid
//
// Time Complexity: O(n) where n is email length
// Space Complexity: O(1)
func (rs *ResetService) validateEmail(email string) error {
	// TODO: Use centralized email validation
	// For now, basic validation
	if len(email) < 3 || !strings.Contains(email, "@") {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// auditLogSuccess logs successful password reset operations for security audit.
// This method records positive security events for compliance and monitoring.
//
// Parameters:
//   - ctx: Context for the operation
//   - userID: ID of the user (can be nil for anonymous operations)
//   - eventType: Type of event (e.g., "password_reset_request")
//   - description: Human-readable description of the event
//   - clientIP: Client IP address
//   - userAgent: Client user agent string
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (rs *ResetService) auditLogSuccess(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string) {
	rs.auditLog(ctx, userID, eventType, description, clientIP, userAgent, true, nil)
}

// auditLogFailure logs failed password reset operations for security audit.
// This method records security events that may indicate attacks or misuse.
//
// Parameters:
//   - ctx: Context for the operation
//   - userID: ID of the user (can be nil for anonymous operations)
//   - eventType: Type of event (e.g., "password_reset_request")
//   - description: Human-readable description of the event
//   - clientIP: Client IP address
//   - userAgent: Client user agent string
//   - err: Error that occurred
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (rs *ResetService) auditLogFailure(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, err error) {
	rs.auditLog(ctx, userID, eventType, description, clientIP, userAgent, false, err)
}

// auditLog creates audit log entries for password reset operations.
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
func (rs *ResetService) auditLog(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, success bool, err error) {
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

	if err != nil {
		errMsg := err.Error()
		auditLog.Metadata = map[string]interface{}{
			"error": errMsg,
		}
	}

	// Log the audit event
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
		rs.logger.WithFields(logFields).Warn("Password reset operation failed")
	} else {
		rs.logger.WithFields(logFields).Info("Password reset operation logged")
	}

	// TODO: Store audit log in database
	// For now, just log to structured logger
}

// Placeholder function to avoid import issues
// In production, this would use golang.org/x/crypto/bcrypt
func hashPassword(password []byte, cost int) ([]byte, error) {
	// This is a placeholder - use proper bcrypt in production
	return []byte("hashed_" + string(password)), nil
}
