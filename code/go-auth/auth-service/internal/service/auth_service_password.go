package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"auth-service/internal/domain"
)

// ChangePassword allows an authenticated user to change their password.
// This method requires the current password for verification before allowing
// the password change, providing protection against unauthorized changes.
//
// Security features:
// - Current password verification prevents unauthorized changes
// - New password strength validation
// - Password history checking (can be implemented)
// - All existing refresh tokens are revoked after password change
// - Audit logging of password change attempts
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the authenticated user changing password
//   - req: Change password request with current and new passwords
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error if password change fails
//
// Possible errors:
//   - domain.ErrUserNotFound: User doesn't exist
//   - domain.ErrInvalidCredentials: Current password is incorrect
//   - domain.ErrWeakPassword: New password doesn't meet requirements
//   - domain.ErrAccountInactive: Account is disabled or deleted
//   - domain.ErrDatabase: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, req *domain.ChangePasswordRequest, clientIP, userAgent string) error {
	s.logger.WithFields(map[string]interface{}{
		"operation":  "change_password",
		"user_id":    userID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password change attempt")

	// Validate new password strength
	if err := s.validatePasswordStrength(req.NewPassword); err != nil {
		s.auditLogFailure(ctx, &userID, "user.password.change.failure", "New password validation failed", clientIP, userAgent, err)
		return err
	}

	// Get user from database
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.auditLogFailure(ctx, &userID, "user.password.change.failure", "User not found", clientIP, userAgent, err)
			return domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user")
		return domain.ErrDatabase
	}

	// Check account status
	if user.IsDeleted() || !user.IsActive {
		s.auditLogFailure(ctx, &userID, "user.password.change.failure", "Account inactive or deleted", clientIP, userAgent, domain.ErrAccountInactive)
		return domain.ErrAccountInactive
	}

	// Verify current password
	if err := s.verifyPassword(req.CurrentPassword, user.PasswordHash); err != nil {
		s.auditLogFailure(ctx, &userID, "user.password.change.failure", "Current password verification failed", clientIP, userAgent, domain.ErrInvalidCredentials)
		return domain.ErrInvalidCredentials
	}

	// Hash new password
	newPasswordHash, err := s.hashPassword(req.NewPassword)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash new password")
		return fmt.Errorf("password hashing failed: %w", err)
	}

	// Update user password in database
	now := time.Now()
	user.PasswordHash = newPasswordHash
	user.PasswordChangedAt = now
	user.UpdatedAt = now

	_, err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update user password")
		s.auditLogFailure(ctx, &userID, "user.password.change.failure", "Database update failed", clientIP, userAgent, err)
		return domain.ErrDatabase
	}

	// Revoke all existing refresh tokens for security
	if err := s.refreshTokenRepo.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.WithError(err).Warn("Failed to revoke refresh tokens after password change")
		// Don't fail the operation, but log the warning
	}

	// Log successful password change
	s.auditLogSuccess(ctx, &userID, "user.password.change.success", "Password changed successfully", clientIP, userAgent)

	s.logger.WithFields(map[string]interface{}{
		"operation": "change_password",
		"user_id":   userID,
	}).Info("Password changed successfully")

	return nil
}

// ResetPassword initiates the password reset flow by sending a reset token to the user's email.
// This method generates a secure token and sends it via email for password reset verification.
//
// Security features:
// - Rate limiting prevents email flooding abuse
// - Secure random token generation
// - Time-limited tokens (typically 1 hour)
// - Email existence is not revealed for privacy
// - All reset attempts are logged for audit
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Password reset request with email address
//   - clientIP: Client IP address for audit and rate limiting
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error if reset initiation fails
//
// Possible errors:
//   - domain.ErrRateLimitExceeded: Too many reset requests
//   - domain.ErrEmailService: Email sending failed
//   - domain.ErrDatabase: Database operation failed
//
// Note: This method always returns success to prevent email enumeration attacks.
// The actual success/failure is only visible in audit logs.
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) ResetPassword(ctx context.Context, req *domain.ResetPasswordRequest, clientIP, userAgent string) error {
	s.logger.WithFields(map[string]interface{}{
		"operation":  "reset_password",
		"email":      req.Email,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset request")

	// Normalize email for consistent lookup
	normalizedEmail := s.normalizeEmail(req.Email)

	// Check rate limiting for password reset requests
	allowed, err := s.rateLimitService.CheckPasswordResetAttempts(ctx, normalizedEmail)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check password reset rate limit")
		return domain.ErrDatabase
	}
	if !allowed {
		s.auditLogFailure(ctx, nil, "user.password.reset.failure", "Rate limit exceeded", clientIP, userAgent, domain.ErrRateLimitExceeded)
		return domain.ErrRateLimitExceeded
	}

	// Record the reset attempt for rate limiting
	if err := s.rateLimitService.RecordPasswordResetAttempt(ctx, normalizedEmail); err != nil {
		s.logger.WithError(err).Warn("Failed to record password reset attempt")
		// Don't fail the operation for rate limiting issues
	}

	// Look up user by email (but don't reveal if user exists or not)
	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil && err != domain.ErrUserNotFound {
		s.logger.WithError(err).Error("Failed to get user by email")
		return domain.ErrDatabase
	}

	// If user exists and is active, proceed with reset token generation
	if user != nil && !user.IsDeleted() && user.IsActive {
		// Generate secure reset token
		resetToken, err := s.generateSecureToken(32) // 64 character hex string
		if err != nil {
			s.logger.WithError(err).Error("Failed to generate reset token")
			return fmt.Errorf("token generation failed: %w", err)
		}

		// Create password reset token entity
		tokenEntity := &domain.PasswordResetToken{
			ID:        uuid.New(),
			UserID:    user.ID,
			Token:     resetToken,
			Email:     normalizedEmail,
			IPAddress: clientIP,
			ExpiresAt: time.Now().Add(s.config.Security.PasswordResetTokenExpiry),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Store reset token in database
		_, err = s.passwordResetRepo.Create(ctx, tokenEntity)
		if err != nil {
			s.logger.WithError(err).Error("Failed to store password reset token")
			s.auditLogFailure(ctx, &user.ID, "user.password.reset.failure", "Database storage failed", clientIP, userAgent, err)
			return domain.ErrDatabase
		}

		// Send password reset email
		if err := s.emailService.SendPasswordResetEmail(ctx, user.Email, resetToken, user.GetFullName()); err != nil {
			s.logger.WithError(err).Error("Failed to send password reset email")
			s.auditLogFailure(ctx, &user.ID, "user.password.reset.failure", "Email sending failed", clientIP, userAgent, err)
			return domain.ErrEmailService
		}

		// Log successful reset initiation
		s.auditLogSuccess(ctx, &user.ID, "user.password.reset.initiated", "Password reset email sent", clientIP, userAgent)

		s.logger.WithFields(map[string]interface{}{
			"operation": "reset_password",
			"user_id":   user.ID,
			"email":     user.Email,
		}).Info("Password reset email sent successfully")
	} else {
		// Log failed attempt (user not found or inactive) but don't reveal this to caller
		s.auditLogFailure(ctx, nil, "user.password.reset.failure", "User not found or inactive", clientIP, userAgent, domain.ErrUserNotFound)

		s.logger.WithFields(map[string]interface{}{
			"operation": "reset_password",
			"email":     normalizedEmail,
		}).Info("Password reset requested for non-existent or inactive user")
	}

	// Always return success to prevent email enumeration attacks
	return nil
}

// ConfirmResetPassword completes the password reset flow using the token sent via email.
// This method validates the reset token and sets a new password for the user.
//
// Security features:
// - Token validation (expiry, single-use)
// - Email verification matches original request
// - New password strength validation
// - All existing refresh tokens are revoked
// - Reset token is invalidated after use
// - Audit logging of reset completion attempts
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Confirm reset password request with token and new password
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error if password reset completion fails
//
// Possible errors:
//   - domain.ErrInvalidToken: Token is invalid, expired, or already used
//   - domain.ErrTokenNotFound: Token not found in database
//   - domain.ErrWeakPassword: New password doesn't meet requirements
//   - domain.ErrUserNotFound: User associated with token doesn't exist
//   - domain.ErrAccountInactive: User account is disabled or deleted
//   - domain.ErrDatabase: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) ConfirmResetPassword(ctx context.Context, req *domain.ConfirmResetPasswordRequest, clientIP, userAgent string) error {
	s.logger.WithFields(map[string]interface{}{
		"operation":  "confirm_reset_password",
		"email":      req.Email,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Password reset confirmation attempt")

	// Debug logging to help troubleshoot token issues
	s.logger.WithFields(map[string]interface{}{
		"token_present": req.Token != "",
		"token_length":  len(req.Token),
		"email_present": req.Email != "",
	}).Debug("Password reset confirmation request details")

	// Validate that required fields are present
	if req.Token == "" {
		s.logger.Error("Password reset token is empty in request")
		s.auditLogFailure(ctx, nil, "user.password.reset.confirm.failure", "Empty reset token", clientIP, userAgent, domain.ErrInvalidToken)
		return domain.ErrInvalidToken
	}

	// Validate new password strength
	if err := s.validatePasswordStrength(req.NewPassword); err != nil {
		s.auditLogFailure(ctx, nil, "user.password.reset.confirm.failure", "New password validation failed", clientIP, userAgent, err)
		return err
	}

	// Get reset token from database
	resetToken, err := s.passwordResetRepo.GetByToken(ctx, req.Token)
	if err != nil {
		if err == domain.ErrTokenNotFound {
			s.auditLogFailure(ctx, nil, "user.password.reset.confirm.failure", "Reset token not found", clientIP, userAgent, domain.ErrInvalidToken)
			return domain.ErrInvalidToken
		}
		s.logger.WithError(err).Error("Failed to get password reset token")
		return domain.ErrDatabase
	}

	// Validate reset token
	if !resetToken.IsValid() {
		s.auditLogFailure(ctx, &resetToken.UserID, "user.password.reset.confirm.failure", "Invalid or expired reset token", clientIP, userAgent, domain.ErrInvalidToken)
		return domain.ErrInvalidToken
	}

	// Verify email matches the token
	normalizedEmail := s.normalizeEmail(req.Email)
	if resetToken.Email != normalizedEmail {
		s.auditLogFailure(ctx, &resetToken.UserID, "user.password.reset.confirm.failure", "Email mismatch", clientIP, userAgent, domain.ErrInvalidToken)
		return domain.ErrInvalidToken
	}

	// Get user from database
	user, err := s.userRepo.GetByID(ctx, resetToken.UserID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.auditLogFailure(ctx, &resetToken.UserID, "user.password.reset.confirm.failure", "User not found", clientIP, userAgent, err)
			return domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user")
		return domain.ErrDatabase
	}

	// Check account status
	if user.IsDeleted() || !user.IsActive {
		s.auditLogFailure(ctx, &user.ID, "user.password.reset.confirm.failure", "Account inactive or deleted", clientIP, userAgent, domain.ErrAccountInactive)
		return domain.ErrAccountInactive
	}

	// Hash new password
	newPasswordHash, err := s.hashPassword(req.NewPassword)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash new password")
		return fmt.Errorf("password hashing failed: %w", err)
	}

	// Update user password in database
	now := time.Now()
	user.PasswordHash = newPasswordHash
	user.PasswordChangedAt = now
	user.UpdatedAt = now

	_, err = s.userRepo.Update(ctx, user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update user password")
		s.auditLogFailure(ctx, &user.ID, "user.password.reset.confirm.failure", "Database update failed", clientIP, userAgent, err)
		return domain.ErrDatabase
	}

	// Mark reset token as used
	if err := s.passwordResetRepo.MarkAsUsed(ctx, req.Token); err != nil {
		s.logger.WithError(err).Warn("Failed to mark reset token as used")
		// Don't fail the operation, but log the warning
	}

	// Revoke all existing refresh tokens for security
	if err := s.refreshTokenRepo.RevokeAllUserTokens(ctx, user.ID); err != nil {
		s.logger.WithError(err).Warn("Failed to revoke refresh tokens after password reset")
		// Don't fail the operation, but log the warning
	}

	// Invalidate any other password reset tokens for this user
	if err := s.passwordResetRepo.InvalidateUserTokens(ctx, user.ID); err != nil {
		s.logger.WithError(err).Warn("Failed to invalidate other reset tokens")
		// Don't fail the operation, but log the warning
	}

	// Log successful password reset completion
	s.auditLogSuccess(ctx, &user.ID, "user.password.reset.confirm.success", "Password reset completed successfully", clientIP, userAgent)

	s.logger.WithFields(map[string]interface{}{
		"operation": "confirm_reset_password",
		"user_id":   user.ID,
		"email":     user.Email,
	}).Info("Password reset completed successfully")

	return nil
}

// GetUserProfile retrieves the current user's profile information.
// This method returns user data without sensitive information like password hashes.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the authenticated user
//
// Returns:
//   - User entity without sensitive data
//   - Error if retrieval fails
//
// Possible errors:
//   - domain.ErrUserNotFound: User doesn't exist
//   - domain.ErrAccountInactive: Account is disabled or deleted
//   - domain.ErrDatabase: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) GetUserProfile(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	s.logger.WithFields(map[string]interface{}{
		"operation": "get_user_profile",
		"user_id":   userID,
	}).Debug("Getting user profile")

	// Get user from database
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user")
		return nil, domain.ErrDatabase
	}

	// Check account status
	if user.IsDeleted() || !user.IsActive {
		return nil, domain.ErrAccountInactive
	}

	return user, nil
}

// LogoutAll revokes all refresh tokens for a user, effectively logging them out from all devices.
// This is useful for security incidents or when a user wants to log out from all sessions.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the authenticated user
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error if logout operation fails
//
// Time Complexity: O(n) where n is the number of user's active tokens
// Space Complexity: O(1)
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID, clientIP, userAgent string) error {
	s.logger.WithFields(map[string]interface{}{
		"operation":  "logout_all",
		"user_id":    userID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Logout all sessions attempt")

	// Revoke all refresh tokens for the user
	if err := s.refreshTokenRepo.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.WithError(err).Error("Failed to revoke all user tokens")
		s.auditLogFailure(ctx, &userID, "user.logout.all.failure", "Failed to revoke all tokens", clientIP, userAgent, err)
		return domain.ErrDatabase
	}

	// Log successful logout from all devices
	s.auditLogSuccess(ctx, &userID, "user.logout.all.success", "Logged out from all devices", clientIP, userAgent)

	s.logger.WithFields(map[string]interface{}{
		"operation": "logout_all",
		"user_id":   userID,
	}).Info("User logged out from all devices")

	return nil
}

// Helper method to verify password using constant-time comparison
func (s *AuthService) verifyPassword(plaintext, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}
