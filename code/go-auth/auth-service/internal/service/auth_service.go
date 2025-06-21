package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// EmailService defines the interface for sending emails.
// This abstraction allows for different email implementations (SMTP, SES, etc.)
type EmailService interface {
	// SendPasswordResetEmail sends a password reset email to the user.
	SendPasswordResetEmail(ctx context.Context, email, resetToken, userName string) error

	// SendWelcomeEmail sends a welcome email to newly registered users.
	SendWelcomeEmail(ctx context.Context, email, userName, verificationToken string) error
}

// RateLimitService defines the interface for rate limiting operations.
// This prevents abuse and brute force attacks on authentication endpoints.
type RateLimitService interface {
	// CheckLoginAttempts checks if login attempts from IP/email are within limits.
	CheckLoginAttempts(ctx context.Context, identifier string) (bool, error)

	// RecordLoginAttempt records a login attempt (successful or failed).
	RecordLoginAttempt(ctx context.Context, identifier string, success bool) error

	// CheckPasswordResetAttempts checks if password reset attempts are within limits.
	CheckPasswordResetAttempts(ctx context.Context, identifier string) (bool, error)

	// RecordPasswordResetAttempt records a password reset attempt.
	RecordPasswordResetAttempt(ctx context.Context, identifier string) error
}

// AuthMetricsRecorder defines the interface for recording authentication metrics.
// This abstraction allows the auth service to record business metrics without
// directly depending on the metrics implementation (Prometheus, etc.).
type AuthMetricsRecorder interface {
	// RecordAuthOperation records metrics for authentication operations.
	RecordAuthOperation(operation, result string)

	// RecordTokenOperation records metrics for JWT token operations.
	RecordTokenOperation(operation, tokenType, result string)

	// SetActiveUsers updates the active users gauge.
	SetActiveUsers(count float64)

	// Registration metrics
	RecordRegistrationAttempt()
	RecordRegistrationSuccess()
	RecordRegistrationFailure(reason string)

	// Login metrics
	RecordLoginAttempt()
	RecordLoginSuccess()
	RecordLoginFailure(reason string)

	// Logout metrics
	RecordLogoutAttempt()
	RecordLogoutSuccess()
	RecordLogoutFailure(reason string)
}

// AuthService acts as a facade/coordinator for all authentication operations.
// This service delegates to specialized sub-services while maintaining backward
// compatibility with existing code that depends on the AuthService interface.
//
// Architecture:
// - AuthServiceCore: Handles user registration, login, and logout
// - AuthServiceTokens: Manages JWT tokens (generation, refresh, validation)
// - AuthServiceProfile: Handles user profile management and password operations
// - AuthServiceUtils: Provides shared utility functions
//
// This design follows the facade pattern and composition over inheritance,
// promoting single responsibility principle while maintaining a clean API.
//
// Benefits:
// - Eliminates code duplication between modular services
// - Maintains backward compatibility
// - Provides a single entry point for authentication operations
// - Enables easier testing and mocking of individual components
// - Follows SOLID principles
type AuthService struct {
	// Composed services for delegated operations
	core    *AuthServiceCore
	tokens  *AuthServiceTokens
	profile *AuthServiceProfile
}

// NewAuthService creates a new AuthService instance by composing the modular services.
// This constructor creates and configures all the sub-services and returns a facade
// that delegates operations to the appropriate specialized service.
//
// Parameters:
//   - userRepo: Repository for user data operations
//   - refreshTokenRepo: Repository for refresh token operations
//   - passwordResetRepo: Repository for password reset token operations
//   - auditRepo: Repository for audit log operations
//   - logger: Structured logger for service events
//   - config: Service configuration
//   - emailService: Service for sending emails
//   - rateLimitService: Service for rate limiting
//   - metricsRecorder: Service for recording metrics
//
// Returns:
//   - Configured AuthService facade
//   - Error if any dependency is invalid
//
// Example usage:
//
//	authService, err := NewAuthService(
//	    userRepo, tokenRepo, resetRepo, auditRepo,
//	    logger, config, emailSvc, rateLimitSvc, metricsRecorder,
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewAuthService(
	userRepo domain.UserRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	passwordResetRepo domain.PasswordResetTokenRepository,
	auditRepo domain.AuditLogRepository,
	logger *logrus.Logger,
	config *config.Config,
	emailService EmailService,
	rateLimitService RateLimitService,
	metricsRecorder AuthMetricsRecorder,
) (*AuthService, error) {
	// Validate required dependencies
	if userRepo == nil {
		return nil, fmt.Errorf("user repository is required")
	}
	if refreshTokenRepo == nil {
		return nil, fmt.Errorf("refresh token repository is required")
	}
	if passwordResetRepo == nil {
		return nil, fmt.Errorf("password reset repository is required")
	}
	if auditRepo == nil {
		return nil, fmt.Errorf("audit repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if emailService == nil {
		return nil, fmt.Errorf("email service is required")
	}
	if rateLimitService == nil {
		return nil, fmt.Errorf("rate limit service is required")
	}
	if metricsRecorder == nil {
		return nil, fmt.Errorf("metrics recorder is required")
	}

	// Create shared utilities
	utils, err := NewAuthServiceUtils(config, logger, auditRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service utils: %w", err)
	}

	// Create specialized services
	core, err := NewAuthServiceCore(
		userRepo, refreshTokenRepo, auditRepo, logger, config,
		emailService, rateLimitService, metricsRecorder, utils,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service core: %w", err)
	}

	tokens, err := NewAuthServiceTokens(refreshTokenRepo, logger, config, utils)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service tokens: %w", err)
	}

	profile, err := NewAuthServiceProfile(
		userRepo, passwordResetRepo, logger, config, utils,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service profile: %w", err)
	}

	return &AuthService{
		core:    core,
		tokens:  tokens,
		profile: profile,
	}, nil
}

// ====================================================================================
// CORE AUTHENTICATION OPERATIONS
// These methods delegate to AuthServiceCore
// ====================================================================================

// Register creates a new user account with the provided registration data.
// This method delegates to the core service for user registration.
//
// See AuthServiceCore.Register for detailed documentation.
func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest, clientIP, userAgent string) (*domain.User, error) {
	return s.core.Register(ctx, req, clientIP, userAgent)
}

// Login authenticates a user with email and password credentials.
// This method delegates to the core service for user authentication.
//
// See AuthServiceCore.Login for detailed documentation.
func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest, clientIP, userAgent string) (*domain.AuthResponse, error) {
	return s.core.Login(ctx, req, clientIP, userAgent)
}

// Logout invalidates the user's current session by revoking the refresh token.
// This method delegates to the core service for session termination.
//
// See AuthServiceCore.Logout for detailed documentation.
func (s *AuthService) Logout(ctx context.Context, refreshToken, clientIP, userAgent string) error {
	return s.core.Logout(ctx, refreshToken, clientIP, userAgent)
}

// LogoutAll revokes all refresh tokens for a user, effectively logging them out from all devices.
// This method delegates to the core service for comprehensive session termination.
//
// See AuthServiceCore.LogoutAll for detailed documentation.
func (s *AuthService) LogoutAll(ctx context.Context, userID uuid.UUID, clientIP, userAgent string) error {
	return s.core.LogoutAll(ctx, userID, clientIP, userAgent)
}

// ====================================================================================
// TOKEN MANAGEMENT OPERATIONS
// These methods delegate to AuthServiceTokens
// ====================================================================================

// RefreshToken generates a new access token using a valid refresh token.
// This method delegates to the tokens service for token refresh operations.
//
// See AuthServiceTokens.RefreshToken for detailed documentation.
func (s *AuthService) RefreshToken(ctx context.Context, req *domain.RefreshTokenRequest, clientIP, userAgent string) (*domain.AuthResponse, error) {
	return s.tokens.RefreshToken(ctx, req, clientIP, userAgent)
}

// ====================================================================================
// USER PROFILE OPERATIONS
// These methods delegate to AuthServiceProfile
// ====================================================================================

// GetUserByID retrieves a user by their unique identifier.
// This method delegates to the profile service for user lookup.
//
// See AuthServiceProfile.GetUserByID for detailed documentation.
func (s *AuthService) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	return s.profile.GetUserByID(ctx, id)
}

// GetUserByEmail retrieves a user by their email address.
// This method delegates to the profile service for email-based user lookup.
//
// See AuthServiceProfile.GetUserByEmail for detailed documentation.
func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.profile.GetUserByEmail(ctx, email)
}

// UpdateProfile updates a user's profile information with partial update support.
// This method delegates to the profile service for profile management.
//
// See AuthServiceProfile.UpdateProfile for detailed documentation.
func (s *AuthService) UpdateProfile(ctx context.Context, userID string, updateData map[string]interface{}) error {
	return s.profile.UpdateProfile(ctx, userID, updateData)
}

// RequestPasswordReset initiates a password reset process for a user.
// This method delegates to the profile service for password reset operations.
//
// See AuthServiceProfile.RequestPasswordReset for detailed documentation.
func (s *AuthService) RequestPasswordReset(ctx context.Context, req *domain.ResetPasswordRequest, clientIP, userAgent string) error {
	return s.profile.RequestPasswordReset(ctx, req, clientIP, userAgent)
}

// ResetPassword completes the password reset process using a valid reset token.
// This method delegates to the profile service for password reset completion.
//
// See AuthServiceProfile.ResetPassword for detailed documentation.
func (s *AuthService) ResetPassword(ctx context.Context, req *domain.ConfirmResetPasswordRequest, clientIP, userAgent string) error {
	return s.profile.ResetPassword(ctx, req, clientIP, userAgent)
}

// ====================================================================================
// AUDIT LOGGING OPERATIONS
// These methods provide access to audit logging functionality
// ====================================================================================

// LogAuditEvent logs an audit event for security and compliance purposes.
// This method provides a public interface to the audit logging functionality.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - auditLog: Audit log entry to record
//
// Returns:
//   - Error if audit logging fails
//
// Note: This method should be non-blocking for the calling operation.
// Audit logging failures should not fail the primary business operation.
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (s *AuthService) LogAuditEvent(ctx context.Context, auditLog *domain.AuditLog) error {
	// For now, just return nil since audit logging is handled internally by the sub-services
	// In the future, this could delegate to a dedicated audit service
	return nil
}
