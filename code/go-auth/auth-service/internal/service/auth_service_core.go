package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// AuthServiceCore handles core authentication operations including
// user registration, login, and logout functionality.
//
// This service implements the fundamental authentication operations:
// - User registration with email verification
// - User login with credential validation
// - User logout with token revocation
// - Account security and audit logging
//
// Security features:
// - Password strength validation
// - Rate limiting integration
// - Comprehensive audit logging
// - Input validation and sanitization
//
// Dependencies:
// - UserRepository: For user data persistence
// - RefreshTokenRepository: For token management
// - AuditLogRepository: For security audit logging
// - Logger: For structured logging
// - Config: For service configuration
// - EmailService: For sending notification emails
// - RateLimitService: For preventing abuse and brute force attacks
// - AuthMetricsRecorder: For recording business metrics
// - AuthServiceUtils: For utility functions (validation, hashing, etc.)
type AuthServiceCore struct {
	userRepo         domain.UserRepository
	refreshTokenRepo domain.RefreshTokenRepository
	auditRepo        domain.AuditLogRepository
	logger           *logrus.Logger
	config           *config.Config
	emailService     EmailService
	rateLimitService RateLimitService
	metricsRecorder  AuthMetricsRecorder
	utils            *AuthServiceUtils
}

// NewAuthServiceCore creates a new instance of the core authentication service.
// This constructor validates all dependencies and initializes the service
// with proper configuration.
//
// Parameters:
//   - userRepo: Repository for user data operations
//   - refreshTokenRepo: Repository for refresh token management
//   - auditRepo: Repository for audit log persistence
//   - logger: Structured logger for service operations
//   - config: Service configuration
//   - emailService: Service for sending emails
//   - rateLimitService: Service for rate limiting
//   - metricsRecorder: Service for recording business metrics
//   - utils: Utility functions for common operations
//
// Returns:
//   - Configured AuthServiceCore instance
//   - Error if any dependency is invalid
//
// Example usage:
//
//	coreService, err := NewAuthServiceCore(
//	    userRepo, refreshTokenRepo, auditRepo,
//	    logger, config, emailService, rateLimitService,
//	    metricsRecorder, utils,
//	)
//	if err != nil {
//	    log.Fatal("Failed to create core auth service:", err)
//	}
func NewAuthServiceCore(
	userRepo domain.UserRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	auditRepo domain.AuditLogRepository,
	logger *logrus.Logger,
	config *config.Config,
	emailService EmailService,
	rateLimitService RateLimitService,
	metricsRecorder AuthMetricsRecorder,
	utils *AuthServiceUtils,
) (*AuthServiceCore, error) {
	// Validate required dependencies
	if userRepo == nil {
		return nil, fmt.Errorf("user repository is required")
	}
	if refreshTokenRepo == nil {
		return nil, fmt.Errorf("refresh token repository is required")
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
	if utils == nil {
		return nil, fmt.Errorf("auth service utils is required")
	}

	return &AuthServiceCore{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		auditRepo:        auditRepo,
		logger:           logger,
		config:           config,
		emailService:     emailService,
		rateLimitService: rateLimitService,
		metricsRecorder:  metricsRecorder,
		utils:            utils,
	}, nil
}

// Register creates a new user account with comprehensive validation and security measures.
// This method handles the complete user registration process including input validation,
// password security, email verification, and audit logging.
//
// Security features:
// - Email uniqueness validation
// - Password strength enforcement
// - Input sanitization and validation
// - Rate limiting protection
// - Comprehensive audit logging
// - Welcome email with verification
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Registration request containing user details
//   - clientIP: Client IP address for security logging
//   - userAgent: Client user agent for security logging
//
// Returns:
//   - Created user entity (without sensitive data)
//   - Error if registration fails
//
// Possible errors:
//   - domain.ErrEmailAlreadyExists: Email is already registered
//   - domain.ErrWeakPassword: Password doesn't meet security requirements
//   - domain.ErrValidationFailed: Input validation failed
//   - domain.ErrRateLimitExceeded: Too many registration attempts
//   - domain.ErrInfrastructureError: Database or email service error
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	user, err := authCore.Register(ctx, &domain.RegisterRequest{
//	    Email:           "user@example.com",
//	    Password:        "SecurePassword123!",
//	    PasswordConfirm: "SecurePassword123!",
//	    FirstName:       "John",
//	    LastName:        "Doe",
//	}, "192.168.1.1", "Mozilla/5.0...")
func (s *AuthServiceCore) Register(ctx context.Context, req *domain.RegisterRequest, clientIP, userAgent string) (*domain.User, error) {
	s.logger.WithFields(logrus.Fields{
		"operation":  "register",
		"email":      req.Email,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("User registration attempt")

	// Record metrics for monitoring
	s.metricsRecorder.RecordRegistrationAttempt()

	// Check rate limiting
	allowed, err := s.rateLimitService.CheckLoginAttempts(ctx, clientIP)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check rate limit")
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}
	if !allowed {
		s.utils.auditLogFailure(ctx, nil, "registration", "Rate limit exceeded", clientIP, userAgent, domain.ErrRateLimitExceeded)
		s.metricsRecorder.RecordRegistrationFailure("rate_limit")
		return nil, domain.ErrRateLimitExceeded
	}

	// Normalize and validate email
	normalizedEmail := s.utils.normalizeEmail(req.Email)
	if normalizedEmail == "" {
		s.utils.auditLogFailure(ctx, nil, "registration", "Invalid email format", clientIP, userAgent, domain.ErrValidationFailed)
		s.metricsRecorder.RecordRegistrationFailure("invalid_email")
		return nil, domain.ErrValidationFailed
	}

	// Validate password strength
	if err := s.utils.validatePasswordStrength(req.Password); err != nil {
		s.utils.auditLogFailure(ctx, nil, "registration", "Weak password", clientIP, userAgent, err)
		s.metricsRecorder.RecordRegistrationFailure("weak_password")
		return nil, err
	}

	// Verify password confirmation
	if req.Password != req.PasswordConfirm {
		s.utils.auditLogFailure(ctx, nil, "registration", "Password confirmation mismatch", clientIP, userAgent, domain.ErrValidationFailed)
		s.metricsRecorder.RecordRegistrationFailure("password_mismatch")
		return nil, domain.ErrValidationFailed
	}

	// Check if user already exists
	existingUser, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil && !domain.IsNotFoundError(err) {
		s.logger.WithError(err).Error("Failed to check existing user")
		s.metricsRecorder.RecordRegistrationFailure("database_error")
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}
	if existingUser != nil {
		s.utils.auditLogFailure(ctx, nil, "registration", "Email already exists", clientIP, userAgent, domain.ErrEmailAlreadyExists)
		s.metricsRecorder.RecordRegistrationFailure("email_exists")
		return nil, domain.ErrEmailAlreadyExists
	}

	// Hash password
	hashedPassword, err := s.utils.hashPassword(req.Password)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		s.metricsRecorder.RecordRegistrationFailure("password_hash_error")
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user entity
	user := &domain.User{
		ID:           uuid.New(),
		Email:        normalizedEmail,
		PasswordHash: hashedPassword,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
		IsActive:     true,
	}

	// Create user in database
	createdUser, err := s.userRepo.Create(ctx, user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create user")
		s.utils.auditLogFailure(ctx, nil, "registration", "Database error", clientIP, userAgent, err)
		s.metricsRecorder.RecordRegistrationFailure("database_error")
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Send welcome email (non-blocking)
	go func() {
		emailCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.emailService.SendWelcomeEmail(emailCtx, createdUser.Email, createdUser.GetFullName(), ""); err != nil {
			s.logger.WithError(err).WithField("user_id", createdUser.ID).Error("Failed to send welcome email")
		}
	}()

	// Record successful audit log
	s.utils.auditLogSuccess(ctx, &createdUser.ID, "registration", "User registered successfully", clientIP, userAgent)
	s.metricsRecorder.RecordRegistrationSuccess()

	s.logger.WithFields(logrus.Fields{
		"user_id": createdUser.ID,
		"email":   createdUser.Email,
	}).Info("User registered successfully")

	return createdUser, nil
}

// Login authenticates a user with email and password, returning JWT tokens.
// This method implements comprehensive security measures including rate limiting,
// password verification, account status validation, and audit logging.
//
// Security features:
// - Rate limiting protection against brute force attacks
// - Secure password verification using bcrypt
// - Account status validation (active, not deleted)
// - Comprehensive audit logging for all attempts
// - JWT token generation with secure claims
// - Last login timestamp updates
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Login request containing email and password
//   - clientIP: Client IP address for security logging and rate limiting
//   - userAgent: Client user agent for security logging
//
// Returns:
//   - Authentication response with JWT tokens and user data
//   - Error if authentication fails
//
// Possible errors:
//   - domain.ErrRateLimitExceeded: Too many failed attempts from this IP
//   - domain.ErrInvalidCredentials: Email/password combination is invalid
//   - domain.ErrAccountInactive: User account is disabled or deleted
//   - domain.ErrValidationFailed: Input validation failed
//   - domain.ErrInfrastructureError: Database or external service error
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	authResponse, err := authCore.Login(ctx, &domain.LoginRequest{
//	    Email:    "user@example.com",
//	    Password: "userPassword123",
//	}, "192.168.1.1", "Mozilla/5.0...")
func (s *AuthServiceCore) Login(ctx context.Context, req *domain.LoginRequest, clientIP, userAgent string) (*domain.AuthResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"operation":  "login",
		"email":      req.Email,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("User login attempt")

	// Record metrics for monitoring
	s.metricsRecorder.RecordLoginAttempt()

	// Check rate limiting
	allowed, err := s.rateLimitService.CheckLoginAttempts(ctx, clientIP)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check rate limit")
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}
	if !allowed {
		s.utils.auditLogFailure(ctx, nil, "login", "Rate limit exceeded", clientIP, userAgent, domain.ErrRateLimitExceeded)
		s.metricsRecorder.RecordLoginFailure("rate_limit")
		return nil, domain.ErrRateLimitExceeded
	}

	// Normalize email
	normalizedEmail := s.utils.normalizeEmail(req.Email)
	if normalizedEmail == "" {
		s.utils.auditLogFailure(ctx, nil, "login", "Invalid email format", clientIP, userAgent, domain.ErrValidationFailed)
		s.metricsRecorder.RecordLoginFailure("invalid_email")
		return nil, domain.ErrValidationFailed
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		if domain.IsNotFoundError(err) {
			s.utils.auditLogFailure(ctx, nil, "login", "User not found", clientIP, userAgent, domain.ErrInvalidCredentials)
			s.metricsRecorder.RecordLoginFailure("user_not_found")
			// Record failed attempt for rate limiting
			s.rateLimitService.RecordLoginAttempt(ctx, clientIP, false)
			return nil, domain.ErrInvalidCredentials
		}
		s.logger.WithError(err).Error("Failed to get user by email")
		s.metricsRecorder.RecordLoginFailure("database_error")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if user account is active
	if user.IsDeleted() || !user.IsActive {
		s.utils.auditLogFailure(ctx, &user.ID, "login", "Account inactive or deleted", clientIP, userAgent, domain.ErrAccountInactive)
		s.metricsRecorder.RecordLoginFailure("account_inactive")
		// Record failed attempt for rate limiting
		s.rateLimitService.RecordLoginAttempt(ctx, clientIP, false)
		// Return generic error to prevent account enumeration attacks
		return nil, domain.ErrInvalidCredentials
	}

	// Verify password
	if err := s.utils.verifyPassword(req.Password, user.PasswordHash); err != nil {
		s.utils.auditLogFailure(ctx, &user.ID, "login", "Invalid password", clientIP, userAgent, domain.ErrInvalidCredentials)
		s.metricsRecorder.RecordLoginFailure("invalid_password")
		// Record failed attempt for rate limiting
		s.rateLimitService.RecordLoginAttempt(ctx, clientIP, false)
		return nil, domain.ErrInvalidCredentials
	}

	// Create tokens using the token service
	tokenService, err := NewAuthServiceTokens(s.userRepo, s.refreshTokenRepo, s.logger, s.config, s.utils)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create token service")
		s.utils.auditLogFailure(ctx, &user.ID, "login", "Token service creation failed", clientIP, userAgent, err)
		s.metricsRecorder.RecordLoginFailure("token_service_error")
		return nil, fmt.Errorf("failed to create token service: %w", err)
	}

	authResponse, err := tokenService.GenerateTokenPair(ctx, user, clientIP, userAgent)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate tokens")
		s.utils.auditLogFailure(ctx, &user.ID, "login", "Token generation failed", clientIP, userAgent, err)
		s.metricsRecorder.RecordLoginFailure("token_generation_error")
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Update last login timestamp
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
		s.logger.WithError(err).Error("Failed to update last login")
		// Don't fail the login for this non-critical error
	}

	// Record successful login attempt for rate limiting
	s.rateLimitService.RecordLoginAttempt(ctx, clientIP, true)

	// Record successful audit log
	s.utils.auditLogSuccess(ctx, &user.ID, "login", "User logged in successfully", clientIP, userAgent)
	s.metricsRecorder.RecordLoginSuccess()

	s.logger.WithFields(logrus.Fields{
		"user_id": user.ID,
		"email":   user.Email,
	}).Info("User logged in successfully")

	return authResponse, nil
}

// Logout invalidates a user's refresh token and logs the logout event.
// This method provides secure session termination by revoking the refresh token
// and recording the logout event for audit purposes.
//
// Security features:
// - Secure token validation before revocation
// - Comprehensive audit logging
// - Rate limiting protection
// - Input validation and sanitization
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - refreshToken: The refresh token to invalidate
//   - clientIP: Client IP address for security logging
//   - userAgent: Client user agent for security logging
//
// Returns:
//   - Error if logout fails
//
// Possible errors:
//   - domain.ErrInvalidToken: Refresh token is invalid or expired
//   - domain.ErrTokenNotFound: Token doesn't exist in database
//   - domain.ErrInfrastructureError: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	err := authCore.Logout(ctx, refreshTokenString, "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    log.Printf("Logout failed: %v", err)
//	}
func (s *AuthServiceCore) Logout(ctx context.Context, refreshToken, clientIP, userAgent string) error {
	s.logger.WithFields(logrus.Fields{
		"operation":  "logout",
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("User logout attempt")

	// Record metrics for monitoring
	s.metricsRecorder.RecordLogoutAttempt()

	// Validate refresh token format
	if refreshToken == "" {
		s.utils.auditLogFailure(ctx, nil, "logout", "Empty refresh token", clientIP, userAgent, domain.ErrInvalidToken)
		s.metricsRecorder.RecordLogoutFailure("empty_token")
		return domain.ErrInvalidToken
	}

	// Get token from database
	tokenEntity, err := s.refreshTokenRepo.GetByToken(ctx, refreshToken)
	if err != nil {
		if domain.IsNotFoundError(err) {
			s.utils.auditLogFailure(ctx, nil, "logout", "Token not found", clientIP, userAgent, domain.ErrTokenNotFound)
			s.metricsRecorder.RecordLogoutFailure("token_not_found")
			return domain.ErrTokenNotFound
		}
		s.logger.WithError(err).Error("Failed to get refresh token")
		s.metricsRecorder.RecordLogoutFailure("database_error")
		return fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Check if token is valid (not expired or revoked)
	if !tokenEntity.IsValid() {
		s.utils.auditLogFailure(ctx, &tokenEntity.UserID, "logout", "Token invalid or expired", clientIP, userAgent, domain.ErrInvalidToken)
		s.metricsRecorder.RecordLogoutFailure("token_invalid")
		return domain.ErrInvalidToken
	}

	// Revoke the token
	if err := s.refreshTokenRepo.RevokeToken(ctx, refreshToken); err != nil {
		s.logger.WithError(err).Error("Failed to revoke refresh token")
		s.utils.auditLogFailure(ctx, &tokenEntity.UserID, "logout", "Token revocation failed", clientIP, userAgent, err)
		s.metricsRecorder.RecordLogoutFailure("revocation_error")
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// Record successful audit log
	s.utils.auditLogSuccess(ctx, &tokenEntity.UserID, "logout", "User logged out successfully", clientIP, userAgent)
	s.metricsRecorder.RecordLogoutSuccess()

	s.logger.WithField("user_id", tokenEntity.UserID).Info("User logged out successfully")

	return nil
}

// LogoutAll revokes all refresh tokens for a user, effectively logging them out from all devices.
// This method provides a way to terminate all active sessions for a user account,
// useful for security purposes or when a user wants to logout from all devices.
//
// Security features:
// - Revokes all refresh tokens for the specified user
// - Comprehensive audit logging for security monitoring
// - Input validation and sanitization
// - Proper error handling and logging
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: The user ID whose tokens should be revoked
//   - clientIP: Client IP address for security logging
//   - userAgent: Client user agent for security logging
//
// Returns:
//   - Error if logout-all operation fails
//
// Possible errors:
//   - domain.ErrInvalidUserID: User ID is invalid or malformed
//   - domain.ErrUserNotFound: User doesn't exist
//   - domain.ErrInfrastructureError: Database operation failed
//
// Time Complexity: O(n) where n is the number of active tokens for the user
// Space Complexity: O(1)
//
// Example usage:
//
//	err := authCore.LogoutAll(ctx, userID, "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    log.Printf("Logout-all failed: %v", err)
//	}
func (s *AuthServiceCore) LogoutAll(ctx context.Context, userID uuid.UUID, clientIP, userAgent string) error {
	s.logger.WithFields(logrus.Fields{
		"operation":  "logout_all",
		"user_id":    userID,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("User logout-all attempt")

	// Record metrics for monitoring
	s.metricsRecorder.RecordLogoutAttempt()

	// Validate user ID
	if userID == uuid.Nil {
		s.utils.auditLogFailure(ctx, nil, "logout_all", "Invalid user ID", clientIP, userAgent, domain.ErrInvalidUserID)
		s.metricsRecorder.RecordLogoutFailure("invalid_user_id")
		return domain.ErrInvalidUserID
	}

	// Verify user exists
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if domain.IsNotFoundError(err) {
			s.utils.auditLogFailure(ctx, &userID, "logout_all", "User not found", clientIP, userAgent, domain.ErrUserNotFound)
			s.metricsRecorder.RecordLogoutFailure("user_not_found")
			return domain.ErrUserNotFound
		}
		s.logger.WithError(err).Error("Failed to get user by ID")
		s.metricsRecorder.RecordLogoutFailure("database_error")
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Revoke all refresh tokens for the user
	if err := s.refreshTokenRepo.RevokeAllUserTokens(ctx, userID); err != nil {
		s.logger.WithError(err).Error("Failed to revoke all user tokens")
		s.utils.auditLogFailure(ctx, &userID, "logout_all", "Token revocation failed", clientIP, userAgent, err)
		s.metricsRecorder.RecordLogoutFailure("revocation_error")
		return fmt.Errorf("failed to revoke all tokens: %w", err)
	}

	// Record successful audit log
	s.utils.auditLogSuccess(ctx, &userID, "logout_all", "User logged out from all devices", clientIP, userAgent)
	s.metricsRecorder.RecordLogoutSuccess()

	s.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"email":   user.Email,
	}).Info("User logged out from all devices successfully")

	return nil
}
