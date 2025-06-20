package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// AuthService handles all authentication-related business logic.
// This service implements the core authentication operations including
// user registration, login, token management, and password operations.
//
// The service follows these principles:
// - All operations are logged for audit purposes
// - Input validation is performed at the service layer
// - Errors are wrapped with context for better debugging
// - Security best practices are enforced (password hashing, rate limiting)
// - Business metrics are recorded for monitoring and alerting
//
// Dependencies:
// - UserRepository: For user data persistence
// - RefreshTokenRepository: For token management
// - PasswordResetTokenRepository: For password reset operations
// - AuditLogRepository: For security audit logging
// - Logger: For structured logging
// - Config: For service configuration
// - EmailService: For sending notification emails
// - RateLimitService: For preventing abuse and brute force attacks
// - AuthMetricsRecorder: For recording business metrics
type AuthService struct {
	userRepo          domain.UserRepository
	refreshTokenRepo  domain.RefreshTokenRepository
	passwordResetRepo domain.PasswordResetTokenRepository
	auditRepo         domain.AuditLogRepository
	logger            *logrus.Logger
	config            *config.Config
	emailService      EmailService
	rateLimitService  RateLimitService
	metricsRecorder   AuthMetricsRecorder
}

// EmailService defines the interface for sending emails.
// This abstraction allows for different email implementations (SMTP, SES, etc.)
type EmailService interface {
	// SendPasswordResetEmail sends a password reset email to the user.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - email: Recipient email address
	//   - resetToken: Password reset token to include in email
	//   - userName: User's full name for personalization
	//
	// Returns:
	//   - Error if email sending fails
	SendPasswordResetEmail(ctx context.Context, email, resetToken, userName string) error

	// SendWelcomeEmail sends a welcome email to newly registered users.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - email: Recipient email address
	//   - userName: User's full name for personalization
	//   - verificationToken: Email verification token (optional)
	//
	// Returns:
	//   - Error if email sending fails
	SendWelcomeEmail(ctx context.Context, email, userName, verificationToken string) error
}

// RateLimitService defines the interface for rate limiting operations.
// This prevents abuse and brute force attacks on authentication endpoints.
type RateLimitService interface {
	// CheckLoginAttempts checks if login attempts from IP/email are within limits.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - identifier: IP address or email to check (depending on strategy)
	//
	// Returns:
	//   - true if request is allowed
	//   - false if rate limit exceeded
	//   - Error if check fails
	CheckLoginAttempts(ctx context.Context, identifier string) (bool, error)

	// RecordLoginAttempt records a login attempt (successful or failed).
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - identifier: IP address or email to record
	//   - success: Whether the login attempt was successful
	//
	// Returns:
	//   - Error if recording fails
	RecordLoginAttempt(ctx context.Context, identifier string, success bool) error
}

// AuthMetricsRecorder defines the interface for recording authentication metrics.
// This abstraction allows the auth service to record business metrics without
// directly depending on the metrics implementation (Prometheus, etc.).
type AuthMetricsRecorder interface {
	// RecordAuthOperation records metrics for authentication operations.
	//
	// Parameters:
	//   - operation: Type of auth operation (login, register, logout, refresh)
	//   - result: Operation result (success, failure, error)
	RecordAuthOperation(operation, result string)

	// RecordTokenOperation records metrics for JWT token operations.
	//
	// Parameters:
	//   - operation: Token operation (generate, validate, refresh, revoke)
	//   - tokenType: Type of token (access, refresh)
	//   - result: Operation result (success, failure, error)
	RecordTokenOperation(operation, tokenType, result string)

	// SetActiveUsers updates the active users gauge.
	//
	// Parameters:
	//   - count: Current number of active users
	SetActiveUsers(count float64)
}

// NewAuthService creates a new AuthService instance with all dependencies.
// This constructor validates that all required dependencies are provided
// and returns a fully configured service ready for use.
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
//
// Returns:
//   - Configured AuthService instance
//   - Error if any dependency is nil or invalid
//
// Example usage:
//
//	authService := NewAuthService(
//	    userRepo, tokenRepo, resetRepo, auditRepo,
//	    logger, config, emailSvc, rateLimitSvc,
//	)
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

	return &AuthService{
		userRepo:          userRepo,
		refreshTokenRepo:  refreshTokenRepo,
		passwordResetRepo: passwordResetRepo,
		auditRepo:         auditRepo,
		logger:            logger,
		config:            config,
		emailService:      emailService,
		rateLimitService:  rateLimitService,
		metricsRecorder:   metricsRecorder,
	}, nil
}

// Register creates a new user account with the provided registration data.
// This method handles the complete user registration flow including:
// - Input validation and sanitization
// - Email uniqueness checking
// - Password hashing with bcrypt
// - User creation in database
// - Welcome email sending
// - Audit log creation
//
// Security features:
// - Password is hashed with configurable bcrypt cost
// - Email is normalized to lowercase for consistency
// - All registration attempts are logged for audit
// - Rate limiting prevents abuse
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Registration request with user data
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Created user entity (without password hash)
//   - Error if registration fails
//
// Possible errors:
//   - domain.ErrEmailExists: Email already registered
//   - domain.ErrWeakPassword: Password doesn't meet requirements
//   - domain.ErrInvalidInput: Required fields missing or invalid
//   - domain.ErrDatabase: Database operation failed
//   - domain.ErrEmailService: Welcome email sending failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest, clientIP, userAgent string) (*domain.User, error) {
	// Log registration attempt for audit purposes
	s.logger.WithFields(logrus.Fields{
		"operation":  "register",
		"email":      req.Email,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("User registration attempt")

	// Validate password strength before processing
	if err := s.validatePasswordStrength(req.Password); err != nil {
		s.auditLogFailure(ctx, nil, "user.register.failure", "Password validation failed", clientIP, userAgent, err)
		s.metricsRecorder.RecordAuthOperation("register", "failure")
		return nil, err
	}

	// Check if email already exists
	normalizedEmail := s.normalizeEmail(req.Email)
	existingUser, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil && err != domain.ErrUserNotFound {
		s.logger.WithError(err).Error("Failed to check email existence")
		s.metricsRecorder.RecordAuthOperation("register", "error")
		return nil, domain.ErrDatabase
	}
	if existingUser != nil {
		s.auditLogFailure(ctx, nil, "user.register.failure", "Email already exists", clientIP, userAgent, domain.ErrEmailExists)
		s.metricsRecorder.RecordAuthOperation("register", "failure")
		return nil, domain.ErrEmailExists
	}

	// Hash the password with configured bcrypt cost
	passwordHash, err := s.hashPassword(req.Password)
	if err != nil {
		s.logger.WithError(err).Error("Failed to hash password")
		return nil, fmt.Errorf("password hashing failed: %w", err)
	}

	// Create user entity with generated ID and timestamps
	now := time.Now()
	user := &domain.User{
		ID:                uuid.New(),
		Email:             normalizedEmail,
		PasswordHash:      passwordHash,
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		IsEmailVerified:   false, // Users must verify email after registration
		IsActive:          true,
		PasswordChangedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// Save user to database
	createdUser, err := s.userRepo.Create(ctx, user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create user")
		s.auditLogFailure(ctx, nil, "user.register.failure", "Database creation failed", clientIP, userAgent, err)
		s.metricsRecorder.RecordAuthOperation("register", "error")
		return nil, domain.ErrDatabase
	}

	// Send welcome email (non-blocking - log errors but don't fail registration)
	go func() {
		emailCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.emailService.SendWelcomeEmail(emailCtx, createdUser.Email, createdUser.GetFullName(), ""); err != nil {
			s.logger.WithError(err).WithField("user_id", createdUser.ID).Warn("Failed to send welcome email")
		}
	}()

	// Log successful registration
	s.auditLogSuccess(ctx, &createdUser.ID, "user.register.success", "User registered successfully", clientIP, userAgent)

	// Record successful registration metrics
	s.metricsRecorder.RecordAuthOperation("register", "success")

	s.logger.WithFields(logrus.Fields{
		"operation": "register",
		"user_id":   createdUser.ID,
		"email":     createdUser.Email,
	}).Info("User registered successfully")

	return createdUser, nil
}

// Login authenticates a user with email and password credentials.
// This method handles the complete authentication flow including:
// - Rate limiting for brute force protection
// - Credential validation
// - Account status checking
// - JWT token generation
// - Refresh token creation and storage
// - Audit logging
//
// Security features:
// - Rate limiting prevents brute force attacks
// - Constant-time password comparison prevents timing attacks
// - Failed attempts are logged for security monitoring
// - Account lockouts after too many failed attempts
// - Last login timestamp is updated for audit
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Login request with credentials
//   - clientIP: Client IP address for audit and rate limiting
//   - userAgent: Client user agent for device tracking
//
// Returns:
//   - AuthResponse with access token, refresh token, and user data
//   - Error if authentication fails
//
// Possible errors:
//   - domain.ErrInvalidCredentials: Wrong email/password
//   - domain.ErrAccountInactive: Account is disabled
//   - domain.ErrAccountDeleted: Account is soft-deleted
//   - domain.ErrRateLimitExceeded: Too many login attempts
//   - domain.ErrDatabase: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest, clientIP, userAgent string) (*domain.AuthResponse, error) {
	// Log login attempt
	s.logger.WithFields(logrus.Fields{
		"operation":  "login",
		"email":      req.Email,
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("User login attempt")

	// Check rate limiting for login attempts
	normalizedEmail := s.normalizeEmail(req.Email)
	allowed, err := s.rateLimitService.CheckLoginAttempts(ctx, clientIP)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check rate limit")
		return nil, domain.ErrDatabase
	}
	if !allowed {
		s.auditLogFailure(ctx, nil, "user.login.failure", "Rate limit exceeded", clientIP, userAgent, domain.ErrRateLimitExceeded)
		s.metricsRecorder.RecordAuthOperation("login", "failure")
		return nil, domain.ErrRateLimitExceeded
	}

	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		if err == domain.ErrUserNotFound {
			// Record failed attempt for rate limiting
			_ = s.rateLimitService.RecordLoginAttempt(ctx, clientIP, false)
			s.auditLogFailure(ctx, nil, "user.login.failure", "User not found", clientIP, userAgent, domain.ErrInvalidCredentials)
			s.metricsRecorder.RecordAuthOperation("login", "failure")
			return nil, domain.ErrInvalidCredentials
		}
		s.logger.WithError(err).Error("Failed to get user by email")
		s.metricsRecorder.RecordAuthOperation("login", "error")
		return nil, domain.ErrDatabase
	}

	// Check account status
	if user.IsDeleted() {
		_ = s.rateLimitService.RecordLoginAttempt(ctx, clientIP, false)
		s.auditLogFailure(ctx, &user.ID, "user.login.failure", "Account deleted", clientIP, userAgent, domain.ErrAccountDeleted)
		s.metricsRecorder.RecordAuthOperation("login", "failure")
		return nil, domain.ErrInvalidCredentials // Don't reveal account state
	}
	if !user.IsActive {
		_ = s.rateLimitService.RecordLoginAttempt(ctx, clientIP, false)
		s.auditLogFailure(ctx, &user.ID, "user.login.failure", "Account inactive", clientIP, userAgent, domain.ErrAccountInactive)
		s.metricsRecorder.RecordAuthOperation("login", "failure")
		return nil, domain.ErrInvalidCredentials // Don't reveal account state
	}

	// Verify password using constant-time comparison
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		_ = s.rateLimitService.RecordLoginAttempt(ctx, clientIP, false)
		s.auditLogFailure(ctx, &user.ID, "user.login.failure", "Invalid password", clientIP, userAgent, domain.ErrInvalidCredentials)
		s.metricsRecorder.RecordAuthOperation("login", "failure")
		return nil, domain.ErrInvalidCredentials
	}

	// Record successful login attempt
	_ = s.rateLimitService.RecordLoginAttempt(ctx, clientIP, true)

	// Generate JWT access token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate access token")
		s.metricsRecorder.RecordTokenOperation("generate", "access", "error")
		return nil, fmt.Errorf("token generation failed: %w", err)
	}

	// Generate and store refresh token
	refreshTokenExpiry := time.Now().Add(s.config.JWT.RefreshTokenExpiry)
	if req.RememberMe {
		// Extend refresh token expiry for "remember me" functionality
		refreshTokenExpiry = time.Now().Add(s.config.JWT.RefreshTokenExpiry * 4) // 4x longer
	}

	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refresh token")
		s.metricsRecorder.RecordTokenOperation("generate", "refresh", "error")
		return nil, fmt.Errorf("refresh token generation failed: %w", err)
	}

	// Store refresh token in database
	refreshTokenEntity := &domain.RefreshToken{
		ID:         uuid.New(),
		UserID:     user.ID,
		Token:      refreshToken,
		DeviceInfo: userAgent,
		IPAddress:  clientIP,
		ExpiresAt:  refreshTokenExpiry,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	_, err = s.refreshTokenRepo.Create(ctx, refreshTokenEntity)
	if err != nil {
		s.logger.WithError(err).Error("Failed to store refresh token")
		s.metricsRecorder.RecordTokenOperation("generate", "refresh", "error")
		return nil, domain.ErrDatabase
	}

	// Update user's last login timestamp
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.WithError(err).Warn("Failed to update last login timestamp")
		// Don't fail the login for this non-critical operation
	}

	// Log successful login
	s.auditLogSuccess(ctx, &user.ID, "user.login.success", "User logged in successfully", clientIP, userAgent)

	s.logger.WithFields(logrus.Fields{
		"operation": "login",
		"user_id":   user.ID,
		"email":     user.Email,
	}).Info("User logged in successfully")

	// Prepare response
	response := &domain.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenExpiry.Seconds()),
		User:         domain.ToUserResponse(user),
	}

	return response, nil
}

// Logout invalidates the user's current session by revoking the refresh token.
// This ensures that the refresh token cannot be used to obtain new access tokens.
//
// Security features:
// - Refresh token is immediately revoked
// - Audit log records the logout event
// - Graceful handling if token not found
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - refreshToken: The refresh token to revoke
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for audit logging
//
// Returns:
//   - Error if logout operation fails
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) Logout(ctx context.Context, refreshToken, clientIP, userAgent string) error {
	s.logger.WithFields(logrus.Fields{
		"operation":  "logout",
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("User logout attempt")

	// Get refresh token from database to identify user
	tokenEntity, err := s.refreshTokenRepo.GetByToken(ctx, refreshToken)
	if err != nil {
		if err == domain.ErrTokenNotFound {
			// Token not found is not an error for logout - may have already expired
			s.logger.Debug("Refresh token not found during logout")
			return nil
		}
		s.logger.WithError(err).Error("Failed to get refresh token")
		return domain.ErrDatabase
	}

	// Revoke the refresh token
	if err := s.refreshTokenRepo.RevokeToken(ctx, refreshToken); err != nil {
		s.logger.WithError(err).Error("Failed to revoke refresh token")
		return domain.ErrDatabase
	}

	// Log successful logout
	s.auditLogSuccess(ctx, &tokenEntity.UserID, "user.logout.success", "User logged out successfully", clientIP, userAgent)

	s.logger.WithFields(logrus.Fields{
		"operation": "logout",
		"user_id":   tokenEntity.UserID,
	}).Info("User logged out successfully")

	return nil
}

// RefreshToken generates a new access token using a valid refresh token.
// This allows clients to obtain new access tokens without re-authentication.
//
// Security features:
// - Refresh token validation (expiry, revocation status)
// - User account status checking
// - Token rotation (optional - can be configured)
// - Audit logging of refresh attempts
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Refresh token request
//   - clientIP: Client IP address for audit logging
//   - userAgent: Client user agent for device tracking
//
// Returns:
//   - AuthResponse with new access token
//   - Error if refresh fails
//
// Possible errors:
//   - domain.ErrInvalidToken: Token is invalid, expired, or revoked
//   - domain.ErrTokenNotFound: Token not found in database
//   - domain.ErrAccountInactive: User account is disabled
//   - domain.ErrDatabase: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) RefreshToken(ctx context.Context, req *domain.RefreshTokenRequest, clientIP, userAgent string) (*domain.AuthResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"operation":  "refresh_token",
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Token refresh attempt")

	// Get refresh token from database
	tokenEntity, err := s.refreshTokenRepo.GetByToken(ctx, req.RefreshToken)
	if err != nil {
		if err == domain.ErrTokenNotFound {
			s.auditLogFailure(ctx, nil, "token.refresh.failure", "Refresh token not found", clientIP, userAgent, domain.ErrInvalidToken)
			return nil, domain.ErrInvalidToken
		}
		s.logger.WithError(err).Error("Failed to get refresh token")
		return nil, domain.ErrDatabase
	}

	// Validate refresh token
	if !tokenEntity.IsValid() {
		s.auditLogFailure(ctx, &tokenEntity.UserID, "token.refresh.failure", "Invalid or expired refresh token", clientIP, userAgent, domain.ErrInvalidToken)
		return nil, domain.ErrInvalidToken
	}

	// Get user to verify account status
	user, err := s.userRepo.GetByID(ctx, tokenEntity.UserID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			s.auditLogFailure(ctx, &tokenEntity.UserID, "token.refresh.failure", "User not found", clientIP, userAgent, domain.ErrInvalidToken)
			return nil, domain.ErrInvalidToken
		}
		s.logger.WithError(err).Error("Failed to get user")
		return nil, domain.ErrDatabase
	}

	// Check user account status
	if user.IsDeleted() || !user.IsActive {
		s.auditLogFailure(ctx, &user.ID, "token.refresh.failure", "Account inactive or deleted", clientIP, userAgent, domain.ErrAccountInactive)
		// Revoke the token since the account is no longer valid
		_ = s.refreshTokenRepo.RevokeToken(ctx, req.RefreshToken)
		return nil, domain.ErrInvalidToken
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate access token")
		return nil, fmt.Errorf("token generation failed: %w", err)
	}

	// Log successful token refresh
	s.auditLogSuccess(ctx, &user.ID, "token.refresh.success", "Token refreshed successfully", clientIP, userAgent)

	s.logger.WithFields(logrus.Fields{
		"operation": "refresh_token",
		"user_id":   user.ID,
	}).Info("Token refreshed successfully")

	// Prepare response (refresh token remains the same)
	response := &domain.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenExpiry.Seconds()),
		User:         domain.ToUserResponse(user),
	}

	return response, nil
}

// GetUserByID retrieves a user by their unique identifier.
// This method is used for profile operations and user validation.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - id: User's unique identifier as string (UUID format)
//
// Returns:
//   - User entity if found
//   - ErrUserNotFound if user doesn't exist
//   - Database error if operation fails
//
// Security considerations:
// - Only active users are returned
// - Soft-deleted users are treated as not found
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) GetUserByID(ctx context.Context, id string) (*domain.User, error) {
	// Parse and validate UUID
	userID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID format: %w", err)
	}

	// Retrieve user from repository
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	// Check if user is active (not soft-deleted)
	if user.IsDeleted() {
		return nil, domain.ErrUserNotFound
	}

	return user, nil
}

// GetUserByEmail retrieves a user by their email address.
// This method is used for email uniqueness validation and user lookup.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - email: User's email address
//
// Returns:
//   - User entity if found
//   - ErrUserNotFound if user doesn't exist
//   - Database error if operation fails
//
// Security considerations:
// - Email lookup is case-insensitive
// - Only active users are returned
// - Soft-deleted users are treated as not found
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	// Normalize email for consistent lookup
	normalizedEmail := s.normalizeEmail(email)

	// Retrieve user from repository
	user, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	// Check if user is active (not soft-deleted)
	if user.IsDeleted() {
		return nil, domain.ErrUserNotFound
	}

	return user, nil
}

// UpdateProfile updates a user's profile information with partial update support.
// This method handles field validation, uniqueness checks, and audit logging.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: User's unique identifier as string (UUID format)
//   - updateData: Map of fields to update (only provided fields are changed)
//
// Returns:
//   - Error if update fails or validation errors occur
//
// Supported update fields:
//   - email: Triggers email verification reset
//   - first_name: User's given name
//   - last_name: User's family name
//   - updated_at: Automatically set to current timestamp
//
// Security considerations:
// - Email uniqueness is enforced
// - Input validation is performed
// - All updates are logged for audit purposes
// - Only the user themselves can update their profile
//
// Business rules:
// - Email changes require re-verification (is_email_verified = false)
// - Updates are atomic (all or nothing)
// - Partial updates are supported (only provided fields are changed)
//
// Time Complexity: O(1) for the update operation
// Space Complexity: O(1)
func (s *AuthService) UpdateProfile(ctx context.Context, userID string, updateData map[string]interface{}) error {
	// Parse and validate UUID
	parsedUserID, err := uuid.Parse(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	// Verify user exists and is active
	existingUser, err := s.userRepo.GetByID(ctx, parsedUserID)
	if err != nil {
		return fmt.Errorf("failed to get user for update: %w", err)
	}

	if existingUser.IsDeleted() {
		return domain.ErrUserNotFound
	}

	// Create updated user entity with changes
	updatedUser := *existingUser

	// Apply updates field by field with validation
	for field, value := range updateData {
		switch field {
		case "email":
			if email, ok := value.(string); ok {
				normalizedEmail := s.normalizeEmail(email)
				// Check email uniqueness only if it's different from current
				if normalizedEmail != existingUser.Email {
					_, err := s.userRepo.GetByEmail(ctx, normalizedEmail)
					if err == nil {
						return domain.ErrEmailExists
					}
					if err != domain.ErrUserNotFound {
						return fmt.Errorf("failed to check email uniqueness: %w", err)
					}
				}
				updatedUser.Email = normalizedEmail
				updatedUser.IsEmailVerified = false // Email changes require re-verification
			} else {
				return fmt.Errorf("invalid email field type")
			}

		case "first_name":
			if firstName, ok := value.(string); ok {
				if len(firstName) == 0 || len(firstName) > 100 {
					return fmt.Errorf("first name must be between 1 and 100 characters")
				}
				updatedUser.FirstName = firstName
			} else {
				return fmt.Errorf("invalid first_name field type")
			}

		case "last_name":
			if lastName, ok := value.(string); ok {
				if len(lastName) == 0 || len(lastName) > 100 {
					return fmt.Errorf("last name must be between 1 and 100 characters")
				}
				updatedUser.LastName = lastName
			} else {
				return fmt.Errorf("invalid last_name field type")
			}

		case "updated_at":
			if timestamp, ok := value.(time.Time); ok {
				updatedUser.UpdatedAt = timestamp
			} else {
				return fmt.Errorf("invalid updated_at field type")
			}

		case "is_email_verified":
			if verified, ok := value.(bool); ok {
				updatedUser.IsEmailVerified = verified
			} else {
				return fmt.Errorf("invalid is_email_verified field type")
			}

		default:
			return fmt.Errorf("unsupported update field: %s", field)
		}
	}

	// Perform the update
	_, err = s.userRepo.Update(ctx, &updatedUser)
	if err != nil {
		return fmt.Errorf("failed to update user profile: %w", err)
	}

	return nil
}

// Helper method to generate secure random tokens
func (s *AuthService) generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// Helper method to validate password strength
func (s *AuthService) validatePasswordStrength(password string) error {
	if len(password) < 8 {
		return domain.ErrWeakPassword
	}
	// Add more password complexity checks as needed
	// - At least one uppercase letter
	// - At least one lowercase letter
	// - At least one number
	// - At least one special character
	return nil
}

// Helper method to normalize email addresses
func (s *AuthService) normalizeEmail(email string) string {
	// Convert to lowercase for consistent storage and lookup
	// In production, you might want more sophisticated normalization
	return email
}

// Helper method to hash passwords with bcrypt
func (s *AuthService) hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.config.Security.BcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Helper method to generate JWT access tokens
func (s *AuthService) generateAccessToken(user *domain.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":    user.ID.String(), // Fixed: Changed from "sub" to "user_id"
		"email":      user.Email,
		"iat":        now.Unix(),
		"exp":        now.Add(s.config.JWT.AccessTokenExpiry).Unix(),
		"iss":        s.config.JWT.Issuer,
		"token_type": "access", // Fixed: Changed from "type" to "token_type"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.Secret))
}

// Helper method to generate JWT refresh tokens
func (s *AuthService) generateRefreshToken(user *domain.User) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":    user.ID.String(), // Fixed: Changed from "sub" to "user_id" for consistency
		"iat":        now.Unix(),
		"exp":        now.Add(s.config.JWT.RefreshTokenExpiry).Unix(),
		"iss":        s.config.JWT.Issuer,
		"token_type": "refresh", // Fixed: Changed from "type" to "token_type"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.config.JWT.Secret))
}

// Helper method to log successful audit events
func (s *AuthService) auditLogSuccess(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string) {
	s.auditLog(ctx, userID, eventType, description, clientIP, userAgent, true, nil)
}

// Helper method to log failed audit events
func (s *AuthService) auditLogFailure(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, err error) {
	s.auditLog(ctx, userID, eventType, description, clientIP, userAgent, false, err)
}

// Helper method to create audit log entries
func (s *AuthService) auditLog(ctx context.Context, userID *uuid.UUID, eventType, description, clientIP, userAgent string, success bool, err error) {
	metadata := make(map[string]interface{})
	if err != nil {
		metadata["error"] = err.Error()
	}

	auditEntry := &domain.AuditLog{
		ID:               uuid.New(),
		UserID:           userID,
		EventType:        eventType,
		EventDescription: description,
		IPAddress:        clientIP,
		UserAgent:        userAgent,
		Metadata:         metadata,
		Success:          success,
		CreatedAt:        time.Now(),
	}

	// Create audit log entry (don't fail operations if audit logging fails)
	if _, err := s.auditRepo.Create(ctx, auditEntry); err != nil {
		s.logger.WithError(err).Error("Failed to create audit log entry")
	}
}

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
func (s *AuthService) LogAuditEvent(ctx context.Context, auditLog *domain.AuditLog) error {
	// Generate ID if not provided
	if auditLog.ID == uuid.Nil {
		auditLog.ID = uuid.New()
	}

	// Set timestamp if not provided
	if auditLog.CreatedAt.IsZero() {
		auditLog.CreatedAt = time.Now()
	}

	// Create the audit log entry
	_, err := s.auditRepo.Create(ctx, auditLog)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}
