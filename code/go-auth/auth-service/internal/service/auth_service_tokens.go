package service

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth-service/internal/config"
	"auth-service/internal/domain"
)

// AuthServiceTokens handles JWT token operations including generation,
// validation, refresh, and revocation.
//
// This service implements secure token management:
// - JWT access token generation with configurable expiry
// - Refresh token management with database persistence
// - Token validation with comprehensive security checks
// - Token refresh with rotation for enhanced security
// - Token revocation for logout operations
//
// Security features:
// - Configurable token expiration times
// - Secure token signing with HMAC-SHA256
// - Refresh token rotation to prevent replay attacks
// - Comprehensive audit logging for all token operations
// - Input validation and sanitization
//
// Dependencies:
// - UserRepository: For user lookup and validation during token operations
// - RefreshTokenRepository: For refresh token persistence
// - Logger: For structured logging
// - Config: For JWT configuration (secret, expiry times)
// - AuthServiceUtils: For utility functions
type AuthServiceTokens struct {
	userRepo         domain.UserRepository
	refreshTokenRepo domain.RefreshTokenRepository
	logger           *logrus.Logger
	config           *config.Config
	utils            *AuthServiceUtils
}

// NewAuthServiceTokens creates a new instance of the token service.
// This constructor validates dependencies and returns a configured service.
//
// Parameters:
//   - userRepo: Repository for user operations
//   - refreshTokenRepo: Repository for refresh token operations
//   - logger: Structured logger for service operations
//   - config: Service configuration containing JWT settings
//   - utils: Utility functions for common operations
//
// Returns:
//   - Configured AuthServiceTokens instance
//   - Error if any dependency is invalid
//
// Example usage:
//
//	tokenService, err := NewAuthServiceTokens(userRepo, refreshTokenRepo, logger, config, utils)
//	if err != nil {
//	    log.Fatal("Failed to create token service:", err)
//	}
func NewAuthServiceTokens(
	userRepo domain.UserRepository,
	refreshTokenRepo domain.RefreshTokenRepository,
	logger *logrus.Logger,
	config *config.Config,
	utils *AuthServiceUtils,
) (*AuthServiceTokens, error) {
	if userRepo == nil {
		return nil, fmt.Errorf("user repository is required")
	}
	if refreshTokenRepo == nil {
		return nil, fmt.Errorf("refresh token repository is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}
	if utils == nil {
		return nil, fmt.Errorf("auth service utils is required")
	}

	return &AuthServiceTokens{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		logger:           logger,
		config:           config,
		utils:            utils,
	}, nil
}

// GenerateTokenPair creates both access and refresh tokens for a user.
// This method generates a complete authentication response with both tokens
// and stores the refresh token in the database for future validation.
//
// Token characteristics:
// - Access Token: Short-lived (15 minutes), contains user claims
// - Refresh Token: Long-lived (7 days), stored in database
// - Both tokens use HMAC-SHA256 signing
// - Tokens include security claims (iss, aud, exp, iat, nbf)
//
// Security considerations:
// - IP address and device info are stored for audit and security monitoring
// - IP address defaults to "127.0.0.1" if empty to satisfy database constraints
// - Device info defaults to "Unknown" if empty for better tracking
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - user: User entity for whom to generate tokens
//   - clientIP: Client IP address for security tracking (required for database)
//   - userAgent: Client user agent string for device identification
//
// Returns:
//   - AuthResponse containing both tokens and user data
//   - Error if token generation fails
//
// Possible errors:
//   - domain.ErrTokenGenerationFailed: JWT signing failed
//   - domain.ErrInfrastructureError: Database storage failed
//
// Time Complexity: O(1)
// Space Complexity: O(1)
//
// Example usage:
//
//	authResponse, err := tokenService.GenerateTokenPair(ctx, user, "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//	    return fmt.Errorf("failed to generate tokens: %w", err)
//	}
func (s *AuthServiceTokens) GenerateTokenPair(ctx context.Context, user *domain.User, clientIP, userAgent string) (*domain.AuthResponse, error) {
	s.logger.WithField("user_id", user.ID).Debug("Generating token pair")

	// Validate and sanitize input parameters for database constraints
	// IP address cannot be empty for INET field - use localhost as fallback
	if clientIP == "" {
		clientIP = "127.0.0.1"
		s.logger.WithField("user_id", user.ID).Warn("Empty client IP provided, using localhost as fallback")
	}

	// Device info cannot be empty - use a meaningful default
	if userAgent == "" {
		userAgent = "Unknown"
		s.logger.WithField("user_id", user.ID).Warn("Empty user agent provided, using default")
	}

	// Generate access token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken(user)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create refresh token entity for database storage with required fields
	refreshTokenEntity := &domain.RefreshToken{
		ID:         uuid.New(),
		UserID:     user.ID,
		Token:      refreshToken,
		DeviceInfo: userAgent, // Store user agent for device tracking
		IPAddress:  clientIP,  // Store IP address for security auditing
		ExpiresAt:  time.Now().UTC().Add(s.config.JWT.RefreshTokenExpiry),
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}

	// Store refresh token in database
	if _, err := s.refreshTokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"user_id":   user.ID,
			"client_ip": clientIP,
		}).Error("Failed to store refresh token")
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	// Create authentication response
	authResponse := &domain.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.config.JWT.AccessTokenExpiry.Seconds()),
		User:         domain.ToUserResponse(user),
	}

	s.logger.WithFields(logrus.Fields{
		"user_id":   user.ID,
		"client_ip": clientIP,
	}).Info("Token pair generated successfully")

	return authResponse, nil
}

// RefreshToken validates a refresh token and issues new access/refresh tokens.
// This method implements token rotation for enhanced security by invalidating
// the old refresh token and issuing a new pair.
//
// Security features:
// - Refresh token validation (existence, expiry, revocation status)
// - Token rotation (old token invalidated, new tokens issued)
// - User validation (account status, existence)
// - Comprehensive audit logging
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - req: Refresh token request containing the token to refresh
//   - clientIP: Client IP address for security logging
//   - userAgent: Client user agent for security logging
//
// Returns:
//   - New AuthResponse with fresh tokens
//   - Error if refresh fails
//
// Possible errors:
//   - domain.ErrInvalidToken: Token is invalid, expired, or revoked
//   - domain.ErrTokenNotFound: Token doesn't exist in database
//   - domain.ErrUserNotFound: Associated user doesn't exist
//   - domain.ErrAccountInactive: User account is disabled
//   - domain.ErrInfrastructureError: Database operation failed
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
//
// Example usage:
//
//	authResponse, err := tokenService.RefreshToken(ctx, &domain.RefreshTokenRequest{
//	    RefreshToken: "existing_refresh_token",
//	}, "192.168.1.1", "Mozilla/5.0...")
func (s *AuthServiceTokens) RefreshToken(ctx context.Context, req *domain.RefreshTokenRequest, clientIP, userAgent string) (*domain.AuthResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"operation":  "refresh_token",
		"client_ip":  clientIP,
		"user_agent": userAgent,
	}).Info("Token refresh attempt")

	// Validate refresh token format
	if req.RefreshToken == "" {
		s.utils.auditLogFailure(ctx, nil, "token_refresh", "Empty refresh token", clientIP, userAgent, domain.ErrInvalidToken)
		return nil, domain.ErrInvalidToken
	}

	// Get refresh token from database
	tokenEntity, err := s.refreshTokenRepo.GetByToken(ctx, req.RefreshToken)
	if err != nil {
		if err == domain.ErrTokenNotFound {
			s.utils.auditLogFailure(ctx, nil, "token_refresh", "Token not found", clientIP, userAgent, domain.ErrTokenNotFound)
			return nil, domain.ErrTokenNotFound
		}
		s.logger.WithError(err).Error("Failed to get refresh token")
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	// Check if token is valid (not expired or revoked)
	if !tokenEntity.IsValid() {
		s.utils.auditLogFailure(ctx, &tokenEntity.UserID, "token_refresh", "Token invalid or expired", clientIP, userAgent, domain.ErrInvalidToken)
		return nil, domain.ErrInvalidToken
	}

	// Get user associated with the token
	user, err := s.getUserForToken(ctx, tokenEntity.UserID)
	if err != nil {
		s.utils.auditLogFailure(ctx, &tokenEntity.UserID, "token_refresh", "User lookup failed", clientIP, userAgent, err)
		return nil, err
	}

	// Revoke the old refresh token (token rotation)
	if err := s.refreshTokenRepo.RevokeToken(ctx, req.RefreshToken); err != nil {
		s.logger.WithError(err).Error("Failed to revoke old refresh token")
		s.utils.auditLogFailure(ctx, &tokenEntity.UserID, "token_refresh", "Token revocation failed", clientIP, userAgent, err)
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Generate new token pair
	authResponse, err := s.GenerateTokenPair(ctx, user, clientIP, userAgent)
	if err != nil {
		s.logger.WithError(err).Error("Failed to generate new token pair")
		s.utils.auditLogFailure(ctx, &tokenEntity.UserID, "token_refresh", "Token generation failed", clientIP, userAgent, err)
		return nil, fmt.Errorf("failed to generate new tokens: %w", err)
	}

	// Record successful audit log
	s.utils.auditLogSuccess(ctx, &user.ID, "token_refresh", "Token refreshed successfully", clientIP, userAgent)

	s.logger.WithField("user_id", user.ID).Info("Token refreshed successfully")

	return authResponse, nil
}

// generateAccessToken creates a JWT access token for a user.
// Access tokens are short-lived and contain user claims for API access.
//
// Token claims:
// - sub: User ID (subject)
// - email: User email address
// - iss: Token issuer (service name)
// - aud: Token audience (API identifier)
// - exp: Expiration time
// - iat: Issued at time
// - nbf: Not before time
//
// Parameters:
//   - user: User entity for token generation
//
// Returns:
//   - Signed JWT token string
//   - Error if signing fails
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (s *AuthServiceTokens) generateAccessToken(user *domain.User) (string, error) {
	now := time.Now().UTC()

	claims := jwt.MapClaims{
		"user_id":    user.ID,          // Required for JWT service validation (as UUID)
		"sub":        user.ID.String(), // Standard subject claim (as string)
		"email":      user.Email,
		"token_type": "access", // Required for token type validation
		"iss":        s.config.JWT.Issuer,
		"aud":        s.config.JWT.Issuer, // Use issuer as audience for now
		"exp":        now.Add(s.config.JWT.AccessTokenExpiry).Unix(),
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return tokenString, nil
}

// generateRefreshToken creates a JWT refresh token for a user.
// Refresh tokens are long-lived and used to obtain new access tokens.
//
// Token claims:
// - sub: User ID (subject)
// - email: User email address
// - type: Token type ("refresh")
// - iss: Token issuer (service name)
// - aud: Token audience (API identifier)
// - exp: Expiration time
// - iat: Issued at time
// - nbf: Not before time
//
// Parameters:
//   - user: User entity for token generation
//
// Returns:
//   - Signed JWT token string
//   - Error if signing fails
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (s *AuthServiceTokens) generateRefreshToken(user *domain.User) (string, error) {
	now := time.Now().UTC()

	claims := jwt.MapClaims{
		"user_id":    user.ID,          // Required for JWT service validation (as UUID)
		"sub":        user.ID.String(), // Standard subject claim (as string)
		"email":      user.Email,
		"token_type": "refresh", // Use consistent token_type field
		"iss":        s.config.JWT.Issuer,
		"aud":        s.config.JWT.Issuer, // Use issuer as audience for now
		"exp":        now.Add(s.config.JWT.RefreshTokenExpiry).Unix(),
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return tokenString, nil
}

// getUserForToken retrieves and validates a user for token operations.
// This method ensures the user exists and is in a valid state for token operations.
//
// Parameters:
//   - ctx: Context for cancellation and timeouts
//   - userID: ID of the user to retrieve
//
// Returns:
//   - User entity if valid
//   - Error if user is invalid or not found
//
// Possible errors:
//   - domain.ErrUserNotFound: User doesn't exist
//   - domain.ErrAccountInactive: User account is disabled
//   - domain.ErrAccountDeleted: User account is soft deleted
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (s *AuthServiceTokens) getUserForToken(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	// Validate input
	if userID == uuid.Nil {
		return nil, fmt.Errorf("invalid user ID: cannot be nil")
	}

	// Retrieve user from repository
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		// Log the error for debugging but don't expose internal details
		s.logger.WithError(err).WithField("user_id", userID).
			Warn("Failed to retrieve user for token operation")

		// Return a generic user not found error
		return nil, domain.ErrUserNotFound
	}

	// Validate user state for token operations
	if user.DeletedAt != nil {
		s.logger.WithField("user_id", userID).
			Warn("Token operation attempted on deleted user account")
		return nil, domain.ErrAccountDeleted
	}

	// Check if user account is active
	if !user.IsActive {
		s.logger.WithField("user_id", userID).
			Warn("Token operation attempted on inactive user account")
		return nil, domain.ErrAccountInactive
	}

	return user, nil
}
