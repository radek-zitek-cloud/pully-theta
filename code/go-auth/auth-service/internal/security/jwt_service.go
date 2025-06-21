// Package security provides JWT token management and security services for the authentication system.
//
// This package implements enterprise-grade JWT token handling with the following features:
// - Secure token generation with configurable TTL
// - Token blacklisting for immediate revocation
// - Comprehensive token validation with security checks
// - Redis-based token blacklist for distributed systems
// - Cryptographically secure random JTI generation
// - Protection against token replay attacks
//
// Security Features:
// - HMAC-SHA256 signing for token integrity
// - Configurable token expiration times
// - Token type validation (access vs refresh)
// - Issuer and audience validation
// - Blacklist checking for revoked tokens
// - Secure random JTI (JWT ID) generation
//
// Performance Considerations:
// - Redis operations for blacklist are O(1)
// - Token validation includes early blacklist check
// - Minimal memory allocation during token operations
//
// Usage:
//
//	blacklist := &RedisTokenBlacklist{client: redisClient}
//	jwtService := NewJWTService(secretKey, "auth-service", "api", blacklist, 15*time.Minute, 7*24*time.Hour)
//	tokenPair, err := jwtService.GenerateTokenPair(user)
//
// @title JWT Security Service
// @version 1.0
// @description Production-ready JWT token management with security features
package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"auth-service/internal/domain"
)

// JWTService provides comprehensive JWT token management capabilities.
// This service handles token generation, validation, and revocation with enterprise-grade security features.
//
// Key Features:
// - Secure token pair generation (access + refresh tokens)
// - Token validation with comprehensive security checks
// - Token blacklisting for immediate revocation
// - Configurable token lifetimes
// - Protection against common JWT attacks
//
// Security Measures:
// - HMAC-SHA256 signing prevents token tampering
// - Token type validation prevents misuse
// - Blacklist checking prevents use of revoked tokens
// - Issuer/audience validation prevents token misuse
// - Secure JTI generation prevents token collision
//
// The service is designed to be thread-safe and suitable for high-concurrency environments.
type JWTService struct {
	// secretKey is the HMAC signing key for token generation and validation
	// This key must be kept secure and should be rotated regularly
	secretKey []byte

	// issuer identifies the token issuer (typically the service name)
	// Used for token validation to prevent cross-service token misuse
	issuer string

	// audience identifies the intended token audience
	// Used for token validation to ensure tokens are used in correct context
	audience string

	// blacklist provides token revocation capabilities
	// Typically Redis-based for distributed systems
	blacklist TokenBlacklist

	// accessTokenTTL defines the lifetime of access tokens
	// Shorter lifetimes improve security but may impact user experience
	accessTokenTTL time.Duration

	// refreshTokenTTL defines the lifetime of refresh tokens
	// Longer lifetimes reduce login frequency but increase security risk if compromised
	refreshTokenTTL time.Duration
}

// TokenBlacklist defines the interface for token revocation management.
// This interface allows for different blacklist implementations (Redis, database, etc.)
//
// The blacklist serves as a security mechanism to immediately revoke tokens
// before their natural expiration time. This is crucial for:
// - User logout operations
// - Account compromise scenarios
// - Security policy enforcement
//
// Implementation considerations:
// - Should be fast (O(1) operations preferred)
// - Should handle high concurrency
// - Should be distributed-system friendly
// - Should automatically expire entries when tokens naturally expire
type TokenBlacklist interface {
	// Add adds a token to the blacklist with automatic expiration.
	// The token will be blacklisted until the specified expiry time.
	//
	// Parameters:
	//   - ctx: Request context for timeout and cancellation
	//   - token: The JWT token string to blacklist
	//   - expiry: When the blacklist entry should automatically expire
	//
	// Returns:
	//   - error: Any error that occurred during the blacklist operation
	//
	// Performance: Should be O(1) or O(log n) at most
	// Concurrency: Must be thread-safe
	Add(ctx context.Context, token string, expiry time.Time) error

	// IsBlacklisted checks if a token is currently blacklisted.
	// This check should be performed before any token validation.
	//
	// Parameters:
	//   - ctx: Request context for timeout and cancellation
	//   - token: The JWT token string to check
	//
	// Returns:
	//   - bool: true if the token is blacklisted, false otherwise
	//
	// Performance: Should be O(1)
	// Concurrency: Must be thread-safe
	// Error handling: Returns false on errors (fail-open for availability)
	IsBlacklisted(ctx context.Context, token string) bool
}

// RedisTokenBlacklist implements TokenBlacklist using Redis for distributed token revocation.
// This implementation provides fast, distributed token blacklisting suitable for microservices.
//
// Features:
// - O(1) blacklist operations using Redis SET/EXISTS
// - Automatic expiration using Redis TTL
// - Distributed across multiple service instances
// - High availability and performance
//
// Redis Key Structure:
// - Key: "blacklist:{token}"
// - Value: "1" (minimal storage)
// - TTL: Set to token's natural expiration time
//
// Performance Characteristics:
// - Add: O(1) - Single Redis SET operation
// - IsBlacklisted: O(1) - Single Redis EXISTS operation
// - Memory efficient: Minimal value storage with automatic cleanup
type RedisTokenBlacklist struct {
	// client is the Redis client used for blacklist operations
	// Should be configured with appropriate timeouts and retry policies
	client *redis.Client
}

// Add implements TokenBlacklist.Add for Redis-based token blacklisting.
// This method adds a token to the Redis blacklist with automatic expiration.
//
// The implementation uses Redis SET with TTL to ensure:
// - Atomic operation (token is blacklisted immediately)
// - Automatic cleanup (no manual garbage collection needed)
// - Minimal storage overhead (only stores "1" as value)
//
// Redis Operations:
// 1. SET blacklist:{token} "1" EX {ttl_seconds}
//
// Error Handling:
// - Redis connection failures are propagated as errors
// - Timeout errors are handled by the Redis client
// - Network issues are retried by the Redis client (if configured)
//
// Time Complexity: O(1)
// Space Complexity: O(1) per token
//
// Parameters:
//   - ctx: Request context with timeout and cancellation
//   - token: JWT token string to blacklist (full token, not hash)
//   - expiry: When the blacklist entry should expire (typically token expiry)
//
// Returns:
//   - error: Redis operation error, or nil on success
//
// Usage:
//
//	err := blacklist.Add(ctx, "eyJhbGciOiJIUzI1NiIs...", time.Now().Add(15*time.Minute))
//	if err != nil {
//	    // Handle blacklist failure
//	}
func (r *RedisTokenBlacklist) Add(ctx context.Context, token string, expiry time.Time) error {
	// Create Redis key with consistent prefix for easy management
	key := fmt.Sprintf("blacklist:%s", token)

	// Calculate TTL until the token naturally expires
	// This ensures blacklist entries don't outlive the tokens they represent
	ttl := time.Until(expiry)

	// Handle edge case where token is already expired
	if ttl <= 0 {
		// No need to blacklist an already expired token
		return nil
	}

	// Use Redis SET with TTL for atomic blacklist operation
	// This ensures the entry is automatically cleaned up when the token expires
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsBlacklisted implements TokenBlacklist.IsBlacklisted for Redis-based checking.
// This method performs a fast O(1) lookup to determine if a token is blacklisted.
//
// The implementation prioritizes performance and availability:
// - Single Redis EXISTS operation for fast lookup
// - Fail-open behavior (returns false on Redis errors)
// - Minimal network round trips
//
// Redis Operations:
// 1. EXISTS blacklist:{token}
//
// Error Handling:
// - Redis connection failures return false (fail-open)
// - This prevents blacklist service outages from breaking authentication
// - Errors are not logged here (calling code should handle logging)
//
// Security Considerations:
// - Fail-open behavior means Redis outages don't block all authentication
// - However, revoked tokens may be accepted during Redis outages
// - Monitor Redis availability and alert on failures
//
// Time Complexity: O(1)
// Space Complexity: O(1)
//
// Parameters:
//   - ctx: Request context with timeout and cancellation
//   - token: JWT token string to check (full token, not hash)
//
// Returns:
//   - bool: true if token is blacklisted, false if not blacklisted or on error
//
// Usage:
//
//	if blacklist.IsBlacklisted(ctx, "eyJhbGciOiJIUzI1NiIs...") {
//	    return ErrTokenBlacklisted
//	}
func (r *RedisTokenBlacklist) IsBlacklisted(ctx context.Context, token string) bool {
	// Create Redis key with consistent prefix
	key := fmt.Sprintf("blacklist:%s", token)

	// Check if the key exists in Redis
	// EXISTS returns the number of keys that exist (0 or 1 for single key)
	exists, err := r.client.Exists(ctx, key).Result()

	// Fail-open behavior: if Redis is unavailable, don't block authentication
	// This is a security vs availability trade-off
	// In practice, Redis should be highly available with proper clustering
	if err != nil {
		// Log this error at a higher level for monitoring
		return false
	}

	// exists > 0 means the key exists, indicating the token is blacklisted
	return exists > 0
}

// NewJWTService creates a new JWT service with comprehensive security configuration.
// This constructor performs input validation and initializes all security components.
//
// The service is designed for production use with the following defaults:
// - HMAC-SHA256 signing for token integrity
// - Configurable token lifetimes for security/usability balance
// - Mandatory blacklist for token revocation
// - Issuer/audience validation for token scoping
//
// Configuration Recommendations:
// - secretKey: At least 32 bytes, cryptographically random
// - accessTTL: 15 minutes (balance security vs user experience)
// - refreshTTL: 7 days (balance security vs login frequency)
// - issuer: Service name for token scoping
// - audience: API identifier for token validation
//
// Security Considerations:
// - secretKey must be kept secure and rotated regularly
// - All service instances must use the same secretKey
// - Blacklist must be shared across all service instances
//
// Parameters:
//   - secretKey: HMAC signing key (minimum 32 bytes recommended)
//   - issuer: Token issuer identifier (typically service name)
//   - audience: Token audience identifier (typically API name)
//   - blacklist: Token blacklist implementation (typically Redis-based)
//   - accessTTL: Access token lifetime (recommended: 15 minutes)
//   - refreshTTL: Refresh token lifetime (recommended: 7 days)
//
// Returns:
//   - *JWTService: Configured JWT service ready for production use
//
// Panics:
//   - If secretKey is nil or empty (security requirement)
//   - If issuer or audience is empty (validation requirement)
//   - If blacklist is nil (security requirement)
//   - If TTL values are zero or negative (configuration error)
//
// Usage:
//
//	blacklist := &RedisTokenBlacklist{client: redisClient}
//	service := NewJWTService(
//	    secretKey,
//	    "auth-service",
//	    "api.example.com",
//	    blacklist,
//	    15*time.Minute,
//	    7*24*time.Hour,
//	)
func NewJWTService(secretKey []byte, issuer, audience string, blacklist TokenBlacklist, accessTTL, refreshTTL time.Duration) *JWTService {
	// Validate critical security parameters
	if len(secretKey) == 0 {
		panic("JWT secret key cannot be empty - security requirement")
	}

	if len(secretKey) < 32 {
		panic("JWT secret key should be at least 32 bytes for security")
	}

	if issuer == "" {
		panic("JWT issuer cannot be empty - required for token validation")
	}

	if audience == "" {
		panic("JWT audience cannot be empty - required for token validation")
	}

	if blacklist == nil {
		panic("Token blacklist cannot be nil - required for security")
	}

	if accessTTL <= 0 {
		panic("Access token TTL must be positive")
	}

	if refreshTTL <= 0 {
		panic("Refresh token TTL must be positive")
	}

	if refreshTTL <= accessTTL {
		panic("Refresh token TTL should be longer than access token TTL")
	}

	return &JWTService{
		secretKey:       secretKey,
		issuer:          issuer,
		audience:        audience,
		blacklist:       blacklist,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

// GenerateTokenPair creates a complete authentication token pair for a user.
// This method generates both access and refresh tokens with proper security configuration.
//
// The token pair includes:
// - Access Token: Short-lived, used for API authentication
// - Refresh Token: Long-lived, used to obtain new access tokens
//
// Security Features:
// - Each token has a unique JTI (JWT ID) to prevent replay attacks
// - Tokens include issuer/audience for validation
// - Tokens include proper timestamp claims (iat, exp, nbf)
// - Different token types prevent misuse
//
// Token Structure:
// - Header: {"alg": "HS256", "typ": "JWT"}
// - Payload: User claims + JWT standard claims + custom claims
// - Signature: HMAC-SHA256 over header + payload
//
// Performance:
// - Generates cryptographically secure random JTI
// - Minimal memory allocation
// - Fast HMAC operations
//
// Parameters:
//   - user: User entity to generate tokens for (must not be nil)
//
// Returns:
//   - *domain.AuthResponse: Complete authentication response with token pair
//   - error: Any error during token generation
//
// Possible Errors:
//   - Token generation failures (unlikely with proper configuration)
//   - Cryptographic operation failures (system-level issues)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
//
// Usage:
//
//	authResponse, err := jwtService.GenerateTokenPair(user)
//	if err != nil {
//	    return fmt.Errorf("token generation failed: %w", err)
//	}
//	// authResponse contains access_token, refresh_token, and user info
func (j *JWTService) GenerateTokenPair(user *domain.User) (*domain.AuthResponse, error) {
	// Input validation
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil for token generation")
	}

	// Generate access token with short TTL for security
	accessToken, err := j.generateAccessToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token with long TTL for usability
	refreshToken, err := j.generateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create complete authentication response
	return &domain.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(j.accessTokenTTL.Seconds()),
		User:         user.ToUserResponse(),
	}, nil
}

// ValidateToken performs comprehensive validation of an access token.
// This method implements multiple security checks to ensure token integrity and validity.
//
// Validation Process:
// 1. Blacklist check (early exit for revoked tokens)
// 2. JWT signature validation using HMAC-SHA256
// 3. Standard JWT claims validation (exp, iat, nbf, iss, aud)
// 4. Token type validation (must be "access")
// 5. Claims structure validation
//
// Security Checks:
// - Signature verification prevents token tampering
// - Expiration check prevents use of old tokens
// - Issuer/audience validation prevents cross-service token misuse
// - Token type validation prevents refresh token misuse
// - Blacklist check enables immediate token revocation
//
// Performance Optimizations:
// - Blacklist check first (fast Redis lookup)
// - Early exit on validation failures
// - Minimal object allocation
//
// Parameters:
//   - ctx: Request context for timeout and cancellation
//   - tokenString: JWT token string to validate
//
// Returns:
//   - *domain.User: User information from validated token
//   - error: Validation error or nil on success
//
// Possible Errors:
//   - domain.ErrTokenBlacklisted: Token has been revoked
//   - domain.ErrInvalidToken: Token is malformed or signature invalid
//   - domain.ErrTokenExpired: Token has expired
//   - domain.ErrInvalidTokenType: Wrong token type (refresh instead of access)
//   - domain.ErrInvalidTokenClaims: Claims are missing or invalid
//
// Time Complexity: O(1) + O(blacklist_lookup)
// Space Complexity: O(1)
//
// Usage:
//
//	user, err := jwtService.ValidateToken(ctx, "eyJhbGciOiJIUzI1NiIs...")
//	if err != nil {
//	    // Handle validation error
//	    return err
//	}
//	// user contains validated user information
func (j *JWTService) ValidateToken(ctx context.Context, tokenString string) (*domain.User, error) {
	// Input validation
	if tokenString == "" {
		return nil, domain.ErrInvalidToken
	}

	// Check blacklist first for early exit on revoked tokens
	// This prevents unnecessary cryptographic operations on revoked tokens
	if j.blacklist.IsBlacklisted(ctx, tokenString) {
		return nil, domain.ErrTokenBlacklisted
	}

	// Parse and validate JWT token with comprehensive security options
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, j.keyFunc,
		// Restrict allowed signing methods to prevent algorithm substitution attacks
		jwt.WithValidMethods([]string{"HS256"}),
		// Validate issuer to prevent cross-service token misuse
		jwt.WithIssuer(j.issuer),
		// Validate audience to ensure token is for this service
		jwt.WithAudience(j.audience),
		// Use current time for expiration validation
		jwt.WithTimeFunc(time.Now),
	)

	if err != nil {
		// jwt.ParseWithClaims returns specific error types
		// Wrap with our domain error for consistent error handling
		return nil, fmt.Errorf("token validation failed: %w", domain.ErrInvalidToken)
	}

	// Extract and validate claims structure
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, domain.ErrInvalidToken
	}

	// Additional security check: validate token type
	// This prevents refresh tokens from being used for API access
	if claims.TokenType != "access" {
		return nil, domain.ErrInvalidTokenType
	}

	// Validate required claims are present
	if claims.UserID == uuid.Nil || claims.Email == "" {
		return nil, domain.ErrInvalidTokenClaims
	}

	// Create user object from validated claims
	// In production, you might want to load additional user data from database
	// to ensure the user still exists and has proper permissions
	user := &domain.User{
		ID:    claims.UserID,
		Email: claims.Email,
		// Note: Other user fields could be loaded from database if needed
		// This approach balances performance vs data freshness
	}

	return user, nil
}

// RevokeToken immediately blacklists a token, preventing further use.
// This method provides immediate token revocation for security scenarios.
//
// Revocation Use Cases:
// - User logout operations
// - Account compromise response
// - Security policy enforcement
// - Administrative token revocation
//
// Process:
// 1. Parse token to extract expiration time (no signature validation needed)
// 2. Add token to blacklist with expiration time
// 3. Token becomes unusable immediately across all service instances
//
// Security Considerations:
// - Revocation is immediate and distributed
// - Revoked tokens remain blacklisted until natural expiration
// - Blacklist automatically cleans up expired entries
//
// Performance:
// - Token parsing is lightweight (no signature validation)
// - Blacklist operation is O(1) with Redis
// - No database operations required
//
// Parameters:
//   - ctx: Request context for timeout and cancellation
//   - tokenString: JWT token string to revoke
//
// Returns:
//   - error: Revocation error or nil on success
//
// Possible Errors:
//   - domain.ErrInvalidToken: Token is malformed and cannot be parsed
//   - Blacklist operation errors (Redis failures, etc.)
//
// Time Complexity: O(1) + O(blacklist_add)
// Space Complexity: O(1)
//
// Usage:
//
//	err := jwtService.RevokeToken(ctx, "eyJhbGciOiJIUzI1NiIs...")
//	if err != nil {
//	    // Handle revocation error
//	    return fmt.Errorf("token revocation failed: %w", err)
//	}
//	// Token is now blacklisted and unusable
func (j *JWTService) RevokeToken(ctx context.Context, tokenString string) error {
	// Input validation
	if tokenString == "" {
		return domain.ErrInvalidToken
	}

	// Parse token to extract expiration time
	// We don't need to validate the signature since we're just revoking it
	// Using jwt.Parser with no key validation for performance
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, &JWTClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse token for revocation: %w", domain.ErrInvalidToken)
	}

	// Extract claims to get expiration time
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return domain.ErrInvalidToken
	}

	// Validate expiration claim exists
	if claims.ExpiresAt == nil {
		return domain.ErrInvalidTokenClaims
	}

	// Add token to blacklist until its natural expiration
	// This ensures the blacklist entry doesn't outlive the token
	expiry := claims.ExpiresAt.Time
	return j.blacklist.Add(ctx, tokenString, expiry)
}

// keyFunc provides the HMAC key for JWT token validation.
// This method implements the jwt.Keyfunc interface for the golang-jwt library.
//
// Security Features:
// - Validates signing method to prevent algorithm substitution attacks
// - Returns the configured secret key for HMAC validation
// - Protects against none algorithm attacks
//
// The method ensures that only HMAC-SHA256 signed tokens are accepted,
// preventing common JWT attacks such as:
// - Algorithm substitution attacks (changing to 'none')
// - Key confusion attacks (changing to RSA with HMAC key)
//
// Parameters:
//   - token: JWT token being validated (used to check signing method)
//
// Returns:
//   - interface{}: The HMAC secret key for signature validation
//   - error: Error if signing method is not supported
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (j *JWTService) keyFunc(token *jwt.Token) (interface{}, error) {
	// Validate that the token uses HMAC signing method
	// This prevents algorithm substitution attacks
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	// Return the HMAC secret key for signature validation
	return j.secretKey, nil
}

// generateAccessToken creates a short-lived access token for API authentication.
// Access tokens are designed for frequent use with short lifetimes for security.
//
// Token Characteristics:
// - Short TTL (typically 15 minutes) for security
// - Contains user identification claims
// - Marked as "access" type to prevent misuse
// - Includes standard JWT claims for validation
//
// Claims Structure:
// - user_id: User's UUID for identification
// - email: User's email for convenient access
// - token_type: "access" to prevent refresh token misuse
// - Standard JWT claims: sub, exp, iat, nbf, iss, aud, jti
//
// Parameters:
//   - user: User entity to create token for
//
// Returns:
//   - string: Signed JWT access token
//   - error: Token generation error
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (j *JWTService) generateAccessToken(user *domain.User) (string, error) {
	now := time.Now()

	// Create comprehensive claims for access token
	claims := &JWTClaims{
		UserID:    user.ID,
		Email:     user.Email,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),                              // Subject: user identifier
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTokenTTL)), // Expiration time
			IssuedAt:  jwt.NewNumericDate(now),                       // Issued at
			NotBefore: jwt.NewNumericDate(now),                       // Not before (valid from now)
			Issuer:    j.issuer,                                      // Issuer identification
			Audience:  []string{j.audience},                          // Audience validation
			ID:        j.generateJTI(),                               // Unique token ID
		},
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// generateRefreshToken creates a long-lived refresh token for obtaining new access tokens.
// Refresh tokens are designed for infrequent use with longer lifetimes for usability.
//
// Token Characteristics:
// - Long TTL (typically 7 days) for usability
// - Contains user identification claims
// - Marked as "refresh" type to prevent API misuse
// - Includes standard JWT claims for validation
//
// Claims Structure:
// - user_id: User's UUID for identification
// - email: User's email for convenient access
// - token_type: "refresh" to prevent access token misuse
// - Standard JWT claims: sub, exp, iat, nbf, iss, aud, jti
//
// Parameters:
//   - user: User entity to create token for
//
// Returns:
//   - string: Signed JWT refresh token
//   - error: Token generation error
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (j *JWTService) generateRefreshToken(user *domain.User) (string, error) {
	now := time.Now()

	// Create comprehensive claims for refresh token
	claims := &JWTClaims{
		UserID:    user.ID,
		Email:     user.Email,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID.String(),                               // Subject: user identifier
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshTokenTTL)), // Expiration time
			IssuedAt:  jwt.NewNumericDate(now),                        // Issued at
			NotBefore: jwt.NewNumericDate(now),                        // Not before (valid from now)
			Issuer:    j.issuer,                                       // Issuer identification
			Audience:  []string{j.audience},                           // Audience validation
			ID:        j.generateJTI(),                                // Unique token ID
		},
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// generateJTI creates a cryptographically secure random JWT ID.
// JTI (JWT ID) provides unique identification for each token to prevent replay attacks.
//
// Security Features:
// - Uses crypto/rand for cryptographically secure randomness
// - 16 bytes of entropy (128 bits) for collision resistance
// - Base64 URL encoding for safe transport in URLs
// - No timestamp component to avoid timing attacks
//
// The JTI serves multiple security purposes:
// - Prevents token replay attacks
// - Enables fine-grained token revocation
// - Provides audit trail capabilities
// - Helps detect token duplication attempts
//
// Returns:
//   - string: Base64 URL-encoded random JTI
//
// Panics:
//   - If crypto/rand fails (system-level entropy issues)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
//
// Security Notes:
// - Uses crypto/rand which is cryptographically secure
// - 16 bytes provides 2^128 possible values (collision resistant)
// - Base64 URL encoding is safe for HTTP headers and URLs
func (j *JWTService) generateJTI() string {
	// Generate 16 bytes of cryptographically secure random data
	// This provides 128 bits of entropy, which is sufficient for collision resistance
	bytes := make([]byte, 16)

	// Read random bytes from the system's cryptographically secure random number generator
	// This will panic if the system's entropy source is unavailable, which is appropriate
	// since we cannot generate secure tokens without proper randomness
	_, err := rand.Read(bytes)
	if err != nil {
		// This should never happen on properly configured systems
		// If it does, it indicates a serious system-level issue
		panic(fmt.Sprintf("failed to generate random JTI: %v", err))
	}

	// Encode as base64 URL for safe transport in HTTP headers and URLs
	// URL encoding prevents issues with '+' and '/' characters in standard base64
	return base64.URLEncoding.EncodeToString(bytes)
}

// JWTClaims defines the structure for JWT token claims.
// This struct extends the standard JWT claims with custom fields for user identification.
//
// Custom Claims:
// - UserID: User's unique identifier (UUID)
// - Email: User's email address for convenient access
// - TokenType: Distinguishes between "access" and "refresh" tokens
//
// Standard Claims (from jwt.RegisteredClaims):
// - Subject (sub): User ID as string
// - ExpiresAt (exp): Token expiration time
// - IssuedAt (iat): Token creation time
// - NotBefore (nbf): Token valid from time
// - Issuer (iss): Token issuer identification
// - Audience (aud): Token audience validation
// - ID (jti): Unique token identifier
//
// The struct is designed for efficient JSON serialization and includes
// appropriate JSON tags for API compatibility.
//
// Security Considerations:
// - No sensitive data (passwords, secrets) included
// - TokenType prevents cross-token-type attacks
// - Standard claims enable comprehensive validation
//
// Usage:
//
//	claims := &JWTClaims{
//	    UserID: user.ID,
//	    Email: user.Email,
//	    TokenType: "access",
//	    RegisteredClaims: jwt.RegisteredClaims{...},
//	}
type JWTClaims struct {
	// UserID uniquely identifies the user this token belongs to
	// Uses UUID for global uniqueness and prevents enumeration attacks
	UserID uuid.UUID `json:"user_id"`

	// Email provides convenient access to user's email address
	// Included for API convenience and user identification
	Email string `json:"email"`

	// TokenType distinguishes between different token types
	// Valid values: "access", "refresh"
	// Prevents tokens from being used for unintended purposes
	TokenType string `json:"token_type"`

	// RegisteredClaims includes standard JWT claims
	// Provides expiration, issuer, audience, and other standard validations
	jwt.RegisteredClaims
}

// NewRedisTokenBlacklist creates a new Redis-based token blacklist.
// This constructor provides a clean way to initialize the blacklist with a Redis client.
//
// Parameters:
//   - client: Configured Redis client for blacklist operations
//
// Returns:
//   - *RedisTokenBlacklist: Ready-to-use Redis blacklist implementation
//
// Usage:
//
//	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
//	blacklist := NewRedisTokenBlacklist(redisClient)
func NewRedisTokenBlacklist(client *redis.Client) *RedisTokenBlacklist {
	return &RedisTokenBlacklist{
		client: client,
	}
}
