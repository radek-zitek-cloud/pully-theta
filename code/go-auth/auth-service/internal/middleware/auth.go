package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"auth-service/internal/config"
	"auth-service/internal/domain"
	"auth-service/internal/security"
)

// ContextKey defines custom context keys to avoid key collisions
type ContextKey string

const (
	// UserIDKey is the context key for the authenticated user ID
	UserIDKey ContextKey = "user_id"
	// UserKey is the context key for the full user entity
	UserKey ContextKey = "user"
	// RequestIDKey is the context key for request correlation ID
	RequestIDKey ContextKey = "request_id"
)

// JWTClaims represents the claims stored in our JWT tokens.
// This structure extends the standard JWT claims with custom fields
// for user identification and session management.
type JWTClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	TokenType string `json:"token_type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// JWTMiddleware provides JWT token validation and user context injection.
// This middleware validates JWT tokens using the enhanced security service,
// and injects the user context into the request for downstream handlers.
//
// Features:
// - Bearer token extraction from Authorization header
// - Enhanced JWT signature validation using security service
// - Token blacklist checking for immediate revocation
// - Token expiration and type validation
// - User context injection for handlers
// - Comprehensive security logging and metrics
//
// The middleware expects tokens in the format: "Bearer <token>"
// and validates them using the enhanced JWT security service.
type JWTMiddleware struct {
	jwtService *security.JWTService
	config     *config.Config
	logger     *logrus.Logger
}

// NewJWTMiddleware creates a new JWT authentication middleware instance.
// This constructor initializes the middleware with the enhanced JWT security service
// for production-grade token validation and security features.
//
// Parameters:
//   - jwtService: Enhanced JWT security service for token operations
//   - cfg: Application configuration containing JWT settings
//   - logger: Logger for authentication events and errors
//
// Returns:
//   - Configured JWT middleware instance with enhanced security
//
// Usage:
//
//	jwtMiddleware := NewJWTMiddleware(jwtService, cfg, logger)
//	router.Use(jwtMiddleware.RequireAuth())
func NewJWTMiddleware(jwtService *security.JWTService, cfg *config.Config, logger *logrus.Logger) *JWTMiddleware {
	return &JWTMiddleware{
		jwtService: jwtService,
		config:     cfg,
		logger:     logger,
	}
}

// RequireAuth creates a Gin middleware that enforces JWT authentication.
// This middleware validates JWT tokens using the enhanced security service
// and injects user context into requests.
//
// Authentication flow:
// 1. Extract Bearer token from Authorization header
// 2. Validate token using enhanced JWT security service (includes blacklist check)
// 3. Extract user information from validated token
// 4. Inject user context into request for downstream handlers
// 5. Continue to next handler or return authentication error
//
// Security features:
// - Token blacklist checking for immediate revocation
// - Algorithm validation to prevent substitution attacks
// - Comprehensive token validation (signature, expiration, claims)
// - Protection against common JWT security vulnerabilities
//
// Error responses:
// - 401 Unauthorized: Missing, invalid, expired, or blacklisted token
// - 500 Internal Server Error: System errors during validation
//
// Context injection:
// - user_id: UUID of the authenticated user
// - request_id: Correlation ID for request tracing
//
// Returns:
//   - Gin middleware function for enhanced JWT authentication
func (m *JWTMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate request ID for correlation
		requestID := uuid.New().String()
		c.Set(string(RequestIDKey), requestID)

		// Extract token from Authorization header
		tokenString, err := m.extractTokenFromHeader(c)
		if err != nil {
			m.logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"error":      err.Error(),
				"ip":         c.ClientIP(),
				"user_agent": c.GetHeader("User-Agent"),
			}).Warn("Authentication failed: token extraction error")

			c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
				Error:     "unauthorized",
				Message:   "Authentication required",
				RequestID: requestID,
				Timestamp: time.Now(),
			})
			c.Abort()
			return
		}

		// Validate token using enhanced JWT security service
		// This includes blacklist checking, signature validation, and comprehensive security checks
		user, err := m.jwtService.ValidateToken(c.Request.Context(), tokenString)
		if err != nil {
			// Determine error type for appropriate response
			var message string
			var logLevel logrus.Level = logrus.WarnLevel

			switch err {
			case domain.ErrTokenBlacklisted:
				message = "Token has been revoked"
			case domain.ErrInvalidToken:
				message = "Invalid or malformed token"
			case domain.ErrTokenExpired:
				message = "Token has expired"
			case domain.ErrInvalidTokenType:
				message = "Invalid token type"
			case domain.ErrInvalidTokenClaims:
				message = "Invalid token claims"
			default:
				message = "Token validation failed"
				logLevel = logrus.ErrorLevel // System errors should be logged as errors
			}

			m.logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"error":      err.Error(),
				"ip":         c.ClientIP(),
				"user_agent": c.GetHeader("User-Agent"),
			}).Log(logLevel, "Authentication failed: token validation error")

			c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
				Error:     "unauthorized",
				Message:   message,
				RequestID: requestID,
				Timestamp: time.Now(),
			})
			c.Abort()
			return
		}

		// Validate user object from token
		if user == nil || user.ID == uuid.Nil {
			m.logger.WithFields(logrus.Fields{
				"request_id": requestID,
			}).Error("Authentication failed: invalid user from token")

			c.JSON(http.StatusInternalServerError, domain.ErrorResponse{
				Error:     "internal_error",
				Message:   "Authentication system error",
				RequestID: requestID,
				Timestamp: time.Now(),
			})
			c.Abort()
			return
		}

		// Inject user context into request
		c.Set(string(UserIDKey), user.ID)
		c.Set(string(UserKey), user)

		// Log successful authentication
		m.logger.WithFields(logrus.Fields{
			"request_id": requestID,
			"user_id":    user.ID.String(),
			"email":      user.Email,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
		}).Debug("User authenticated successfully with enhanced JWT security")

		// Continue to next handler
		c.Next()
	}
}

// RequireNoAuth creates a middleware that rejects authenticated requests.
// This middleware allows requests with no authentication or expired/invalid tokens,
// but rejects requests with valid, non-expired access tokens.
//
// Design rationale:
// - Users with expired tokens should be able to login again
// - Users with invalid tokens (corrupted, wrong format) should be able to login
// - Only users with valid, active tokens should be rejected (they're already authenticated)
//
// This provides better UX compared to strict rejection of any token presence.
//
// Returns:
//   - Gin middleware function that rejects only valid authenticated requests
func (m *JWTMiddleware) RequireNoAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if Authorization header is present
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			// No auth header, allow request
			c.Next()
			return
		}

		// Extract token from header
		token, err := m.extractTokenFromHeader(c)
		if err != nil {
			// Invalid token format (not "Bearer <token>"), allow request to continue
			m.logger.WithFields(logrus.Fields{
				"ip":     c.ClientIP(),
				"method": c.Request.Method,
				"path":   c.Request.URL.Path,
				"error":  err.Error(),
			}).Debug("Invalid token format in auth header, allowing request")
			c.Next()
			return
		}

		// Validate token
		claims, err := m.validateToken(token)
		if err != nil {
			// Invalid or expired token, allow request to continue
			m.logger.WithFields(logrus.Fields{
				"ip":     c.ClientIP(),
				"method": c.Request.Method,
				"path":   c.Request.URL.Path,
				"error":  err.Error(),
			}).Debug("Invalid/expired token in auth header, allowing request")
			c.Next()
			return
		}

		// Token is valid, check if it's an access token
		if claims.TokenType != "access" {
			// Not an access token (probably refresh), allow request
			m.logger.WithFields(logrus.Fields{
				"ip":         c.ClientIP(),
				"method":     c.Request.Method,
				"path":       c.Request.URL.Path,
				"token_type": claims.TokenType,
			}).Debug("Non-access token in auth header, allowing request")
			c.Next()
			return
		}

		// Valid access token present, reject request
		m.logger.WithFields(logrus.Fields{
			"ip":         c.ClientIP(),
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"user_id":    claims.UserID,
			"user_agent": c.GetHeader("User-Agent"),
		}).Warn("Authenticated user attempted to access auth endpoint")

		c.JSON(http.StatusForbidden, domain.ErrorResponse{
			Error:     "forbidden",
			Message:   "This endpoint requires no authentication. You are already authenticated.",
			Timestamp: time.Now(),
		})
		c.Abort()
	}
}

// extractTokenFromHeader extracts the JWT token from the Authorization header.
// Expected format: "Bearer <token>"
//
// Parameters:
//   - c: Gin context containing HTTP headers
//
// Returns:
//   - Extracted JWT token string
//   - Error if header is missing or has invalid format
func (m *JWTMiddleware) extractTokenFromHeader(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", domain.ErrTokenMissing
	}

	// Check for Bearer prefix
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", domain.ErrInvalidTokenFormat
	}

	// Extract token after "Bearer "
	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		return "", domain.ErrTokenMissing
	}

	return token, nil
}

// validateToken parses and validates a JWT token string.
// This function performs comprehensive token validation including
// signature verification, expiration checking, and claims parsing.
//
// Validation steps:
// 1. Parse token with HMAC-SHA256 signature verification
// 2. Validate token signature against configured secret
// 3. Check token expiration timestamp
// 4. Verify required claims are present
// 5. Return parsed claims for use by handlers
//
// Parameters:
//   - tokenString: JWT token to validate
//
// Returns:
//   - Parsed and validated JWT claims
//   - Error if token is invalid, expired, or malformed
func (m *JWTMiddleware) validateToken(tokenString string) (*JWTClaims, error) {
	// Parse token with custom claims
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.ErrInvalidSigningMethod
		}
		return []byte(m.config.JWT.Secret), nil
	})

	if err != nil {
		// Parse error - could be expired, invalid signature, etc.
		return nil, domain.ErrInvalidToken
	}

	// Extract claims and verify token validity
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, domain.ErrInvalidToken
	}

	// Verify required claims are present
	if claims.UserID == "" {
		return nil, domain.ErrInvalidTokenClaims
	}

	// Additional expiration check (jwt library should handle this, but double-check)
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, domain.ErrTokenExpired
	}

	return claims, nil
}

// GetUserIDFromContext extracts the authenticated user ID from the request context.
// This helper function is used by handlers to access the user ID injected
// by the JWT middleware.
//
// Parameters:
//   - c: Gin context containing user information
//
// Returns:
//   - User ID as UUID
//   - Error if user is not authenticated or ID is invalid
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	userID, exists := c.Get(string(UserIDKey))
	if !exists {
		return uuid.UUID{}, domain.ErrUserNotFound
	}

	id, ok := userID.(uuid.UUID)
	if !ok {
		return uuid.UUID{}, domain.ErrInvalidUserID
	}

	return id, nil
}

// GetRequestIDFromContext extracts the request correlation ID from the context.
// This helper function provides access to the request ID for logging
// and tracing purposes.
//
// Parameters:
//   - c: Gin context containing request information
//
// Returns:
//   - Request correlation ID as string
//   - Empty string if no request ID is set
func GetRequestIDFromContext(c *gin.Context) string {
	requestID, exists := c.Get(string(RequestIDKey))
	if !exists {
		return ""
	}

	id, ok := requestID.(string)
	if !ok {
		return ""
	}

	return id
}
