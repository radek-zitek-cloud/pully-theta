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
// This middleware validates JWT tokens, extracts user information,
// and injects the user context into the request for downstream handlers.
//
// Features:
// - Bearer token extraction from Authorization header
// - JWT signature validation using configured secret
// - Token expiration checking
// - User context injection for handlers
// - Proper error responses for authentication failures
//
// The middleware expects tokens in the format: "Bearer <token>"
// and validates them against the configured JWT secret.
type JWTMiddleware struct {
	config *config.Config
	logger *logrus.Logger
}

// NewJWTMiddleware creates a new JWT authentication middleware instance.
//
// Parameters:
//   - cfg: Application configuration containing JWT settings
//   - logger: Logger for authentication events and errors
//
// Returns:
//   - Configured JWT middleware instance
func NewJWTMiddleware(cfg *config.Config, logger *logrus.Logger) *JWTMiddleware {
	return &JWTMiddleware{
		config: cfg,
		logger: logger,
	}
}

// RequireAuth creates a Gin middleware that enforces JWT authentication.
// This middleware validates JWT tokens and injects user context into requests.
//
// Authentication flow:
// 1. Extract Bearer token from Authorization header
// 2. Parse and validate JWT token signature
// 3. Check token expiration and type (must be "access")
// 4. Extract user ID and inject into request context
// 5. Continue to next handler or return authentication error
//
// Error responses:
// - 401 Unauthorized: Missing, invalid, or expired token
// - 403 Forbidden: Valid token but insufficient permissions
//
// Context injection:
// - user_id: UUID of the authenticated user
// - request_id: Correlation ID for request tracing
//
// Returns:
//   - Gin middleware function for JWT authentication
func (m *JWTMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate request ID for correlation
		requestID := uuid.New().String()
		c.Set(string(RequestIDKey), requestID)

		// Extract token from Authorization header
		token, err := m.extractTokenFromHeader(c)
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

		// Parse and validate JWT token
		claims, err := m.validateToken(token)
		if err != nil {
			m.logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"error":      err.Error(),
				"ip":         c.ClientIP(),
			}).Warn("Authentication failed: token validation error")

			c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
				Error:     "unauthorized",
				Message:   "Invalid or expired token",
				RequestID: requestID,
				Timestamp: time.Now(),
			})
			c.Abort()
			return
		}

		// Verify token type is "access"
		if claims.TokenType != "access" {
			m.logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"token_type": claims.TokenType,
				"user_id":    claims.UserID,
			}).Warn("Authentication failed: invalid token type")

			c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
				Error:     "unauthorized",
				Message:   "Invalid token type",
				RequestID: requestID,
				Timestamp: time.Now(),
			})
			c.Abort()
			return
		}

		// Parse user ID as UUID
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			m.logger.WithFields(logrus.Fields{
				"request_id": requestID,
				"user_id":    claims.UserID,
				"error":      err.Error(),
			}).Error("Authentication failed: invalid user ID format")

			c.JSON(http.StatusUnauthorized, domain.ErrorResponse{
				Error:     "unauthorized",
				Message:   "Invalid user identifier",
				RequestID: requestID,
				Timestamp: time.Now(),
			})
			c.Abort()
			return
		}

		// Inject user context into request
		c.Set(string(UserIDKey), userID)

		// Log successful authentication
		m.logger.WithFields(logrus.Fields{
			"request_id": requestID,
			"user_id":    userID.String(),
			"email":      claims.Email,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
		}).Debug("User authenticated successfully")

		// Continue to next handler
		c.Next()
	}
}

// RequireNoAuth creates a middleware that rejects authenticated requests.
// This is useful for endpoints like login/register that should only
// be accessible to unauthenticated users.
//
// Returns:
//   - Gin middleware function that rejects authenticated requests
func (m *JWTMiddleware) RequireNoAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if Authorization header is present
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Next()
			return
		}

		// Extract and validate token
		token, err := m.extractTokenFromHeader(c)
		if err != nil {
			// Invalid token format, allow request to continue
			c.Next()
			return
		}

		// Check if token is valid
		_, err = m.validateToken(token)
		if err != nil {
			// Invalid or expired token, allow request to continue
			c.Next()
			return
		}

		// Valid token present, reject request
		m.logger.WithFields(logrus.Fields{
			"ip":         c.ClientIP(),
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"user_agent": c.GetHeader("User-Agent"),
		}).Warn("Authenticated user attempted to access auth endpoint")

		c.JSON(http.StatusForbidden, domain.ErrorResponse{
			Error:     "forbidden",
			Message:   "This endpoint requires no authentication",
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
