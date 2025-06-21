# 🚀 Refactoring Implementation Plan

## Phase 1: Quick Wins (Priority 1)

### 1.1 File Structure Optimization

#### Split Large Files
Create smaller, focused modules from oversized files:

```bash
# Current structure
internal/service/auth_service.go (977 lines)
internal/api/auth_handler.go (858 lines)

# Proposed structure
internal/service/
├── auth_service_core.go      # Register, login, logout (300 lines)
├── auth_service_tokens.go    # JWT operations, refresh (200 lines)
├── auth_service_profile.go   # User profile management (150 lines)
├── auth_service_utils.go     # Validation, hashing utilities (200 lines)

internal/api/
├── auth_handler_core.go      # Core auth endpoints (300 lines)
├── auth_handler_profile.go   # Profile management (200 lines)
├── auth_handler_utils.go     # Common utilities (200 lines)
```

#### Consolidate Password Operations
Merge password-related files into dedicated package:

```bash
# Current
internal/service/auth_service_password.go (474 lines)
internal/api/auth_handler_password.go (480 lines)

# Proposed
internal/password/
├── service.go               # Password business logic
├── handler.go              # Password HTTP handlers
├── validator.go            # Password strength validation
├── reset.go                # Password reset functionality
```

### 1.2 Database Connection Pool Configuration

Add to `internal/config/config.go`:

```go
type DatabaseConfig struct {
    Host            string        `env:"DB_HOST" json:"host"`
    Port            int           `env:"DB_PORT" json:"port" default:"5432"`
    Username        string        `env:"DB_USER" json:"username"`
    Password        string        `env:"DB_PASSWORD" json:"password"`
    Database        string        `env:"DB_NAME" json:"database"`
    SSLMode         string        `env:"DB_SSLMODE" json:"ssl_mode" default:"disable"`
    MaxOpenConns    int           `env:"DB_MAX_OPEN_CONNS" json:"max_open_conns" default:"25"`
    MaxIdleConns    int           `env:"DB_MAX_IDLE_CONNS" json:"max_idle_conns" default:"5"`
    ConnMaxLifetime time.Duration `env:"DB_CONN_MAX_LIFETIME" json:"conn_max_lifetime" default:"1h"`
    ConnMaxIdleTime time.Duration `env:"DB_CONN_MAX_IDLE_TIME" json:"conn_max_idle_time" default:"15m"`
}
```

### 1.3 Centralized Error Mapping

Create `internal/api/error_mapper.go`:

```go
package api

import (
    "net/http"
    "github.com/gin-gonic/gin"
    "github.com/sirupsen/logrus"
    "auth-service/internal/domain"
)

type HTTPErrorMapper struct {
    logger *logrus.Logger
}

func NewHTTPErrorMapper(logger *logrus.Logger) *HTTPErrorMapper {
    return &HTTPErrorMapper{logger: logger}
}

func (m *HTTPErrorMapper) MapError(c *gin.Context, err error, operation, requestID string) {
    m.logger.WithError(err).WithFields(logrus.Fields{
        "operation":  operation,
        "request_id": requestID,
        "method":     c.Request.Method,
        "path":       c.Request.URL.Path,
    }).Error("Request failed")

    var httpCode int
    var errorCode string
    var message string

    switch {
    case domain.IsValidationError(err):
        httpCode = http.StatusBadRequest
        errorCode = "validation_error"
        message = err.Error()
    case domain.IsAuthenticationError(err):
        httpCode = http.StatusUnauthorized
        errorCode = "authentication_error"
        message = "Authentication failed"
    case domain.IsAuthorizationError(err):
        httpCode = http.StatusForbidden
        errorCode = "authorization_error"
        message = "Access denied"
    case domain.IsRateLimitError(err):
        httpCode = http.StatusTooManyRequests
        errorCode = "rate_limit_error"
        message = "Too many requests"
    case domain.IsInfrastructureError(err):
        httpCode = http.StatusServiceUnavailable
        errorCode = "service_unavailable"
        message = "Service temporarily unavailable"
    default:
        httpCode = http.StatusInternalServerError
        errorCode = "internal_error"
        message = "Internal server error"
    }

    c.JSON(httpCode, gin.H{
        "error":      errorCode,
        "message":    message,
        "request_id": requestID,
        "timestamp":  time.Now().UTC().Format(time.RFC3339),
    })
}
```

### 1.4 Input Sanitization Utilities

Create `internal/utils/sanitizer.go`:

```go
package utils

import (
    "html"
    "regexp"
    "strings"
    "unicode"
)

type InputSanitizer struct {
    emailRegex *regexp.Regexp
    sqlRegex   *regexp.Regexp
}

func NewInputSanitizer() *InputSanitizer {
    return &InputSanitizer{
        emailRegex: regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
        sqlRegex:   regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter|exec|script)`),
    }
}

func (s *InputSanitizer) SanitizeEmail(email string) string {
    email = strings.TrimSpace(strings.ToLower(email))
    email = s.removeControlCharacters(email)
    
    if !s.emailRegex.MatchString(email) {
        return ""
    }
    
    return email
}

func (s *InputSanitizer) SanitizeName(name string) string {
    name = strings.TrimSpace(name)
    name = html.EscapeString(name)
    name = s.removeControlCharacters(name)
    
    if len(name) > 100 {
        name = name[:100]
    }
    
    if s.sqlRegex.MatchString(name) {
        return ""
    }
    
    return name
}

func (s *InputSanitizer) removeControlCharacters(input string) string {
    return strings.Map(func(r rune) rune {
        if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
            return -1
        }
        return r
    }, input)
}
```

## Phase 2: Architectural Improvements (Priority 2)

### 2.1 Interface Segregation

Create focused service interfaces in `internal/domain/services.go`:

```go
package domain

import (
    "context"
    "github.com/google/uuid"
)

// Core authentication operations
type AuthenticationService interface {
    Register(ctx context.Context, req *RegisterRequest, clientIP, userAgent string) (*User, error)
    Login(ctx context.Context, req *LoginRequest, clientIP, userAgent string) (*AuthResponse, error)
    Logout(ctx context.Context, refreshToken, clientIP, userAgent string) error
    LogoutAll(ctx context.Context, userID uuid.UUID, clientIP, userAgent string) error
}

// Token management operations
type TokenService interface {
    RefreshToken(ctx context.Context, req *RefreshTokenRequest, clientIP, userAgent string) (*AuthResponse, error)
    ValidateToken(ctx context.Context, token string) (*User, error)
    RevokeToken(ctx context.Context, token string) error
}

// Password management operations
type PasswordService interface {
    ChangePassword(ctx context.Context, userID uuid.UUID, req *ChangePasswordRequest, clientIP, userAgent string) error
    ResetPassword(ctx context.Context, req *ResetPasswordRequest, clientIP, userAgent string) error
    ConfirmResetPassword(ctx context.Context, req *ConfirmResetPasswordRequest, clientIP, userAgent string) error
}

// User profile operations
type UserProfileService interface {
    GetProfile(ctx context.Context, userID uuid.UUID) (*User, error)
    UpdateProfile(ctx context.Context, userID string, updateData map[string]interface{}) error
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    GetUserByID(ctx context.Context, id string) (*User, error)
}
```

### 2.2 Generic Repository Pattern

Create `internal/repository/base.go`:

```go
package repository

import (
    "context"
    "database/sql"
    "github.com/google/uuid"
    "github.com/sirupsen/logrus"
)

// BaseRepository provides common database operations
type BaseRepository struct {
    db     *sql.DB
    logger *logrus.Logger
}

func NewBaseRepository(db *sql.DB, logger *logrus.Logger) *BaseRepository {
    return &BaseRepository{
        db:     db,
        logger: logger,
    }
}

// Common query patterns
func (r *BaseRepository) Exists(ctx context.Context, table, column string, value interface{}) (bool, error) {
    query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM %s WHERE %s = $1)", table, column)
    var exists bool
    err := r.db.QueryRowContext(ctx, query, value).Scan(&exists)
    return exists, err
}

func (r *BaseRepository) CountByCondition(ctx context.Context, table, condition string, args ...interface{}) (int64, error) {
    query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s", table, condition)
    var count int64
    err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
    return count, err
}

// Transaction helpers
func (r *BaseRepository) WithTransaction(ctx context.Context, fn func(*sql.Tx) error) error {
    tx, err := r.db.BeginTx(ctx, nil)
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    
    defer func() {
        if p := recover(); p != nil {
            tx.Rollback()
            panic(p)
        }
    }()
    
    if err := fn(tx); err != nil {
        if rbErr := tx.Rollback(); rbErr != nil {
            r.logger.WithError(rbErr).Error("Failed to rollback transaction")
        }
        return err
    }
    
    return tx.Commit()
}
```

## Phase 3: Performance & Security Enhancements (Priority 3)

### 3.1 Redis-Based Rate Limiting

Create `internal/service/redis_rate_limit_service.go`:

```go
package service

import (
    "context"
    "fmt"
    "time"
    
    "github.com/redis/go-redis/v9"
    "github.com/sirupsen/logrus"
    "auth-service/internal/domain"
)

type RedisRateLimitService struct {
    client *redis.Client
    config RateLimitConfig
    logger *logrus.Logger
}

func NewRedisRateLimitService(client *redis.Client, config RateLimitConfig, logger *logrus.Logger) *RedisRateLimitService {
    return &RedisRateLimitService{
        client: client,
        config: config,
        logger: logger,
    }
}

func (r *RedisRateLimitService) CheckLoginAttempts(ctx context.Context, clientIP string) error {
    key := fmt.Sprintf("rate_limit:login:%s", clientIP)
    
    // Use Redis pipeline for atomic operations
    pipe := r.client.Pipeline()
    incr := pipe.Incr(ctx, key)
    pipe.Expire(ctx, key, r.config.LoginWindow)
    
    _, err := pipe.Exec(ctx)
    if err != nil {
        r.logger.WithError(err).Error("Redis rate limit check failed")
        return fmt.Errorf("rate limit check failed: %w", err)
    }
    
    count := incr.Val()
    if count > int64(r.config.LoginMaxAttempts) {
        r.logger.WithFields(logrus.Fields{
            "client_ip": clientIP,
            "attempts":  count,
            "limit":     r.config.LoginMaxAttempts,
        }).Warn("Login rate limit exceeded")
        
        return domain.ErrRateLimitExceeded
    }
    
    return nil
}

func (r *RedisRateLimitService) RecordLoginAttempt(ctx context.Context, clientIP string, success bool) {
    key := fmt.Sprintf("rate_limit:login:%s", clientIP)
    
    if success {
        // Clear rate limit on successful login
        r.client.Del(ctx, key)
    }
    
    r.logger.WithFields(logrus.Fields{
        "client_ip": clientIP,
        "success":   success,
        "operation": "login_attempt",
    }).Debug("Login attempt recorded")
}
```

### 3.2 Enhanced JWT Security

Create `internal/security/jwt_service.go`:

```go
package security

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
    "github.com/redis/go-redis/v9"
    "auth-service/internal/domain"
)

type JWTService struct {
    secretKey     []byte
    issuer        string
    audience      string
    blacklist     TokenBlacklist
    accessTokenTTL time.Duration
    refreshTokenTTL time.Duration
}

type TokenBlacklist interface {
    Add(ctx context.Context, token string, expiry time.Time) error
    IsBlacklisted(ctx context.Context, token string) bool
}

type RedisTokenBlacklist struct {
    client *redis.Client
}

func (r *RedisTokenBlacklist) Add(ctx context.Context, token string, expiry time.Time) error {
    key := fmt.Sprintf("blacklist:%s", token)
    ttl := time.Until(expiry)
    return r.client.Set(ctx, key, "1", ttl).Err()
}

func (r *RedisTokenBlacklist) IsBlacklisted(ctx context.Context, token string) bool {
    key := fmt.Sprintf("blacklist:%s", token)
    exists, err := r.client.Exists(ctx, key).Result()
    return err == nil && exists > 0
}

func NewJWTService(secretKey []byte, issuer, audience string, blacklist TokenBlacklist, accessTTL, refreshTTL time.Duration) *JWTService {
    return &JWTService{
        secretKey:       secretKey,
        issuer:          issuer,
        audience:        audience,
        blacklist:       blacklist,
        accessTokenTTL:  accessTTL,
        refreshTokenTTL: refreshTTL,
    }
}

func (j *JWTService) GenerateTokenPair(user *domain.User) (*domain.AuthResponse, error) {
    // Generate access token
    accessToken, err := j.generateAccessToken(user)
    if err != nil {
        return nil, fmt.Errorf("failed to generate access token: %w", err)
    }
    
    // Generate refresh token
    refreshToken, err := j.generateRefreshToken(user)
    if err != nil {
        return nil, fmt.Errorf("failed to generate refresh token: %w", err)
    }
    
    return &domain.AuthResponse{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        TokenType:    "Bearer",
        ExpiresIn:    int(j.accessTokenTTL.Seconds()),
        User:         user.ToUserResponse(),
    }, nil
}

func (j *JWTService) ValidateToken(ctx context.Context, tokenString string) (*domain.User, error) {
    // Check blacklist first
    if j.blacklist.IsBlacklisted(ctx, tokenString) {
        return nil, domain.ErrTokenBlacklisted
    }
    
    token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, j.keyFunc,
        jwt.WithValidMethods([]string{"HS256"}),
        jwt.WithIssuer(j.issuer),
        jwt.WithAudience(j.audience),
        jwt.WithTimeFunc(time.Now),
    )
    
    if err != nil {
        return nil, fmt.Errorf("invalid token: %w", err)
    }
    
    claims, ok := token.Claims.(*JWTClaims)
    if !ok || !token.Valid {
        return nil, domain.ErrInvalidToken
    }
    
    // Additional security checks
    if claims.TokenType != "access" {
        return nil, domain.ErrInvalidTokenType
    }
    
    user := &domain.User{
        ID:       claims.UserID,
        Email:    claims.Email,
        // Other user fields can be loaded from database if needed
    }
    
    return user, nil
}

func (j *JWTService) RevokeToken(ctx context.Context, tokenString string) error {
    // Parse token to get expiry
    token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, j.keyFunc)
    if err != nil {
        return fmt.Errorf("failed to parse token for revocation: %w", err)
    }
    
    claims, ok := token.Claims.(*JWTClaims)
    if !ok {
        return domain.ErrInvalidToken
    }
    
    expiry := time.Unix(claims.ExpiresAt.Unix(), 0)
    return j.blacklist.Add(ctx, tokenString, expiry)
}

func (j *JWTService) keyFunc(token *jwt.Token) (interface{}, error) {
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return j.secretKey, nil
}

func (j *JWTService) generateAccessToken(user *domain.User) (string, error) {
    claims := &JWTClaims{
        UserID:    user.ID,
        Email:     user.Email,
        TokenType: "access",
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   user.ID.String(),
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.accessTokenTTL)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            Issuer:    j.issuer,
            Audience:  []string{j.audience},
            ID:        j.generateJTI(),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(j.secretKey)
}

func (j *JWTService) generateRefreshToken(user *domain.User) (string, error) {
    claims := &JWTClaims{
        UserID:    user.ID,
        Email:     user.Email,
        TokenType: "refresh",
        RegisteredClaims: jwt.RegisteredClaims{
            Subject:   user.ID.String(),
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.refreshTokenTTL)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            NotBefore: jwt.NewNumericDate(time.Now()),
            Issuer:    j.issuer,
            Audience:  []string{j.audience},
            ID:        j.generateJTI(),
        },
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(j.secretKey)
}

func (j *JWTService) generateJTI() string {
    bytes := make([]byte, 16)
    rand.Read(bytes)
    return base64.URLEncoding.EncodeToString(bytes)
}

type JWTClaims struct {
    UserID    uuid.UUID `json:"user_id"`
    Email     string    `json:"email"`
    TokenType string    `json:"token_type"`
    jwt.RegisteredClaims
}
```

## Phase 4: Testing & Validation

### 4.1 Enhanced Unit Tests

Create comprehensive test suites for new components:

```go
// internal/service/redis_rate_limit_service_test.go
func TestRedisRateLimitService_CheckLoginAttempts(t *testing.T) {
    tests := []struct {
        name           string
        clientIP       string
        attempts       int
        expectedError  error
    }{
        {
            name:          "within_limit",
            clientIP:      "192.168.1.1",
            attempts:      3,
            expectedError: nil,
        },
        {
            name:          "exceeds_limit",
            clientIP:      "192.168.1.2",
            attempts:      6,
            expectedError: domain.ErrRateLimitExceeded,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### 4.2 Integration Tests

Add comprehensive integration tests:

```go
// test/integration/auth_flow_test.go
func TestCompleteAuthenticationFlow(t *testing.T) {
    // Test complete user journey:
    // 1. Register new user
    // 2. Login with credentials
    // 3. Use access token for protected endpoint
    // 4. Refresh token
    // 5. Change password
    // 6. Logout
}
```

### 4.3 Load Testing

Create load testing scripts:

```bash
#!/bin/bash
# scripts/load_test.sh

echo "Running authentication load tests..."

# Test registration endpoint
ab -n 1000 -c 10 -p register_payload.json -T application/json http://localhost:6910/api/v1/auth/register

# Test login endpoint
ab -n 5000 -c 50 -p login_payload.json -T application/json http://localhost:6910/api/v1/auth/login

# Test token refresh
ab -n 3000 -c 30 -p refresh_payload.json -T application/json http://localhost:6910/api/v1/auth/refresh

echo "Load testing completed"
```

## Implementation Timeline

### Week 1: Quick Wins
- [ ] Remove dead code
- [ ] Add database connection pooling
- [ ] Implement centralized error mapping
- [ ] Create input sanitization utilities

### Week 2: File Restructuring
- [ ] Split large service files
- [ ] Split large handler files
- [ ] Consolidate password operations
- [ ] Update imports and dependencies

### Week 3: Architecture Improvements
- [ ] Implement interface segregation
- [ ] Create generic repository pattern
- [ ] Update dependency injection
- [ ] Add comprehensive tests

### Week 4: Performance & Security
- [ ] Implement Redis rate limiting
- [ ] Add JWT security enhancements
- [ ] Optimize database queries
- [ ] Add load testing

### Week 5: Testing & Documentation
- [ ] Complete test coverage
- [ ] Update documentation
- [ ] Performance benchmarking
- [ ] Deployment validation

This plan provides a systematic approach to improving the codebase while maintaining backward compatibility and minimizing disruption to existing functionality.
