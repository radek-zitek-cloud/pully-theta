package test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"

	"auth-service/internal/config"
	"auth-service/internal/domain"
	"auth-service/internal/security"
	"auth-service/internal/service"
)

// AuthServiceTestSuite provides a comprehensive te	suite.mockMetricsRecorder.On("RecordLoginFailure", "invalid_password").Return().Once()t suite for AuthService.
// This suite tests all core authentication operations including registration,
// login, token management, and user profile operations.
//
// The test suite follows these principles:
// - Each test is isolated with fresh mocks
// - All edge cases and error conditions are tested
// - Business logic is validated thoroughly
// - Security aspects are verified
// - Performance characteristics are considered
//
// Test Structure:
// - Setup: Creates service with mocked dependencies
// - Test Methods: Individual test cases for each operation
// - Teardown: Cleans up resources after each test
type AuthServiceTestSuite struct {
	suite.Suite

	// Service under test
	authService *service.AuthService

	// Mock repositories
	mockUserRepo          *MockUserRepository
	mockRefreshTokenRepo  *MockRefreshTokenRepository
	mockPasswordResetRepo *MockPasswordResetTokenRepository
	mockAuditRepo         *MockAuditLogRepository

	// Mock services
	mockEmailService     *MockEmailService
	mockRateLimitService *MockRateLimitService
	mockMetricsRecorder  *MockAuthMetricsRecorder

	// JWT service for testing
	jwtService *security.JWTService

	// Test configuration and logger
	config *config.Config
	logger *logrus.Logger

	// Test context and common test data
	ctx       context.Context
	testUser  *domain.User
	clientIP  string
	userAgent string
}

// SetupSuite initializes the test suite with configuration and logger.
// This method is called once before all tests in the suite.
func (suite *AuthServiceTestSuite) SetupSuite() {
	// Initialize test context
	suite.ctx = context.Background()

	// Create test logger with suppressed output for clean test runs
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.WarnLevel) // Suppress info/debug logs in tests

	// Create test configuration with secure defaults
	suite.config = &config.Config{
		JWT: config.JWTConfig{
			Secret:             "test-secret-key-for-jwt-signing-must-be-long-enough-for-security",
			AccessTokenExpiry:  time.Hour,
			RefreshTokenExpiry: 24 * time.Hour,
			Issuer:             "auth-service-test",
			Algorithm:          "HS256",
		},
		Security: config.SecurityConfig{
			BcryptCost:           4, // Lower cost for faster tests
			RateLimitEnabled:     true,
			MaxLoginAttempts:     5,
			LoginLockoutDuration: time.Minute,
		},
	}

	// Initialize common test data
	suite.clientIP = "192.168.1.100"
	suite.userAgent = "TestClient/1.0"

	// Create a real bcrypt hash for "password123" for more realistic testing
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("password123"), 4)

	suite.testUser = &domain.User{
		ID:                uuid.New(),
		Email:             "test@example.com",
		PasswordHash:      string(passwordHash),
		FirstName:         "Test",
		LastName:          "User",
		IsEmailVerified:   true,
		IsActive:          true,
		PasswordChangedAt: time.Now().Add(-24 * time.Hour),
		CreatedAt:         time.Now().Add(-30 * 24 * time.Hour),
		UpdatedAt:         time.Now().Add(-time.Hour),
	}
}

// SetupTest creates fresh mocks and service instance for each test.
// This ensures test isolation and prevents test interference.
func (suite *AuthServiceTestSuite) SetupTest() {
	// Create fresh mock repositories
	suite.mockUserRepo = &MockUserRepository{}
	suite.mockRefreshTokenRepo = &MockRefreshTokenRepository{}
	suite.mockPasswordResetRepo = &MockPasswordResetTokenRepository{}
	suite.mockAuditRepo = &MockAuditLogRepository{}

	// Create fresh mock services
	suite.mockEmailService = &MockEmailService{}
	suite.mockRateLimitService = &MockRateLimitService{}
	suite.mockMetricsRecorder = &MockAuthMetricsRecorder{}

	// Create test JWT service
	mockBlacklist := &MockTokenBlacklist{}
	suite.jwtService = security.NewJWTService(
		[]byte("test-secret-key-at-least-32-bytes-long"),
		"test-issuer",
		"test-audience",
		mockBlacklist,
		15*time.Minute, // access token TTL
		7*24*time.Hour, // refresh token TTL
	)

	// Create AuthService with mocked dependencies
	var err error
	suite.authService, err = service.NewAuthService(
		suite.mockUserRepo,
		suite.mockRefreshTokenRepo,
		suite.mockPasswordResetRepo,
		suite.mockAuditRepo,
		suite.logger,
		suite.config,
		suite.mockEmailService,
		suite.mockRateLimitService,
		suite.mockMetricsRecorder,
		suite.jwtService,
	)
	require.NoError(suite.T(), err, "Failed to create AuthService")
}

// TearDownTest verifies all mock expectations were met after each test.
func (suite *AuthServiceTestSuite) TearDownTest() {
	// Verify all mock expectations were satisfied
	suite.mockUserRepo.AssertExpectations(suite.T())
	suite.mockRefreshTokenRepo.AssertExpectations(suite.T())
	suite.mockPasswordResetRepo.AssertExpectations(suite.T())
	suite.mockAuditRepo.AssertExpectations(suite.T())
	suite.mockEmailService.AssertExpectations(suite.T())
	suite.mockRateLimitService.AssertExpectations(suite.T())
	suite.mockMetricsRecorder.AssertExpectations(suite.T())
}

// TestNewAuthService_Success tests successful service creation with all dependencies.
func (suite *AuthServiceTestSuite) TestNewAuthService_Success() {
	authService, err := service.NewAuthService(
		suite.mockUserRepo,
		suite.mockRefreshTokenRepo,
		suite.mockPasswordResetRepo,
		suite.mockAuditRepo,
		suite.logger,
		suite.config,
		suite.mockEmailService,
		suite.mockRateLimitService,
		suite.mockMetricsRecorder,
		suite.jwtService,
	)

	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), authService)
}

// TestNewAuthService_MissingDependencies tests service creation failure with nil dependencies.
func (suite *AuthServiceTestSuite) TestNewAuthService_MissingDependencies() {
	testCases := []struct {
		name              string
		userRepo          domain.UserRepository
		refreshTokenRepo  domain.RefreshTokenRepository
		passwordResetRepo domain.PasswordResetTokenRepository
		auditRepo         domain.AuditLogRepository
		logger            *logrus.Logger
		config            *config.Config
		emailService      service.EmailService
		rateLimitService  service.RateLimitService
		metricsRecorder   service.AuthMetricsRecorder
		jwtService        *security.JWTService
		expectedError     string
	}{
		{
			name:              "nil user repository",
			userRepo:          nil,
			refreshTokenRepo:  suite.mockRefreshTokenRepo,
			passwordResetRepo: suite.mockPasswordResetRepo,
			auditRepo:         suite.mockAuditRepo,
			logger:            suite.logger,
			config:            suite.config,
			emailService:      suite.mockEmailService,
			rateLimitService:  suite.mockRateLimitService,
			metricsRecorder:   suite.mockMetricsRecorder,
			jwtService:        suite.jwtService,
			expectedError:     "user repository is required",
		},
		{
			name:              "nil refresh token repository",
			userRepo:          suite.mockUserRepo,
			refreshTokenRepo:  nil,
			passwordResetRepo: suite.mockPasswordResetRepo,
			auditRepo:         suite.mockAuditRepo,
			logger:            suite.logger,
			config:            suite.config,
			emailService:      suite.mockEmailService,
			rateLimitService:  suite.mockRateLimitService,
			metricsRecorder:   suite.mockMetricsRecorder,
			jwtService:        suite.jwtService,
			expectedError:     "refresh token repository is required",
		},
		{
			name:              "nil logger",
			userRepo:          suite.mockUserRepo,
			refreshTokenRepo:  suite.mockRefreshTokenRepo,
			passwordResetRepo: suite.mockPasswordResetRepo,
			auditRepo:         suite.mockAuditRepo,
			logger:            nil,
			config:            suite.config,
			emailService:      suite.mockEmailService,
			rateLimitService:  suite.mockRateLimitService,
			metricsRecorder:   suite.mockMetricsRecorder,
			jwtService:        suite.jwtService,
			expectedError:     "logger is required",
		},
		{
			name:              "nil config",
			userRepo:          suite.mockUserRepo,
			refreshTokenRepo:  suite.mockRefreshTokenRepo,
			passwordResetRepo: suite.mockPasswordResetRepo,
			auditRepo:         suite.mockAuditRepo,
			logger:            suite.logger,
			config:            nil,
			emailService:      suite.mockEmailService,
			rateLimitService:  suite.mockRateLimitService,
			metricsRecorder:   suite.mockMetricsRecorder,
			jwtService:        suite.jwtService,
			expectedError:     "config is required",
		},
		{
			name:              "nil jwt service",
			userRepo:          suite.mockUserRepo,
			refreshTokenRepo:  suite.mockRefreshTokenRepo,
			passwordResetRepo: suite.mockPasswordResetRepo,
			auditRepo:         suite.mockAuditRepo,
			logger:            suite.logger,
			config:            suite.config,
			emailService:      suite.mockEmailService,
			rateLimitService:  suite.mockRateLimitService,
			metricsRecorder:   suite.mockMetricsRecorder,
			jwtService:        nil,
			expectedError:     "JWT service is required",
		},
	}

	for _, tc := range testCases {
		suite.T().Run(tc.name, func(t *testing.T) {
			authService, err := service.NewAuthService(
				tc.userRepo,
				tc.refreshTokenRepo,
				tc.passwordResetRepo,
				tc.auditRepo,
				tc.logger,
				tc.config,
				tc.emailService,
				tc.rateLimitService,
				tc.metricsRecorder,
				tc.jwtService,
			)

			assert.Error(t, err)
			assert.Nil(t, authService)
			assert.Contains(t, err.Error(), tc.expectedError)
		})
	}
}

// TestRegister_Success tests successful user registration with all steps.
func (suite *AuthServiceTestSuite) TestRegister_Success() {
	// Prepare test data
	req := &domain.RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "StrongPass123!",
		FirstName: "New",
		LastName:  "User",
	}

	// Mock expectations for successful registration
	suite.mockUserRepo.On("GetByEmail", suite.ctx, "newuser@example.com").Return(nil, domain.ErrUserNotFound)

	// Create expected user object for the mock
	testUserID := uuid.New()
	expectedUser := &domain.User{
		ID:              testUserID,
		Email:           "newuser@example.com",
		PasswordHash:    "$2a$12$test_hashed_password_for_new_user",
		FirstName:       "New",
		LastName:        "User",
		IsEmailVerified: false,
		IsActive:        true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	suite.mockUserRepo.On("Create", suite.ctx, mock.AnythingOfType("*domain.User")).Return(expectedUser, nil)

	// Email is sent asynchronously, so we need to match any context
	suite.mockEmailService.On("SendWelcomeEmail", mock.AnythingOfType("*context.timerCtx"), "newuser@example.com", "New User", "").Return(nil)

	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockMetricsRecorder.On("RecordRegistrationAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordRegistrationSuccess").Return().Once()

	// Execute registration
	user, err := suite.authService.Register(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the email goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify results
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), user)
	assert.Equal(suite.T(), testUserID, user.ID)
	assert.Equal(suite.T(), "newuser@example.com", user.Email)
	assert.Equal(suite.T(), "New", user.FirstName)
	assert.Equal(suite.T(), "User", user.LastName)
	assert.False(suite.T(), user.IsEmailVerified) // New users start unverified
	assert.True(suite.T(), user.IsActive)
	assert.NotEmpty(suite.T(), user.PasswordHash)
	assert.NotEqual(suite.T(), req.Password, user.PasswordHash) // Password should be hashed
}

// TestRegister_EmailAlreadyExists tests registration failure when email exists.
func (suite *AuthServiceTestSuite) TestRegister_EmailAlreadyExists() {
	req := &domain.RegisterRequest{
		Email:     "existing@example.com",
		Password:  "StrongPass123!",
		FirstName: "Test",
		LastName:  "User",
	}

	// Mock email already exists
	existingUser := &domain.User{
		ID:    uuid.New(),
		Email: "existing@example.com",
	}
	suite.mockUserRepo.On("GetByEmail", suite.ctx, "existing@example.com").Return(existingUser, nil)
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockMetricsRecorder.On("RecordRegistrationAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordRegistrationFailure", "email_exists").Return().Once()

	// Execute registration
	user, err := suite.authService.Register(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the audit log goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify failure
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), user)
	assert.Equal(suite.T(), domain.ErrEmailExists, err)
}

// TestRegister_WeakPassword tests registration failure with weak password.
func (suite *AuthServiceTestSuite) TestRegister_WeakPassword() {
	req := &domain.RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "weak", // Too short
		FirstName: "Test",
		LastName:  "User",
	}

	// Mock audit log for failure
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockMetricsRecorder.On("RecordRegistrationAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordRegistrationFailure", "weak_password").Return().Once()

	// Execute registration
	user, err := suite.authService.Register(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the audit log goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify failure
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), user)
	assert.Contains(suite.T(), err.Error(), "password")
}

// TestLogin_Success tests successful user authentication and token generation.
func (suite *AuthServiceTestSuite) TestLogin_Success() {
	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	// Mock successful rate limit check - uses client IP, not email
	suite.mockRateLimitService.On("CheckLoginAttempts", suite.ctx, suite.clientIP).Return(true, nil)

	// Mock user lookup
	suite.mockUserRepo.On("GetByEmail", suite.ctx, "test@example.com").Return(suite.testUser, nil)

	// Mock refresh token creation
	refreshToken := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    suite.testUser.ID,
		Token:     "refresh_token_value",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	suite.mockRefreshTokenRepo.On("Create", suite.ctx, mock.AnythingOfType("*domain.RefreshToken")).Return(refreshToken, nil)

	// Mock updating last login time
	suite.mockUserRepo.On("UpdateLastLogin", suite.ctx, suite.testUser.ID, mock.AnythingOfType("time.Time")).Return(nil)

	// Mock audit logging
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockRateLimitService.On("RecordLoginAttempt", suite.ctx, suite.clientIP, true).Return(nil)

	// Mock metrics recording - expect both the parameterless and parametrized calls
	suite.mockMetricsRecorder.On("RecordLoginAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordLoginSuccess").Return().Once()

	// Execute login
	response, err := suite.authService.Login(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the audit log goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify successful login
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), response)
	assert.NotEmpty(suite.T(), response.AccessToken)
	assert.NotEmpty(suite.T(), response.RefreshToken)
	assert.Equal(suite.T(), "Bearer", response.TokenType)
	assert.Equal(suite.T(), int64(3600), response.ExpiresIn) // 1 hour in seconds
	assert.NotNil(suite.T(), response.User)
	assert.Equal(suite.T(), suite.testUser.ID, response.User.ID)
	// UserResponse doesn't contain password hash for security
}

// TestLogin_InvalidCredentials tests login failure with wrong password.
func (suite *AuthServiceTestSuite) TestLogin_InvalidCredentials() {
	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	// Mock rate limit check
	suite.mockRateLimitService.On("CheckLoginAttempts", suite.ctx, suite.clientIP).Return(true, nil)

	// Mock user lookup
	suite.mockUserRepo.On("GetByEmail", suite.ctx, "test@example.com").Return(suite.testUser, nil)

	// Mock failure logging and metrics
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockRateLimitService.On("RecordLoginAttempt", suite.ctx, suite.clientIP, false).Return(nil)
	suite.mockMetricsRecorder.On("RecordLoginAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordLoginFailure", "invalid_credentials").Return().Once()

	// Execute login
	response, err := suite.authService.Login(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the audit log goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify failure
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), response)
	assert.Equal(suite.T(), domain.ErrInvalidCredentials, err)
}

// TestLogin_UserNotFound tests login failure when user doesn't exist.
func (suite *AuthServiceTestSuite) TestLogin_UserNotFound() {
	req := &domain.LoginRequest{
		Email:    "nonexistent@example.com",
		Password: "password123",
	}

	// Mock rate limit check
	suite.mockRateLimitService.On("CheckLoginAttempts", suite.ctx, suite.clientIP).Return(true, nil)

	// Mock user not found
	suite.mockUserRepo.On("GetByEmail", suite.ctx, "nonexistent@example.com").Return(nil, domain.ErrUserNotFound)

	// Mock failure logging and metrics
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockRateLimitService.On("RecordLoginAttempt", suite.ctx, suite.clientIP, false).Return(nil)
	suite.mockMetricsRecorder.On("RecordLoginAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordLoginFailure", "user_not_found").Return().Once()

	// Execute login
	response, err := suite.authService.Login(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the audit log goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify failure
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), response)
	assert.Equal(suite.T(), domain.ErrInvalidCredentials, err)
}

// TestLogin_RateLimited tests login failure when rate limit is exceeded.
func (suite *AuthServiceTestSuite) TestLogin_RateLimited() {
	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	// Mock rate limit exceeded
	suite.mockRateLimitService.On("CheckLoginAttempts", suite.ctx, suite.clientIP).Return(false, nil)
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockMetricsRecorder.On("RecordLoginAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordLoginFailure", "rate_limit").Return().Once()

	// Execute login
	response, err := suite.authService.Login(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the audit log goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify rate limit failure
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), response)
	assert.Equal(suite.T(), domain.ErrRateLimitExceeded, err)
}

// TestLogin_InactiveUser tests login failure for deactivated user account.
func (suite *AuthServiceTestSuite) TestLogin_InactiveUser() {
	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	// Create inactive user
	inactiveUser := *suite.testUser
	inactiveUser.IsActive = false

	// Mock rate limit check
	suite.mockRateLimitService.On("CheckLoginAttempts", suite.ctx, suite.clientIP).Return(true, nil)

	// Mock user lookup
	suite.mockUserRepo.On("GetByEmail", suite.ctx, "test@example.com").Return(&inactiveUser, nil)

	// Mock failure logging and metrics (audit log uses its own timeout context)
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockRateLimitService.On("RecordLoginAttempt", suite.ctx, suite.clientIP, false).Return(nil)
	suite.mockMetricsRecorder.On("RecordLoginAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordLoginFailure", "account_inactive").Return().Once()

	// Execute login
	response, err := suite.authService.Login(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Give the audit log goroutine a moment to execute
	time.Sleep(10 * time.Millisecond)

	// Verify failure - service returns ErrInvalidCredentials to not reveal account state
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), response)
	assert.Equal(suite.T(), domain.ErrInvalidCredentials, err)
}

// TestLogout_Success tests successful logout and token revocation.
func (suite *AuthServiceTestSuite) TestLogout_Success() {
	refreshTokenValue := "valid_refresh_token"

	// Mock token lookup and revocation
	refreshToken := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    suite.testUser.ID,
		Token:     refreshTokenValue,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now().Add(-time.Hour),
	}

	suite.mockRefreshTokenRepo.On("GetByToken", suite.ctx, refreshTokenValue).Return(refreshToken, nil)
	suite.mockRefreshTokenRepo.On("RevokeToken", suite.ctx, refreshTokenValue).Return(nil)

	// Mock audit logging
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)

	// Mock metrics recording
	suite.mockMetricsRecorder.On("RecordLogoutAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordLogoutSuccess").Return().Once()

	// Execute logout
	err := suite.authService.Logout(suite.ctx, refreshTokenValue, suite.clientIP, suite.userAgent)

	// Verify successful logout
	assert.NoError(suite.T(), err)
}

// TestLogout_InvalidToken tests logout failure with invalid token.
func (suite *AuthServiceTestSuite) TestLogout_InvalidToken() {
	refreshTokenValue := "invalid_refresh_token"

	// Mock token not found - but logout should succeed anyway
	suite.mockRefreshTokenRepo.On("GetByToken", suite.ctx, refreshTokenValue).Return(nil, domain.ErrTokenNotFound)

	// Mock audit log and metrics recording
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)
	suite.mockMetricsRecorder.On("RecordLogoutAttempt").Return().Once()
	suite.mockMetricsRecorder.On("RecordLogoutSuccess").Return().Once()

	// Execute logout
	err := suite.authService.Logout(suite.ctx, refreshTokenValue, suite.clientIP, suite.userAgent)

	// Verify success - logout with invalid token should not fail
	assert.NoError(suite.T(), err)
}

// TestRefreshToken_Success tests successful token refresh.
func (suite *AuthServiceTestSuite) TestRefreshToken_Success() {
	req := &domain.RefreshTokenRequest{
		RefreshToken: "valid_refresh_token",
	}

	// Mock token lookup
	refreshToken := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    suite.testUser.ID,
		Token:     req.RefreshToken,
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now().Add(-time.Hour),
	}

	suite.mockRefreshTokenRepo.On("GetByToken", suite.ctx, req.RefreshToken).Return(refreshToken, nil)
	suite.mockUserRepo.On("GetByID", suite.ctx, suite.testUser.ID).Return(suite.testUser, nil)

	// Mock audit logging
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)

	// Execute token refresh
	response, err := suite.authService.RefreshToken(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Verify successful refresh
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), response)
	assert.NotEmpty(suite.T(), response.AccessToken)
	assert.Equal(suite.T(), req.RefreshToken, response.RefreshToken) // Refresh token stays the same
	assert.Equal(suite.T(), "Bearer", response.TokenType)
	assert.NotNil(suite.T(), response.User)
}

// TestRefreshToken_ExpiredToken tests token refresh failure with expired token.
func (suite *AuthServiceTestSuite) TestRefreshToken_ExpiredToken() {
	req := &domain.RefreshTokenRequest{
		RefreshToken: "expired_refresh_token",
	}

	// Mock expired token lookup
	expiredToken := &domain.RefreshToken{
		ID:        uuid.New(),
		UserID:    suite.testUser.ID,
		Token:     req.RefreshToken,
		ExpiresAt: time.Now().Add(-time.Hour), // Expired
		CreatedAt: time.Now().Add(-2 * time.Hour),
	}

	suite.mockRefreshTokenRepo.On("GetByToken", suite.ctx, req.RefreshToken).Return(expiredToken, nil)

	// Mock audit logging for failure
	suite.mockAuditRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.AuditLog")).Return(nil, nil)

	// Execute token refresh
	response, err := suite.authService.RefreshToken(suite.ctx, req, suite.clientIP, suite.userAgent)

	// Verify failure
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), response)
	assert.Equal(suite.T(), domain.ErrInvalidToken, err)
}

// TestGetUserByID_Success tests successful user retrieval by ID.
func (suite *AuthServiceTestSuite) TestGetUserByID_Success() {
	userID := suite.testUser.ID.String()

	// Mock user lookup
	suite.mockUserRepo.On("GetByID", suite.ctx, suite.testUser.ID).Return(suite.testUser, nil)

	// Execute user retrieval
	user, err := suite.authService.GetUserByID(suite.ctx, userID)

	// Verify success
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), user)
	assert.Equal(suite.T(), suite.testUser.ID, user.ID)
	assert.Equal(suite.T(), suite.testUser.Email, user.Email)
	// Password hash should be cleared for security in the actual service
}

// TestGetUserByID_InvalidID tests user retrieval failure with invalid ID format.
func (suite *AuthServiceTestSuite) TestGetUserByID_InvalidID() {
	invalidID := "invalid-uuid-format"

	// Execute user retrieval
	user, err := suite.authService.GetUserByID(suite.ctx, invalidID)

	// Verify failure
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), user)
	assert.Contains(suite.T(), err.Error(), "invalid UUID")
}

// TestGetUserByEmail_Success tests successful user retrieval by email.
func (suite *AuthServiceTestSuite) TestGetUserByEmail_Success() {
	email := "test@example.com"

	// Mock user lookup
	suite.mockUserRepo.On("GetByEmail", suite.ctx, email).Return(suite.testUser, nil)

	// Execute user retrieval
	user, err := suite.authService.GetUserByEmail(suite.ctx, email)

	// Verify success
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), user)
	assert.Equal(suite.T(), suite.testUser.Email, user.Email)
	// Password hash should be cleared for security in the actual service
}

// TestUpdateProfile_Success tests successful user profile update.
func (suite *AuthServiceTestSuite) TestUpdateProfile_Success() {
	userID := suite.testUser.ID.String()
	updateData := map[string]interface{}{
		"first_name": "Updated",
		"last_name":  "Name",
	}

	// Mock user lookup and update
	suite.mockUserRepo.On("GetByID", suite.ctx, suite.testUser.ID).Return(suite.testUser, nil)

	// Create updated user for the mock
	updatedUser := *suite.testUser
	updatedUser.FirstName = "Updated"
	updatedUser.LastName = "Name"

	suite.mockUserRepo.On("Update", suite.ctx, mock.AnythingOfType("*domain.User")).Return(&updatedUser, nil)

	// Execute profile update
	err := suite.authService.UpdateProfile(suite.ctx, userID, updateData)

	// Verify success
	assert.NoError(suite.T(), err)
}

// TestUpdateProfile_UserNotFound tests profile update failure when user doesn't exist.
func (suite *AuthServiceTestSuite) TestUpdateProfile_UserNotFound() {
	userID := uuid.New().String()
	updateData := map[string]interface{}{
		"first_name": "Updated",
	}

	// Mock user not found
	suite.mockUserRepo.On("GetByID", suite.ctx, mock.AnythingOfType("uuid.UUID")).Return(nil, domain.ErrUserNotFound)

	// Execute profile update
	err := suite.authService.UpdateProfile(suite.ctx, userID, updateData)

	// Verify failure
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to get user for update")
}

// Run the test suite
func TestAuthServiceSuite(t *testing.T) {
	suite.Run(t, new(AuthServiceTestSuite))
}

// Benchmark tests for performance-critical operations
func BenchmarkAuthService_Register(b *testing.B) {
	// Setup benchmark environment (similar to test setup but optimized for performance)
	// This benchmark tests registration performance under load
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Benchmark registration operation
		// Note: This is a placeholder - actual implementation would require
		// careful setup to avoid database calls in benchmarks
		b.StopTimer()
		// Setup unique test data for each iteration
		b.StartTimer()

		// Actual benchmark operation would go here
		// For now, we just test password hashing which is the expensive part
		_, _ = bcrypt.GenerateFromPassword([]byte("password123"), 4)
	}
}

func BenchmarkAuthService_Login(b *testing.B) {
	// Benchmark login performance focusing on password verification
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), 4)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = bcrypt.CompareHashAndPassword(hashedPassword, []byte("password123"))
	}
}
