package test

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"auth-service/internal/domain"
)

// MockUserRepository provides a mock implementation of domain.UserRepository.
// This mock is used in unit tests to isolate the AuthService from database dependencies.
//
// The mock implements all methods of the UserRepository interface and allows
// setting expectations for method calls and return values during testing.
type MockUserRepository struct {
	mock.Mock
}

// Create mocks the user creation operation.
func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// GetByID mocks user retrieval by ID.
func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// GetByEmail mocks user retrieval by email address.
func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// Update mocks user profile update operation.
func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	args := m.Called(ctx, user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// Delete mocks user deletion (soft delete) operation.
func (m *MockUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// UpdateLastLogin mocks updating user's last login timestamp.
func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, loginTime time.Time) error {
	args := m.Called(ctx, id, loginTime)
	return args.Error(0)
}

// List mocks user listing with pagination.
func (m *MockUserRepository) List(ctx context.Context, offset, limit int) ([]*domain.User, int64, error) {
	args := m.Called(ctx, offset, limit)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*domain.User), args.Get(1).(int64), args.Error(2)
}

// MockRefreshTokenRepository provides a mock implementation of domain.RefreshTokenRepository.
type MockRefreshTokenRepository struct {
	mock.Mock
}

// Create mocks refresh token creation.
func (m *MockRefreshTokenRepository) Create(ctx context.Context, token *domain.RefreshToken) (*domain.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RefreshToken), args.Error(1)
}

// GetByToken mocks refresh token retrieval by token value.
func (m *MockRefreshTokenRepository) GetByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.RefreshToken), args.Error(1)
}

// RevokeToken mocks refresh token revocation.
func (m *MockRefreshTokenRepository) RevokeToken(ctx context.Context, tokenString string) error {
	args := m.Called(ctx, tokenString)
	return args.Error(0)
}

// RevokeAllUserTokens mocks revocation of all user's refresh tokens.
func (m *MockRefreshTokenRepository) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// CleanupExpired mocks cleanup of expired refresh tokens.
func (m *MockRefreshTokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// GetUserTokens mocks retrieval of all user's refresh tokens.
func (m *MockRefreshTokenRepository) GetUserTokens(ctx context.Context, userID uuid.UUID) ([]*domain.RefreshToken, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*domain.RefreshToken), args.Error(1)
}

// MockPasswordResetTokenRepository provides a mock implementation of domain.PasswordResetTokenRepository.
type MockPasswordResetTokenRepository struct {
	mock.Mock
}

// Create mocks password reset token creation.
func (m *MockPasswordResetTokenRepository) Create(ctx context.Context, token *domain.PasswordResetToken) (*domain.PasswordResetToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PasswordResetToken), args.Error(1)
}

// GetByToken mocks password reset token retrieval by token value.
func (m *MockPasswordResetTokenRepository) GetByToken(ctx context.Context, token string) (*domain.PasswordResetToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.PasswordResetToken), args.Error(1)
}

// MarkAsUsed mocks marking password reset token as used.
func (m *MockPasswordResetTokenRepository) MarkAsUsed(ctx context.Context, tokenString string) error {
	args := m.Called(ctx, tokenString)
	return args.Error(0)
}

// CleanupExpired mocks cleanup of expired password reset tokens.
func (m *MockPasswordResetTokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// InvalidateUserTokens mocks invalidation of all user's password reset tokens.
func (m *MockPasswordResetTokenRepository) InvalidateUserTokens(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// MockAuditLogRepository provides a mock implementation of domain.AuditLogRepository.
type MockAuditLogRepository struct {
	mock.Mock
}

// Create mocks audit log creation.
func (m *MockAuditLogRepository) Create(ctx context.Context, auditLog *domain.AuditLog) (*domain.AuditLog, error) {
	args := m.Called(ctx, auditLog)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.AuditLog), args.Error(1)
}

// GetByUserID mocks audit log retrieval by user ID with pagination.
func (m *MockAuditLogRepository) GetByUserID(ctx context.Context, userID uuid.UUID, offset, limit int) ([]*domain.AuditLog, int64, error) {
	args := m.Called(ctx, userID, offset, limit)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*domain.AuditLog), args.Get(1).(int64), args.Error(2)
}

// GetByEventType mocks audit log retrieval by event type with pagination.
func (m *MockAuditLogRepository) GetByEventType(ctx context.Context, eventType string, offset, limit int) ([]*domain.AuditLog, int64, error) {
	args := m.Called(ctx, eventType, offset, limit)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]*domain.AuditLog), args.Get(1).(int64), args.Error(2)
}

// CleanupOld mocks cleanup of old audit logs.
func (m *MockAuditLogRepository) CleanupOld(ctx context.Context, olderThan time.Duration) (int64, error) {
	args := m.Called(ctx, olderThan)
	return args.Get(0).(int64), args.Error(1)
}

// MockEmailService provides a mock implementation of service.EmailService.
type MockEmailService struct {
	mock.Mock
}

// SendPasswordResetEmail mocks sending password reset email.
func (m *MockEmailService) SendPasswordResetEmail(ctx context.Context, email, resetToken, userName string) error {
	args := m.Called(ctx, email, resetToken, userName)
	return args.Error(0)
}

// SendWelcomeEmail mocks sending welcome email to new users.
func (m *MockEmailService) SendWelcomeEmail(ctx context.Context, email, userName, verificationToken string) error {
	args := m.Called(ctx, email, userName, verificationToken)
	return args.Error(0)
}

// MockRateLimitService provides a mock implementation of service.RateLimitService.
type MockRateLimitService struct {
	mock.Mock
}

// CheckLoginAttempts mocks rate limit checking for login attempts.
func (m *MockRateLimitService) CheckLoginAttempts(ctx context.Context, identifier string) (bool, error) {
	args := m.Called(ctx, identifier)
	return args.Bool(0), args.Error(1)
}

// RecordLoginAttempt mocks recording a login attempt for rate limiting.
func (m *MockRateLimitService) RecordLoginAttempt(ctx context.Context, identifier string, success bool) error {
	args := m.Called(ctx, identifier, success)
	return args.Error(0)
}

// CheckPasswordResetAttempts mocks rate limit checking for password reset attempts.
// This method validates whether the user/IP has exceeded the allowed number of
// password reset requests within the configured time window.
//
// Parameters:
//   - ctx: Request context for cancellation and timeout handling
//   - identifier: The identifier to check (email or IP address)
//
// Returns:
//   - bool: true if within rate limits, false if rate limit exceeded
//   - error: Any error that occurred during the rate limit check
func (m *MockRateLimitService) CheckPasswordResetAttempts(ctx context.Context, identifier string) (bool, error) {
	args := m.Called(ctx, identifier)
	return args.Bool(0), args.Error(1)
}

// RecordPasswordResetAttempt mocks recording a password reset attempt for rate limiting.
// This method increments the password reset attempt counter for the given identifier.
//
// Parameters:
//   - ctx: Request context for cancellation and timeout handling
//   - identifier: The identifier to record attempt for (email or IP address)
//
// Returns:
//   - error: Any error that occurred during the recording operation
func (m *MockRateLimitService) RecordPasswordResetAttempt(ctx context.Context, identifier string) error {
	args := m.Called(ctx, identifier)
	return args.Error(0)
}

// GetStats mocks returning statistics about the rate limiting service.
// Returns a map containing configuration, performance metrics, and operational status.
func (m *MockRateLimitService) GetStats() map[string]interface{} {
	args := m.Called()
	return args.Get(0).(map[string]interface{})
}

// HealthCheck mocks verifying that the rate limiting service is healthy and operational.
// This includes checking connectivity to any external dependencies (e.g., Redis).
func (m *MockRateLimitService) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockAuthMetricsRecorder provides a mock implementation of service.AuthMetricsRecorder.
// This mock implements all methods of the AuthMetricsRecorder interface for testing
// authentication and authorization metrics recording operations.
type MockAuthMetricsRecorder struct {
	mock.Mock
}

// RecordAuthOperation mocks recording authentication operation metrics.
func (m *MockAuthMetricsRecorder) RecordAuthOperation(operation, result string) {
	m.Called(operation, result)
}

// RecordTokenOperation mocks recording token operation metrics.
func (m *MockAuthMetricsRecorder) RecordTokenOperation(operation, tokenType, result string) {
	m.Called(operation, tokenType, result)
}

// SetActiveUsers mocks setting the active users gauge metric.
func (m *MockAuthMetricsRecorder) SetActiveUsers(count float64) {
	m.Called(count)
}

// RecordRegistrationAttempt mocks recording registration attempt metrics.
func (m *MockAuthMetricsRecorder) RecordRegistrationAttempt() {
	m.Called()
}

// RecordRegistrationSuccess mocks recording successful registration metrics.
func (m *MockAuthMetricsRecorder) RecordRegistrationSuccess() {
	m.Called()
}

// RecordRegistrationFailure mocks recording failed registration metrics.
func (m *MockAuthMetricsRecorder) RecordRegistrationFailure(reason string) {
	m.Called(reason)
}

// RecordLoginAttempt mocks recording login attempt metrics.
func (m *MockAuthMetricsRecorder) RecordLoginAttempt() {
	m.Called()
}

// RecordLoginSuccess mocks recording successful login metrics.
func (m *MockAuthMetricsRecorder) RecordLoginSuccess() {
	m.Called()
}

// RecordLoginFailure mocks recording failed login metrics.
func (m *MockAuthMetricsRecorder) RecordLoginFailure(reason string) {
	m.Called(reason)
}

// RecordLogoutAttempt mocks recording logout attempt metrics.
func (m *MockAuthMetricsRecorder) RecordLogoutAttempt() {
	m.Called()
}

// RecordLogoutSuccess mocks recording successful logout metrics.
func (m *MockAuthMetricsRecorder) RecordLogoutSuccess() {
	m.Called()
}

// RecordLogoutFailure mocks recording failed logout metrics.
func (m *MockAuthMetricsRecorder) RecordLogoutFailure(reason string) {
	m.Called(reason)
}
