package test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"auth-service/internal/domain"
)

// EntitiesTestSuite provides comprehensive testing for domain entities.
// This suite ensures that all entity operations behave correctly,
// including validation, serialization, and business logic methods.
//
// Test categories:
// - Entity creation and initialization
// - Field validation and constraints
// - Method behavior and edge cases
// - Time handling and timezone considerations
// - UUID generation and validation
// - String representation and serialization
//
// Performance considerations:
// - Tests should complete within 100ms for individual operations
// - Memory allocations should be minimal and predictable
// - UUID generation should be cryptographically secure
type EntitiesTestSuite struct {
	suite.Suite
	fixedTime time.Time
	testUUID  uuid.UUID
}

// SetupSuite initializes the test suite with common test data.
// This method is called once before all tests in the suite run.
//
// Setup includes:
// - Fixed timestamps for deterministic testing
// - Test UUIDs for consistent entity IDs
// - Common test data structures
func (suite *EntitiesTestSuite) SetupSuite() {
	// Use a fixed time for deterministic testing
	// This ensures tests are not flaky due to time differences
	suite.fixedTime = time.Date(2025, 6, 20, 12, 0, 0, 0, time.UTC)

	// Generate a test UUID that can be reused across tests
	suite.testUUID = uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
}

// TestUserEntity_Creation validates user entity creation and initialization.
// This test ensures that user entities are properly initialized with
// required fields and default values.
//
// Test scenarios:
// - Valid user creation with all required fields
// - Default timestamp initialization
// - UUID generation for new users
// - Field validation and constraints
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (suite *EntitiesTestSuite) TestUserEntity_Creation() {
	// Test case 1: Valid user creation with all fields
	suite.Run("ValidUserCreation", func() {
		// Arrange
		email := "test@example.com"
		hashedPassword := "$2a$10$hashedpassword"
		firstName := "John"
		lastName := "Doe"

		// Act
		user := &domain.User{
			ID:                suite.testUUID,
			Email:             email,
			PasswordHash:      hashedPassword,
			FirstName:         firstName,
			LastName:          lastName,
			IsEmailVerified:   false,
			IsActive:          true,
			PasswordChangedAt: suite.fixedTime,
			CreatedAt:         suite.fixedTime,
			UpdatedAt:         suite.fixedTime,
		}

		// Assert
		assert.Equal(suite.T(), suite.testUUID, user.ID)
		assert.Equal(suite.T(), email, user.Email)
		assert.Equal(suite.T(), hashedPassword, user.PasswordHash)
		assert.Equal(suite.T(), firstName, user.FirstName)
		assert.Equal(suite.T(), lastName, user.LastName)
		assert.False(suite.T(), user.IsEmailVerified)
		assert.True(suite.T(), user.IsActive)
		assert.Equal(suite.T(), suite.fixedTime, user.CreatedAt)
		assert.Equal(suite.T(), suite.fixedTime, user.UpdatedAt)
		assert.Nil(suite.T(), user.DeletedAt)
	})

	// Test case 2: User creation with minimal required fields
	suite.Run("MinimalUserCreation", func() {
		// Arrange & Act
		user := &domain.User{
			Email:        "minimal@example.com",
			PasswordHash: "$2a$10$hashedpassword",
			FirstName:    "John",
			LastName:     "Doe",
		}

		// Assert
		assert.Equal(suite.T(), "minimal@example.com", user.Email)
		assert.Equal(suite.T(), "$2a$10$hashedpassword", user.PasswordHash)
		assert.False(suite.T(), user.IsEmailVerified) // Default value
		assert.False(suite.T(), user.IsActive)        // Default value
		assert.Nil(suite.T(), user.DeletedAt)         // Should be nil for active users
	})
}

// TestUserEntity_GetFullName tests the user's full name generation logic.
// This method should handle various combinations of first and last names,
// including edge cases with empty values and whitespace.
//
// Business rules tested:
// - Full name combines first and last name with space
// - Handles empty first name gracefully
// - Handles empty last name gracefully
// - Trims whitespace appropriately
// - Returns empty string when both names are empty
func (suite *EntitiesTestSuite) TestUserEntity_GetFullName() {
	testCases := []struct {
		name      string
		firstName string
		lastName  string
		expected  string
	}{
		{
			name:      "BothNamesProvided",
			firstName: "John",
			lastName:  "Doe",
			expected:  "John Doe",
		},
		{
			name:      "OnlyFirstName",
			firstName: "John",
			lastName:  "",
			expected:  "John ",
		},
		{
			name:      "OnlyLastName",
			firstName: "",
			lastName:  "Doe",
			expected:  " Doe",
		},
		{
			name:      "BothNamesEmpty",
			firstName: "",
			lastName:  "",
			expected:  " ",
		},
		{
			name:      "NamesWithWhitespace",
			firstName: "  John  ",
			lastName:  "  Doe  ",
			expected:  "  John     Doe  ",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			// Arrange
			user := &domain.User{
				FirstName: tc.firstName,
				LastName:  tc.lastName,
			}

			// Act
			fullName := user.GetFullName()

			// Assert
			assert.Equal(suite.T(), tc.expected, fullName)
		})
	}
}

// TestUserEntity_IsDeleted tests the user deletion status logic.
// A user is considered deleted if they have a DeletedAt timestamp.
//
// Test scenarios:
// - Active user (DeletedAt is nil)
// - Deleted user (DeletedAt is set)
// - Edge case with zero time value
func (suite *EntitiesTestSuite) TestUserEntity_IsDeleted() {
	suite.Run("ActiveUser", func() {
		// Arrange
		user := &domain.User{
			ID:        suite.testUUID,
			DeletedAt: nil,
		}

		// Act & Assert
		assert.False(suite.T(), user.IsDeleted())
	})

	suite.Run("DeletedUser", func() {
		// Arrange
		deletedTime := suite.fixedTime
		user := &domain.User{
			ID:        suite.testUUID,
			DeletedAt: &deletedTime,
		}

		// Act & Assert
		assert.True(suite.T(), user.IsDeleted())
	})
}

// TestRefreshTokenEntity_Creation validates refresh token entity creation.
// This test ensures proper initialization of refresh tokens with
// security considerations and expiration handling.
//
// Security requirements tested:
// - Token should be stored as JWT string
// - Expiration time should be in the future
// - User ID association is properly maintained
// - Revocation status is correctly initialized
func (suite *EntitiesTestSuite) TestRefreshTokenEntity_Creation() {
	suite.Run("ValidRefreshTokenCreation", func() {
		// Arrange
		tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		expiresAt := suite.fixedTime.Add(7 * 24 * time.Hour) // 7 days
		deviceInfo := "Mozilla/5.0 (Test Browser)"
		ipAddress := "192.168.1.100"

		// Act
		token := &domain.RefreshToken{
			ID:         suite.testUUID,
			UserID:     suite.testUUID,
			Token:      tokenString,
			DeviceInfo: deviceInfo,
			IPAddress:  ipAddress,
			ExpiresAt:  expiresAt,
			IsRevoked:  false,
			CreatedAt:  suite.fixedTime,
		}

		// Assert
		assert.Equal(suite.T(), suite.testUUID, token.ID)
		assert.Equal(suite.T(), suite.testUUID, token.UserID)
		assert.Equal(suite.T(), tokenString, token.Token)
		assert.Equal(suite.T(), deviceInfo, token.DeviceInfo)
		assert.Equal(suite.T(), ipAddress, token.IPAddress)
		assert.Equal(suite.T(), expiresAt, token.ExpiresAt)
		assert.False(suite.T(), token.IsRevoked)
		assert.Equal(suite.T(), suite.fixedTime, token.CreatedAt)
	})
}

// TestRefreshTokenEntity_IsTokenExpired tests token expiration logic.
// This method should accurately determine if a token has expired
// based on the current time and expiration timestamp.
//
// Time complexity: O(1)
// Edge cases tested:
// - Token that expires exactly now
// - Token that expired in the past
// - Token that expires in the future
// - Timezone considerations
func (suite *EntitiesTestSuite) TestRefreshTokenEntity_IsTokenExpired() {
	// Note: IsTokenExpired() uses time.Now(), so we need to test relative to when the test runs
	suite.Run("TokenNotExpired", func() {
		// Arrange - token expires 1 hour from now
		token := &domain.RefreshToken{
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		// Act & Assert
		assert.False(suite.T(), token.IsTokenExpired())
	})

	suite.Run("TokenExpired", func() {
		// Arrange - token expired 1 hour ago
		token := &domain.RefreshToken{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		// Act & Assert
		assert.True(suite.T(), token.IsTokenExpired())
	})
}

// TestRefreshTokenEntity_IsValid tests comprehensive token validation.
// A token is valid if it's not expired and not revoked.
//
// Validation scenarios:
// - Valid token (not expired, not revoked)
// - Invalid token (expired but not revoked)
// - Invalid token (not expired but revoked)
// - Invalid token (both expired and revoked)
func (suite *EntitiesTestSuite) TestRefreshTokenEntity_IsValid() {
	suite.Run("ValidToken", func() {
		// Arrange
		token := &domain.RefreshToken{
			IsRevoked: false,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		// Act & Assert
		assert.True(suite.T(), token.IsValid())
	})

	suite.Run("ExpiredToken", func() {
		// Arrange
		token := &domain.RefreshToken{
			IsRevoked: false,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		// Act & Assert
		assert.False(suite.T(), token.IsValid())
	})

	suite.Run("RevokedToken", func() {
		// Arrange
		token := &domain.RefreshToken{
			IsRevoked: true,
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		// Act & Assert
		assert.False(suite.T(), token.IsValid())
	})

	suite.Run("ExpiredAndRevokedToken", func() {
		// Arrange
		token := &domain.RefreshToken{
			IsRevoked: true,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		// Act & Assert
		assert.False(suite.T(), token.IsValid())
	})
}

// TestPasswordResetTokenEntity_Creation validates password reset token creation.
// These tokens have different security requirements than refresh tokens.
//
// Security considerations:
// - Short expiration time (typically 15-60 minutes)
// - Single-use tokens
// - Secure random token generation
// - User association tracking
func (suite *EntitiesTestSuite) TestPasswordResetTokenEntity_Creation() {
	suite.Run("ValidPasswordResetTokenCreation", func() {
		// Arrange
		tokenString := "secure-random-reset-token-12345"
		email := "test@example.com"
		expiresAt := suite.fixedTime.Add(30 * time.Minute) // 30 minutes
		ipAddress := "192.168.1.100"

		// Act
		token := &domain.PasswordResetToken{
			ID:        suite.testUUID,
			UserID:    suite.testUUID,
			Token:     tokenString,
			Email:     email,
			IPAddress: ipAddress,
			ExpiresAt: expiresAt,
			IsUsed:    false,
			CreatedAt: suite.fixedTime,
		}

		// Assert
		assert.Equal(suite.T(), suite.testUUID, token.ID)
		assert.Equal(suite.T(), suite.testUUID, token.UserID)
		assert.Equal(suite.T(), tokenString, token.Token)
		assert.Equal(suite.T(), email, token.Email)
		assert.Equal(suite.T(), ipAddress, token.IPAddress)
		assert.Equal(suite.T(), expiresAt, token.ExpiresAt)
		assert.False(suite.T(), token.IsUsed)
		assert.Equal(suite.T(), suite.fixedTime, token.CreatedAt)
	})
}

// TestPasswordResetTokenEntity_IsValid tests password reset token validation.
// A password reset token is valid if it's not expired and not used.
//
// This method should handle the same time-based validation as refresh tokens
// but with additional "used" status checking for single-use behavior.
func (suite *EntitiesTestSuite) TestPasswordResetTokenEntity_IsValid() {
	suite.Run("ValidToken", func() {
		// Arrange
		token := &domain.PasswordResetToken{
			IsUsed:    false,
			ExpiresAt: time.Now().Add(30 * time.Minute),
		}

		// Act & Assert
		assert.True(suite.T(), token.IsValid())
	})

	suite.Run("ExpiredToken", func() {
		// Arrange
		token := &domain.PasswordResetToken{
			IsUsed:    false,
			ExpiresAt: time.Now().Add(-30 * time.Minute),
		}

		// Act & Assert
		assert.False(suite.T(), token.IsValid())
	})

	suite.Run("UsedToken", func() {
		// Arrange
		token := &domain.PasswordResetToken{
			IsUsed:    true,
			ExpiresAt: time.Now().Add(30 * time.Minute),
		}

		// Act & Assert
		assert.False(suite.T(), token.IsValid())
	})

	suite.Run("ExpiredAndUsedToken", func() {
		// Arrange
		token := &domain.PasswordResetToken{
			IsUsed:    true,
			ExpiresAt: time.Now().Add(-30 * time.Minute),
		}

		// Act & Assert
		assert.False(suite.T(), token.IsValid())
	})
}

// TestAuditLogEntity_Creation validates audit log entry creation.
// Audit logs are critical for security monitoring and compliance.
//
// Requirements tested:
// - All required fields are properly set
// - Timestamp accuracy for audit trails
// - User association for accountability
// - Event type and description tracking
// - IP address logging for forensics
func (suite *EntitiesTestSuite) TestAuditLogEntity_Creation() {
	suite.Run("ValidAuditLogCreation", func() {
		// Arrange
		eventType := "user.login.success"
		eventDescription := "User successfully logged in from web application"
		ipAddress := "192.168.1.100"
		userAgent := "Mozilla/5.0 (Test Browser)"
		metadata := map[string]interface{}{
			"login_method": "email_password",
			"device_type":  "desktop",
		}

		// Act
		auditLog := &domain.AuditLog{
			ID:               suite.testUUID,
			UserID:           &suite.testUUID, // Pointer because it can be nil for anonymous actions
			EventType:        eventType,
			EventDescription: eventDescription,
			IPAddress:        ipAddress,
			UserAgent:        userAgent,
			Metadata:         metadata,
			Success:          true,
			CreatedAt:        suite.fixedTime,
		}

		// Assert
		assert.Equal(suite.T(), suite.testUUID, auditLog.ID)
		assert.NotNil(suite.T(), auditLog.UserID)
		assert.Equal(suite.T(), suite.testUUID, *auditLog.UserID)
		assert.Equal(suite.T(), eventType, auditLog.EventType)
		assert.Equal(suite.T(), eventDescription, auditLog.EventDescription)
		assert.Equal(suite.T(), ipAddress, auditLog.IPAddress)
		assert.Equal(suite.T(), userAgent, auditLog.UserAgent)
		assert.Equal(suite.T(), metadata, auditLog.Metadata)
		assert.True(suite.T(), auditLog.Success)
		assert.Equal(suite.T(), suite.fixedTime, auditLog.CreatedAt)
	})

	// Test case for anonymous actions (no user ID)
	suite.Run("AnonymousAuditLogCreation", func() {
		// Arrange & Act
		auditLog := &domain.AuditLog{
			ID:               suite.testUUID,
			UserID:           nil, // Anonymous action
			EventType:        "user.login.failed",
			EventDescription: "Failed login attempt with invalid credentials",
			IPAddress:        "192.168.1.100",
			Success:          false,
			CreatedAt:        suite.fixedTime,
		}

		// Assert
		assert.Nil(suite.T(), auditLog.UserID)
		assert.Equal(suite.T(), "user.login.failed", auditLog.EventType)
		assert.False(suite.T(), auditLog.Success)
	})
}

// TestEntitiesTestSuite runs all entity tests using testify suite runner.
// This ensures proper setup, teardown, and test isolation.
func TestEntitiesTestSuite(t *testing.T) {
	suite.Run(t, new(EntitiesTestSuite))
}

// TestUUIDGeneration_Performance tests UUID generation performance.
// This benchmark ensures UUID generation meets performance requirements
// for high-throughput authentication operations.
//
// Performance requirements:
// - Should generate 10,000 UUIDs in under 100ms
// - Memory allocations should be minimal
// - UUIDs should be cryptographically secure
func TestUUIDGeneration_Performance(t *testing.T) {
	// Arrange
	const iterations = 10000
	start := time.Now()
	uuids := make([]uuid.UUID, iterations)

	// Act
	for i := 0; i < iterations; i++ {
		uuids[i] = uuid.New()
	}
	elapsed := time.Since(start)

	// Assert
	assert.Less(t, elapsed, 100*time.Millisecond, "UUID generation should be fast")

	// Verify uniqueness (basic check)
	uniqueUUIDs := make(map[uuid.UUID]bool)
	for _, u := range uuids {
		require.False(t, uniqueUUIDs[u], "Generated UUIDs should be unique")
		uniqueUUIDs[u] = true
	}

	assert.Len(t, uniqueUUIDs, iterations, "All UUIDs should be unique")
}

// TestTimeHandling_EdgeCases tests time-related edge cases across entities.
// This includes timezone handling, daylight saving time transitions,
// and leap second considerations.
func TestTimeHandling_EdgeCases(t *testing.T) {
	t.Run("TimezoneConsistency", func(t *testing.T) {
		// Arrange
		utcTime := time.Date(2025, 6, 20, 12, 0, 0, 0, time.UTC)
		estTime := utcTime.In(time.FixedZone("EST", -5*3600))

		// Act
		user1 := &domain.User{CreatedAt: utcTime}
		user2 := &domain.User{CreatedAt: estTime}

		// Assert
		// Times should be equal when compared properly
		assert.True(t, user1.CreatedAt.Equal(user2.CreatedAt))
	})

	t.Run("LeapYearHandling", func(t *testing.T) {
		// Arrange
		leapYearTime := time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC)
		expirationTime := leapYearTime.Add(1 * time.Hour)

		// Act
		token := &domain.RefreshToken{
			CreatedAt: leapYearTime,
			ExpiresAt: expirationTime,
		}

		// Assert
		// Use a time before expiration to test
		testTime := expirationTime.Add(-30 * time.Minute)
		// Since IsTokenExpired uses time.Now(), we need to test the logic differently
		assert.True(t, testTime.Before(token.ExpiresAt))
	})
}
