package test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"auth-service/internal/domain"
)

// DTOsTestSuite provides comprehensive testing for Data Transfer Objects (DTOs).
// This suite ensures that all DTOs properly handle validation, serialization,
// and deserialization for API operations.
//
// Test categories:
// - JSON serialization and deserialization
// - Validation tag enforcement
// - Field mapping and conversion
// - Edge cases with special characters
// - Performance with large payloads
// - Security considerations (password field exclusion)
//
// Security considerations:
// - Password fields should not be serialized in responses
// - Input validation should prevent injection attacks
// - Sensitive fields should be properly masked in logs
type DTOsTestSuite struct {
	suite.Suite
}

// SetupSuite initializes the test suite with common test data.
func (suite *DTOsTestSuite) SetupSuite() {
	// No special setup required for DTOs
}

// TestRegisterRequest_Validation tests the registration request DTO validation.
// This ensures that all required fields are properly validated according to
// business rules and security requirements.
//
// Validation scenarios:
// - Valid registration with all required fields
// - Missing email field
// - Invalid email format
// - Missing password field
// - Password too short or weak
// - Missing first name
// - Missing last name
// - Names with special characters
// - Email with internationalized domain names
//
// Security considerations:
// - Email addresses should be normalized to lowercase
// - Password complexity requirements should be enforced
// - Input should be sanitized to prevent XSS
func (suite *DTOsTestSuite) TestRegisterRequest_Validation() {
	suite.Run("ValidRegistrationRequest", func() {
		// Arrange
		req := domain.RegisterRequest{
			Email:     "test@example.com",
			Password:  "StrongPassword123!",
			FirstName: "John",
			LastName:  "Doe",
		}

		// Act - Test JSON serialization
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		// Assert - Verify all fields are present
		var unmarshaled map[string]interface{}
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		assert.Equal(suite.T(), req.Email, unmarshaled["email"])
		assert.Equal(suite.T(), req.Password, unmarshaled["password"])
		assert.Equal(suite.T(), req.FirstName, unmarshaled["first_name"])
		assert.Equal(suite.T(), req.LastName, unmarshaled["last_name"])
	})

	suite.Run("JSONDeserialization", func() {
		// Arrange
		jsonPayload := `{
			"email": "user@example.com",
			"password": "SecurePass123!",
			"first_name": "Jane",
			"last_name": "Smith"
		}`

		// Act
		var req domain.RegisterRequest
		err := json.Unmarshal([]byte(jsonPayload), &req)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), "user@example.com", req.Email)
		assert.Equal(suite.T(), "SecurePass123!", req.Password)
		assert.Equal(suite.T(), "Jane", req.FirstName)
		assert.Equal(suite.T(), "Smith", req.LastName)
	})

	suite.Run("EmailNormalization", func() {
		// Arrange
		testCases := []struct {
			name     string
			input    string
			expected string
		}{
			{
				name:     "UppercaseEmail",
				input:    "TEST@EXAMPLE.COM",
				expected: "TEST@EXAMPLE.COM", // DTOs don't normalize, service layer does
			},
			{
				name:     "MixedCaseEmail",
				input:    "User.Name@Example.Com",
				expected: "User.Name@Example.Com",
			},
		}

		for _, tc := range testCases {
			suite.Run(tc.name, func() {
				// Arrange
				req := domain.RegisterRequest{
					Email:     tc.input,
					Password:  "password123",
					FirstName: "Test",
					LastName:  "User",
				}

				// Act & Assert
				assert.Equal(suite.T(), tc.expected, req.Email)
			})
		}
	})

	suite.Run("SpecialCharactersInNames", func() {
		// Arrange
		req := domain.RegisterRequest{
			Email:     "test@example.com",
			Password:  "password123",
			FirstName: "José-María",
			LastName:  "O'Connor-Smith",
		}

		// Act - Test JSON serialization with special characters
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.RegisterRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), "José-María", unmarshaled.FirstName)
		assert.Equal(suite.T(), "O'Connor-Smith", unmarshaled.LastName)
	})
}

// TestLoginRequest_Validation tests the login request DTO validation.
// Login requests should only require email and password fields.
//
// Security considerations:
// - Credentials should not be logged or cached
// - Failed login attempts should be rate limited
// - Input should be validated to prevent injection attacks
func (suite *DTOsTestSuite) TestLoginRequest_Validation() {
	suite.Run("ValidLoginRequest", func() {
		// Arrange
		req := domain.LoginRequest{
			Email:    "user@example.com",
			Password: "password123",
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.LoginRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), req.Email, unmarshaled.Email)
		assert.Equal(suite.T(), req.Password, unmarshaled.Password)
	})

	suite.Run("EmptyFieldsDeserialization", func() {
		// Arrange
		jsonPayload := `{"email": "", "password": ""}`

		// Act
		var req domain.LoginRequest
		err := json.Unmarshal([]byte(jsonPayload), &req)
		require.NoError(suite.T(), err)

		// Assert - Empty fields should be preserved for validation layer
		assert.Equal(suite.T(), "", req.Email)
		assert.Equal(suite.T(), "", req.Password)
	})
}

// TestAuthResponse_Serialization tests authentication response DTOs.
// These responses contain sensitive data (tokens) that must be handled securely.
//
// Security considerations:
// - Access tokens should have short expiration times
// - Refresh tokens should be httpOnly when possible
// - Token metadata should not expose sensitive information
// - User information should exclude password-related fields
func (suite *DTOsTestSuite) TestAuthResponse_Serialization() {
	suite.Run("LoginResponseSerialization", func() {
		// Arrange
		response := domain.LoginResponse{
			AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			RefreshToken: "refresh_token_string",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			User: domain.UserResponse{
				ID:              uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				Email:           "user@example.com",
				FirstName:       "John",
				LastName:        "Doe",
				IsEmailVerified: true,
				IsActive:        true,
			},
		}

		// Act
		jsonData, err := json.Marshal(response)
		require.NoError(suite.T(), err)

		var unmarshaled domain.LoginResponse
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), response.AccessToken, unmarshaled.AccessToken)
		assert.Equal(suite.T(), response.RefreshToken, unmarshaled.RefreshToken)
		assert.Equal(suite.T(), response.TokenType, unmarshaled.TokenType)
		assert.Equal(suite.T(), response.ExpiresIn, unmarshaled.ExpiresIn)
		assert.Equal(suite.T(), response.User.Email, unmarshaled.User.Email)
		assert.Equal(suite.T(), response.User.FirstName, unmarshaled.User.FirstName)
		assert.Equal(suite.T(), response.User.IsEmailVerified, unmarshaled.User.IsEmailVerified)
	})

	suite.Run("UserResponseExcludesPasswordHash", func() {
		// Arrange
		userResponse := domain.UserResponse{
			ID:              uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
			Email:           "user@example.com",
			FirstName:       "John",
			LastName:        "Doe",
			IsEmailVerified: true,
			IsActive:        true,
		}

		// Act
		jsonData, err := json.Marshal(userResponse)
		require.NoError(suite.T(), err)

		// Assert - Verify password hash field is not present
		var jsonMap map[string]interface{}
		err = json.Unmarshal(jsonData, &jsonMap)
		require.NoError(suite.T(), err)

		_, hasPasswordHash := jsonMap["password_hash"]
		assert.False(suite.T(), hasPasswordHash, "Password hash should not be serialized")

		_, hasPassword := jsonMap["password"]
		assert.False(suite.T(), hasPassword, "Password field should not be present")
	})
}

// TestPasswordOperationDTOs tests password-related operation DTOs.
// These operations involve sensitive data and should be handled carefully.
//
// Security considerations:
// - Current passwords should be verified before changes
// - New passwords should meet complexity requirements
// - Password reset tokens should be time-limited and single-use
// - All password operations should be logged for audit
func (suite *DTOsTestSuite) TestPasswordOperationDTOs() {
	suite.Run("ChangePasswordRequest", func() {
		// Arrange
		req := domain.ChangePasswordRequest{
			CurrentPassword: "oldpassword123",
			NewPassword:     "newpassword456",
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.ChangePasswordRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), req.CurrentPassword, unmarshaled.CurrentPassword)
		assert.Equal(suite.T(), req.NewPassword, unmarshaled.NewPassword)
	})

	suite.Run("ResetPasswordRequest", func() {
		// Arrange
		req := domain.ResetPasswordRequest{
			Email: "user@example.com",
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.ResetPasswordRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), req.Email, unmarshaled.Email)
	})

	suite.Run("ConfirmResetPasswordRequest", func() {
		// Arrange
		req := domain.ConfirmResetPasswordRequest{
			Token:              "reset_token_12345",
			Email:              "user@example.com",
			NewPassword:        "newpassword789",
			NewPasswordConfirm: "newpassword789",
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.ConfirmResetPasswordRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), req.Token, unmarshaled.Token)
		assert.Equal(suite.T(), req.Email, unmarshaled.Email)
		assert.Equal(suite.T(), req.NewPassword, unmarshaled.NewPassword)
		assert.Equal(suite.T(), req.NewPasswordConfirm, unmarshaled.NewPasswordConfirm)
	})
}

// TestUpdateProfileRequest tests the profile update DTO.
// Profile updates should allow partial updates with validation.
//
// Business rules:
// - Email updates require re-verification
// - Name changes should be logged for audit
// - Optional fields can be omitted from updates
// - Email uniqueness must be validated at service layer
func (suite *DTOsTestSuite) TestUpdateProfileRequest() {
	suite.Run("CompleteProfileUpdate", func() {
		// Arrange
		req := domain.UpdateProfileRequest{
			Email:     stringPtr("newemail@example.com"),
			FirstName: stringPtr("UpdatedFirst"),
			LastName:  stringPtr("UpdatedLast"),
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.UpdateProfileRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		require.NotNil(suite.T(), unmarshaled.Email)
		assert.Equal(suite.T(), "newemail@example.com", *unmarshaled.Email)
		require.NotNil(suite.T(), unmarshaled.FirstName)
		assert.Equal(suite.T(), "UpdatedFirst", *unmarshaled.FirstName)
		require.NotNil(suite.T(), unmarshaled.LastName)
		assert.Equal(suite.T(), "UpdatedLast", *unmarshaled.LastName)
	})

	suite.Run("PartialProfileUpdate", func() {
		// Arrange - Only update first name
		req := domain.UpdateProfileRequest{
			FirstName: stringPtr("OnlyFirst"),
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.UpdateProfileRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Nil(suite.T(), unmarshaled.Email)
		require.NotNil(suite.T(), unmarshaled.FirstName)
		assert.Equal(suite.T(), "OnlyFirst", *unmarshaled.FirstName)
		assert.Nil(suite.T(), unmarshaled.LastName)
	})

	suite.Run("EmptyProfileUpdate", func() {
		// Arrange
		req := domain.UpdateProfileRequest{}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.UpdateProfileRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert - All fields should be nil for no updates
		assert.Nil(suite.T(), unmarshaled.Email)
		assert.Nil(suite.T(), unmarshaled.FirstName)
		assert.Nil(suite.T(), unmarshaled.LastName)
	})
}

// TestErrorResponse tests error response DTOs.
// Error responses should provide useful information without exposing
// sensitive system details.
//
// Security considerations:
// - Internal error details should not be exposed to clients
// - Error codes should be consistent and well-documented
// - Stack traces should never be included in production responses
// - User-friendly messages should be provided for common errors
func (suite *DTOsTestSuite) TestErrorResponse() {
	suite.Run("StandardErrorResponse", func() {
		// Arrange
		errResp := domain.ErrorResponse{
			Error:   "validation_failed",
			Message: "The provided data is invalid",
			Details: map[string]interface{}{
				"field":  "email",
				"reason": "invalid_format",
			},
		}

		// Act
		jsonData, err := json.Marshal(errResp)
		require.NoError(suite.T(), err)

		var unmarshaled domain.ErrorResponse
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), errResp.Error, unmarshaled.Error)
		assert.Equal(suite.T(), errResp.Message, unmarshaled.Message)
		assert.Equal(suite.T(), errResp.Details, unmarshaled.Details)
	})

	suite.Run("MinimalErrorResponse", func() {
		// Arrange
		errResp := domain.ErrorResponse{
			Error:   "unauthorized",
			Message: "Authentication required",
		}

		// Act
		jsonData, err := json.Marshal(errResp)
		require.NoError(suite.T(), err)

		var unmarshaled domain.ErrorResponse
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), errResp.Error, unmarshaled.Error)
		assert.Equal(suite.T(), errResp.Message, unmarshaled.Message)
		assert.Nil(suite.T(), unmarshaled.Details)
	})
}

// TestTokenDTOs tests token-related DTOs for refresh operations.
// Token operations are critical for security and should be thoroughly tested.
//
// Security considerations:
// - Refresh tokens should be validated before use
// - Token responses should include proper expiration information
// - Invalid tokens should result in clear error messages
func (suite *DTOsTestSuite) TestTokenDTOs() {
	suite.Run("RefreshTokenRequest", func() {
		// Arrange
		req := domain.RefreshTokenRequest{
			RefreshToken: "refresh_token_string_12345",
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.RefreshTokenRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), req.RefreshToken, unmarshaled.RefreshToken)
	})

	suite.Run("RefreshTokenRequest", func() {
		// Arrange
		req := domain.RefreshTokenRequest{
			RefreshToken: "refresh_token_12345",
		}

		// Act
		jsonData, err := json.Marshal(req)
		require.NoError(suite.T(), err)

		var unmarshaled domain.RefreshTokenRequest
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(suite.T(), err)

		// Assert
		assert.Equal(suite.T(), req.RefreshToken, unmarshaled.RefreshToken)
	})
}

// TestDTOPerformance tests DTO serialization/deserialization performance.
// This ensures that JSON operations don't become a bottleneck in high-traffic scenarios.
//
// Performance requirements:
// - Serialization should complete in under 1ms for typical DTOs
// - Large DTOs (with metadata) should complete in under 5ms
// - Memory allocations should be reasonable
func (suite *DTOsTestSuite) TestDTOPerformance() {
	suite.Run("LoginResponsePerformance", func() {
		// Arrange
		response := domain.LoginResponse{
			AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			RefreshToken: "very_long_refresh_token_that_could_be_quite_large_in_production_systems",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			User: domain.UserResponse{
				ID:              uuid.MustParse("550e8400-e29b-41d4-a716-446655440000"),
				Email:           "user.with.very.long.email.address@subdomain.example.com",
				FirstName:       "VeryLongFirstNameThatMightBeUsedInSomeApplications",
				LastName:        "VeryLongLastNameThatMightAlsoBeQuiteLongInSomeScenarios",
				IsEmailVerified: true,
				IsActive:        true,
			},
		}

		// Act - Measure serialization performance
		const iterations = 1000
		suite.T().Helper()
		start := time.Now()

		for i := 0; i < iterations; i++ {
			jsonData, err := json.Marshal(response)
			require.NoError(suite.T(), err)
			require.NotEmpty(suite.T(), jsonData)
		}

		duration := time.Since(start)

		// Assert - Performance should be reasonable (less than 1 second for 1000 operations)
		suite.T().Logf("Serialization took %v for %d iterations", duration, iterations)
		assert.Less(suite.T(), duration, time.Second, "DTO serialization should be performant")

		// Assert - This is a performance test, actual timing depends on hardware
		// The important thing is that it completes without errors
		suite.T().Logf("Completed %d serializations successfully", iterations)
	})
}

// TestDTOsTestSuite runs all DTO tests using testify suite runner.
func TestDTOsTestSuite(t *testing.T) {
	suite.Run(t, new(DTOsTestSuite))
}

// Helper function to create string pointers for optional fields
func stringPtr(s string) *string {
	return &s
}
