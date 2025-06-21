package domain

import (
	"context"

	"github.com/google/uuid"
)

// AuthenticationService defines the core authentication operations for the system.
// This interface encapsulates user registration, login, and logout functionality.
//
// Design Principles:
// - Single Responsibility: Focused only on authentication operations
// - Interface Segregation: Separated from token and profile management
// - Dependency Inversion: Implementations depend on this abstraction
//
// Security Considerations:
// - All operations should include rate limiting via clientIP tracking
// - Failed authentication attempts must be logged for audit purposes
// - User agent tracking helps detect suspicious login patterns
// - Context propagation ensures request tracing and cancellation
//
// Usage Example:
//
//	authService := service.NewAuthenticationService(...)
//	user, err := authService.Register(ctx, registerReq, "192.168.1.1", "Mozilla/5.0...")
//	if err != nil {
//		return handleRegistrationError(err)
//	}
//
// Error Handling:
// - Returns domain-specific errors (ErrUserExists, ErrInvalidCredentials, etc.)
// - Rate limiting errors should be handled gracefully
// - Infrastructure errors should be wrapped with context
type AuthenticationService interface {
	// Register creates a new user account in the system.
	//
	// This method performs comprehensive user registration including:
	// - Email uniqueness validation
	// - Password strength verification
	// - Input sanitization and validation
	// - Rate limiting based on client IP
	// - Audit logging of registration attempts
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - req: Registration request containing user details and credentials
	//   - clientIP: Client IP address for rate limiting and audit logging
	//   - userAgent: Client user agent for security monitoring
	//
	// Returns:
	//   - *User: Created user entity with populated fields
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrUserAlreadyExists: Email already registered
	//   - ErrWeakPassword: Password doesn't meet security requirements
	//   - ErrValidationError: Invalid input data
	//   - ErrRateLimitExceeded: Too many registration attempts
	//   - ErrInfrastructureError: Database or external service failure
	//
	// Example:
	//   user, err := authService.Register(ctx, &RegisterRequest{
	//       Email: "user@example.com",
	//       Password: "SecurePass123!",
	//       FirstName: "John",
	//       LastName: "Doe",
	//   }, "192.168.1.1", "Mozilla/5.0...")
	Register(ctx context.Context, req *RegisterRequest, clientIP, userAgent string) (*User, error)

	// Login authenticates a user and returns authentication tokens.
	//
	// This method handles user authentication with the following security measures:
	// - Credential verification against stored password hash
	// - Account status validation (active, email verified)
	// - Rate limiting to prevent brute force attacks
	// - Failed attempt tracking and temporary lockouts
	// - Audit logging of all login attempts
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - req: Login request containing email and password
	//   - clientIP: Client IP address for rate limiting and security
	//   - userAgent: Client user agent for device tracking
	//
	// Returns:
	//   - *AuthResponse: Complete authentication response with tokens and user info
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrInvalidCredentials: Wrong email or password
	//   - ErrUserNotFound: Email not registered
	//   - ErrAccountInactive: User account is disabled
	//   - ErrEmailNotVerified: User must verify email first
	//   - ErrRateLimitExceeded: Too many failed login attempts
	//   - ErrAccountLocked: Account temporarily locked due to failed attempts
	//
	// Example:
	//   authResp, err := authService.Login(ctx, &LoginRequest{
	//       Email: "user@example.com",
	//       Password: "SecurePass123!",
	//   }, "192.168.1.1", "Mozilla/5.0...")
	Login(ctx context.Context, req *LoginRequest, clientIP, userAgent string) (*AuthResponse, error)

	// Logout invalidates a specific refresh token and cleans up the user session.
	//
	// This method performs secure logout by:
	// - Validating and parsing the refresh token
	// - Removing the token from active session storage
	// - Adding the token to a blacklist to prevent reuse
	// - Logging the logout event for audit purposes
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - refreshToken: The refresh token to invalidate
	//   - clientIP: Client IP address for audit logging
	//   - userAgent: Client user agent for session tracking
	//
	// Returns:
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrInvalidToken: Token is malformed or expired
	//   - ErrTokenNotFound: Token doesn't exist in storage
	//   - ErrInfrastructureError: Database or cache failure
	//
	// Example:
	//   err := authService.Logout(ctx, refreshToken, "192.168.1.1", "Mozilla/5.0...")
	Logout(ctx context.Context, refreshToken, clientIP, userAgent string) error

	// LogoutAll invalidates all active sessions for a specific user.
	//
	// This method provides enhanced security by allowing users to:
	// - Terminate all active sessions across all devices
	// - Revoke all refresh tokens associated with the account
	// - Clear all cached authentication data
	// - Log the global logout event for security auditing
	//
	// Use cases:
	// - User suspects account compromise
	// - Password change requiring session invalidation
	// - Device loss or theft scenarios
	// - Administrative account suspension
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - userID: Unique identifier of the user
	//   - clientIP: Client IP address for audit logging
	//   - userAgent: Client user agent for session tracking
	//
	// Returns:
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrUserNotFound: User ID doesn't exist
	//   - ErrInfrastructureError: Database or cache failure
	//
	// Example:
	//   err := authService.LogoutAll(ctx, userID, "192.168.1.1", "Mozilla/5.0...")
	LogoutAll(ctx context.Context, userID uuid.UUID, clientIP, userAgent string) error
}

// TokenService defines operations for JWT token management and validation.
// This interface handles the lifecycle of access and refresh tokens.
//
// Design Principles:
// - Separation of Concerns: Token operations isolated from authentication
// - Security by Design: All operations include validation and audit logging
// - Stateless Design: Tokens are self-contained and verifiable
//
// Token Types:
// - Access Token: Short-lived (15 minutes), used for API authorization
// - Refresh Token: Long-lived (7 days), used to obtain new access tokens
//
// Security Features:
// - Token blacklisting for revocation
// - Signature verification using HMAC-SHA256
// - Expiration time validation
// - Issuer and audience validation
// - Rate limiting on refresh operations
//
// Usage Example:
//
//	tokenService := service.NewTokenService(...)
//	user, err := tokenService.ValidateToken(ctx, bearerToken)
//	if err != nil {
//		return handleTokenError(err)
//	}
type TokenService interface {
	// RefreshToken generates new access and refresh token pairs.
	//
	// This method implements the OAuth 2.0 refresh token flow:
	// - Validates the provided refresh token
	// - Checks token expiration and blacklist status
	// - Generates new access and refresh token pair
	// - Invalidates the old refresh token
	// - Rate limits refresh requests per user/IP
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - req: Refresh token request containing the current refresh token
	//   - clientIP: Client IP address for rate limiting and audit
	//   - userAgent: Client user agent for session tracking
	//
	// Returns:
	//   - *AuthResponse: New token pair with updated expiration times
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrInvalidToken: Refresh token is invalid or expired
	//   - ErrTokenBlacklisted: Token has been revoked
	//   - ErrRateLimitExceeded: Too many refresh attempts
	//   - ErrUserNotFound: Token references non-existent user
	//   - ErrAccountInactive: User account has been deactivated
	//
	// Security Considerations:
	// - Old refresh token is immediately invalidated (token rotation)
	// - New tokens have fresh expiration times
	// - Failed refresh attempts are logged for security monitoring
	//
	// Example:
	//   authResp, err := tokenService.RefreshToken(ctx, &RefreshTokenRequest{
	//       RefreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
	//   }, "192.168.1.1", "Mozilla/5.0...")
	RefreshToken(ctx context.Context, req *RefreshTokenRequest, clientIP, userAgent string) (*AuthResponse, error)

	// ValidateToken verifies an access token and returns the associated user.
	//
	// This method performs comprehensive token validation:
	// - Signature verification using the secret key
	// - Expiration time validation
	// - Issuer and audience claims verification
	// - Blacklist checking for revoked tokens
	// - Token type validation (access vs refresh)
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - token: JWT access token to validate
	//
	// Returns:
	//   - *User: User entity associated with the token
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrInvalidToken: Token is malformed, expired, or invalid
	//   - ErrTokenBlacklisted: Token has been revoked
	//   - ErrInvalidTokenType: Wrong token type (refresh instead of access)
	//   - ErrUserNotFound: Token references non-existent user
	//   - ErrAccountInactive: User account has been deactivated
	//
	// Performance Considerations:
	// - Token validation is CPU-intensive due to cryptographic operations
	// - Consider caching validation results for frequently accessed tokens
	// - Use connection pooling for blacklist checks
	//
	// Example:
	//   user, err := tokenService.ValidateToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
	ValidateToken(ctx context.Context, token string) (*User, error)

	// RevokeToken adds a token to the blacklist, preventing future use.
	//
	// This method provides immediate token revocation by:
	// - Parsing the token to extract expiration time
	// - Adding the token to a distributed blacklist (Redis)
	// - Setting appropriate TTL based on token expiration
	// - Logging the revocation event for audit purposes
	//
	// Use Cases:
	// - User-initiated logout
	// - Security incident response
	// - Administrative token revocation
	// - Suspicious activity detection
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - token: JWT token to revoke (access or refresh)
	//
	// Returns:
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrInvalidToken: Token is malformed or unparseable
	//   - ErrInfrastructureError: Blacklist storage failure
	//
	// Implementation Notes:
	// - Blacklist storage should be distributed (Redis) for scalability
	// - TTL should match token expiration to prevent memory leaks
	// - Consider cleanup jobs for expired blacklist entries
	//
	// Example:
	//   err := tokenService.RevokeToken(ctx, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
	RevokeToken(ctx context.Context, token string) error
}

// PasswordService defines operations for password management and security.
// This interface handles password changes, resets, and validation.
//
// Design Principles:
// - Security First: All operations include comprehensive validation
// - Rate Limiting: Protection against brute force and abuse
// - Audit Logging: Complete trail of password-related activities
// - Token-Based Flow: Secure password reset using time-limited tokens
//
// Security Features:
// - Password strength validation
// - Rate limiting on password operations
// - Secure token generation for password resets
// - Email verification for password resets
// - Previous password validation
//
// Compliance Considerations:
// - GDPR: User consent for password processing
// - SOC 2: Audit trails for all password operations
// - PCI DSS: Secure handling of authentication credentials
type PasswordService interface {
	// ChangePassword allows authenticated users to change their password.
	//
	// This method implements secure password change with:
	// - Current password verification
	// - New password strength validation
	// - Password history checking (prevent reuse)
	// - Rate limiting per user and IP
	// - Session invalidation after password change
	// - Audit logging of password change events
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - userID: Unique identifier of the authenticated user
	//   - req: Password change request with current and new passwords
	//   - clientIP: Client IP address for rate limiting and audit
	//   - userAgent: Client user agent for session tracking
	//
	// Returns:
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrInvalidCredentials: Current password is incorrect
	//   - ErrWeakPassword: New password doesn't meet requirements
	//   - ErrPasswordReuse: New password was used recently
	//   - ErrRateLimitExceeded: Too many password change attempts
	//   - ErrUserNotFound: User ID doesn't exist
	//   - ErrAccountInactive: User account is disabled
	//
	// Security Considerations:
	// - All active sessions should be invalidated after password change
	// - Password change should trigger security notification email
	// - Failed attempts should be logged for security monitoring
	//
	// Example:
	//   err := passwordService.ChangePassword(ctx, userID, &ChangePasswordRequest{
	//       CurrentPassword: "OldPass123!",
	//       NewPassword: "NewSecurePass456!",
	//       NewPasswordConfirm: "NewSecurePass456!",
	//   }, "192.168.1.1", "Mozilla/5.0...")
	ChangePassword(ctx context.Context, userID uuid.UUID, req *ChangePasswordRequest, clientIP, userAgent string) error

	// ResetPassword initiates the password reset flow by sending a reset email.
	//
	// This method implements the first step of password reset:
	// - User email validation and lookup
	// - Reset token generation with expiration
	// - Secure token storage with TTL
	// - Password reset email dispatch
	// - Rate limiting to prevent email spam
	// - Audit logging of reset initiation
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - req: Password reset request containing user email
	//   - clientIP: Client IP address for rate limiting and audit
	//   - userAgent: Client user agent for security tracking
	//
	// Returns:
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrUserNotFound: Email is not registered
	//   - ErrRateLimitExceeded: Too many reset requests
	//   - ErrAccountInactive: User account is disabled
	//   - ErrEmailNotVerified: User must verify email first
	//   - ErrInfrastructureError: Email service or storage failure
	//
	// Security Considerations:
	// - Reset tokens should be cryptographically secure
	// - Tokens should have short expiration (15-30 minutes)
	// - Email content should not reveal if email exists
	// - Multiple reset requests should invalidate previous tokens
	//
	// Example:
	//   err := passwordService.ResetPassword(ctx, &ResetPasswordRequest{
	//       Email: "user@example.com",
	//   }, "192.168.1.1", "Mozilla/5.0...")
	ResetPassword(ctx context.Context, req *ResetPasswordRequest, clientIP, userAgent string) error

	// ConfirmResetPassword completes the password reset using a valid reset token.
	//
	// This method implements the second step of password reset:
	// - Reset token validation and expiration check
	// - New password strength validation
	// - Password update with bcrypt hashing
	// - Token invalidation after use
	// - Session invalidation across all devices
	// - Confirmation email notification
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - req: Password reset confirmation with token and new password
	//   - clientIP: Client IP address for audit logging
	//   - userAgent: Client user agent for security tracking
	//
	// Returns:
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrInvalidToken: Reset token is invalid or expired
	//   - ErrTokenUsed: Reset token has already been used
	//   - ErrWeakPassword: New password doesn't meet requirements
	//   - ErrPasswordReuse: New password was used recently
	//   - ErrUserNotFound: Token references non-existent user
	//   - ErrAccountInactive: User account is disabled
	//
	// Security Considerations:
	// - Reset tokens are single-use only
	// - All user sessions should be invalidated
	// - Password reset should trigger security notification
	// - Successful reset should log security event
	//
	// Example:
	//   err := passwordService.ConfirmResetPassword(ctx, &ConfirmResetPasswordRequest{
	//       Token: "secure_reset_token_123",
	//       NewPassword: "NewSecurePass456!",
	//       NewPasswordConfirm: "NewSecurePass456!",
	//   }, "192.168.1.1", "Mozilla/5.0...")
	ConfirmResetPassword(ctx context.Context, req *ConfirmResetPasswordRequest, clientIP, userAgent string) error
}

// UserProfileService defines operations for user profile management.
// This interface handles user data retrieval and updates.
//
// Design Principles:
// - Data Privacy: Sensitive data is filtered based on access context
// - Validation: All updates are validated before persistence
// - Audit Trail: Profile changes are logged for compliance
// - Performance: Efficient queries and caching strategies
//
// Security Considerations:
// - Personal data access should be logged for GDPR compliance
// - Profile updates should be rate limited
// - Email changes should require re-verification
// - Sensitive fields should require additional authentication
//
// Performance Considerations:
// - Profile data is frequently accessed and should be cached
// - Use appropriate database indexes for email and ID lookups
// - Consider read replicas for profile retrieval operations
type UserProfileService interface {
	// GetProfile retrieves complete user profile information.
	//
	// This method returns comprehensive user data including:
	// - Basic profile information (name, email, etc.)
	// - Account status and verification state
	// - Timestamps for tracking and audit
	// - Preference and settings data
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - userID: Unique identifier of the user
	//
	// Returns:
	//   - *User: Complete user entity with all profile data
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrUserNotFound: User ID doesn't exist
	//   - ErrInfrastructureError: Database connection failure
	//
	// Security Considerations:
	// - Sensitive fields (password hash) are excluded from response
	// - Access should be logged for audit purposes
	// - Consider field-level permissions for different user roles
	//
	// Performance Considerations:
	// - Profile data should be cached with appropriate TTL
	// - Use database indexes on user ID for fast retrieval
	// - Consider lazy loading of related data
	//
	// Example:
	//   user, err := profileService.GetProfile(ctx, userID)
	GetProfile(ctx context.Context, userID uuid.UUID) (*User, error)

	// UpdateProfile modifies user profile information.
	//
	// This method allows partial updates of user profile data:
	// - Validates all provided fields
	// - Checks for data conflicts (unique email)
	// - Logs profile changes for audit
	// - Handles special fields (email verification reset)
	// - Rate limits update operations
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - userID: Unique identifier of the user (string for compatibility)
	//   - updateData: Map of field names to new values for partial updates
	//
	// Returns:
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrUserNotFound: User ID doesn't exist
	//   - ErrValidationError: Invalid field values
	//   - ErrEmailAlreadyExists: Email is already in use
	//   - ErrRateLimitExceeded: Too many update attempts
	//   - ErrInfrastructureError: Database operation failure
	//
	// Supported Update Fields:
	// - first_name: User's first name (string, 1-100 chars)
	// - last_name: User's last name (string, 1-100 chars)
	// - email: Email address (triggers re-verification)
	//
	// Security Considerations:
	// - Email changes should reset email verification status
	// - Profile updates should be logged with old and new values
	// - Consider requiring password confirmation for sensitive changes
	//
	// Example:
	//   err := profileService.UpdateProfile(ctx, userID.String(), map[string]interface{}{
	//       "first_name": "John",
	//       "last_name": "Doe",
	//       "email": "newemail@example.com",
	//   })
	UpdateProfile(ctx context.Context, userID string, updateData map[string]interface{}) error

	// GetUserByEmail retrieves a user by their email address.
	//
	// This method provides email-based user lookup for:
	// - Authentication flows (login)
	// - Password reset operations
	// - User existence checking
	// - Administrative user searches
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - email: Email address to search for (case-insensitive)
	//
	// Returns:
	//   - *User: User entity if found
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrUserNotFound: Email is not registered
	//   - ErrInfrastructureError: Database connection failure
	//
	// Performance Considerations:
	// - Email field should have a unique index for fast lookups
	// - Consider caching frequently accessed user data
	// - Email lookup is case-insensitive and should be normalized
	//
	// Security Considerations:
	// - Email lookups should be rate limited to prevent enumeration
	// - Failed lookups should not reveal if email exists
	// - Access should be logged for security monitoring
	//
	// Example:
	//   user, err := profileService.GetUserByEmail(ctx, "user@example.com")
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// GetUserByID retrieves a user by their unique identifier.
	//
	// This method provides ID-based user lookup for:
	// - Token validation and user context
	// - Profile retrieval operations
	// - Administrative user management
	// - Cross-service user references
	//
	// Parameters:
	//   - ctx: Request context for tracing and cancellation
	//   - id: User ID as string (UUID format expected)
	//
	// Returns:
	//   - *User: User entity if found
	//   - error: Domain-specific error or nil on success
	//
	// Possible Errors:
	//   - ErrUserNotFound: User ID doesn't exist
	//   - ErrValidationError: Invalid UUID format
	//   - ErrInfrastructureError: Database connection failure
	//
	// Performance Considerations:
	// - Primary key lookups are inherently fast
	// - Consider caching user data with appropriate TTL
	// - Use connection pooling for database access
	//
	// Security Considerations:
	// - ID-based lookups are less sensitive than email enumeration
	// - Access should still be logged for audit purposes
	// - Validate UUID format to prevent injection attacks
	//
	// Example:
	//   user, err := profileService.GetUserByID(ctx, "123e4567-e89b-12d3-a456-426614174000")
	GetUserByID(ctx context.Context, id string) (*User, error)
}
