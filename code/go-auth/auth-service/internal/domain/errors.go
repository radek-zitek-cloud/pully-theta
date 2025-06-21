package domain

import "errors"

// Authentication and authorization errors
var (
	// ErrUserNotFound is returned when a user cannot be found in the repository.
	// This could be due to an invalid ID, email, or the user being soft-deleted.
	ErrUserNotFound = errors.New("user not found")

	// ErrInvalidCredentials is returned when authentication fails due to
	// incorrect email/password combination. This error should not distinguish
	// between invalid email and invalid password for security reasons.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrEmailExists is returned when attempting to register with an email
	// that is already associated with an existing user account.
	ErrEmailExists = errors.New("email already exists")

	// ErrInvalidToken is returned when a JWT token is malformed, expired,
	// or has an invalid signature. This includes both access and refresh tokens.
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenExpired is returned when a token has passed its expiration time.
	// This is a more specific case of ErrInvalidToken.
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenRevoked is returned when attempting to use a refresh token
	// that has been explicitly revoked.
	ErrTokenRevoked = errors.New("token revoked")

	// ErrTokenNotFound is returned when a refresh token or password reset token
	// cannot be found in the repository.
	ErrTokenNotFound = errors.New("token not found")

	// ErrTokenMissing is returned when no authentication token is provided
	// in the Authorization header when one is required.
	ErrTokenMissing = errors.New("authentication token missing")

	// ErrInvalidTokenFormat is returned when the Authorization header
	// doesn't follow the expected "Bearer <token>" format.
	ErrInvalidTokenFormat = errors.New("invalid token format")

	// ErrInvalidSigningMethod is returned when a JWT token uses an
	// unsupported or unexpected signing method.
	ErrInvalidSigningMethod = errors.New("invalid token signing method")

	// ErrInvalidTokenClaims is returned when JWT token claims are missing
	// required fields or contain invalid data.
	ErrInvalidTokenClaims = errors.New("invalid token claims")

	// ErrTokenBlacklisted is returned when attempting to use a token that has been
	// explicitly blacklisted (revoked) before its natural expiration time.
	ErrTokenBlacklisted = errors.New("token has been blacklisted")

	// ErrInvalidTokenType is returned when a token is of the wrong type for the
	// requested operation (e.g., using a refresh token where access token is expected).
	ErrInvalidTokenType = errors.New("invalid token type")

	// ErrInvalidUserID is returned when a user ID cannot be parsed as a valid UUID
	// or is not in the expected format.
	ErrInvalidUserID = errors.New("invalid user ID format")

	// ErrUnauthorized is returned when a user is not authorized to access a resource
	// or perform an operation due to insufficient permissions.
	ErrUnauthorized = errors.New("unauthorized access")

	// ErrForbidden is returned when a user is authenticated but lacks the required
	// permissions to access a specific resource or perform an operation.
	ErrForbidden = errors.New("access forbidden")

	// ErrInsufficientPermissions is returned when a user has valid credentials
	// but lacks the specific permissions required for the requested operation.
	ErrInsufficientPermissions = errors.New("insufficient permissions")
)

// Input validation errors
var (
	// ErrInvalidInput is returned when request input fails validation.
	// This includes missing required fields, invalid formats, or constraint violations.
	ErrInvalidInput = errors.New("invalid input")

	// ErrValidationFailed is returned when input validation fails.
	// This is a general validation error that encompasses various validation failures.
	ErrValidationFailed = errors.New("validation failed")

	// ErrInvalidEmail is returned when an email address doesn't conform
	// to RFC 5322 standards or domain validation fails.
	ErrInvalidEmail = errors.New("invalid email format")

	// ErrWeakPassword is returned when a password doesn't meet the
	// security requirements (length, complexity, etc.).
	ErrWeakPassword = errors.New("password does not meet security requirements")

	// ErrPasswordMismatch is returned when password confirmation doesn't
	// match the original password during registration or password change.
	ErrPasswordMismatch = errors.New("password confirmation does not match")

	// ErrEmailAlreadyExists is an alias for ErrEmailExists for backward compatibility.
	// Use ErrEmailExists for new code.
	ErrEmailAlreadyExists = ErrEmailExists
)

// Account state errors
var (
	// ErrAccountInactive is returned when attempting to authenticate
	// with an account that has been deactivated.
	ErrAccountInactive = errors.New("account is inactive")

	// ErrAccountDeleted is returned when attempting to perform operations
	// on a soft-deleted user account.
	ErrAccountDeleted = errors.New("account has been deleted")

	// ErrEmailNotVerified is returned when attempting operations that
	// require email verification on an unverified account.
	ErrEmailNotVerified = errors.New("email address not verified")
)

// Rate limiting errors
var (
	// ErrRateLimitExceeded is returned when a client has exceeded
	// the allowed number of requests within the time window.
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// ErrTooManyLoginAttempts is returned when there have been too many
	// failed login attempts for a user or IP address.
	ErrTooManyLoginAttempts = errors.New("too many login attempts")

	// ErrTooManyPasswordResets is returned when there have been too many
	// password reset requests for a user within the time window.
	ErrTooManyPasswordResets = errors.New("too many password reset requests")
)

// Infrastructure errors
var (
	// ErrDatabase is returned when a database operation fails due to
	// connection issues, constraint violations, or other database errors.
	ErrDatabase = errors.New("database error")

	// ErrEmailService is returned when email sending fails due to
	// SMTP issues, network problems, or service configuration errors.
	ErrEmailService = errors.New("email service error")

	// ErrCacheService is returned when cache operations (Redis) fail.
	ErrCacheService = errors.New("cache service error")

	// ErrConfiguration is returned when required configuration values
	// are missing or invalid.
	ErrConfiguration = errors.New("configuration error")
)

// Business logic errors
var (
	// ErrOperationNotAllowed is returned when an operation violates
	// business rules or security policies.
	ErrOperationNotAllowed = errors.New("operation not allowed")

	// ErrConcurrentModification is returned when a record has been
	// modified by another process during an update operation.
	ErrConcurrentModification = errors.New("concurrent modification detected")

	// ErrResourceNotFound is returned when a requested resource
	// (other than user) cannot be found.
	ErrResourceNotFound = errors.New("resource not found")
)

// Security errors
var (
	// ErrSuspiciousActivity is returned when potentially malicious
	// activity is detected (e.g., unusual login patterns).
	ErrSuspiciousActivity = errors.New("suspicious activity detected")

	// ErrIPBlocked is returned when requests are coming from a
	// blocked IP address due to security policies.
	ErrIPBlocked = errors.New("IP address blocked")

	// ErrCSRFTokenInvalid is returned when CSRF token validation fails.
	ErrCSRFTokenInvalid = errors.New("invalid CSRF token")
)

// IsAuthenticationError checks if an error is related to authentication.
// This includes credential validation, token issues, and account state problems.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - true if the error is authentication-related
//   - false for other types of errors
//
// Usage:
//
//	if IsAuthenticationError(err) {
//	    // Handle authentication failure
//	    return http.StatusUnauthorized
//	}
func IsAuthenticationError(err error) bool {
	return err == ErrUserNotFound ||
		err == ErrInvalidCredentials ||
		err == ErrInvalidToken ||
		err == ErrTokenExpired ||
		err == ErrTokenRevoked ||
		err == ErrTokenNotFound ||
		err == ErrAccountInactive ||
		err == ErrAccountDeleted ||
		err == ErrEmailNotVerified
}

// IsValidationError checks if an error is related to input validation.
// These errors typically result in HTTP 400 Bad Request responses.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - true if the error is validation-related
//   - false for other types of errors
//
// Usage:
//
//	if IsValidationError(err) {
//	    // Handle validation error
//	    return http.StatusBadRequest
//	}
func IsValidationError(err error) bool {
	return err == ErrInvalidInput ||
		err == ErrValidationFailed ||
		err == ErrInvalidEmail ||
		err == ErrWeakPassword ||
		err == ErrPasswordMismatch ||
		err == ErrEmailExists
}

// IsRateLimitError checks if an error is related to rate limiting.
// These errors typically result in HTTP 429 Too Many Requests responses.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - true if the error is rate limit-related
//   - false for other types of errors
//
// Usage:
//
//	if IsRateLimitError(err) {
//	    // Handle rate limit error
//	    return http.StatusTooManyRequests
//	}
func IsRateLimitError(err error) bool {
	return err == ErrRateLimitExceeded ||
		err == ErrTooManyLoginAttempts ||
		err == ErrTooManyPasswordResets
}

// IsInfrastructureError checks if an error is related to infrastructure.
// These errors typically result in HTTP 503 Service Unavailable responses.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - true if the error is infrastructure-related
//   - false for other types of errors
//
// Usage:
//
//	if IsInfrastructureError(err) {
//	    // Handle infrastructure error
//	    return http.StatusServiceUnavailable
//	}
func IsInfrastructureError(err error) bool {
	return err == ErrDatabase ||
		err == ErrEmailService ||
		err == ErrCacheService ||
		err == ErrConfiguration
}

// IsSecurityError checks if an error is related to security.
// These errors may require special logging and monitoring.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - true if the error is security-related
//   - false for other types of errors
//
// Usage:
//
//	if IsSecurityError(err) {
//	    // Log security event and possibly block IP
//	    securityLogger.Warn("Security error detected", "error", err)
//	}
func IsSecurityError(err error) bool {
	return err == ErrSuspiciousActivity ||
		err == ErrIPBlocked ||
		err == ErrCSRFTokenInvalid ||
		err == ErrTooManyLoginAttempts
}

// IsNotFoundError checks if an error indicates that a resource was not found.
// This is used to distinguish between "not found" and other database errors.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - true if the error indicates a resource was not found
//   - false for other types of errors
//
// Usage:
//
//	user, err := repo.GetByID(ctx, userID)
//	if err != nil {
//	    if IsNotFoundError(err) {
//	        return domain.ErrUserNotFound
//	    }
//	    return fmt.Errorf("database error: %w", err)
//	}
func IsNotFoundError(err error) bool {
	return err == ErrUserNotFound ||
		err == ErrTokenNotFound ||
		err == ErrResourceNotFound
}

// IsAuthorizationError checks if an error is related to authorization.
// These errors typically result in HTTP 403 Forbidden responses.
//
// Parameters:
//   - err: The error to check
//
// Returns:
//   - true if the error is authorization-related
//   - false for other types of errors
//
// Usage:
//
//	if IsAuthorizationError(err) {
//	    // Handle authorization error
//	    return http.StatusForbidden
//	}
func IsAuthorizationError(err error) bool {
	return err == ErrUnauthorized ||
		err == ErrForbidden ||
		err == ErrInsufficientPermissions ||
		err == ErrOperationNotAllowed
}
