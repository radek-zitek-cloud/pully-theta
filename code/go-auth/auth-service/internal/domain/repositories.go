package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// UserRepository defines the contract for user data access operations.
// This interface abstracts the data layer and allows for different implementations
// (PostgreSQL, MongoDB, in-memory, etc.) without changing business logic.
//
// All methods should be thread-safe and handle database connection errors gracefully.
// Implementations should use proper transaction management for data consistency.
//
// Error handling:
// - Return domain-specific errors (ErrUserNotFound, ErrEmailExists, etc.)
// - Include context information for debugging
// - Log errors appropriately without exposing sensitive data
type UserRepository interface {
	// Create creates a new user in the repository.
	// The user ID should be generated if not provided.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - user: User entity to create (ID may be zero value)
	//
	// Returns:
	//   - Created user with generated ID and timestamps
	//   - Error if creation fails (e.g., email already exists)
	//
	// Errors:
	//   - ErrEmailExists: Email is already registered
	//   - ErrInvalidInput: Required fields are missing or invalid
	//   - ErrDatabase: Database operation failed
	Create(ctx context.Context, user *User) (*User, error)

	// GetByID retrieves a user by their unique identifier.
	// Soft-deleted users should not be returned unless explicitly requested.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - id: User's unique identifier
	//
	// Returns:
	//   - User entity if found
	//   - ErrUserNotFound if user doesn't exist or is soft-deleted
	//
	// Time Complexity: O(1) with proper database indexing
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)

	// GetByEmail retrieves a user by their email address.
	// Email lookup should be case-insensitive for better user experience.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - email: User's email address (case-insensitive)
	//
	// Returns:
	//   - User entity if found
	//   - ErrUserNotFound if no user with that email exists
	//
	// Time Complexity: O(1) with proper database indexing on email
	GetByEmail(ctx context.Context, email string) (*User, error)

	// Update modifies an existing user's information.
	// Only non-zero fields should be updated to allow partial updates.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - user: User entity with updated fields
	//
	// Returns:
	//   - Updated user entity
	//   - Error if update fails
	//
	// Note: UpdatedAt timestamp should be automatically set
	Update(ctx context.Context, user *User) (*User, error)

	// Delete performs a soft delete on the user account.
	// This sets the DeletedAt timestamp instead of removing the record.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - id: User's unique identifier
	//
	// Returns:
	//   - Error if deletion fails or user not found
	//
	// Security note: Soft deletion preserves audit trails and prevents ID reuse
	Delete(ctx context.Context, id uuid.UUID) error

	// UpdateLastLogin updates the user's last login timestamp.
	// This is called after successful authentication for audit purposes.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - id: User's unique identifier
	//   - loginTime: Timestamp of the login event
	//
	// Returns:
	//   - Error if update fails
	UpdateLastLogin(ctx context.Context, id uuid.UUID, loginTime time.Time) error

	// List retrieves a paginated list of users.
	// Useful for admin interfaces and user management.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - offset: Number of records to skip
	//   - limit: Maximum number of records to return
	//
	// Returns:
	//   - Slice of user entities
	//   - Total count of users (for pagination)
	//   - Error if query fails
	List(ctx context.Context, offset, limit int) ([]*User, int64, error)
}

// RefreshTokenRepository defines the contract for refresh token data access.
// Refresh tokens require special handling for security and performance:
// - Automatic cleanup of expired tokens
// - Efficient lookups by token string
// - Bulk operations for user session management
type RefreshTokenRepository interface {
	// Create stores a new refresh token in the repository.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - token: RefreshToken entity to store
	//
	// Returns:
	//   - Created token with generated ID and timestamps
	//   - Error if creation fails
	Create(ctx context.Context, token *RefreshToken) (*RefreshToken, error)

	// GetByToken retrieves a refresh token by its token string.
	// This is the primary lookup method during token refresh operations.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - tokenString: The JWT refresh token string
	//
	// Returns:
	//   - RefreshToken entity if found and valid
	//   - ErrTokenNotFound if token doesn't exist
	//
	// Performance: Should be O(1) with proper indexing on token field
	GetByToken(ctx context.Context, tokenString string) (*RefreshToken, error)

	// RevokeToken marks a specific refresh token as revoked.
	// Revoked tokens cannot be used for future refresh operations.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - tokenString: The JWT refresh token string to revoke
	//
	// Returns:
	//   - Error if revocation fails or token not found
	RevokeToken(ctx context.Context, tokenString string) error

	// RevokeAllUserTokens revokes all refresh tokens for a specific user.
	// Useful for logout-all functionality and security incidents.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - userID: User's unique identifier
	//
	// Returns:
	//   - Error if revocation fails
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error

	// CleanupExpired removes expired refresh tokens from the repository.
	// This should be called periodically to prevent database bloat.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//
	// Returns:
	//   - Number of tokens deleted
	//   - Error if cleanup fails
	CleanupExpired(ctx context.Context) (int64, error)

	// GetUserTokens retrieves all active tokens for a user.
	// Useful for session management and security monitoring.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - userID: User's unique identifier
	//
	// Returns:
	//   - Slice of active refresh tokens
	//   - Error if query fails
	GetUserTokens(ctx context.Context, userID uuid.UUID) ([]*RefreshToken, error)
}

// PasswordResetTokenRepository defines the contract for password reset token operations.
// Reset tokens are short-lived and require special security considerations.
type PasswordResetTokenRepository interface {
	// Create stores a new password reset token.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - token: PasswordResetToken entity to store
	//
	// Returns:
	//   - Created token with generated ID and timestamps
	//   - Error if creation fails
	Create(ctx context.Context, token *PasswordResetToken) (*PasswordResetToken, error)

	// GetByToken retrieves a password reset token by its token string.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - tokenString: The reset token string
	//
	// Returns:
	//   - PasswordResetToken entity if found
	//   - ErrTokenNotFound if token doesn't exist
	GetByToken(ctx context.Context, tokenString string) (*PasswordResetToken, error)

	// MarkAsUsed marks a password reset token as used.
	// Used tokens cannot be reused for security.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - tokenString: The reset token string to mark as used
	//
	// Returns:
	//   - Error if marking fails or token not found
	MarkAsUsed(ctx context.Context, tokenString string) error

	// CleanupExpired removes expired password reset tokens.
	// Should be called periodically to maintain database hygiene.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//
	// Returns:
	//   - Number of tokens deleted
	//   - Error if cleanup fails
	CleanupExpired(ctx context.Context) (int64, error)

	// InvalidateUserTokens invalidates all password reset tokens for a user.
	// Called when password is successfully changed to prevent token reuse.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - userID: User's unique identifier
	//
	// Returns:
	//   - Error if invalidation fails
	InvalidateUserTokens(ctx context.Context, userID uuid.UUID) error
}

// AuditLogRepository defines the contract for audit log operations.
// Audit logs are append-only and should never be modified after creation.
type AuditLogRepository interface {
	// Create stores a new audit log entry.
	// Audit logs are immutable once created for security and compliance.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - log: AuditLog entity to store
	//
	// Returns:
	//   - Created log entry with generated ID and timestamp
	//   - Error if creation fails
	Create(ctx context.Context, log *AuditLog) (*AuditLog, error)

	// GetByUserID retrieves audit logs for a specific user.
	// Useful for security monitoring and user activity tracking.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - userID: User's unique identifier
	//   - offset: Number of records to skip
	//   - limit: Maximum number of records to return
	//
	// Returns:
	//   - Slice of audit log entries (newest first)
	//   - Total count of logs for this user
	//   - Error if query fails
	GetByUserID(ctx context.Context, userID uuid.UUID, offset, limit int) ([]*AuditLog, int64, error)

	// GetByEventType retrieves audit logs by event type.
	// Useful for analyzing specific types of events across all users.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - eventType: Type of event to filter by
	//   - offset: Number of records to skip
	//   - limit: Maximum number of records to return
	//
	// Returns:
	//   - Slice of audit log entries
	//   - Total count of logs for this event type
	//   - Error if query fails
	GetByEventType(ctx context.Context, eventType string, offset, limit int) ([]*AuditLog, int64, error)

	// CleanupOld removes audit logs older than specified duration.
	// Useful for compliance with data retention policies.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeouts
	//   - olderThan: Duration to determine which logs to delete
	//
	// Returns:
	//   - Number of logs deleted
	//   - Error if cleanup fails
	CleanupOld(ctx context.Context, olderThan time.Duration) (int64, error)
}
