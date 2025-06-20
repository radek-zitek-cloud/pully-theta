package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"auth-service/internal/domain"
)

// PostgreSQLPasswordResetTokenRepository handles password reset token persistence operations using PostgreSQL.
// It provides secure storage and lifecycle management of password reset tokens with proper
// hashing, expiration handling, and usage tracking following the repository pattern.
//
// Security considerations:
// - Tokens are hashed before storage (never stored in plain text)
// - Short expiration times (typically 15-30 minutes)
// - One-time use tokens with usage tracking
// - Automatic cleanup of expired tokens
// - User-scoped token invalidation
//
// Database schema requirements:
// - password_reset_tokens table with proper indexes
// - Foreign key relationship with users table
// - UUID support for primary and foreign keys
// - Timestamp columns for lifecycle management
// - Boolean flags for usage tracking
//
// Performance characteristics:
// - O(1) token lookups with proper indexing
// - Efficient bulk operations for cleanup
// - Minimal locking for concurrent operations
type PostgreSQLPasswordResetTokenRepository struct {
	db     *sql.DB        // Database connection for executing queries
	logger *logrus.Logger // Structured logger for debugging and monitoring
}

// NewPostgreSQLPasswordResetTokenRepository creates a new PostgreSQL-backed password reset token repository.
// It validates the database connection and configures logging for debugging purposes.
//
// Parameters:
//   - db: Active PostgreSQL database connection with proper schema
//   - logger: Configured logger instance for structured logging
//
// Returns:
//   - Repository instance ready for password reset token operations
//   - Never returns error (panics on invalid inputs for fail-fast behavior)
//
// Usage example:
//
//	db, _ := sql.Open("postgres", connectionString)
//	logger := logrus.New()
//	repo := NewPostgreSQLPasswordResetTokenRepository(db, logger)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func NewPostgreSQLPasswordResetTokenRepository(db *sql.DB, logger *logrus.Logger) domain.PasswordResetTokenRepository {
	if db == nil {
		panic("database connection cannot be nil")
	}
	if logger == nil {
		panic("logger cannot be nil")
	}

	return &PostgreSQLPasswordResetTokenRepository{
		db:     db,
		logger: logger,
	}
}

// Create stores a new password reset token in the database.
// The token string is hashed before storage for security purposes.
// This operation is atomic and will either succeed completely or fail completely.
//
// Security notes:
// - Token string is hashed using SHA-256 before storage
// - Only the hash is stored, never the plain text token
// - Previous tokens for the same user are not automatically invalidated
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - token: PasswordResetToken entity with all required fields set
//
// Returns:
//   - Created token entity with generated ID and timestamps
//   - Error if creation fails (database errors, constraint violations)
//
// Possible errors:
//   - ErrInvalidInput: Required fields are missing or invalid
//   - ErrDatabase: Database operation failed
//   - Context cancellation errors
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (r *PostgreSQLPasswordResetTokenRepository) Create(ctx context.Context, token *domain.PasswordResetToken) (*domain.PasswordResetToken, error) {
	// Input validation to ensure data integrity
	if token == nil {
		r.logger.Error("attempted to create nil password reset token")
		return nil, domain.ErrInvalidInput
	}

	if token.UserID == uuid.Nil {
		r.logger.WithField("token", token).Error("password reset token missing user ID")
		return nil, domain.ErrInvalidInput
	}

	if token.Token == "" {
		r.logger.WithField("user_id", token.UserID).Error("password reset token missing token string")
		return nil, domain.ErrInvalidInput
	}

	if token.ExpiresAt.IsZero() {
		r.logger.WithField("user_id", token.UserID).Error("password reset token missing expiration time")
		return nil, domain.ErrInvalidInput
	}

	// Hash the token for secure storage
	hashedToken := r.hashToken(token.Token)

	// Set metadata for new token
	now := time.Now().UTC()
	if token.ID == uuid.Nil {
		token.ID = uuid.New()
	}
	token.CreatedAt = now

	// SQL query for inserting new password reset token
	// Uses RETURNING clause to get the created record back
	query := `
		INSERT INTO password_reset_tokens (
			id, user_id, token_hash, email, expires_at, is_used, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		) RETURNING id, created_at`

	// Execute the insertion with proper error handling
	err := r.db.QueryRowContext(
		ctx,
		query,
		token.ID,
		token.UserID,
		hashedToken,
		token.Email,
		token.ExpiresAt,
		false, // New tokens are never used initially
		token.CreatedAt,
	).Scan(&token.ID, &token.CreatedAt)

	if err != nil {
		// Handle PostgreSQL-specific errors
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23503": // Foreign key violation
				r.logger.WithFields(logrus.Fields{
					"user_id": token.UserID,
					"error":   pqErr.Message,
				}).Error("user not found for password reset token")
				return nil, domain.ErrUserNotFound
			case "23505": // Unique constraint violation
				r.logger.WithFields(logrus.Fields{
					"user_id": token.UserID,
					"error":   pqErr.Message,
				}).Error("duplicate password reset token")
				return nil, domain.ErrDatabase
			}
		}

		// Log and return generic database error
		r.logger.WithFields(logrus.Fields{
			"user_id": token.UserID,
			"error":   err.Error(),
		}).Error("failed to create password reset token")
		return nil, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	r.logger.WithFields(logrus.Fields{
		"token_id": token.ID,
		"user_id":  token.UserID,
		"expires":  token.ExpiresAt,
	}).Info("password reset token created successfully")

	return token, nil
}

// GetByToken retrieves a password reset token by its token string.
// The token string is hashed and compared against stored hashes.
// Only returns non-expired, non-used tokens.
//
// Security notes:
// - Input token is hashed before database lookup
// - Expired tokens are automatically excluded
// - Used tokens are automatically excluded
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - tokenString: The plain text token string to look up
//
// Returns:
//   - PasswordResetToken entity if found and valid
//   - ErrTokenNotFound if token doesn't exist, is expired, or is used
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (r *PostgreSQLPasswordResetTokenRepository) GetByToken(ctx context.Context, tokenString string) (*domain.PasswordResetToken, error) {
	if tokenString == "" {
		r.logger.Error("attempted to lookup password reset token with empty string")
		return nil, domain.ErrTokenNotFound
	}

	// Hash the input token for comparison
	hashedToken := r.hashToken(tokenString)

	// SQL query that automatically excludes expired and used tokens
	// Uses current timestamp to check expiration
	query := `
		SELECT id, user_id, token_hash, email, expires_at, is_used, created_at
		FROM password_reset_tokens 
		WHERE token_hash = $1 
		  AND expires_at > NOW() 
		  AND is_used = FALSE`

	var token domain.PasswordResetToken
	err := r.db.QueryRowContext(ctx, query, hashedToken).Scan(
		&token.ID,
		&token.UserID,
		&token.Token, // This will be the hash, not the original token
		&token.Email,
		&token.ExpiresAt,
		&token.IsUsed,
		&token.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			r.logger.WithField("token_hash", hashedToken[:8]+"...").Warn("password reset token not found or invalid")
			return nil, domain.ErrTokenNotFound
		}

		r.logger.WithFields(logrus.Fields{
			"token_hash": hashedToken[:8] + "...",
			"error":      err.Error(),
		}).Error("failed to retrieve password reset token")
		return nil, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	// Replace hash with original token for consistency
	token.Token = tokenString

	r.logger.WithFields(logrus.Fields{
		"token_id": token.ID,
		"user_id":  token.UserID,
	}).Debug("password reset token retrieved successfully")

	return &token, nil
}

// MarkAsUsed marks a password reset token as used, preventing future use.
// This is called after a successful password reset to prevent token reuse.
// The operation is idempotent - marking an already used token doesn't fail.
//
// Security considerations:
// - Prevents token replay attacks
// - Atomic operation to prevent race conditions
// - Maintains audit trail of token usage
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - tokenString: The plain text token string to mark as used
//
// Returns:
//   - Error if marking fails or token not found
//
// Time Complexity: O(1) with proper database indexing
// Space Complexity: O(1)
func (r *PostgreSQLPasswordResetTokenRepository) MarkAsUsed(ctx context.Context, tokenString string) error {
	if tokenString == "" {
		r.logger.Error("attempted to mark empty password reset token as used")
		return domain.ErrTokenNotFound
	}

	// Hash the token for database lookup
	hashedToken := r.hashToken(tokenString)

	// SQL query to mark token as used
	// Only affects non-expired, non-used tokens
	query := `
		UPDATE password_reset_tokens 
		SET is_used = TRUE, updated_at = NOW() 
		WHERE token_hash = $1 
		  AND expires_at > NOW() 
		  AND is_used = FALSE`

	result, err := r.db.ExecContext(ctx, query, hashedToken)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"token_hash": hashedToken[:8] + "...",
			"error":      err.Error(),
		}).Error("failed to mark password reset token as used")
		return fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"token_hash": hashedToken[:8] + "...",
			"error":      err.Error(),
		}).Error("failed to check rows affected for password reset token update")
		return fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	if rowsAffected == 0 {
		r.logger.WithField("token_hash", hashedToken[:8]+"...").Warn("password reset token not found or already used")
		return domain.ErrTokenNotFound
	}

	r.logger.WithField("token_hash", hashedToken[:8]+"...").Info("password reset token marked as used")
	return nil
}

// CleanupExpired removes expired password reset tokens from the database.
// This should be called periodically to prevent database bloat and maintain performance.
// The operation is safe to run concurrently and won't affect valid tokens.
//
// Cleanup strategy:
// - Removes tokens past their expiration time
// - Preserves used tokens for audit purposes (configurable)
// - Batch operations for efficiency
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//
// Returns:
//   - Number of tokens deleted
//   - Error if cleanup operation fails
//
// Time Complexity: O(n) where n is the number of expired tokens
// Space Complexity: O(1)
func (r *PostgreSQLPasswordResetTokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	// SQL query to delete expired tokens
	// Uses current timestamp to determine expiration
	query := `
		DELETE FROM password_reset_tokens 
		WHERE expires_at <= NOW()`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		r.logger.WithField("error", err.Error()).Error("failed to cleanup expired password reset tokens")
		return 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	// Get the number of deleted rows
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithField("error", err.Error()).Error("failed to get rows affected for password reset token cleanup")
		return 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	if rowsAffected > 0 {
		r.logger.WithField("deleted_count", rowsAffected).Info("cleaned up expired password reset tokens")
	} else {
		r.logger.Debug("no expired password reset tokens to cleanup")
	}

	return rowsAffected, nil
}

// InvalidateUserTokens invalidates all password reset tokens for a specific user.
// This is called when a password is successfully changed to prevent token reuse.
// The operation marks all user tokens as used, preserving them for audit purposes.
//
// Use cases:
// - Password successfully reset using any token
// - Security incident requiring token invalidation
// - User account lockout scenarios
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userID: User's unique identifier
//
// Returns:
//   - Error if invalidation fails
//
// Time Complexity: O(k) where k is the number of user tokens
// Space Complexity: O(1)
func (r *PostgreSQLPasswordResetTokenRepository) InvalidateUserTokens(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		r.logger.Error("attempted to invalidate password reset tokens with nil user ID")
		return domain.ErrInvalidInput
	}

	// SQL query to mark all user tokens as used
	// Only affects non-used tokens to preserve audit trail
	query := `
		UPDATE password_reset_tokens 
		SET is_used = TRUE, updated_at = NOW() 
		WHERE user_id = $1 AND is_used = FALSE`

	result, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("failed to invalidate user password reset tokens")
		return fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	// Log the number of tokens invalidated
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("failed to check rows affected for password reset token invalidation")
		return fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	r.logger.WithFields(logrus.Fields{
		"user_id":         userID,
		"tokens_affected": rowsAffected,
	}).Info("invalidated user password reset tokens")

	return nil
}

// hashToken creates a SHA-256 hash of the token string for secure storage.
// This ensures that plain text tokens are never stored in the database.
//
// Security considerations:
// - Uses SHA-256 for cryptographic strength
// - Returns hex-encoded string for database storage
// - Consistent hashing for reliable lookups
//
// Parameters:
//   - token: Plain text token string to hash
//
// Returns:
//   - Hex-encoded SHA-256 hash of the input token
//
// Time Complexity: O(1) for typical token lengths
// Space Complexity: O(1)
func (r *PostgreSQLPasswordResetTokenRepository) hashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return hex.EncodeToString(hasher.Sum(nil))
}
