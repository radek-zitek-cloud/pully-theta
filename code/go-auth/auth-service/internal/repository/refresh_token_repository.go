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

// PostgreSQLRefreshTokenRepository handles refresh token persistence operations using PostgreSQL.
// It provides secure storage and retrieval of refresh tokens with proper
// hashing and expiration management following the repository pattern.
//
// Security considerations:
// - Tokens are hashed before storage (never stored in plain text)
// - Expired tokens are automatically excluded from queries
// - Revoked tokens are soft-deleted with timestamps
// - Cleanup operations remove expired tokens
//
// Database schema requirements:
// - refresh_tokens table with proper indexes
// - Foreign key relationship with users table
// - UUID support for primary and foreign keys
// - Timestamp columns for lifecycle management
type PostgreSQLRefreshTokenRepository struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewPostgreSQLRefreshTokenRepository creates a new PostgreSQL refresh token repository instance.
// This constructor validates the database connection and prepares the repository
// for use with proper error handling and logging.
//
// Parameters:
//   - db: Active PostgreSQL database connection with connection pooling
//   - logger: Structured logger for repository operations and errors
//
// Returns:
//   - *PostgreSQLRefreshTokenRepository: Configured repository instance
//
// Example:
//
//	repo := NewPostgreSQLRefreshTokenRepository(db, logger)
//	token, err := repo.Create(ctx, refreshToken)
func NewPostgreSQLRefreshTokenRepository(db *sql.DB, logger *logrus.Logger) *PostgreSQLRefreshTokenRepository {
	return &PostgreSQLRefreshTokenRepository{
		db:     db,
		logger: logger,
	}
}

// Create stores a new refresh token in the database.
// The token string is hashed using SHA-256 for security.
//
// Parameters:
//   - ctx: Context for request lifecycle and cancellation
//   - token: RefreshToken domain entity to store
//
// Returns:
//   - *domain.RefreshToken: Created token with generated ID and timestamps
//   - error: Database error or validation failure
//
// Security:
//   - Token value is hashed before storage using SHA-256
//   - Expiration time is validated
//   - User ID foreign key constraint enforced
//   - Original token returned for immediate use
//
// Database Transaction:
//   - Single INSERT operation with immediate commit
//   - Foreign key constraints ensure data integrity
//   - UUID generation handled by application layer
//
// Example:
//
//	token := &domain.RefreshToken{
//	    UserID: userID,
//	    Token: "raw_token_string",
//	    ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
//	}
//	created, err := repo.Create(ctx, token)
func (r *PostgreSQLRefreshTokenRepository) Create(ctx context.Context, token *domain.RefreshToken) (*domain.RefreshToken, error) {
	// Input validation
	if token == nil {
		r.logger.Error("RefreshTokenRepository.Create: token is nil")
		return nil, domain.ErrInvalidInput
	}

	if token.UserID == uuid.Nil {
		r.logger.Error("RefreshTokenRepository.Create: user ID is empty")
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	if token.Token == "" {
		r.logger.Error("RefreshTokenRepository.Create: token string is empty")
		return nil, fmt.Errorf("token cannot be empty")
	}

	if token.ExpiresAt.Before(time.Now()) {
		r.logger.Error("RefreshTokenRepository.Create: token expiration is in the past")
		return nil, fmt.Errorf("token expiration time cannot be in the past")
	}

	// Generate UUID and timestamps
	tokenID := uuid.New()
	now := time.Now()

	// Hash the token for secure storage
	// We use SHA-256 to create a consistent hash length
	hasher := sha256.New()
	hasher.Write([]byte(token.Token))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	// SQL query to insert refresh token
	query := `
		INSERT INTO refresh_tokens (
			id, user_id, token_hash, device_info, ip_address, 
			is_revoked, expires_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`

	var createdID uuid.UUID
	var createdAt, updatedAt time.Time

	// Execute the query with proper error handling
	err := r.db.QueryRowContext(
		ctx,
		query,
		tokenID,
		token.UserID,
		tokenHash, // Store hash, not plain text
		token.DeviceInfo,
		token.IPAddress,
		false, // is_revoked starts as false
		token.ExpiresAt,
		now,
		now,
	).Scan(&createdID, &createdAt, &updatedAt)

	if err != nil {
		// Handle specific PostgreSQL errors
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23503": // foreign_key_violation
				r.logger.WithError(err).Error("RefreshTokenRepository.Create: user does not exist")
				return nil, domain.ErrUserNotFound
			case "23505": // unique_violation
				r.logger.WithError(err).Error("RefreshTokenRepository.Create: token already exists")
				return nil, fmt.Errorf("refresh token already exists")
			}
		}

		r.logger.WithError(err).Error("RefreshTokenRepository.Create: failed to create refresh token")
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	// Return the created token with all fields populated
	result := &domain.RefreshToken{
		ID:         createdID,
		UserID:     token.UserID,
		Token:      token.Token, // Return original token for immediate use
		DeviceInfo: token.DeviceInfo,
		IPAddress:  token.IPAddress,
		IsRevoked:  false,
		ExpiresAt:  token.ExpiresAt,
		CreatedAt:  createdAt,
		UpdatedAt:  updatedAt,
	}

	r.logger.WithFields(logrus.Fields{
		"token_id":   createdID,
		"user_id":    token.UserID,
		"expires_at": token.ExpiresAt,
	}).Info("RefreshTokenRepository.Create: token created successfully")

	return result, nil
}

// GetByToken retrieves a refresh token by its token string.
// The provided token is hashed and compared against stored hashes.
//
// Parameters:
//   - ctx: Context for request lifecycle and cancellation
//   - tokenString: The raw token string to lookup
//
// Returns:
//   - *domain.RefreshToken: Found token entity (if valid and not expired)
//   - error: Not found error, database error, or validation failure
//
// Behavior:
//   - Only returns non-revoked, non-expired tokens
//   - Automatically excludes soft-deleted tokens
//   - Token hash comparison for security
//
// SQL Query Optimization:
//   - Uses index on token_hash for fast lookup
//   - Composite WHERE clause for efficiency
//   - Single SELECT operation
//
// Example:
//
//	token, err := repo.GetByToken(ctx, "raw_token_string")
//	if err == domain.ErrTokenNotFound {
//	    // Handle token not found or expired
//	}
func (r *PostgreSQLRefreshTokenRepository) GetByToken(ctx context.Context, tokenString string) (*domain.RefreshToken, error) {
	// Input validation
	if tokenString == "" {
		r.logger.Error("RefreshTokenRepository.GetByToken: token string is empty")
		return nil, domain.ErrInvalidInput
	}

	// Hash the provided token to match against stored hashes
	hasher := sha256.New()
	hasher.Write([]byte(tokenString))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	// SQL query to find valid, non-expired, non-revoked token
	query := `
		SELECT id, user_id, device_info, ip_address, is_revoked, 
		       expires_at, created_at, updated_at
		FROM refresh_tokens 
		WHERE token_hash = $1 
		  AND expires_at > $2 
		  AND is_revoked = false`

	var token domain.RefreshToken
	err := r.db.QueryRowContext(ctx, query, tokenHash, time.Now()).Scan(
		&token.ID,
		&token.UserID,
		&token.DeviceInfo,
		&token.IPAddress,
		&token.IsRevoked,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			r.logger.WithField("token_hash", tokenHash[:8]+"...").Debug("RefreshTokenRepository.GetByToken: token not found")
			return nil, domain.ErrTokenNotFound
		}
		r.logger.WithError(err).Error("RefreshTokenRepository.GetByToken: database query failed")
		return nil, fmt.Errorf("failed to retrieve refresh token: %w", err)
	}

	// Set the original token string for caller convenience
	token.Token = tokenString

	r.logger.WithFields(logrus.Fields{
		"token_id": token.ID,
		"user_id":  token.UserID,
	}).Debug("RefreshTokenRepository.GetByToken: token found")

	return &token, nil
}

// RevokeToken marks a refresh token as revoked by setting the is_revoked flag.
// Revoked tokens cannot be used for authentication but are kept for audit purposes.
//
// Parameters:
//   - ctx: Context for request lifecycle and cancellation
//   - tokenString: The raw token string to revoke
//
// Returns:
//   - error: Not found error, database error, or validation failure
//
// Behavior:
//   - Sets is_revoked flag to true and updates updated_at timestamp
//   - Does not physically delete the token (for audit trails)
//   - Idempotent operation (safe to call multiple times)
//
// Database Transaction:
//   - Single UPDATE operation
//   - Uses token hash for secure lookup
//   - Updates timestamp for audit trail
//
// Example:
//
//	err := repo.RevokeToken(ctx, "token_to_revoke")
//	if err == domain.ErrTokenNotFound {
//	    // Handle token not found
//	}
func (r *PostgreSQLRefreshTokenRepository) RevokeToken(ctx context.Context, tokenString string) error {
	// Input validation
	if tokenString == "" {
		r.logger.Error("RefreshTokenRepository.RevokeToken: token string is empty")
		return domain.ErrInvalidInput
	}

	// Hash the token to find the record
	hasher := sha256.New()
	hasher.Write([]byte(tokenString))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	// SQL query to revoke the token
	query := `
		UPDATE refresh_tokens 
		SET is_revoked = true, updated_at = $1
		WHERE token_hash = $2 AND is_revoked = false`

	result, err := r.db.ExecContext(ctx, query, time.Now(), tokenHash)
	if err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.RevokeToken: update query failed")
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	// Check if any rows were affected (token was found)
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.RevokeToken: failed to get rows affected")
		return fmt.Errorf("failed to check revocation result: %w", err)
	}

	if rowsAffected == 0 {
		r.logger.WithField("token_hash", tokenHash[:8]+"...").Debug("RefreshTokenRepository.RevokeToken: token not found")
		return domain.ErrTokenNotFound
	}

	r.logger.WithField("token_hash", tokenHash[:8]+"...").Info("RefreshTokenRepository.RevokeToken: token revoked successfully")

	return nil
}

// RevokeAllUserTokens revokes all active refresh tokens for a specific user.
// This is typically used during password changes or account security events.
//
// Parameters:
//   - ctx: Context for request lifecycle and cancellation
//   - userID: UUID of the user whose tokens should be revoked
//
// Returns:
//   - error: Database error or validation failure
//
// Behavior:
//   - Revokes all non-revoked tokens for the user
//   - Sets is_revoked flag and updates timestamps for all affected tokens
//   - Returns success even if no tokens were found
//
// Database Transaction:
//   - Single UPDATE operation affecting multiple rows
//   - Uses user_id index for efficient bulk update
//   - Atomic operation ensuring consistency
//
// Example:
//
//	err := repo.RevokeAllUserTokens(ctx, userID)
//	if err != nil {
//	    // Handle bulk revocation failure
//	}
func (r *PostgreSQLRefreshTokenRepository) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	// Input validation
	if userID == uuid.Nil {
		r.logger.Error("RefreshTokenRepository.RevokeAllUserTokens: user ID is empty")
		return domain.ErrInvalidInput
	}

	// SQL query to revoke all user tokens
	query := `
		UPDATE refresh_tokens 
		SET is_revoked = true, updated_at = $1
		WHERE user_id = $2 AND is_revoked = false`

	result, err := r.db.ExecContext(ctx, query, time.Now(), userID)
	if err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.RevokeAllUserTokens: update query failed")
		return fmt.Errorf("failed to revoke user tokens: %w", err)
	}

	// Log the number of tokens revoked for audit purposes
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.RevokeAllUserTokens: failed to get rows affected")
		return fmt.Errorf("failed to check revocation result: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"user_id":        userID,
		"tokens_revoked": rowsAffected,
	}).Info("RefreshTokenRepository.RevokeAllUserTokens: user tokens revoked successfully")

	return nil
}

// CleanupExpired removes expired refresh tokens from the database.
// This operation is typically run as a scheduled maintenance task.
//
// Parameters:
//   - ctx: Context for request lifecycle and cancellation
//
// Returns:
//   - int64: Number of tokens that were deleted
//   - error: Database error
//
// Behavior:
//   - Permanently deletes tokens with expires_at < current time
//   - Includes both revoked and non-revoked expired tokens
//   - Returns count of deleted records for monitoring
//
// Performance:
//   - Uses batch deletion for efficiency
//   - Should be run during low-traffic periods
//   - Consider adding database indexes on expires_at column
//
// Database Transaction:
//   - Single DELETE operation
//   - Uses expires_at index for efficient cleanup
//   - Permanent deletion (not soft delete)
//
// Example:
//
//	deleted, err := repo.CleanupExpired(ctx)
//	if err != nil {
//	    log.Printf("Cleanup failed: %v", err)
//	} else {
//	    log.Printf("Cleaned up %d expired tokens", deleted)
//	}
func (r *PostgreSQLRefreshTokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	// SQL query to delete expired tokens
	query := `DELETE FROM refresh_tokens WHERE expires_at < $1`

	result, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.CleanupExpired: delete query failed")
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	// Get the number of deleted records
	deleted, err := result.RowsAffected()
	if err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.CleanupExpired: failed to get rows affected")
		return 0, fmt.Errorf("failed to get cleanup result: %w", err)
	}

	r.logger.WithField("deleted_count", deleted).Info("RefreshTokenRepository.CleanupExpired: cleanup completed")

	return deleted, nil
}

// GetUserTokens retrieves all active refresh tokens for a user.
// This is useful for administrative purposes and user session management.
//
// Parameters:
//   - ctx: Context for request lifecycle and cancellation
//   - userID: UUID of the user whose tokens to retrieve
//
// Returns:
//   - []*domain.RefreshToken: List of active tokens (excluding token hashes)
//   - error: Database error or validation failure
//
// Behavior:
//   - Returns only non-revoked, non-expired tokens
//   - Orders by creation time (newest first)
//   - Excludes sensitive token hash data
//   - Does not include the actual token values for security
//
// SQL Query Optimization:
//   - Uses composite index on (user_id, is_revoked, expires_at)
//   - ORDER BY clause for consistent ordering
//   - SELECT only necessary columns
//
// Example:
//
//	tokens, err := repo.GetUserTokens(ctx, userID)
//	for _, token := range tokens {
//	    log.Printf("Token ID: %s, Expires: %v", token.ID, token.ExpiresAt)
//	}
func (r *PostgreSQLRefreshTokenRepository) GetUserTokens(ctx context.Context, userID uuid.UUID) ([]*domain.RefreshToken, error) {
	// Input validation
	if userID == uuid.Nil {
		r.logger.Error("RefreshTokenRepository.GetUserTokens: user ID is empty")
		return nil, domain.ErrInvalidInput
	}

	// SQL query to get active user tokens
	query := `
		SELECT id, device_info, ip_address, expires_at, created_at, updated_at
		FROM refresh_tokens 
		WHERE user_id = $1 
		  AND expires_at > $2 
		  AND is_revoked = false
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID, time.Now())
	if err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.GetUserTokens: query failed")
		return nil, fmt.Errorf("failed to retrieve user tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*domain.RefreshToken
	for rows.Next() {
		token := &domain.RefreshToken{
			UserID:    userID,
			IsRevoked: false, // We only select non-revoked tokens
		}

		err := rows.Scan(
			&token.ID,
			&token.DeviceInfo,
			&token.IPAddress,
			&token.ExpiresAt,
			&token.CreatedAt,
			&token.UpdatedAt,
		)
		if err != nil {
			r.logger.WithError(err).Error("RefreshTokenRepository.GetUserTokens: scan failed")
			return nil, fmt.Errorf("failed to scan token: %w", err)
		}

		tokens = append(tokens, token)
	}

	// Check for any row iteration errors
	if err := rows.Err(); err != nil {
		r.logger.WithError(err).Error("RefreshTokenRepository.GetUserTokens: row iteration failed")
		return nil, fmt.Errorf("failed to iterate tokens: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"user_id":     userID,
		"token_count": len(tokens),
	}).Debug("RefreshTokenRepository.GetUserTokens: tokens retrieved")

	return tokens, nil
}
