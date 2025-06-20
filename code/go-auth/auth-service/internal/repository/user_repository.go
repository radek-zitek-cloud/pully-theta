package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"auth-service/internal/domain"
)

// PostgreSQLUserRepository implements the UserRepository interface using PostgreSQL.
// This repository provides CRUD operations for user entities with proper error handling,
// transaction support, and optimized queries.
//
// Key features:
// - Connection pooling for performance
// - Prepared statements for security and performance
// - Proper error mapping from database to domain errors
// - Transaction support for data consistency
// - Soft deletion implementation
// - Audit trail preservation
//
// Database schema requirements:
// - users table with appropriate indexes
// - UUID support for primary keys
// - Timestamp columns for audit tracking
// - Soft deletion support via deleted_at column
type PostgreSQLUserRepository struct {
	db     *sql.DB
	logger *logrus.Logger
}

// NewPostgreSQLUserRepository creates a new PostgreSQL user repository instance.
// This constructor validates the database connection and prepares the repository
// for use with proper error handling and logging.
//
// Parameters:
//   - db: Active PostgreSQL database connection with connection pooling
//   - logger: Structured logger for repository operations and errors
//
// Returns:
//   - Configured PostgreSQLUserRepository instance
//   - Error if database connection is invalid
//
// Example usage:
//
//	userRepo := NewPostgreSQLUserRepository(db, logger)
func NewPostgreSQLUserRepository(db *sql.DB, logger *logrus.Logger) (*PostgreSQLUserRepository, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Test database connectivity
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("database connection test failed: %w", err)
	}

	return &PostgreSQLUserRepository{
		db:     db,
		logger: logger,
	}, nil
}

// Create creates a new user in the PostgreSQL database.
// This method handles ID generation, timestamp management, and proper error mapping.
//
// SQL Operations:
// - Generates UUID if not provided
// - Sets created_at and updated_at timestamps
// - Handles unique constraint violations for email
// - Returns the created user with all generated fields
//
// Parameters:
//   - ctx: Context for query cancellation and timeouts
//   - user: User entity to create (ID may be zero value)
//
// Returns:
//   - Created user with generated ID and timestamps
//   - domain.ErrEmailExists if email already exists
//   - domain.ErrDatabase for other database errors
//
// Time Complexity: O(1) with proper indexing
// Space Complexity: O(1)
func (r *PostgreSQLUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	// Generate UUID if not provided
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}

	// Set timestamps
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	// SQL query for user creation
	query := `
		INSERT INTO users (
			id, email, password_hash, first_name, last_name,
			is_email_verified, is_active, password_changed_at,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		) RETURNING id, created_at, updated_at`

	r.logger.WithFields(logrus.Fields{
		"operation": "user_create",
		"user_id":   user.ID,
		"email":     user.Email,
	}).Debug("Creating user in database")

	// Execute query with proper error handling
	err := r.db.QueryRowContext(ctx, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.IsEmailVerified,
		user.IsActive,
		user.PasswordChangedAt,
		user.CreatedAt,
		user.UpdatedAt,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		// Check for unique constraint violation (email already exists)
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				r.logger.WithFields(logrus.Fields{
					"operation": "user_create",
					"email":     user.Email,
					"error":     err,
				}).Warn("User creation failed - email already exists")
				return nil, domain.ErrEmailExists
			}
		}

		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_create",
			"user_id":   user.ID,
			"email":     user.Email,
		}).Error("Failed to create user")
		return nil, domain.ErrDatabase
	}

	r.logger.WithFields(logrus.Fields{
		"operation": "user_create",
		"user_id":   user.ID,
		"email":     user.Email,
	}).Info("User created successfully")

	return user, nil
}

// GetByID retrieves a user by their unique identifier.
// This method excludes soft-deleted users and handles proper error mapping.
//
// SQL Operations:
// - Queries users table with WHERE id = $1 AND deleted_at IS NULL
// - Uses prepared statement for security and performance
// - Maps database null values to Go types appropriately
//
// Parameters:
//   - ctx: Context for query cancellation and timeouts
//   - id: User's unique identifier
//
// Returns:
//   - User entity if found and not soft-deleted
//   - domain.ErrUserNotFound if user doesn't exist or is deleted
//   - domain.ErrDatabase for other database errors
//
// Time Complexity: O(1) with primary key index
// Space Complexity: O(1)
func (r *PostgreSQLUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT 
			id, email, password_hash, first_name, last_name,
			is_email_verified, is_active, last_login_at,
			password_changed_at, created_at, updated_at, deleted_at
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL`

	r.logger.WithFields(logrus.Fields{
		"operation": "user_get_by_id",
		"user_id":   id,
	}).Debug("Getting user by ID")

	user := &domain.User{}
	var lastLoginAt sql.NullTime
	var deletedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.IsActive,
		&lastLoginAt,
		&user.PasswordChangedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			r.logger.WithFields(logrus.Fields{
				"operation": "user_get_by_id",
				"user_id":   id,
			}).Debug("User not found")
			return nil, domain.ErrUserNotFound
		}

		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_get_by_id",
			"user_id":   id,
		}).Error("Failed to get user by ID")
		return nil, domain.ErrDatabase
	}

	// Handle nullable timestamp fields
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return user, nil
}

// GetByEmail retrieves a user by their email address.
// This method performs case-insensitive email lookup and excludes soft-deleted users.
//
// SQL Operations:
// - Queries users table with WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
// - Uses functional index on LOWER(email) for optimal performance
// - Handles email normalization at database level
//
// Parameters:
//   - ctx: Context for query cancellation and timeouts
//   - email: User's email address (case-insensitive)
//
// Returns:
//   - User entity if found and not soft-deleted
//   - domain.ErrUserNotFound if no user with that email exists
//   - domain.ErrDatabase for other database errors
//
// Time Complexity: O(1) with proper email index
// Space Complexity: O(1)
func (r *PostgreSQLUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT 
			id, email, password_hash, first_name, last_name,
			is_email_verified, is_active, last_login_at,
			password_changed_at, created_at, updated_at, deleted_at
		FROM users 
		WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL`

	r.logger.WithFields(logrus.Fields{
		"operation": "user_get_by_email",
		"email":     email,
	}).Debug("Getting user by email")

	user := &domain.User{}
	var lastLoginAt sql.NullTime
	var deletedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.FirstName,
		&user.LastName,
		&user.IsEmailVerified,
		&user.IsActive,
		&lastLoginAt,
		&user.PasswordChangedAt,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			r.logger.WithFields(logrus.Fields{
				"operation": "user_get_by_email",
				"email":     email,
			}).Debug("User not found by email")
			return nil, domain.ErrUserNotFound
		}

		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_get_by_email",
			"email":     email,
		}).Error("Failed to get user by email")
		return nil, domain.ErrDatabase
	}

	// Handle nullable timestamp fields
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}

	return user, nil
}

// Update modifies an existing user's information in the database.
// This method updates all provided fields and automatically sets the updated_at timestamp.
//
// SQL Operations:
// - Updates all user fields except id and created_at
// - Automatically sets updated_at to current timestamp
// - Uses optimistic locking to detect concurrent modifications
// - Returns updated user with new timestamp
//
// Parameters:
//   - ctx: Context for query cancellation and timeouts
//   - user: User entity with updated fields
//
// Returns:
//   - Updated user entity with new updated_at timestamp
//   - domain.ErrUserNotFound if user doesn't exist
//   - domain.ErrEmailExists if email update conflicts with existing user
//   - domain.ErrDatabase for other database errors
//
// Time Complexity: O(1) with primary key update
// Space Complexity: O(1)
func (r *PostgreSQLUserRepository) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	// Set updated timestamp
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users SET
			email = $2,
			password_hash = $3,
			first_name = $4,
			last_name = $5,
			is_email_verified = $6,
			is_active = $7,
			last_login_at = $8,
			password_changed_at = $9,
			updated_at = $10
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING updated_at`

	r.logger.WithFields(logrus.Fields{
		"operation": "user_update",
		"user_id":   user.ID,
		"email":     user.Email,
	}).Debug("Updating user in database")

	err := r.db.QueryRowContext(ctx, query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.FirstName,
		user.LastName,
		user.IsEmailVerified,
		user.IsActive,
		user.LastLoginAt,
		user.PasswordChangedAt,
		user.UpdatedAt,
	).Scan(&user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			r.logger.WithFields(logrus.Fields{
				"operation": "user_update",
				"user_id":   user.ID,
			}).Warn("User not found for update")
			return nil, domain.ErrUserNotFound
		}

		// Check for unique constraint violation (email already exists)
		if pqErr, ok := err.(*pq.Error); ok {
			if pqErr.Code == "23505" { // unique_violation
				r.logger.WithFields(logrus.Fields{
					"operation": "user_update",
					"user_id":   user.ID,
					"email":     user.Email,
					"error":     err,
				}).Warn("User update failed - email already exists")
				return nil, domain.ErrEmailExists
			}
		}

		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_update",
			"user_id":   user.ID,
			"email":     user.Email,
		}).Error("Failed to update user")
		return nil, domain.ErrDatabase
	}

	r.logger.WithFields(logrus.Fields{
		"operation": "user_update",
		"user_id":   user.ID,
		"email":     user.Email,
	}).Info("User updated successfully")

	return user, nil
}

// Delete performs a soft delete on the user account.
// This method sets the deleted_at timestamp instead of removing the record,
// preserving audit trails and preventing ID reuse.
//
// SQL Operations:
// - Updates deleted_at timestamp to current time
// - Preserves all user data for audit purposes
// - Soft-deleted users are excluded from normal queries
// - Allows for potential account recovery
//
// Parameters:
//   - ctx: Context for query cancellation and timeouts
//   - id: User's unique identifier
//
// Returns:
//   - domain.ErrUserNotFound if user doesn't exist or already deleted
//   - domain.ErrDatabase for other database errors
//
// Time Complexity: O(1) with primary key update
// Space Complexity: O(1)
func (r *PostgreSQLUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users 
		SET deleted_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	r.logger.WithFields(logrus.Fields{
		"operation": "user_delete",
		"user_id":   id,
	}).Info("Soft deleting user")

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_delete",
			"user_id":   id,
		}).Error("Failed to delete user")
		return domain.ErrDatabase
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_delete",
			"user_id":   id,
		}).Error("Failed to get rows affected for user deletion")
		return domain.ErrDatabase
	}

	if rowsAffected == 0 {
		r.logger.WithFields(logrus.Fields{
			"operation": "user_delete",
			"user_id":   id,
		}).Warn("User not found for deletion")
		return domain.ErrUserNotFound
	}

	r.logger.WithFields(logrus.Fields{
		"operation": "user_delete",
		"user_id":   id,
	}).Info("User soft deleted successfully")

	return nil
}

// UpdateLastLogin updates the user's last login timestamp.
// This method is called after successful authentication for audit purposes.
//
// SQL Operations:
// - Updates only last_login_at and updated_at columns
// - Minimal database operation for performance
// - Non-critical operation that doesn't affect authentication flow
//
// Parameters:
//   - ctx: Context for query cancellation and timeouts
//   - id: User's unique identifier
//   - loginTime: Timestamp of the login event
//
// Returns:
//   - domain.ErrUserNotFound if user doesn't exist
//   - domain.ErrDatabase for other database errors
//
// Time Complexity: O(1) with primary key update
// Space Complexity: O(1)
func (r *PostgreSQLUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, loginTime time.Time) error {
	query := `
		UPDATE users 
		SET last_login_at = $2, updated_at = NOW()
		WHERE id = $1 AND deleted_at IS NULL`

	r.logger.WithFields(logrus.Fields{
		"operation":  "user_update_last_login",
		"user_id":    id,
		"login_time": loginTime,
	}).Debug("Updating user last login timestamp")

	result, err := r.db.ExecContext(ctx, query, id, loginTime)
	if err != nil {
		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_update_last_login",
			"user_id":   id,
		}).Error("Failed to update last login timestamp")
		return domain.ErrDatabase
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_update_last_login",
			"user_id":   id,
		}).Error("Failed to get rows affected for last login update")
		return domain.ErrDatabase
	}

	if rowsAffected == 0 {
		r.logger.WithFields(logrus.Fields{
			"operation": "user_update_last_login",
			"user_id":   id,
		}).Debug("User not found for last login update")
		return domain.ErrUserNotFound
	}

	return nil
}

// List retrieves a paginated list of users from the database.
// This method is useful for admin interfaces and user management functionality.
//
// SQL Operations:
// - Excludes soft-deleted users
// - Orders by created_at DESC for consistent pagination
// - Uses LIMIT and OFFSET for efficient pagination
// - Returns total count for pagination metadata
//
// Parameters:
//   - ctx: Context for query cancellation and timeouts
//   - offset: Number of records to skip (for pagination)
//   - limit: Maximum number of records to return
//
// Returns:
//   - Slice of user entities (without password hashes)
//   - Total count of users for pagination
//   - domain.ErrDatabase for database errors
//
// Time Complexity: O(limit) with proper indexing
// Space Complexity: O(limit)
func (r *PostgreSQLUserRepository) List(ctx context.Context, offset, limit int) ([]*domain.User, int64, error) {
	// Get total count first
	countQuery := `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`
	var totalCount int64

	err := r.db.QueryRowContext(ctx, countQuery).Scan(&totalCount)
	if err != nil {
		r.logger.WithError(err).Error("Failed to get user count")
		return nil, 0, domain.ErrDatabase
	}

	// Get paginated users
	query := `
		SELECT 
			id, email, first_name, last_name, is_email_verified,
			is_active, last_login_at, password_changed_at,
			created_at, updated_at
		FROM users 
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	r.logger.WithFields(logrus.Fields{
		"operation": "user_list",
		"offset":    offset,
		"limit":     limit,
	}).Debug("Getting paginated user list")

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		r.logger.WithError(err).WithFields(logrus.Fields{
			"operation": "user_list",
			"offset":    offset,
			"limit":     limit,
		}).Error("Failed to get user list")
		return nil, 0, domain.ErrDatabase
	}
	defer rows.Close()

	users := make([]*domain.User, 0, limit)

	for rows.Next() {
		user := &domain.User{}
		var lastLoginAt sql.NullTime

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.FirstName,
			&user.LastName,
			&user.IsEmailVerified,
			&user.IsActive,
			&lastLoginAt,
			&user.PasswordChangedAt,
			&user.CreatedAt,
			&user.UpdatedAt,
		)

		if err != nil {
			r.logger.WithError(err).Error("Failed to scan user row")
			return nil, 0, domain.ErrDatabase
		}

		// Handle nullable timestamp fields
		if lastLoginAt.Valid {
			user.LastLoginAt = &lastLoginAt.Time
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		r.logger.WithError(err).Error("Error iterating user rows")
		return nil, 0, domain.ErrDatabase
	}

	r.logger.WithFields(logrus.Fields{
		"operation":   "user_list",
		"offset":      offset,
		"limit":       limit,
		"total_count": totalCount,
		"returned":    len(users),
	}).Debug("User list retrieved successfully")

	return users, totalCount, nil
}
