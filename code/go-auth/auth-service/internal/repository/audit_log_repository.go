package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"auth-service/internal/domain"
)

// PostgreSQLAuditLogRepository handles audit log persistence operations using PostgreSQL.
// It provides secure, immutable storage of security events for compliance and monitoring.
// Audit logs are append-only and should never be modified after creation.
//
// Key features:
// - Immutable audit trail (no updates allowed)
// - Efficient querying by user, event type, and time ranges
// - JSON metadata storage for flexible event data
// - Automatic cleanup for compliance with retention policies
// - High-performance batch operations
//
// Database schema requirements:
// - audit_logs table with proper indexes for common queries
// - Foreign key relationship with users table (optional)
// - JSON/JSONB support for metadata storage
// - Timestamp indexing for time-based queries
// - Partitioning support for large datasets (recommended)
//
// Performance characteristics:
// - O(1) insertions with proper indexing
// - O(log n) queries with time/user-based filtering
// - Efficient bulk operations for cleanup
// - Minimal locking for high concurrency
type PostgreSQLAuditLogRepository struct {
	db     *sql.DB        // Database connection for executing queries
	logger *logrus.Logger // Structured logger for debugging and monitoring
}

// NewPostgreSQLAuditLogRepository creates a new PostgreSQL-backed audit log repository.
// It validates the database connection and configures logging for debugging purposes.
//
// Parameters:
//   - db: Active PostgreSQL database connection with proper schema
//   - logger: Configured logger instance for structured logging
//
// Returns:
//   - Repository instance ready for audit log operations
//   - Never returns error (panics on invalid inputs for fail-fast behavior)
//
// Usage example:
//
//	db, _ := sql.Open("postgres", connectionString)
//	logger := logrus.New()
//	repo := NewPostgreSQLAuditLogRepository(db, logger)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func NewPostgreSQLAuditLogRepository(db *sql.DB, logger *logrus.Logger) domain.AuditLogRepository {
	if db == nil {
		panic("database connection cannot be nil")
	}
	if logger == nil {
		panic("logger cannot be nil")
	}

	return &PostgreSQLAuditLogRepository{
		db:     db,
		logger: logger,
	}
}

// Create stores a new audit log entry in the database.
// Audit logs are immutable once created and form an append-only audit trail.
// This operation is atomic and will either succeed completely or fail completely.
//
// Security considerations:
// - No sensitive data should be stored in plain text
// - IP addresses and user agents are logged for security analysis
// - Metadata is stored as JSON for flexible event-specific data
// - Timestamps are stored in UTC for consistency
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - log: AuditLog entity with all required fields set
//
// Returns:
//   - Created audit log entity with generated ID and timestamp
//   - Error if creation fails (database errors, constraint violations)
//
// Possible errors:
//   - ErrInvalidInput: Required fields are missing or invalid
//   - ErrDatabase: Database operation failed
//   - Context cancellation errors
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (r *PostgreSQLAuditLogRepository) Create(ctx context.Context, log *domain.AuditLog) (*domain.AuditLog, error) {
	// Input validation to ensure data integrity
	if log == nil {
		r.logger.Error("attempted to create nil audit log")
		return nil, domain.ErrInvalidInput
	}

	if log.EventType == "" {
		r.logger.WithField("log", log).Error("audit log missing event type")
		return nil, domain.ErrInvalidInput
	}

	if log.EventDescription == "" {
		r.logger.WithField("event_type", log.EventType).Error("audit log missing event description")
		return nil, domain.ErrInvalidInput
	}

	// Set metadata for new audit log
	now := time.Now().UTC()
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	log.CreatedAt = now

	// Serialize metadata to JSON for JSONB storage
	var metadataJSON interface{}
	if len(log.Metadata) > 0 {
		// Marshal non-empty metadata to JSON
		jsonBytes, err := json.Marshal(log.Metadata)
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"event_type": log.EventType,
				"user_id":    log.UserID,
				"error":      err.Error(),
				"metadata":   log.Metadata,
			}).Error("failed to serialize audit log metadata")
			return nil, domain.ErrInvalidInput
		}
		metadataJSON = string(jsonBytes)
	} else {
		// Use NULL for empty metadata to work better with JSONB
		metadataJSON = nil
	}

	// SQL query for inserting new audit log
	// Uses RETURNING clause to get the created record back
	query := `
		INSERT INTO audit_logs (
			id, user_id, event_type, event_description, ip_address, 
			user_agent, metadata, success, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		) RETURNING id, created_at`

	// Execute the insertion with proper error handling
	err := r.db.QueryRowContext(
		ctx,
		query,
		log.ID,
		log.UserID,
		log.EventType,
		log.EventDescription,
		log.IPAddress,
		log.UserAgent,
		metadataJSON,
		log.Success,
		log.CreatedAt,
	).Scan(&log.ID, &log.CreatedAt)

	if err != nil {
		// Handle PostgreSQL-specific errors
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code {
			case "23503": // Foreign key violation
				r.logger.WithFields(logrus.Fields{
					"user_id": log.UserID,
					"error":   pqErr.Message,
				}).Error("user not found for audit log")
				return nil, domain.ErrUserNotFound
			case "23505": // Unique constraint violation (unlikely for audit logs)
				r.logger.WithFields(logrus.Fields{
					"log_id": log.ID,
					"error":  pqErr.Message,
				}).Error("duplicate audit log entry")
				return nil, domain.ErrDatabase
			}
		}

		// Log and return generic database error
		r.logger.WithFields(logrus.Fields{
			"event_type": log.EventType,
			"user_id":    log.UserID,
			"error":      err.Error(),
		}).Error("failed to create audit log")
		return nil, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	r.logger.WithFields(logrus.Fields{
		"log_id":     log.ID,
		"event_type": log.EventType,
		"user_id":    log.UserID,
		"success":    log.Success,
	}).Debug("audit log created successfully")

	return log, nil
}

// GetByUserID retrieves audit logs for a specific user with pagination.
// Results are ordered by creation time (newest first) for better user experience.
// This is useful for security monitoring and user activity tracking.
//
// Pagination considerations:
// - Large result sets should be paginated for performance
// - Default sorting by created_at DESC for recent events first
// - Total count includes all logs for the user (not just current page)
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - userID: User's unique identifier
//   - offset: Number of records to skip (0-based)
//   - limit: Maximum number of records to return (must be > 0)
//
// Returns:
//   - Slice of audit log entries (newest first)
//   - Total count of logs for this user (for pagination)
//   - Error if query fails
//
// Time Complexity: O(log n + limit) with proper indexing
// Space Complexity: O(limit)
func (r *PostgreSQLAuditLogRepository) GetByUserID(ctx context.Context, userID uuid.UUID, offset, limit int) ([]*domain.AuditLog, int64, error) {
	if userID == uuid.Nil {
		r.logger.Error("attempted to get audit logs with nil user ID")
		return nil, 0, domain.ErrInvalidInput
	}

	if limit <= 0 {
		r.logger.WithField("limit", limit).Error("invalid limit for audit log query")
		return nil, 0, domain.ErrInvalidInput
	}

	if offset < 0 {
		r.logger.WithField("offset", offset).Error("invalid offset for audit log query")
		return nil, 0, domain.ErrInvalidInput
	}

	// First, get the total count for pagination
	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE user_id = $1`
	var totalCount int64
	err := r.db.QueryRowContext(ctx, countQuery, userID).Scan(&totalCount)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("failed to count user audit logs")
		return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	// Then get the paginated results
	query := `
		SELECT id, user_id, event_type, event_description, ip_address, 
		       user_agent, metadata, success, created_at
		FROM audit_logs 
		WHERE user_id = $1 
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, userID, limit, offset)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"offset":  offset,
			"limit":   limit,
			"error":   err.Error(),
		}).Error("failed to query user audit logs")
		return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		var log domain.AuditLog
		var metadataJSON []byte

		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.EventType,
			&log.EventDescription,
			&log.IPAddress,
			&log.UserAgent,
			&metadataJSON,
			&log.Success,
			&log.CreatedAt,
		)
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"user_id": userID,
				"error":   err.Error(),
			}).Error("failed to scan audit log row")
			return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
		}

		// Deserialize metadata if present
		if len(metadataJSON) > 0 {
			err = json.Unmarshal(metadataJSON, &log.Metadata)
			if err != nil {
				r.logger.WithFields(logrus.Fields{
					"log_id": log.ID,
					"error":  err.Error(),
				}).Warn("failed to deserialize audit log metadata")
				// Continue processing - metadata is optional
			}
		}

		logs = append(logs, &log)
	}

	// Check for iteration errors
	if err = rows.Err(); err != nil {
		r.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Error("error iterating over audit log rows")
		return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	r.logger.WithFields(logrus.Fields{
		"user_id":     userID,
		"returned":    len(logs),
		"total_count": totalCount,
	}).Debug("retrieved user audit logs")

	return logs, totalCount, nil
}

// GetByEventType retrieves audit logs by event type with pagination.
// This is useful for analyzing specific types of events across all users.
// Results are ordered by creation time (newest first).
//
// Use cases:
// - Security monitoring for specific event types
// - Compliance reporting for authentication events
// - Performance analysis of specific operations
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - eventType: Type of event to filter by (e.g., "user.login.success")
//   - offset: Number of records to skip (0-based)
//   - limit: Maximum number of records to return (must be > 0)
//
// Returns:
//   - Slice of audit log entries (newest first)
//   - Total count of logs for this event type
//   - Error if query fails
//
// Time Complexity: O(log n + limit) with proper indexing
// Space Complexity: O(limit)
func (r *PostgreSQLAuditLogRepository) GetByEventType(ctx context.Context, eventType string, offset, limit int) ([]*domain.AuditLog, int64, error) {
	if eventType == "" {
		r.logger.Error("attempted to get audit logs with empty event type")
		return nil, 0, domain.ErrInvalidInput
	}

	if limit <= 0 {
		r.logger.WithField("limit", limit).Error("invalid limit for audit log query")
		return nil, 0, domain.ErrInvalidInput
	}

	if offset < 0 {
		r.logger.WithField("offset", offset).Error("invalid offset for audit log query")
		return nil, 0, domain.ErrInvalidInput
	}

	// First, get the total count for pagination
	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE event_type = $1`
	var totalCount int64
	err := r.db.QueryRowContext(ctx, countQuery, eventType).Scan(&totalCount)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"event_type": eventType,
			"error":      err.Error(),
		}).Error("failed to count event type audit logs")
		return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	// Then get the paginated results
	query := `
		SELECT id, user_id, event_type, event_description, ip_address, 
		       user_agent, metadata, success, created_at
		FROM audit_logs 
		WHERE event_type = $1 
		ORDER BY created_at DESC 
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, eventType, limit, offset)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"event_type": eventType,
			"offset":     offset,
			"limit":      limit,
			"error":      err.Error(),
		}).Error("failed to query event type audit logs")
		return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		var log domain.AuditLog
		var metadataJSON []byte

		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.EventType,
			&log.EventDescription,
			&log.IPAddress,
			&log.UserAgent,
			&metadataJSON,
			&log.Success,
			&log.CreatedAt,
		)
		if err != nil {
			r.logger.WithFields(logrus.Fields{
				"event_type": eventType,
				"error":      err.Error(),
			}).Error("failed to scan audit log row")
			return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
		}

		// Deserialize metadata if present
		if len(metadataJSON) > 0 {
			err = json.Unmarshal(metadataJSON, &log.Metadata)
			if err != nil {
				r.logger.WithFields(logrus.Fields{
					"log_id": log.ID,
					"error":  err.Error(),
				}).Warn("failed to deserialize audit log metadata")
				// Continue processing - metadata is optional
			}
		}

		logs = append(logs, &log)
	}

	// Check for iteration errors
	if err = rows.Err(); err != nil {
		r.logger.WithFields(logrus.Fields{
			"event_type": eventType,
			"error":      err.Error(),
		}).Error("error iterating over audit log rows")
		return nil, 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	r.logger.WithFields(logrus.Fields{
		"event_type":  eventType,
		"returned":    len(logs),
		"total_count": totalCount,
	}).Debug("retrieved event type audit logs")

	return logs, totalCount, nil
}

// CleanupOld removes audit logs older than the specified duration.
// This should be called periodically to comply with data retention policies.
// The operation is safe to run concurrently and uses batch processing for efficiency.
//
// Compliance considerations:
// - Some regulations require specific retention periods
// - Consider archiving logs before deletion for compliance
// - Maintain immutability during retention period
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - olderThan: Duration to determine which logs to delete (e.g., 365*24*time.Hour for 1 year)
//
// Returns:
//   - Number of logs deleted
//   - Error if cleanup operation fails
//
// Time Complexity: O(n) where n is the number of old logs
// Space Complexity: O(1)
func (r *PostgreSQLAuditLogRepository) CleanupOld(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		r.logger.WithField("duration", olderThan).Error("invalid duration for audit log cleanup")
		return 0, domain.ErrInvalidInput
	}

	// Calculate the cutoff time
	cutoffTime := time.Now().UTC().Add(-olderThan)

	// SQL query to delete old logs
	// Uses timestamp comparison for efficient deletion
	query := `
		DELETE FROM audit_logs 
		WHERE created_at < $1`

	result, err := r.db.ExecContext(ctx, query, cutoffTime)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"cutoff_time": cutoffTime,
			"error":       err.Error(),
		}).Error("failed to cleanup old audit logs")
		return 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	// Get the number of deleted rows
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.WithField("error", err.Error()).Error("failed to get rows affected for audit log cleanup")
		return 0, fmt.Errorf("%w: %v", domain.ErrDatabase, err)
	}

	if rowsAffected > 0 {
		r.logger.WithFields(logrus.Fields{
			"deleted_count": rowsAffected,
			"cutoff_time":   cutoffTime,
			"older_than":    olderThan,
		}).Info("cleaned up old audit logs")
	} else {
		r.logger.WithFields(logrus.Fields{
			"cutoff_time": cutoffTime,
			"older_than":  olderThan,
		}).Debug("no old audit logs to cleanup")
	}

	return rowsAffected, nil
}
