package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents the core user entity in the authentication system.
// This entity encapsulates all user-related data and business rules.
//
// The User entity follows the following principles:
// - Immutable ID once created
// - Email must be unique across the system
// - Password is stored as a bcrypt hash
// - Timestamps track creation and updates
//
// Security considerations:
// - Password field should never be serialized to JSON
// - Email should be validated and normalized
// - Soft deletion is implemented via DeletedAt field
type User struct {
	// ID is the unique identifier for the user, generated using UUID v4
	// This ensures global uniqueness and prevents enumeration attacks
	ID uuid.UUID `json:"id" db:"id"`

	// Email is the user's email address, used as the primary login identifier
	// Must be unique across the system and follow RFC 5322 format
	Email string `json:"email" db:"email" validate:"required,email,max=255"`

	// PasswordHash stores the bcrypt hash of the user's password
	// The actual password is never stored in plain text
	// This field is excluded from JSON serialization for security
	PasswordHash string `json:"-" db:"password_hash" validate:"required"`

	// FirstName is the user's given name
	FirstName string `json:"first_name" db:"first_name" validate:"required,min=1,max=100"`

	// LastName is the user's family name
	LastName string `json:"last_name" db:"last_name" validate:"required,min=1,max=100"`

	// IsEmailVerified indicates whether the user has verified their email address
	// New users start with false and must verify via email confirmation
	IsEmailVerified bool `json:"is_email_verified" db:"is_email_verified"`

	// IsActive indicates whether the user account is active
	// Inactive accounts cannot authenticate or perform actions
	IsActive bool `json:"is_active" db:"is_active"`

	// LastLoginAt tracks the user's last successful authentication
	// Used for security auditing and inactive account cleanup
	LastLoginAt *time.Time `json:"last_login_at,omitempty" db:"last_login_at"`

	// PasswordChangedAt tracks when the password was last changed
	// Used for password expiry policies and security auditing
	PasswordChangedAt time.Time `json:"password_changed_at" db:"password_changed_at"`

	// CreatedAt tracks when the user account was created
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt tracks when the user account was last modified
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// DeletedAt implements soft deletion - when set, the user is considered deleted
	// This allows for data retention and audit trails
	DeletedAt *time.Time `json:"deleted_at,omitempty" db:"deleted_at"`
}

// RefreshToken represents a JWT refresh token stored in the database.
// Refresh tokens are used to obtain new access tokens without re-authentication.
//
// Security features:
// - Each token has a unique identifier to prevent replay attacks
// - Tokens can be revoked individually or by user
// - Automatic cleanup of expired tokens
// - Device/session tracking for security monitoring
type RefreshToken struct {
	// ID is the unique identifier for this refresh token
	ID uuid.UUID `json:"id" db:"id"`

	// UserID links this token to a specific user
	// Foreign key relationship with User.ID
	UserID uuid.UUID `json:"user_id" db:"user_id" validate:"required"`

	// Token is the actual JWT refresh token string
	// This is what gets sent to clients and validated on refresh requests
	Token string `json:"token" db:"token" validate:"required"`

	// DeviceInfo stores information about the device/client that created this token
	// Used for security monitoring and user session management
	DeviceInfo string `json:"device_info" db:"device_info"`

	// IPAddress stores the IP address from which this token was created
	// Used for security auditing and anomaly detection
	IPAddress string `json:"ip_address" db:"ip_address"`

	// IsRevoked indicates whether this token has been manually revoked
	// Revoked tokens cannot be used to obtain new access tokens
	IsRevoked bool `json:"is_revoked" db:"is_revoked"`

	// ExpiresAt indicates when this refresh token expires
	// Expired tokens are automatically considered invalid
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`

	// CreatedAt tracks when this refresh token was issued
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt tracks when this refresh token was last modified
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// PasswordResetToken represents a token used for password reset operations.
// These tokens are short-lived and single-use for security.
//
// Security features:
// - Short expiration time (typically 1 hour)
// - Single-use tokens that are invalidated after use
// - Cryptographically secure random generation
// - IP address tracking for audit trails
type PasswordResetToken struct {
	// ID is the unique identifier for this reset token
	ID uuid.UUID `json:"id" db:"id"`

	// UserID links this token to a specific user
	UserID uuid.UUID `json:"user_id" db:"user_id" validate:"required"`

	// Token is the secure random token sent to the user's email
	// This should be cryptographically random and URL-safe
	Token string `json:"token" db:"token" validate:"required"`

	// Email stores the email address this reset was requested for
	// Used for validation and audit purposes
	Email string `json:"email" db:"email" validate:"required,email"`

	// IPAddress stores the IP from which the reset was requested
	IPAddress string `json:"ip_address" db:"ip_address"`

	// IsUsed indicates whether this token has been consumed
	// Used tokens cannot be reused for security
	IsUsed bool `json:"is_used" db:"is_used"`

	// ExpiresAt indicates when this token expires (typically 1 hour)
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`

	// CreatedAt tracks when this reset token was created
	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// UpdatedAt tracks when this token was last modified
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// AuditLog represents security-related events for auditing purposes.
// This helps with compliance, security monitoring, and incident response.
//
// Common event types:
// - user.login.success / user.login.failure
// - user.logout
// - user.password.changed
// - user.password.reset.requested
// - token.refresh.success / token.refresh.failure
// - account.created / account.deleted
type AuditLog struct {
	// ID is the unique identifier for this audit entry
	ID uuid.UUID `json:"id" db:"id"`

	// UserID links this event to a user (optional for system events)
	UserID *uuid.UUID `json:"user_id,omitempty" db:"user_id"`

	// EventType categorizes the type of event that occurred
	EventType string `json:"event_type" db:"event_type" validate:"required"`

	// EventDescription provides human-readable details about the event
	EventDescription string `json:"event_description" db:"event_description"`

	// IPAddress stores the IP address from which the event originated
	IPAddress string `json:"ip_address" db:"ip_address"`

	// UserAgent stores the user agent string from the request
	UserAgent string `json:"user_agent" db:"user_agent"`

	// Metadata stores additional structured data about the event
	// Stored as JSON for flexibility in event-specific data
	Metadata map[string]interface{} `json:"metadata,omitempty" db:"metadata"`

	// Success indicates whether the audited operation was successful
	Success bool `json:"success" db:"success"`

	// CreatedAt tracks when this audit event occurred
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// GetFullName returns the user's full name by concatenating first and last names.
// This is a convenience method for display purposes.
//
// Returns:
//   - The concatenated first and last name with a space separator
//
// Time Complexity: O(1)
// Space Complexity: O(n) where n is the length of the names
func (u *User) GetFullName() string {
	return u.FirstName + " " + u.LastName
}

// IsDeleted checks if the user has been soft deleted.
// Soft deleted users should be treated as if they don't exist for most operations.
//
// Returns:
//   - true if the user has been soft deleted (DeletedAt is not nil)
//   - false if the user is active (DeletedAt is nil)
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (u *User) IsDeleted() bool {
	return u.DeletedAt != nil
}

// IsTokenExpired checks if the refresh token has expired.
// Expired tokens should not be accepted for token refresh operations.
//
// Returns:
//   - true if the token has expired (ExpiresAt is before current time)
//   - false if the token is still valid
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (rt *RefreshToken) IsTokenExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsValid checks if the refresh token is valid for use.
// A token is valid if it's not expired and not revoked.
//
// Returns:
//   - true if the token can be used for refresh operations
//   - false if the token is expired or revoked
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsTokenExpired() && !rt.IsRevoked
}

// IsTokenExpired checks if the password reset token has expired.
// Expired reset tokens should not be accepted for password reset operations.
//
// Returns:
//   - true if the token has expired
//   - false if the token is still valid
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (prt *PasswordResetToken) IsTokenExpired() bool {
	return time.Now().After(prt.ExpiresAt)
}

// IsValid checks if the password reset token is valid for use.
// A token is valid if it's not expired and not already used.
//
// Returns:
//   - true if the token can be used for password reset
//   - false if the token is expired or already used
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func (prt *PasswordResetToken) IsValid() bool {
	return !prt.IsTokenExpired() && !prt.IsUsed
}
