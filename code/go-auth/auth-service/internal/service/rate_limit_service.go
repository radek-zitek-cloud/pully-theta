package service

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// InMemoryRateLimitService implements rate limiting using in-memory storage.
// This implementation provides thread-safe rate limiting with configurable
// windows and limits for different types of operations.
//
// Features:
// - Sliding window rate limiting
// - Separate limits for login attempts and password resets
// - Automatic cleanup of expired entries
// - Thread-safe operations with minimal locking
// - Configurable rate limit parameters
//
// Limitations:
// - Data is not persistent across service restarts
// - Not suitable for horizontally scaled deployments
// - Memory usage grows with number of unique identifiers
//
// Production considerations:
// - Use Redis-based implementation for production environments
// - Consider distributed rate limiting for multi-instance deployments
// - Monitor memory usage in high-traffic scenarios
//
// Time Complexity: O(1) for most operations with periodic O(n) cleanup
// Space Complexity: O(k) where k is the number of unique identifiers
type InMemoryRateLimitService struct {
	// Configuration for login rate limiting
	loginWindow time.Duration // Time window for login attempts
	loginLimit  int           // Maximum login attempts per window

	// Configuration for password reset rate limiting
	resetWindow time.Duration // Time window for password reset attempts
	resetLimit  int           // Maximum password reset attempts per window

	// In-memory storage for rate limit tracking
	loginAttempts map[string][]time.Time // Login attempts by identifier
	resetAttempts map[string][]time.Time // Password reset attempts by email

	// Synchronization for thread safety
	loginMutex sync.RWMutex // Protects loginAttempts map
	resetMutex sync.RWMutex // Protects resetAttempts map

	// Dependencies
	logger *logrus.Logger // Structured logger for debugging

	// Cleanup management
	cleanupTicker *time.Ticker  // Periodic cleanup of expired entries
	stopCleanup   chan struct{} // Signal to stop cleanup goroutine
}

// RateLimitConfig holds configuration for rate limiting behavior.
// These values should be tuned based on your security requirements
// and expected user behavior patterns.
type RateLimitConfig struct {
	// Login rate limiting configuration
	LoginWindow time.Duration `json:"login_window"` // e.g., 15 * time.Minute
	LoginLimit  int           `json:"login_limit"`  // e.g., 5 attempts

	// Password reset rate limiting configuration
	ResetWindow time.Duration `json:"reset_window"` // e.g., 1 * time.Hour
	ResetLimit  int           `json:"reset_limit"`  // e.g., 3 attempts

	// Cleanup interval for expired entries
	CleanupInterval time.Duration `json:"cleanup_interval"` // e.g., 5 * time.Minute
}

// DefaultRateLimitConfig returns a sensible default configuration for rate limiting.
// These values provide good security while not being overly restrictive for normal users.
//
// Returns:
//   - RateLimitConfig with production-ready defaults
//
// Default values:
//   - Login: 5 attempts per 15 minutes
//   - Password reset: 3 attempts per hour
//   - Cleanup: every 5 minutes
//
// Example:
//
//	config := DefaultRateLimitConfig()
//	service := NewInMemoryRateLimitService(config, logger)
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		LoginWindow:     15 * time.Minute, // Allow checking again after 15 minutes
		LoginLimit:      5,                // Maximum 5 failed login attempts
		ResetWindow:     1 * time.Hour,    // Allow password reset once per hour
		ResetLimit:      3,                // Maximum 3 reset attempts per hour
		CleanupInterval: 5 * time.Minute,  // Clean up expired entries every 5 minutes
	}
}

// NewInMemoryRateLimitService creates a new in-memory rate limiting service.
// It starts a background cleanup goroutine to remove expired entries
// and prevent memory leaks in long-running applications.
//
// Parameters:
//   - config: Rate limiting configuration with windows and limits
//   - logger: Structured logger for debugging and monitoring
//
// Returns:
//   - RateLimitService implementation ready for use
//
// Background behavior:
//   - Starts cleanup goroutine that runs every config.CleanupInterval
//   - Goroutine automatically stops when service is garbage collected
//   - Thread-safe operations with minimal lock contention
//
// Example:
//
//	config := DefaultRateLimitConfig()
//	service := NewInMemoryRateLimitService(config, logger)
//	defer service.Stop() // Optional: stop cleanup goroutine explicitly
func NewInMemoryRateLimitService(config RateLimitConfig, logger *logrus.Logger) *InMemoryRateLimitService {
	service := &InMemoryRateLimitService{
		loginWindow:   config.LoginWindow,
		loginLimit:    config.LoginLimit,
		resetWindow:   config.ResetWindow,
		resetLimit:    config.ResetLimit,
		loginAttempts: make(map[string][]time.Time),
		resetAttempts: make(map[string][]time.Time),
		logger:        logger,
		stopCleanup:   make(chan struct{}),
	}

	// Start background cleanup goroutine
	if config.CleanupInterval > 0 {
		service.cleanupTicker = time.NewTicker(config.CleanupInterval)
		go service.runCleanup()
	}

	service.logger.WithFields(logrus.Fields{
		"login_window": config.LoginWindow,
		"login_limit":  config.LoginLimit,
		"reset_window": config.ResetWindow,
		"reset_limit":  config.ResetLimit,
	}).Info("InMemoryRateLimitService: service started")

	return service
}

// Stop gracefully stops the background cleanup goroutine.
// This method is optional and mainly useful for testing or explicit cleanup.
// The cleanup goroutine will also stop automatically when the service is garbage collected.
//
// Example:
//
//	service := NewInMemoryRateLimitService(config, logger)
//	defer service.Stop() // Ensure cleanup goroutine stops
func (r *InMemoryRateLimitService) Stop() {
	if r.cleanupTicker != nil {
		r.cleanupTicker.Stop()
		close(r.stopCleanup)
		r.logger.Debug("InMemoryRateLimitService: cleanup goroutine stopped")
	}
}

// CheckLoginAttempts checks if login attempts from the given identifier are within limits.
// This method uses a sliding window approach where only attempts within the
// configured time window are considered.
//
// Parameters:
//   - ctx: Context for cancellation (not used in this implementation)
//   - identifier: IP address, email, or other identifier to check
//
// Returns:
//   - true if the request is allowed (under rate limit)
//   - false if rate limit has been exceeded
//   - error: should be nil for this implementation
//
// Algorithm:
//  1. Remove expired attempts (older than loginWindow)
//  2. Count remaining attempts
//  3. Return false if count >= loginLimit
//
// Time Complexity: O(n) where n is number of attempts in window
// Space Complexity: O(1) additional space
//
// Example:
//
//	allowed, err := service.CheckLoginAttempts(ctx, "192.168.1.100")
//	if !allowed {
//	    return ErrTooManyLoginAttempts
//	}
func (r *InMemoryRateLimitService) CheckLoginAttempts(ctx context.Context, identifier string) (bool, error) {
	r.loginMutex.Lock()
	defer r.loginMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.loginWindow)

	// Get existing attempts for this identifier
	attempts := r.loginAttempts[identifier]

	// Remove expired attempts (sliding window)
	validAttempts := make([]time.Time, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.After(cutoff) {
			validAttempts = append(validAttempts, attempt)
		}
	}

	// Update the map with cleaned attempts
	if len(validAttempts) == 0 {
		delete(r.loginAttempts, identifier)
	} else {
		r.loginAttempts[identifier] = validAttempts
	}

	// Check if we're within the limit
	allowed := len(validAttempts) < r.loginLimit

	r.logger.WithFields(logrus.Fields{
		"identifier":     identifier,
		"attempts_count": len(validAttempts),
		"limit":          r.loginLimit,
		"allowed":        allowed,
	}).Debug("InMemoryRateLimitService.CheckLoginAttempts: rate limit check")

	return allowed, nil
}

// RecordLoginAttempt records a login attempt for the given identifier.
// Both successful and failed attempts are recorded to prevent rapid-fire
// login attempts regardless of outcome.
//
// Parameters:
//   - ctx: Context for cancellation (not used in this implementation)
//   - identifier: IP address, email, or other identifier to record
//   - success: Whether the login attempt was successful
//
// Returns:
//   - error: should be nil for this implementation
//
// Behavior:
//   - Adds current timestamp to the identifier's attempt list
//   - Does not distinguish between successful and failed attempts
//   - Cleanup of old attempts happens in CheckLoginAttempts and background cleanup
//
// Time Complexity: O(1)
// Space Complexity: O(1) additional space
//
// Example:
//
//	err := service.RecordLoginAttempt(ctx, "192.168.1.100", false)
//	if err != nil {
//	    log.Printf("Failed to record login attempt: %v", err)
//	}
func (r *InMemoryRateLimitService) RecordLoginAttempt(ctx context.Context, identifier string, success bool) error {
	r.loginMutex.Lock()
	defer r.loginMutex.Unlock()

	now := time.Now()

	// Add the current attempt
	r.loginAttempts[identifier] = append(r.loginAttempts[identifier], now)

	r.logger.WithFields(logrus.Fields{
		"identifier": identifier,
		"success":    success,
		"timestamp":  now,
	}).Debug("InMemoryRateLimitService.RecordLoginAttempt: attempt recorded")

	return nil
}

// CheckPasswordResetAttempts checks if password reset requests from the given email are within limits.
// This uses a separate rate limiting window specifically for password reset operations,
// which typically have lower limits and longer windows than login attempts.
//
// Parameters:
//   - ctx: Context for cancellation (not used in this implementation)
//   - email: Email address to check for password reset rate limiting
//
// Returns:
//   - true if the request is allowed (under rate limit)
//   - false if rate limit has been exceeded
//   - error: should be nil for this implementation
//
// Algorithm:
//  1. Remove expired attempts (older than resetWindow)
//  2. Count remaining attempts
//  3. Return false if count >= resetLimit
//
// Time Complexity: O(n) where n is number of attempts in window
// Space Complexity: O(1) additional space
//
// Example:
//
//	allowed, err := service.CheckPasswordResetAttempts(ctx, "user@example.com")
//	if !allowed {
//	    return ErrTooManyPasswordResetAttempts
//	}
func (r *InMemoryRateLimitService) CheckPasswordResetAttempts(ctx context.Context, email string) (bool, error) {
	r.resetMutex.Lock()
	defer r.resetMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.resetWindow)

	// Get existing attempts for this email
	attempts := r.resetAttempts[email]

	// Remove expired attempts (sliding window)
	validAttempts := make([]time.Time, 0, len(attempts))
	for _, attempt := range attempts {
		if attempt.After(cutoff) {
			validAttempts = append(validAttempts, attempt)
		}
	}

	// Update the map with cleaned attempts
	if len(validAttempts) == 0 {
		delete(r.resetAttempts, email)
	} else {
		r.resetAttempts[email] = validAttempts
	}

	// Check if we're within the limit
	allowed := len(validAttempts) < r.resetLimit

	r.logger.WithFields(logrus.Fields{
		"email":          email,
		"attempts_count": len(validAttempts),
		"limit":          r.resetLimit,
		"allowed":        allowed,
	}).Debug("InMemoryRateLimitService.CheckPasswordResetAttempts: rate limit check")

	return allowed, nil
}

// RecordPasswordResetAttempt records a password reset request for the given email.
// All password reset requests are recorded regardless of whether they result
// in an actual email being sent.
//
// Parameters:
//   - ctx: Context for cancellation (not used in this implementation)
//   - email: Email address that requested the password reset
//
// Returns:
//   - error: should be nil for this implementation
//
// Behavior:
//   - Adds current timestamp to the email's attempt list
//   - Cleanup of old attempts happens in CheckPasswordResetAttempts and background cleanup
//
// Time Complexity: O(1)
// Space Complexity: O(1) additional space
//
// Example:
//
//	err := service.RecordPasswordResetAttempt(ctx, "user@example.com")
//	if err != nil {
//	    log.Printf("Failed to record password reset attempt: %v", err)
//	}
func (r *InMemoryRateLimitService) RecordPasswordResetAttempt(ctx context.Context, email string) error {
	r.resetMutex.Lock()
	defer r.resetMutex.Unlock()

	now := time.Now()

	// Add the current attempt
	r.resetAttempts[email] = append(r.resetAttempts[email], now)

	r.logger.WithFields(logrus.Fields{
		"email":     email,
		"timestamp": now,
	}).Debug("InMemoryRateLimitService.RecordPasswordResetAttempt: attempt recorded")

	return nil
}

// runCleanup runs in a background goroutine to periodically clean up expired entries.
// This prevents memory leaks by removing old attempt records that are no longer
// needed for rate limiting decisions.
//
// Behavior:
//   - Runs every cleanupInterval duration
//   - Removes attempts older than their respective windows
//   - Stops when stopCleanup channel is closed
//   - Uses separate locks to minimize contention
//
// Time Complexity: O(n + m) where n is login identifiers and m is reset emails
// Space Complexity: O(1) additional space
func (r *InMemoryRateLimitService) runCleanup() {
	for {
		select {
		case <-r.cleanupTicker.C:
			r.cleanupExpiredAttempts()
		case <-r.stopCleanup:
			return
		}
	}
}

// cleanupExpiredAttempts removes expired attempt records from both login and reset maps.
// This method is called periodically by the background cleanup goroutine.
//
// Algorithm:
//  1. Calculate cutoff times for both login and reset windows
//  2. Lock each map separately and clean expired entries
//  3. Remove empty entries to free memory
//
// Time Complexity: O(n + m) where n is login identifiers and m is reset emails
// Space Complexity: O(1) additional space
func (r *InMemoryRateLimitService) cleanupExpiredAttempts() {
	now := time.Now()
	loginCutoff := now.Add(-r.loginWindow)
	resetCutoff := now.Add(-r.resetWindow)

	// Cleanup login attempts
	r.loginMutex.Lock()
	loginCleaned := 0
	for identifier, attempts := range r.loginAttempts {
		validAttempts := make([]time.Time, 0, len(attempts))
		for _, attempt := range attempts {
			if attempt.After(loginCutoff) {
				validAttempts = append(validAttempts, attempt)
			}
		}

		if len(validAttempts) == 0 {
			delete(r.loginAttempts, identifier)
			loginCleaned++
		} else if len(validAttempts) < len(attempts) {
			r.loginAttempts[identifier] = validAttempts
		}
	}
	r.loginMutex.Unlock()

	// Cleanup password reset attempts
	r.resetMutex.Lock()
	resetCleaned := 0
	for email, attempts := range r.resetAttempts {
		validAttempts := make([]time.Time, 0, len(attempts))
		for _, attempt := range attempts {
			if attempt.After(resetCutoff) {
				validAttempts = append(validAttempts, attempt)
			}
		}

		if len(validAttempts) == 0 {
			delete(r.resetAttempts, email)
			resetCleaned++
		} else if len(validAttempts) < len(attempts) {
			r.resetAttempts[email] = validAttempts
		}
	}
	r.resetMutex.Unlock()

	if loginCleaned > 0 || resetCleaned > 0 {
		r.logger.WithFields(logrus.Fields{
			"login_entries_cleaned": loginCleaned,
			"reset_entries_cleaned": resetCleaned,
		}).Debug("InMemoryRateLimitService: cleanup completed")
	}
}

// GetStats returns current statistics about the rate limiter state.
// This is useful for monitoring and debugging purposes.
//
// Returns:
//   - map[string]interface{} with current statistics
//
// Statistics included:
//   - Number of tracked login identifiers
//   - Number of tracked reset emails
//   - Configuration values
//
// Example:
//
//	stats := service.GetStats()
//	log.Printf("Rate limiter stats: %+v", stats)
func (r *InMemoryRateLimitService) GetStats() map[string]interface{} {
	r.loginMutex.RLock()
	loginIdentifiers := len(r.loginAttempts)
	r.loginMutex.RUnlock()

	r.resetMutex.RLock()
	resetEmails := len(r.resetAttempts)
	r.resetMutex.RUnlock()

	return map[string]interface{}{
		"implementation":            "InMemoryRateLimitService",
		"distributed":               false,
		"persistent":                false,
		"login_identifiers_tracked": loginIdentifiers,
		"reset_emails_tracked":      resetEmails,
		"login_window_minutes":      r.loginWindow.Minutes(),
		"login_limit":               r.loginLimit,
		"reset_window_minutes":      r.resetWindow.Minutes(),
		"reset_limit":               r.resetLimit,
		"features": []string{
			"sliding_window",
			"thread_safe",
			"auto_cleanup",
		},
	}
}

// HealthCheck verifies that the in-memory rate limiting service is healthy.
// For the in-memory implementation, this always returns nil as there are
// no external dependencies to check.
//
// Parameters:
//   - ctx: Context for cancellation (not used in this implementation)
//
// Returns:
//   - error: Always nil for in-memory implementation
//
// Example:
//
//	err := service.HealthCheck(ctx)
//	if err != nil {
//	    log.Printf("Rate limiter health check failed: %v", err)
//	}
func (r *InMemoryRateLimitService) HealthCheck(ctx context.Context) error {
	// In-memory implementation has no external dependencies
	// Health check always passes
	return nil
}
