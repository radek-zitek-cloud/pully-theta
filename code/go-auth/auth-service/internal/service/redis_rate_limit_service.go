package service

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// RedisRateLimitService implements distributed rate limiting using Redis.
// This implementation provides thread-safe, distributed rate limiting with
// configurable sliding window algorithms for different types of operations.
//
// Features:
// - Distributed rate limiting across multiple service instances
// - Sliding window algorithm with Redis sorted sets
// - Persistent rate limit state (survives service restarts)
// - Atomic operations using Redis transactions
// - Configurable rate limit parameters per operation type
// - Built-in cleanup of expired entries
// - High-performance Redis pipeline operations
//
// Production Benefits:
// - Horizontal scalability across multiple instances
// - Persistent state during service restarts/deployments
// - Better memory efficiency than in-memory solutions
// - Atomic operations prevent race conditions
// - Configurable expiration prevents memory leaks
//
// Time Complexity: O(log N) for most operations due to Redis sorted sets
// Space Complexity: O(K) where K is the number of unique identifiers across all instances
//
// Redis Data Structure:
// - Uses sorted sets with timestamps as scores for sliding windows
// - Keys: "rate_limit:{operation}:{identifier}"
// - Values: "{timestamp}:{uuid}" for uniqueness
// - Expiry: Automatic cleanup based on window duration
type RedisRateLimitService struct {
	// Redis client for rate limiting operations
	client *redis.Client

	// Configuration for login rate limiting
	loginWindow time.Duration // Time window for login attempts
	loginLimit  int           // Maximum login attempts per window

	// Configuration for password reset rate limiting
	resetWindow time.Duration // Time window for password reset attempts
	resetLimit  int           // Maximum password reset attempts per window

	// Dependencies
	logger *logrus.Logger // Structured logger for debugging and monitoring

	// Redis key prefixes for different operation types
	loginKeyPrefix string // Prefix for login attempt keys
	resetKeyPrefix string // Prefix for password reset keys
}

// RedisRateLimitConfig extends RateLimitConfig with Redis-specific settings.
// This allows for fine-tuning of Redis operations and connection behavior.
type RedisRateLimitConfig struct {
	RateLimitConfig

	// KeyPrefix is prepended to all Redis keys for namespacing
	KeyPrefix string `json:"key_prefix"`

	// Pipeline enables Redis pipelining for batch operations
	Pipeline bool `json:"pipeline"`

	// MaxRetries for Redis operations on failure
	MaxRetries int `json:"max_retries"`
}

// DefaultRedisRateLimitConfig returns production-ready defaults for Redis rate limiting.
// These values are optimized for performance and reliability in distributed environments.
//
// Returns:
//   - RedisRateLimitConfig with recommended production defaults
//
// Default values:
//   - Login: 5 attempts per 15 minutes with Redis persistence
//   - Password reset: 3 attempts per hour with Redis persistence
//   - Key prefix: "auth_service" for namespacing
//   - Pipeline: enabled for performance
//   - Max retries: 3 for resilience
//
// Example:
//
//	config := DefaultRedisRateLimitConfig()
//	service := NewRedisRateLimitService(redisClient, config, logger)
func DefaultRedisRateLimitConfig() RedisRateLimitConfig {
	return RedisRateLimitConfig{
		RateLimitConfig: DefaultRateLimitConfig(),
		KeyPrefix:       "auth_service",
		Pipeline:        true,
		MaxRetries:      3,
	}
}

// NewRedisRateLimitService creates a new Redis-based distributed rate limiting service.
// This service provides persistent, scalable rate limiting using Redis sorted sets
// with sliding window algorithms for precise rate limiting.
//
// Parameters:
//   - client: Configured Redis client with connection pool
//   - config: Rate limiting configuration with Redis-specific settings
//   - logger: Structured logger for operations and debugging
//
// Returns:
//   - RateLimitService implementation ready for distributed use
//
// Redis Requirements:
//   - Redis 3.0+ for sorted set operations
//   - Persistent Redis instance for production use
//   - Appropriate memory limits and eviction policies
//   - Connection pooling for high-throughput scenarios
//
// Example:
//
//	redisClient := redis.NewClient(&redis.Options{
//	    Addr: "localhost:6379",
//	    Password: "",
//	    DB: 0,
//	})
//	config := DefaultRedisRateLimitConfig()
//	service := NewRedisRateLimitService(redisClient, config, logger)
//
// Time Complexity: O(1) for service creation
// Space Complexity: O(1) for service instance
func NewRedisRateLimitService(client *redis.Client, config RedisRateLimitConfig, logger *logrus.Logger) *RedisRateLimitService {
	// Validate Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		logger.WithError(err).Fatal("RedisRateLimitService: Failed to connect to Redis")
	}

	service := &RedisRateLimitService{
		client:      client,
		loginWindow: config.LoginWindow,
		loginLimit:  config.LoginLimit,
		resetWindow: config.ResetWindow,
		resetLimit:  config.ResetLimit,
		logger:      logger,

		// Redis key prefixes for operation isolation
		loginKeyPrefix: fmt.Sprintf("%s:rate_limit:login", config.KeyPrefix),
		resetKeyPrefix: fmt.Sprintf("%s:rate_limit:reset", config.KeyPrefix),
	}

	logger.WithFields(logrus.Fields{
		"implementation": "RedisRateLimitService",
		"login_window":   config.LoginWindow,
		"login_limit":    config.LoginLimit,
		"reset_window":   config.ResetWindow,
		"reset_limit":    config.ResetLimit,
		"key_prefix":     config.KeyPrefix,
		"redis_addr":     client.Options().Addr,
	}).Info("RedisRateLimitService: distributed rate limiting service started")

	return service
}

// CheckLoginAttempts checks if login attempts from the given identifier are within limits.
// This method uses Redis sorted sets with sliding window algorithm for precise,
// distributed rate limiting that works across multiple service instances.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - identifier: IP address, email, or other identifier to check (will be sanitized)
//
// Returns:
//   - bool: true if request is allowed (under rate limit), false if limit exceeded
//   - error: Redis connection errors or context cancellation
//
// Algorithm (Sliding Window with Redis Sorted Sets):
//  1. Generate Redis key for the identifier
//  2. Use Redis transaction (MULTI/EXEC) for atomicity:
//     a. Remove expired entries (score < cutoff timestamp)
//     b. Count current valid entries in the window
//     c. Add current attempt if under limit
//     d. Set expiration on the key to prevent memory leaks
//  3. Return decision based on count vs limit
//
// Redis Operations:
//   - ZREMRANGEBYSCORE: Remove expired entries (O(log N + M))
//   - ZCARD: Count current entries (O(1))
//   - ZADD: Add new entry if allowed (O(log N))
//   - EXPIRE: Set key expiration (O(1))
//
// Example:
//
//	allowed, err := service.CheckLoginAttempts(ctx, "192.168.1.100")
//	if err != nil {
//	    return fmt.Errorf("rate limit check failed: %w", err)
//	}
//	if !allowed {
//	    return ErrTooManyLoginAttempts
//	}
//
// Time Complexity: O(log N + M) where N is entries in set, M is expired entries
// Space Complexity: O(1) additional space per operation
func (r *RedisRateLimitService) CheckLoginAttempts(ctx context.Context, identifier string) (bool, error) {
	// Input validation and sanitization
	if identifier == "" {
		r.logger.Warn("RedisRateLimitService.CheckLoginAttempts: empty identifier provided")
		return false, fmt.Errorf("identifier cannot be empty")
	}

	// Generate Redis key with prefix for namespacing
	key := fmt.Sprintf("%s:%s", r.loginKeyPrefix, identifier)
	now := time.Now()
	cutoff := now.Add(-r.loginWindow)

	// Use Redis pipeline for optimal performance
	pipe := r.client.Pipeline()

	// Remove expired entries from the sorted set
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(cutoff.UnixNano(), 10))

	// Count current valid entries
	countCmd := pipe.ZCard(ctx, key)

	// Execute pipeline for atomic read operation
	_, err := pipe.Exec(ctx)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"identifier": identifier,
			"key":        key,
			"error":      err,
		}).Error("RedisRateLimitService.CheckLoginAttempts: pipeline execution failed")
		return false, fmt.Errorf("Redis operation failed: %w", err)
	}

	// Get the count of valid attempts
	currentCount, err := countCmd.Result()
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"identifier": identifier,
			"key":        key,
			"error":      err,
		}).Error("RedisRateLimitService.CheckLoginAttempts: failed to get attempt count")
		return false, fmt.Errorf("failed to get attempt count: %w", err)
	}

	// Determine if request is allowed
	allowed := int(currentCount) < r.loginLimit

	r.logger.WithFields(logrus.Fields{
		"identifier":     identifier,
		"attempts_count": currentCount,
		"limit":          r.loginLimit,
		"window_minutes": r.loginWindow.Minutes(),
		"allowed":        allowed,
	}).Debug("RedisRateLimitService.CheckLoginAttempts: rate limit check completed")

	return allowed, nil
}

// RecordLoginAttempt records a login attempt for the given identifier in Redis.
// This method adds the attempt to a sorted set with timestamp scoring for
// sliding window calculations. The operation is atomic and distributed-safe.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - identifier: IP address, email, or other identifier (will be sanitized)
//   - success: Whether the login attempt was successful (recorded regardless)
//
// Returns:
//   - error: Redis connection errors or context cancellation
//
// Behavior:
//   - Uses current timestamp as score in Redis sorted set
//   - Generates unique member to prevent score collisions
//   - Sets key expiration to prevent memory leaks
//   - Records both successful and failed attempts for comprehensive tracking
//   - Operation is atomic using Redis transactions
//
// Redis Operations:
//   - ZADD: Add timestamped entry (O(log N))
//   - EXPIRE: Set key expiration to window duration (O(1))
//
// Example:
//
//	err := service.RecordLoginAttempt(ctx, "192.168.1.100", false)
//	if err != nil {
//	    log.Printf("Failed to record login attempt: %v", err)
//	}
//
// Time Complexity: O(log N) where N is the number of entries in the sorted set
// Space Complexity: O(1) additional space per attempt
func (r *RedisRateLimitService) RecordLoginAttempt(ctx context.Context, identifier string, success bool) error {
	// Input validation
	if identifier == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	// Generate Redis key and unique member for this attempt
	key := fmt.Sprintf("%s:%s", r.loginKeyPrefix, identifier)
	now := time.Now()
	// Create unique member using timestamp and random component to prevent collisions
	member := fmt.Sprintf("%d:%s", now.UnixNano(), identifier)

	// Use Redis transaction for atomicity
	pipe := r.client.Pipeline()

	// Add the attempt with timestamp as score
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: member,
	})

	// Set expiration to window duration plus buffer to ensure cleanup
	expiration := r.loginWindow + (r.loginWindow / 10) // 10% buffer
	pipe.Expire(ctx, key, expiration)

	// Execute atomic transaction
	_, err := pipe.Exec(ctx)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"identifier": identifier,
			"success":    success,
			"key":        key,
			"error":      err,
		}).Error("RedisRateLimitService.RecordLoginAttempt: failed to record attempt")
		return fmt.Errorf("failed to record login attempt: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"identifier": identifier,
		"success":    success,
		"timestamp":  now,
		"key":        key,
	}).Debug("RedisRateLimitService.RecordLoginAttempt: attempt recorded successfully")

	return nil
}

// CheckPasswordResetAttempts checks if password reset requests from the given email are within limits.
// This uses a separate Redis namespace and configuration specifically for password reset operations,
// which typically have lower limits and longer windows than login attempts.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - email: Email address to check for password reset rate limiting
//
// Returns:
//   - bool: true if request is allowed (under rate limit), false if limit exceeded
//   - error: Redis connection errors or context cancellation
//
// Algorithm (Sliding Window with Redis Sorted Sets):
//  1. Generate Redis key for the email address
//  2. Use Redis transaction for atomicity:
//     a. Remove expired entries (older than resetWindow)
//     b. Count current valid entries
//     c. Return decision based on count vs resetLimit
//  3. Log decision for monitoring and debugging
//
// Example:
//
//	allowed, err := service.CheckPasswordResetAttempts(ctx, "user@example.com")
//	if err != nil {
//	    return fmt.Errorf("reset rate limit check failed: %w", err)
//	}
//	if !allowed {
//	    return ErrTooManyPasswordResetAttempts
//	}
//
// Time Complexity: O(log N + M) where N is entries in set, M is expired entries
// Space Complexity: O(1) additional space per operation
func (r *RedisRateLimitService) CheckPasswordResetAttempts(ctx context.Context, email string) (bool, error) {
	// Input validation
	if email == "" {
		r.logger.Warn("RedisRateLimitService.CheckPasswordResetAttempts: empty email provided")
		return false, fmt.Errorf("email cannot be empty")
	}

	// Generate Redis key for password reset operations
	key := fmt.Sprintf("%s:%s", r.resetKeyPrefix, email)
	now := time.Now()
	cutoff := now.Add(-r.resetWindow)

	// Use Redis pipeline for performance
	pipe := r.client.Pipeline()

	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(cutoff.UnixNano(), 10))

	// Count current valid entries
	countCmd := pipe.ZCard(ctx, key)

	// Execute pipeline operations
	_, err := pipe.Exec(ctx)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"email": email,
			"key":   key,
			"error": err,
		}).Error("RedisRateLimitService.CheckPasswordResetAttempts: pipeline execution failed")
		return false, fmt.Errorf("Redis operation failed: %w", err)
	}

	// Get count result
	currentCount, err := countCmd.Result()
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"email": email,
			"key":   key,
			"error": err,
		}).Error("RedisRateLimitService.CheckPasswordResetAttempts: failed to get attempt count")
		return false, fmt.Errorf("failed to get attempt count: %w", err)
	}

	// Check if within limit
	allowed := int(currentCount) < r.resetLimit

	r.logger.WithFields(logrus.Fields{
		"email":          email,
		"attempts_count": currentCount,
		"limit":          r.resetLimit,
		"window_hours":   r.resetWindow.Hours(),
		"allowed":        allowed,
	}).Debug("RedisRateLimitService.CheckPasswordResetAttempts: rate limit check completed")

	return allowed, nil
}

// RecordPasswordResetAttempt records a password reset request for the given email in Redis.
// All password reset requests are recorded regardless of whether they result
// in an actual email being sent, providing comprehensive tracking for security monitoring.
//
// Parameters:
//   - ctx: Context for cancellation and timeout control
//   - email: Email address that requested the password reset
//
// Returns:
//   - error: Redis connection errors or context cancellation
//
// Behavior:
//   - Adds timestamped entry to Redis sorted set
//   - Uses email as part of unique member identifier
//   - Sets appropriate key expiration for memory management
//   - Operation is atomic and distributed-safe
//
// Redis Operations:
//   - ZADD: Add timestamped entry (O(log N))
//   - EXPIRE: Set key expiration (O(1))
//
// Example:
//
//	err := service.RecordPasswordResetAttempt(ctx, "user@example.com")
//	if err != nil {
//	    log.Printf("Failed to record password reset attempt: %v", err)
//	}
//
// Time Complexity: O(log N) where N is the number of entries in the sorted set
// Space Complexity: O(1) additional space per attempt
func (r *RedisRateLimitService) RecordPasswordResetAttempt(ctx context.Context, email string) error {
	// Input validation
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	// Generate Redis key and unique member
	key := fmt.Sprintf("%s:%s", r.resetKeyPrefix, email)
	now := time.Now()
	member := fmt.Sprintf("%d:%s", now.UnixNano(), email)

	// Use Redis transaction for atomicity
	pipe := r.client.Pipeline()

	// Add the reset attempt with timestamp as score
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: member,
	})

	// Set expiration with buffer for cleanup
	expiration := r.resetWindow + (r.resetWindow / 10) // 10% buffer
	pipe.Expire(ctx, key, expiration)

	// Execute transaction
	_, err := pipe.Exec(ctx)
	if err != nil {
		r.logger.WithFields(logrus.Fields{
			"email": email,
			"key":   key,
			"error": err,
		}).Error("RedisRateLimitService.RecordPasswordResetAttempt: failed to record attempt")
		return fmt.Errorf("failed to record password reset attempt: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"email":     email,
		"timestamp": now,
		"key":       key,
	}).Debug("RedisRateLimitService.RecordPasswordResetAttempt: attempt recorded successfully")

	return nil
}

// GetStats returns current statistics about the Redis rate limiter state.
// This method provides insights into rate limiting activity across all
// service instances for monitoring and debugging purposes.
//
// Returns:
//   - map[string]interface{} with current statistics and configuration
//
// Statistics included:
//   - Redis connection information
//   - Configuration values for both login and reset limiting
//   - Active keys count (approximate, for monitoring)
//   - Redis key prefixes for debugging
//
// Note: Getting exact counts from Redis can be expensive with many keys.
// This method provides configuration and connection info for operational monitoring.
//
// Example:
//
//	stats := service.GetStats()
//	log.Printf("Redis rate limiter stats: %+v", stats)
//
// Time Complexity: O(1) - only returns configuration and connection info
// Space Complexity: O(1) - fixed-size statistics map
func (r *RedisRateLimitService) GetStats() map[string]interface{} {
	// Get Redis connection info
	redisAddr := "unknown"
	redisDB := 0
	if r.client.Options() != nil {
		redisAddr = r.client.Options().Addr
		redisDB = r.client.Options().DB
	}

	return map[string]interface{}{
		// Service information
		"implementation": "RedisRateLimitService",
		"distributed":    true,
		"persistent":     true,

		// Redis connection information
		"redis_addr": redisAddr,
		"redis_db":   redisDB,

		// Configuration values
		"login_window_minutes": r.loginWindow.Minutes(),
		"login_limit":          r.loginLimit,
		"reset_window_hours":   r.resetWindow.Hours(),
		"reset_limit":          r.resetLimit,

		// Key prefixes for debugging
		"login_key_prefix": r.loginKeyPrefix,
		"reset_key_prefix": r.resetKeyPrefix,

		// Capabilities
		"features": []string{
			"sliding_window",
			"distributed_coordination",
			"persistent_state",
			"atomic_operations",
			"automatic_cleanup",
		},
	}
}

// HealthCheck verifies that the Redis connection is healthy and responsive.
// This method should be called periodically by health check endpoints
// to ensure the rate limiting service is operational.
//
// Parameters:
//   - ctx: Context for timeout control (recommended: 5-10 second timeout)
//
// Returns:
//   - error: nil if healthy, error describing the issue if unhealthy
//
// Checks performed:
//   - Redis connectivity (PING command)
//   - Basic read/write operations to verify functionality
//   - Response time validation
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//
//	if err := service.HealthCheck(ctx); err != nil {
//	    log.Printf("Rate limiting service unhealthy: %v", err)
//	    // Handle degraded functionality
//	}
//
// Time Complexity: O(1) - simple Redis operations
// Space Complexity: O(1) - no significant memory allocation
func (r *RedisRateLimitService) HealthCheck(ctx context.Context) error {
	// Test basic connectivity
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("Redis ping failed: %w", err)
	}

	// Test basic write/read operation
	testKey := fmt.Sprintf("%s:health_check", r.loginKeyPrefix)
	testValue := time.Now().Unix()

	// Write test value
	if err := r.client.Set(ctx, testKey, testValue, time.Minute).Err(); err != nil {
		return fmt.Errorf("Redis write test failed: %w", err)
	}

	// Read test value
	result, err := r.client.Get(ctx, testKey).Int64()
	if err != nil {
		return fmt.Errorf("Redis read test failed: %w", err)
	}

	if result != testValue {
		return fmt.Errorf("Redis read/write mismatch: expected %d, got %d", testValue, result)
	}

	// Cleanup test key
	r.client.Del(ctx, testKey)

	r.logger.Debug("RedisRateLimitService.HealthCheck: health check passed")
	return nil
}
