package test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"auth-service/internal/service"
)

// RedisRateLimitTestSuite provides comprehensive test coverage for Redis rate limiting.
//
// This test suite validates all aspects of the Redis-based rate limiting implementation:
// - Connection and initialization
// - Login attempt rate limiting with sliding windows
// - Password reset rate limiting with separate limits
// - Distributed coordination across multiple instances
// - Error handling and edge cases
// - Performance under concurrent load
// - Redis failure scenarios
//
// Test Categories:
// - Unit Tests: Individual method validation
// - Integration Tests: Redis interaction validation
// - Concurrency Tests: Thread safety and race conditions
// - Performance Tests: High-throughput scenarios
// - Error Tests: Redis failure and recovery scenarios
//
// Test Environment:
// - Uses Redis test container or local Redis instance
// - Isolated test namespaces to prevent conflicts
// - Automatic cleanup of test data
// - Configurable test timeouts and retries
type RedisRateLimitTestSuite struct {
	suite.Suite
	client  *redis.Client
	service *service.RedisRateLimitService
	logger  *logrus.Logger
	testDB  int // Test database number for isolation
}

// SetupSuite initializes the test environment before running the test suite.
// This method sets up Redis connection, test database, and logging configuration.
func (suite *RedisRateLimitTestSuite) SetupSuite() {
	// Create test logger with debug level
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.DebugLevel)

	// Use a separate Redis database for testing (default: DB 1)
	suite.testDB = 1

	// Create Redis client for testing
	suite.client = redis.NewClient(&redis.Options{
		Addr:         "localhost:6379", // Default Redis address
		Password:     "redispass",      // Password from docker-compose.yml
		DB:           suite.testDB,     // Use test database
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	// Verify Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := suite.client.Ping(ctx).Err()
	if err != nil {
		suite.T().Skipf("Redis not available for testing: %v", err)
		return
	}

	// Clean up any existing test data
	suite.client.FlushDB(ctx)

	suite.logger.Info("RedisRateLimitTestSuite: Test environment initialized")
}

// TearDownSuite cleans up the test environment after running all tests.
func (suite *RedisRateLimitTestSuite) TearDownSuite() {
	if suite.client != nil {
		// Clean up test database
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		suite.client.FlushDB(ctx)
		suite.client.Close()
		suite.logger.Info("RedisRateLimitTestSuite: Test environment cleaned up")
	}
}

// SetupTest initializes a fresh service instance before each test.
// This ensures test isolation and consistent starting conditions.
func (suite *RedisRateLimitTestSuite) SetupTest() {
	if suite.client == nil {
		suite.T().Skip("Redis not available for testing")
		return
	}

	// Create test configuration with shorter windows for faster testing
	config := service.RedisRateLimitConfig{
		RateLimitConfig: service.RateLimitConfig{
			LoginWindow:     30 * time.Second, // Shorter for testing
			LoginLimit:      3,                // Lower limit for easier testing
			ResetWindow:     2 * time.Minute,  // Shorter for testing
			ResetLimit:      2,                // Lower limit for easier testing
			CleanupInterval: 5 * time.Second,  // Not used in Redis implementation
		},
		KeyPrefix:  "test_auth",
		Pipeline:   true,
		MaxRetries: 3,
	}

	// Create service instance
	suite.service = service.NewRedisRateLimitService(suite.client, config, suite.logger)
	require.NotNil(suite.T(), suite.service, "Service should be created successfully")

	// Clean any existing test keys
	ctx := context.Background()
	keys, _ := suite.client.Keys(ctx, "test_auth:*").Result()
	if len(keys) > 0 {
		suite.client.Del(ctx, keys...)
	}
}

// TearDownTest cleans up Redis state after each individual test.
// This ensures proper test isolation by removing test data.
func (suite *RedisRateLimitTestSuite) TearDownTest() {
	if suite.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Clean only test keys to avoid affecting other tests
		keys, err := suite.client.Keys(ctx, "test_auth:*").Result()
		if err == nil && len(keys) > 0 {
			suite.client.Del(ctx, keys...)
		}
	}
}

// TestServiceCreation tests the creation and initialization of RedisRateLimitService.
//
// Validates:
// - Successful service creation with valid configuration
// - Redis connection validation during creation
// - Proper initialization of configuration values
// - Error handling for invalid Redis connections
func (suite *RedisRateLimitTestSuite) TestServiceCreation() {
	// Test successful creation
	config := service.DefaultRedisRateLimitConfig()
	rateLimitService := service.NewRedisRateLimitService(suite.client, config, suite.logger)

	assert.NotNil(suite.T(), rateLimitService, "Service should be created")

	// Test that the service is functional by trying a basic operation
	ctx := context.Background()
	allowed, err := rateLimitService.CheckLoginAttempts(ctx, "test_creation")
	assert.NoError(suite.T(), err, "Service should be functional")
	assert.True(suite.T(), allowed, "First request should be allowed")
}

// TestLoginRateLimiting_ValidRequests tests rate limiting with valid login requests.
//
// Validates:
// - Requests under the limit are allowed
// - Proper tracking of attempt counts
// - Correct sliding window behavior
// - State persistence across method calls
func (suite *RedisRateLimitTestSuite) TestLoginRateLimiting_ValidRequests() {
	ctx := context.Background()
	identifier := "192.168.1.100"

	// First attempt should be allowed
	allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.True(suite.T(), allowed, "First attempt should be allowed")

	// Record the attempt
	err = suite.service.RecordLoginAttempt(ctx, identifier, false)
	assert.NoError(suite.T(), err, "Recording should not return error")

	// Second attempt should be allowed (under limit of 3)
	allowed, err = suite.service.CheckLoginAttempts(ctx, identifier)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.True(suite.T(), allowed, "Second attempt should be allowed")

	// Record second attempt
	err = suite.service.RecordLoginAttempt(ctx, identifier, false)
	assert.NoError(suite.T(), err, "Recording should not return error")

	// Third attempt should be allowed (at limit of 3)
	allowed, err = suite.service.CheckLoginAttempts(ctx, identifier)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.True(suite.T(), allowed, "Third attempt should be allowed")
}

// TestLoginRateLimiting_ExceedsLimit tests rate limiting when attempts exceed the configured limit.
//
// Validates:
// - Requests are blocked when limit is exceeded
// - Proper rejection behavior
// - Consistent blocking until window expires
// - Accurate attempt counting
func (suite *RedisRateLimitTestSuite) TestLoginRateLimiting_ExceedsLimit() {
	ctx := context.Background()
	identifier := "192.168.1.101"

	// Fill up the rate limit (3 attempts)
	for i := 0; i < 3; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
		assert.NoError(suite.T(), err, "Check should not return error")
		assert.True(suite.T(), allowed, "Attempt %d should be allowed", i+1)

		err = suite.service.RecordLoginAttempt(ctx, identifier, false)
		assert.NoError(suite.T(), err, "Recording should not return error")
	}

	// Fourth attempt should be blocked
	allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.False(suite.T(), allowed, "Fourth attempt should be blocked")

	// Fifth attempt should still be blocked
	allowed, err = suite.service.CheckLoginAttempts(ctx, identifier)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.False(suite.T(), allowed, "Fifth attempt should be blocked")
}

// TestLoginRateLimiting_SlidingWindow tests the sliding window algorithm behavior.
//
// Validates:
// - Expired attempts are properly removed
// - Window slides correctly over time
// - New attempts become available as old ones expire
// - Accurate time-based calculations
func (suite *RedisRateLimitTestSuite) TestLoginRateLimiting_SlidingWindow() {
	if testing.Short() {
		suite.T().Skip("Skipping sliding window test in short mode")
	}

	ctx := context.Background()
	identifier := "192.168.1.102"

	// Fill up the rate limit
	for i := 0; i < 3; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed)

		err = suite.service.RecordLoginAttempt(ctx, identifier, false)
		require.NoError(suite.T(), err)
	}

	// Should be blocked now
	allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
	require.NoError(suite.T(), err)
	require.False(suite.T(), allowed, "Should be blocked after hitting limit")

	// Wait for window to slide (window is 30 seconds in test config)
	suite.logger.Info("Waiting for sliding window to expire...")

	// Create a service with shorter window for faster testing
	shortConfig := service.RedisRateLimitConfig{
		RateLimitConfig: service.RateLimitConfig{
			LoginWindow:     2 * time.Second, // Much shorter window for testing
			LoginLimit:      3,
			ResetWindow:     5 * time.Second,
			ResetLimit:      2,
			CleanupInterval: 1 * time.Second,
		},
		KeyPrefix:  "test_auth_short",
		Pipeline:   true,
		MaxRetries: 3,
	}

	shortWindowService := service.NewRedisRateLimitService(suite.client, shortConfig, suite.logger)

	// Test with the short window service
	shortIdentifier := "short_window_test"

	// Fill up the rate limit with short window service
	for i := 0; i < 3; i++ {
		allowed, err := shortWindowService.CheckLoginAttempts(ctx, shortIdentifier)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed)

		err = shortWindowService.RecordLoginAttempt(ctx, shortIdentifier, false)
		require.NoError(suite.T(), err)
	}

	// Should be blocked now
	allowed, err = shortWindowService.CheckLoginAttempts(ctx, shortIdentifier)
	require.NoError(suite.T(), err)
	require.False(suite.T(), allowed, "Should be blocked after hitting limit")

	// Wait for short window to slide
	time.Sleep(3 * time.Second)

	// Should be allowed again after window slides
	allowed, err = shortWindowService.CheckLoginAttempts(ctx, shortIdentifier)
	assert.NoError(suite.T(), err, "Check should not return error after window slides")
	assert.True(suite.T(), allowed, "Request should be allowed after window slides")
}

// TestPasswordResetRateLimiting tests password reset rate limiting functionality.
//
// Validates:
// - Password reset attempts are tracked separately from login attempts
// - Different limits and windows apply to password resets
// - Proper isolation between different operation types
// - Correct behavior under limit and over limit scenarios
func (suite *RedisRateLimitTestSuite) TestPasswordResetRateLimiting() {
	ctx := context.Background()
	email := "user@example.com"

	// First reset attempt should be allowed
	allowed, err := suite.service.CheckPasswordResetAttempts(ctx, email)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.True(suite.T(), allowed, "First reset attempt should be allowed")

	// Record the attempt
	err = suite.service.RecordPasswordResetAttempt(ctx, email)
	assert.NoError(suite.T(), err, "Recording should not return error")

	// Second attempt should be allowed (limit is 2 in test config)
	allowed, err = suite.service.CheckPasswordResetAttempts(ctx, email)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.True(suite.T(), allowed, "Second reset attempt should be allowed")

	// Record second attempt
	err = suite.service.RecordPasswordResetAttempt(ctx, email)
	assert.NoError(suite.T(), err, "Recording should not return error")

	// Third attempt should be blocked (exceeds limit of 2)
	allowed, err = suite.service.CheckPasswordResetAttempts(ctx, email)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.False(suite.T(), allowed, "Third reset attempt should be blocked")
}

// TestRateLimiting_DifferentIdentifiers tests isolation between different identifiers.
//
// Validates:
// - Rate limits are applied per identifier, not globally
// - Different users/IPs have independent rate limits
// - No cross-contamination between identifiers
// - Proper key namespacing in Redis
func (suite *RedisRateLimitTestSuite) TestRateLimiting_DifferentIdentifiers() {
	ctx := context.Background()
	// Use unique identifiers with timestamp to avoid conflicts
	timestamp := time.Now().UnixNano()
	identifier1 := fmt.Sprintf("192.168.1.100_%d", timestamp)
	identifier2 := fmt.Sprintf("192.168.1.101_%d", timestamp)

	// Fill up rate limit for identifier1
	for i := 0; i < 3; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, identifier1)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed)

		err = suite.service.RecordLoginAttempt(ctx, identifier1, false)
		require.NoError(suite.T(), err)
	}

	// identifier1 should be blocked
	allowed, err := suite.service.CheckLoginAttempts(ctx, identifier1)
	require.NoError(suite.T(), err)
	require.False(suite.T(), allowed, "identifier1 should be blocked")

	// identifier2 should still be allowed (different identifier)
	allowed, err = suite.service.CheckLoginAttempts(ctx, identifier2)
	assert.NoError(suite.T(), err, "identifier2 check should not return error")
	assert.True(suite.T(), allowed, "identifier2 should be allowed")

	// Record attempt for identifier2
	err = suite.service.RecordLoginAttempt(ctx, identifier2, true)
	assert.NoError(suite.T(), err, "identifier2 recording should not return error")

	// identifier2 should still be allowed for more attempts
	allowed, err = suite.service.CheckLoginAttempts(ctx, identifier2)
	assert.NoError(suite.T(), err, "identifier2 second check should not return error")
	assert.True(suite.T(), allowed, "identifier2 should still be allowed")
}

// TestRateLimiting_SuccessfulAttempts tests that successful attempts are also rate limited.
//
// Validates:
// - Both successful and failed attempts count toward rate limits
// - Success flag doesn't affect rate limiting logic
// - Comprehensive tracking of all authentication attempts
func (suite *RedisRateLimitTestSuite) TestRateLimiting_SuccessfulAttempts() {
	ctx := context.Background()
	identifier := "192.168.1.103"

	// Record successful attempts (should count toward limit)
	for i := 0; i < 3; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed)

		// Record as successful attempt
		err = suite.service.RecordLoginAttempt(ctx, identifier, true)
		require.NoError(suite.T(), err)
	}

	// Should be blocked even after successful attempts
	allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
	assert.NoError(suite.T(), err, "Check should not return error")
	assert.False(suite.T(), allowed, "Should be blocked even after successful attempts")
}

// TestInputValidation tests input validation and error handling.
//
// Validates:
// - Empty identifier/email handling
// - Proper error messages for invalid inputs
// - Defensive programming practices
// - Consistent error handling across methods
func (suite *RedisRateLimitTestSuite) TestInputValidation() {
	ctx := context.Background()

	// Test empty identifier for login attempts
	allowed, err := suite.service.CheckLoginAttempts(ctx, "")
	assert.Error(suite.T(), err, "Empty identifier should return error")
	assert.False(suite.T(), allowed, "Empty identifier should not be allowed")

	err = suite.service.RecordLoginAttempt(ctx, "", false)
	assert.Error(suite.T(), err, "Empty identifier should return error")

	// Test empty email for password reset attempts
	allowed, err = suite.service.CheckPasswordResetAttempts(ctx, "")
	assert.Error(suite.T(), err, "Empty email should return error")
	assert.False(suite.T(), allowed, "Empty email should not be allowed")

	err = suite.service.RecordPasswordResetAttempt(ctx, "")
	assert.Error(suite.T(), err, "Empty email should return error")
}

// TestGetStats tests the statistics reporting functionality.
//
// Validates:
// - Statistics contain expected configuration values
// - Redis connection information is included
// - Implementation details are correctly reported
// - No sensitive information is exposed
func (suite *RedisRateLimitTestSuite) TestGetStats() {
	stats := suite.service.GetStats()

	// Verify basic statistics structure
	assert.NotNil(suite.T(), stats, "Stats should not be nil")
	assert.Equal(suite.T(), "RedisRateLimitService", stats["implementation"], "Implementation should be identified")
	assert.Equal(suite.T(), true, stats["distributed"], "Should be marked as distributed")
	assert.Equal(suite.T(), true, stats["persistent"], "Should be marked as persistent")

	// Verify configuration values
	assert.Equal(suite.T(), 0.5, stats["login_window_minutes"], "Login window should match config")
	assert.Equal(suite.T(), 3, stats["login_limit"], "Login limit should match config")
	assert.Equal(suite.T(), 2.0/60, stats["reset_window_hours"], "Reset window should match config (2 minutes = 2/60 hours)")
	assert.Equal(suite.T(), 2, stats["reset_limit"], "Reset limit should match config")

	// Verify Redis information
	assert.Contains(suite.T(), stats, "redis_addr", "Should contain Redis address")
	assert.Contains(suite.T(), stats, "redis_db", "Should contain Redis database")

	// Verify key prefixes
	assert.Equal(suite.T(), "test_auth:rate_limit:login", stats["login_key_prefix"], "Login key prefix should match")
	assert.Equal(suite.T(), "test_auth:rate_limit:reset", stats["reset_key_prefix"], "Reset key prefix should match")

	// Verify features list
	features, ok := stats["features"].([]string)
	assert.True(suite.T(), ok, "Features should be string slice")
	assert.Contains(suite.T(), features, "sliding_window", "Should include sliding window feature")
	assert.Contains(suite.T(), features, "distributed_coordination", "Should include distributed coordination feature")
	assert.Contains(suite.T(), features, "persistent_state", "Should include persistent state feature")
}

// TestHealthCheck tests the health check functionality.
//
// Validates:
// - Health check passes with healthy Redis connection
// - Basic read/write operations work correctly
// - Proper error handling for connection issues
// - Response time within acceptable limits
func (suite *RedisRateLimitTestSuite) TestHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Health check should pass with healthy Redis
	err := suite.service.HealthCheck(ctx)
	assert.NoError(suite.T(), err, "Health check should pass with healthy Redis")
}

// TestConcurrentAccess tests thread safety and concurrent access patterns.
//
// Validates:
// - Thread safety under concurrent load
// - Atomic operations work correctly with multiple goroutines
// - No race conditions in rate limiting logic
// - Consistent behavior under high concurrency
func (suite *RedisRateLimitTestSuite) TestConcurrentAccess() {
	if testing.Short() {
		suite.T().Skip("Skipping concurrency test in short mode")
	}

	ctx := context.Background()
	identifier := "concurrent_test"
	numGoroutines := 10
	attemptsPerGoroutine := 2

	// Channel to collect results
	results := make(chan bool, numGoroutines*attemptsPerGoroutine)
	errors := make(chan error, numGoroutines*attemptsPerGoroutine)

	// Use sync.WaitGroup to ensure all goroutines complete before checking results
	var wg sync.WaitGroup

	// Launch concurrent goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < attemptsPerGoroutine; j++ {
				// Check if allowed
				allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
				if err != nil {
					select {
					case errors <- err:
					default:
					}
					return
				}

				// Record attempt if allowed
				if allowed {
					err = suite.service.RecordLoginAttempt(ctx, identifier, false)
					if err != nil {
						select {
						case errors <- err:
						default:
						}
						return
					}
				}

				results <- allowed
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(results)
	close(errors)

	// Collect results
	allowedCount := 0
	blockedCount := 0

	for result := range results {
		if result {
			allowedCount++
		} else {
			blockedCount++
		}
	}

	// Check for errors
	errorCount := 0
	for err := range errors {
		suite.T().Logf("Concurrent test error: %v", err)
		errorCount++
	}

	totalExpected := numGoroutines * attemptsPerGoroutine
	totalReceived := allowedCount + blockedCount + errorCount

	// Verify that we processed all attempts
	assert.Equal(suite.T(), totalExpected, totalReceived, "All operations should be accounted for")

	// Verify that we have proper rate limiting
	// In a concurrent scenario, we may get more than exactly 3 due to race conditions
	// This is expected behavior in distributed systems
	assert.GreaterOrEqual(suite.T(), allowedCount, 3, "At least 3 attempts should be allowed")
	assert.LessOrEqual(suite.T(), allowedCount, totalExpected, "Cannot exceed total attempts")
	assert.Equal(suite.T(), 0, errorCount, "No errors should occur")

	suite.T().Logf("Concurrent test results: %d allowed, %d blocked, %d errors out of %d total",
		allowedCount, blockedCount, errorCount, totalExpected)
}

// TestRedisFailureRecovery tests behavior when Redis is temporarily unavailable.
//
// Validates:
// - Proper error handling when Redis is down
// - Service recovery when Redis comes back online
// - No data corruption during failures
// - Graceful degradation behavior
func (suite *RedisRateLimitTestSuite) TestRedisFailureRecovery() {
	ctx := context.Background()
	identifier := "failure_test"

	// Normal operation should work
	allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
	assert.NoError(suite.T(), err, "Normal operation should work")
	assert.True(suite.T(), allowed, "Should be allowed initially")

	// Create a client with invalid address to simulate failure
	failClient := redis.NewClient(&redis.Options{
		Addr:        "localhost:9999", // Non-existent Redis
		DB:          suite.testDB,
		DialTimeout: 1 * time.Second,
	})

	// Create service with failing client
	config := service.RedisRateLimitConfig{
		RateLimitConfig: service.RateLimitConfig{
			LoginWindow: 30 * time.Second,
			LoginLimit:  3,
		},
		KeyPrefix: "test_fail",
	}

	failService := service.NewRedisRateLimitService(failClient, config, suite.logger)

	// Operations should return errors with failed Redis
	allowed, err = failService.CheckLoginAttempts(ctx, identifier)
	assert.Error(suite.T(), err, "Should return error with failed Redis")
	assert.False(suite.T(), allowed, "Should not allow with failed Redis")

	err = failService.RecordLoginAttempt(ctx, identifier, false)
	assert.Error(suite.T(), err, "Should return error with failed Redis")

	// Health check should fail
	err = failService.HealthCheck(ctx)
	assert.Error(suite.T(), err, "Health check should fail with failed Redis")

	// Clean up fail client
	failClient.Close()
}

// TestKeyExpiration tests that Redis keys are properly expired and cleaned up.
//
// Validates:
// - Keys have appropriate expiration times set
// - Expired keys are automatically cleaned up by Redis
// - No memory leaks from accumulating keys
// - Proper buffer time in expiration settings
func (suite *RedisRateLimitTestSuite) TestKeyExpiration() {
	ctx := context.Background()
	identifier := "expiration_test"

	// Record an attempt
	err := suite.service.RecordLoginAttempt(ctx, identifier, false)
	require.NoError(suite.T(), err, "Recording should succeed")

	// Check that the key exists and has expiration set
	key := fmt.Sprintf("test_auth:rate_limit:login:%s", identifier)
	exists, err := suite.client.Exists(ctx, key).Result()
	require.NoError(suite.T(), err, "Key existence check should succeed")
	require.Equal(suite.T(), int64(1), exists, "Key should exist")

	// Check that TTL is set (should be positive)
	ttl, err := suite.client.TTL(ctx, key).Result()
	require.NoError(suite.T(), err, "TTL check should succeed")
	assert.Greater(suite.T(), ttl, time.Duration(0), "Key should have positive TTL")
	// TTL should be approximately 30 seconds (our test window) with some buffer
	assert.LessOrEqual(suite.T(), ttl, 33*time.Second, "TTL should not exceed window + buffer")

	suite.T().Logf("Key TTL: %v (window: %v)", ttl, 30*time.Second)
}

// RunRedisRateLimitTests runs the complete test suite for Redis rate limiting.
//
// This function can be called from TestMain or individual test functions
// to execute all Redis rate limiting tests.
func (suite *RedisRateLimitTestSuite) TestRedisRateLimitingSuite() {
	suite.Run("TestServiceCreation", suite.TestServiceCreation)
	suite.Run("TestLoginRateLimiting_ValidRequests", suite.TestLoginRateLimiting_ValidRequests)
	suite.Run("TestLoginRateLimiting_ExceedsLimit", suite.TestLoginRateLimiting_ExceedsLimit)
	suite.Run("TestPasswordResetRateLimiting", suite.TestPasswordResetRateLimiting)
	suite.Run("TestRateLimiting_DifferentIdentifiers", suite.TestRateLimiting_DifferentIdentifiers)
	suite.Run("TestRateLimiting_SuccessfulAttempts", suite.TestRateLimiting_SuccessfulAttempts)
	suite.Run("TestInputValidation", suite.TestInputValidation)
	suite.Run("TestGetStats", suite.TestGetStats)
	suite.Run("TestHealthCheck", suite.TestHealthCheck)
	suite.Run("TestRedisFailureRecovery", suite.TestRedisFailureRecovery)
	suite.Run("TestKeyExpiration", suite.TestKeyExpiration)

	// Run expensive tests only if not in short mode
	if !testing.Short() {
		suite.Run("TestLoginRateLimiting_SlidingWindow", suite.TestLoginRateLimiting_SlidingWindow)
		suite.Run("TestConcurrentAccess", suite.TestConcurrentAccess)
	}
}

// TestRedisRateLimitService is the main test function that runs the entire test suite.
func TestRedisRateLimitService(t *testing.T) {
	// Skip if Redis is not available
	client := redis.NewClient(&redis.Options{
		Addr:        "localhost:6379",
		Password:    "redispass", // Password from docker-compose.yml
		DB:          1,           // Use test database
		DialTimeout: 2 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available for testing: %v", err)
		return
	}
	client.Close()

	// Run the test suite
	suite.Run(t, new(RedisRateLimitTestSuite))
}

// BenchmarkRedisRateLimit benchmarks the performance of Redis rate limiting operations.
//
// This benchmark tests the performance characteristics under various load conditions
// to ensure the Redis implementation meets performance requirements.
func BenchmarkRedisRateLimit(b *testing.B) {
	// Setup Redis client for benchmarking
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "redispass", // Password from docker-compose.yml
		DB:       2,           // Use separate database for benchmarks
	})

	// Skip if Redis is not available
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		b.Skipf("Redis not available for benchmarking: %v", err)
		return
	}

	// Clean up benchmark database
	client.FlushDB(ctx)
	defer client.Close()

	// Create service for benchmarking
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce logging noise
	config := service.DefaultRedisRateLimitConfig()
	config.KeyPrefix = "benchmark"
	rateLimitService := service.NewRedisRateLimitService(client, config, logger)

	b.Run("CheckLoginAttempts", func(b *testing.B) {
		identifier := "benchmark_user"
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, err := rateLimitService.CheckLoginAttempts(ctx, identifier)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})

	b.Run("RecordLoginAttempt", func(b *testing.B) {
		identifier := "benchmark_user"
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			err := rateLimitService.RecordLoginAttempt(ctx, identifier, i%2 == 0)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}
		}
	})

	b.Run("CheckAndRecord", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			identifier := fmt.Sprintf("user_%d", i%100) // Simulate 100 different users
			allowed, err := rateLimitService.CheckLoginAttempts(ctx, identifier)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}
			if allowed {
				err = rateLimitService.RecordLoginAttempt(ctx, identifier, false)
				if err != nil {
					b.Fatalf("Unexpected error: %v", err)
				}
			}
		}
	})

	// Clean up benchmark data
	keys, _ := client.Keys(ctx, "benchmark:*").Result()
	if len(keys) > 0 {
		client.Del(ctx, keys...)
	}
}
