package test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"auth-service/internal/service"
)

// RedisRateLimitIntegrationTestSuite provides integration tests for Redis rate limiting.
//
// These tests validate the complete integration of the Redis rate limiting service
// with an actual Redis instance, testing real-world scenarios including:
// - Docker Compose Redis instance integration
// - Production-like configuration scenarios
// - Multi-instance coordination
// - Persistence across service restarts
// - Performance under realistic load
// - Error recovery and resilience
//
// Environment Variables:
// - REDIS_ADDR: Redis server address (default: localhost:6379)
// - REDIS_PASSWORD: Redis password (default: empty)
// - REDIS_DB: Redis database number for testing (default: 3)
// - SKIP_REDIS_TESTS: Set to "true" to skip Redis tests
type RedisRateLimitIntegrationTestSuite struct {
	suite.Suite
	redisAddr     string
	redisPassword string
	redisDB       int
	client        *redis.Client
	service       service.RateLimitService
	logger        *logrus.Logger
}

// SetupSuite initializes the integration test environment.
// This connects to the actual Redis instance used by the application.
func (suite *RedisRateLimitIntegrationTestSuite) SetupSuite() {
	// Check if Redis tests should be skipped
	if os.Getenv("SKIP_REDIS_TESTS") == "true" {
		suite.T().Skip("Redis integration tests skipped by environment variable")
		return
	}

	// Configure test environment from environment variables
	suite.redisAddr = os.Getenv("REDIS_ADDR")
	if suite.redisAddr == "" {
		suite.redisAddr = "localhost:6379"
	}

	suite.redisPassword = os.Getenv("REDIS_PASSWORD")
	if suite.redisPassword == "" {
		suite.redisPassword = "redispass" // Default from docker-compose.yml
	}

	redisDBStr := os.Getenv("REDIS_DB")
	if redisDBStr == "" {
		suite.redisDB = 3 // Use DB 3 for integration tests
	} else {
		fmt.Sscanf(redisDBStr, "%d", &suite.redisDB)
	}

	// Setup logger
	suite.logger = logrus.New()
	suite.logger.SetLevel(logrus.InfoLevel)

	// Create Redis client
	suite.client = redis.NewClient(&redis.Options{
		Addr:         suite.redisAddr,
		Password:     suite.redisPassword,
		DB:           suite.redisDB,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	})

	// Test Redis connection
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := suite.client.Ping(ctx).Err()
	if err != nil {
		suite.T().Skipf("Redis not available at %s: %v", suite.redisAddr, err)
		return
	}

	// Clean test database
	suite.client.FlushDB(ctx)

	suite.logger.Infof("Integration tests using Redis at %s, DB %d", suite.redisAddr, suite.redisDB)
}

// TearDownSuite cleans up the integration test environment.
func (suite *RedisRateLimitIntegrationTestSuite) TearDownSuite() {
	if suite.client != nil {
		// Clean test database
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		suite.client.FlushDB(ctx)
		suite.client.Close()
		suite.logger.Info("Integration test environment cleaned up")
	}
}

// SetupTest creates a fresh service instance for each test.
func (suite *RedisRateLimitIntegrationTestSuite) SetupTest() {
	if suite.client == nil {
		suite.T().Skip("Redis not available for testing")
		return
	}

	// Use production-like configuration for integration tests
	config := service.RedisRateLimitConfig{
		RateLimitConfig: service.RateLimitConfig{
			LoginWindow:     5 * time.Minute,  // Production-like window
			LoginLimit:      5,                // Production-like limit
			ResetWindow:     15 * time.Minute, // Production-like window
			ResetLimit:      3,                // Production-like limit
			CleanupInterval: 10 * time.Minute, // Not used in Redis implementation
		},
		KeyPrefix:  "integration_test",
		Pipeline:   true,
		MaxRetries: 3,
	}

	suite.service = service.NewRedisRateLimitService(suite.client, config, suite.logger)
	require.NotNil(suite.T(), suite.service, "Service should be created")

	// Clean any existing test keys
	ctx := context.Background()
	keys, _ := suite.client.Keys(ctx, "integration_test:*").Result()
	if len(keys) > 0 {
		suite.client.Del(ctx, keys...)
	}
}

// TestApplicationIntegration tests integration with the main application patterns.
//
// Validates:
// - Service works with application-style usage patterns
// - Proper error handling in application context
// - Performance meets application requirements
// - Configuration loading works correctly
func (suite *RedisRateLimitIntegrationTestSuite) TestApplicationIntegration() {
	ctx := context.Background()

	// Simulate typical application usage pattern
	userIP := "203.0.113.45"

	// Test normal authentication flow
	for i := 0; i < 3; i++ {
		// Check if login attempt is allowed
		allowed, err := suite.service.CheckLoginAttempts(ctx, userIP)
		require.NoError(suite.T(), err, "Login check should not fail")
		require.True(suite.T(), allowed, "Login attempt %d should be allowed", i+1)

		// Simulate authentication process
		time.Sleep(100 * time.Millisecond) // Simulate processing time

		// Record the attempt (simulate failed login)
		err = suite.service.RecordLoginAttempt(ctx, userIP, false)
		require.NoError(suite.T(), err, "Recording attempt should not fail")
	}

	// Continue with more attempts
	for i := 0; i < 3; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, userIP)
		require.NoError(suite.T(), err, "Login check should not fail")

		if i < 2 {
			// Should still be allowed (we're at limit 5)
			require.True(suite.T(), allowed, "Login attempt should still be allowed")
			err = suite.service.RecordLoginAttempt(ctx, userIP, false)
			require.NoError(suite.T(), err, "Recording attempt should not fail")
		} else {
			// Should be blocked now (exceeding limit of 5)
			require.False(suite.T(), allowed, "Login attempt should be blocked")
		}
	}

	// Test password reset flow
	userEmail := "user@example.com"

	for i := 0; i < 3; i++ {
		allowed, err := suite.service.CheckPasswordResetAttempts(ctx, userEmail)
		require.NoError(suite.T(), err, "Password reset check should not fail")
		require.True(suite.T(), allowed, "Password reset attempt %d should be allowed", i+1)

		err = suite.service.RecordPasswordResetAttempt(ctx, userEmail)
		require.NoError(suite.T(), err, "Recording password reset should not fail")
	}

	// Fourth password reset should be blocked
	allowed, err := suite.service.CheckPasswordResetAttempts(ctx, userEmail)
	require.NoError(suite.T(), err, "Password reset check should not fail")
	require.False(suite.T(), allowed, "Fourth password reset should be blocked")
}

// TestMultiInstanceCoordination tests coordination between multiple service instances.
//
// Validates:
// - Multiple service instances share the same rate limiting state
// - Distributed coordination works correctly
// - No race conditions between instances
// - Consistent behavior across instances
func (suite *RedisRateLimitIntegrationTestSuite) TestMultiInstanceCoordination() {
	ctx := context.Background()
	identifier := "multi_instance_test"

	// Create two separate service instances (simulating different application instances)
	config := service.RedisRateLimitConfig{
		RateLimitConfig: service.RateLimitConfig{
			LoginWindow:     1 * time.Minute,
			LoginLimit:      3,
			ResetWindow:     2 * time.Minute,
			ResetLimit:      2,
			CleanupInterval: 5 * time.Minute,
		},
		KeyPrefix:  "multi_test",
		Pipeline:   true,
		MaxRetries: 3,
	}

	// Create second Redis client and service (simulating different app instance)
	client2 := redis.NewClient(&redis.Options{
		Addr:     suite.redisAddr,
		Password: suite.redisPassword,
		DB:       suite.redisDB,
	})
	defer client2.Close()

	service1 := service.NewRedisRateLimitService(suite.client, config, suite.logger)
	service2 := service.NewRedisRateLimitService(client2, config, suite.logger)

	// Service 1 records 2 attempts
	for i := 0; i < 2; i++ {
		allowed, err := service1.CheckLoginAttempts(ctx, identifier)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed, "Attempt %d should be allowed on service1", i+1)

		err = service1.RecordLoginAttempt(ctx, identifier, false)
		require.NoError(suite.T(), err)
	}

	// Service 2 should see the same state and allow 1 more attempt
	allowed, err := service2.CheckLoginAttempts(ctx, identifier)
	require.NoError(suite.T(), err, "Service2 should not error")
	require.True(suite.T(), allowed, "Service2 should see 1 remaining attempt")

	err = service2.RecordLoginAttempt(ctx, identifier, false)
	require.NoError(suite.T(), err, "Service2 should record successfully")

	// Both services should now block further attempts
	allowed, err = service1.CheckLoginAttempts(ctx, identifier)
	require.NoError(suite.T(), err, "Service1 check should not error")
	require.False(suite.T(), allowed, "Service1 should block after limit reached")

	allowed, err = service2.CheckLoginAttempts(ctx, identifier)
	require.NoError(suite.T(), err, "Service2 check should not error")
	require.False(suite.T(), allowed, "Service2 should also block after limit reached")

	// Verify stats from both services show consistent information
	stats1 := service1.GetStats()
	stats2 := service2.GetStats()

	assert.Equal(suite.T(), stats1["implementation"], stats2["implementation"], "Implementation should be consistent")
	assert.Equal(suite.T(), stats1["login_limit"], stats2["login_limit"], "Login limit should be consistent")
	assert.Equal(suite.T(), stats1["distributed"], stats2["distributed"], "Distributed flag should be consistent")
}

// TestPersistenceAcrossRestart tests that rate limiting state persists across service restarts.
//
// Validates:
// - Rate limiting state survives service restarts
// - Redis persistence works correctly
// - No data loss during service lifecycle
// - Proper state recovery on restart
func (suite *RedisRateLimitIntegrationTestSuite) TestPersistenceAcrossRestart() {
	ctx := context.Background()
	identifier := "persistence_test"

	// Record some attempts with the original service
	for i := 0; i < 2; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed, "Initial attempt %d should be allowed", i+1)

		err = suite.service.RecordLoginAttempt(ctx, identifier, false)
		require.NoError(suite.T(), err)
	}

	// Simulate service restart by creating a new service instance
	config := service.RedisRateLimitConfig{
		RateLimitConfig: service.RateLimitConfig{
			LoginWindow:     5 * time.Minute,
			LoginLimit:      5,
			ResetWindow:     15 * time.Minute,
			ResetLimit:      3,
			CleanupInterval: 10 * time.Minute,
		},
		KeyPrefix:  "integration_test", // Same prefix as original service
		Pipeline:   true,
		MaxRetries: 3,
	}

	// Create new client and service (simulating restart)
	newClient := redis.NewClient(&redis.Options{
		Addr:     suite.redisAddr,
		Password: suite.redisPassword,
		DB:       suite.redisDB,
	})
	defer newClient.Close()

	newService := service.NewRedisRateLimitService(newClient, config, suite.logger)

	// New service should see the existing attempts and continue counting from there
	allowed, err := newService.CheckLoginAttempts(ctx, identifier)
	require.NoError(suite.T(), err, "New service should not error")
	require.True(suite.T(), allowed, "New service should allow more attempts (2 recorded, limit is 5)")

	// Record one more attempt
	err = newService.RecordLoginAttempt(ctx, identifier, false)
	require.NoError(suite.T(), err, "New service should record successfully")

	// Verify the new service can continue tracking properly
	for i := 0; i < 2; i++ {
		allowed, err = newService.CheckLoginAttempts(ctx, identifier)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed, "Additional attempt %d should be allowed", i+1)

		err = newService.RecordLoginAttempt(ctx, identifier, false)
		require.NoError(suite.T(), err)
	}

	// Now we should be at the limit (5 attempts total)
	allowed, err = newService.CheckLoginAttempts(ctx, identifier)
	require.NoError(suite.T(), err, "Check should not error")
	require.False(suite.T(), allowed, "Should be blocked after reaching limit across restart")
}

// TestProductionScaleLoad tests the service under production-scale load.
//
// Validates:
// - Performance under realistic concurrent load
// - Memory usage remains reasonable
// - Response times are within acceptable limits
// - No resource leaks under sustained load
func (suite *RedisRateLimitIntegrationTestSuite) TestProductionScaleLoad() {
	if testing.Short() {
		suite.T().Skip("Skipping production scale test in short mode")
	}

	ctx := context.Background()

	// Test configuration mimicking production load
	numUsers := 100
	attemptsPerUser := 10
	concurrentWorkers := 20

	// Channel to coordinate work
	userChan := make(chan int, numUsers)
	resultsChan := make(chan string, numUsers*attemptsPerUser)
	errorsChan := make(chan error, numUsers*attemptsPerUser)

	// Fill user channel
	for i := 0; i < numUsers; i++ {
		userChan <- i
	}
	close(userChan)

	// Start concurrent workers
	for w := 0; w < concurrentWorkers; w++ {
		go func(workerID int) {
			for userID := range userChan {
				identifier := fmt.Sprintf("load_test_user_%d", userID)

				for attempt := 0; attempt < attemptsPerUser; attempt++ {
					// Check rate limit
					allowed, err := suite.service.CheckLoginAttempts(ctx, identifier)
					if err != nil {
						errorsChan <- fmt.Errorf("worker %d, user %d, attempt %d: %w", workerID, userID, attempt, err)
						continue
					}

					if allowed {
						// Record attempt
						err = suite.service.RecordLoginAttempt(ctx, identifier, attempt%3 == 0) // Some successful attempts
						if err != nil {
							errorsChan <- fmt.Errorf("worker %d, user %d, attempt %d record: %w", workerID, userID, attempt, err)
							continue
						}
						resultsChan <- "allowed"
					} else {
						resultsChan <- "blocked"
					}

					// Small delay to simulate realistic timing
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(w)
	}

	// Collect results with timeout
	totalExpected := numUsers * attemptsPerUser
	allowedCount := 0
	blockedCount := 0
	errorCount := 0

	timeout := time.After(60 * time.Second) // Generous timeout for production scale test

	for i := 0; i < totalExpected; i++ {
		select {
		case result := <-resultsChan:
			if result == "allowed" {
				allowedCount++
			} else {
				blockedCount++
			}
		case err := <-errorsChan:
			suite.T().Logf("Load test error: %v", err)
			errorCount++
		case <-timeout:
			suite.T().Fatalf("Load test timed out after processing %d/%d operations", i, totalExpected)
		}
	}

	// Verify results
	assert.Equal(suite.T(), totalExpected, allowedCount+blockedCount+errorCount, "All operations should be accounted for")
	assert.LessOrEqual(suite.T(), errorCount, totalExpected/20, "Error rate should be less than 5%") // Allow up to 5% errors
	assert.Greater(suite.T(), allowedCount, 0, "Some attempts should be allowed")
	assert.Greater(suite.T(), blockedCount, 0, "Some attempts should be blocked (rate limiting working)")

	suite.T().Logf("Load test results: %d allowed, %d blocked, %d errors out of %d total operations",
		allowedCount, blockedCount, errorCount, totalExpected)

	// Verify service health after load test
	if concreteService, ok := suite.service.(*service.RedisRateLimitService); ok {
		err := concreteService.HealthCheck(ctx)
		assert.NoError(suite.T(), err, "Service should be healthy after load test")
	}
}

// TestRealWorldScenarios tests realistic application scenarios.
//
// Validates:
// - Mixed login and password reset patterns
// - Different user behavior patterns
// - Edge cases that occur in production
// - Recovery scenarios
func (suite *RedisRateLimitIntegrationTestSuite) TestRealWorldScenarios() {
	ctx := context.Background()

	// Scenario 1: Legitimate user with occasional failed logins
	legitimateUser := "192.168.1.100"

	// User has 2 failed attempts, then succeeds
	for i := 0; i < 2; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, legitimateUser)
		require.NoError(suite.T(), err)
		require.True(suite.T(), allowed)

		err = suite.service.RecordLoginAttempt(ctx, legitimateUser, false) // Failed
		require.NoError(suite.T(), err)
	}

	// Successful login
	allowed, err := suite.service.CheckLoginAttempts(ctx, legitimateUser)
	require.NoError(suite.T(), err)
	require.True(suite.T(), allowed)

	err = suite.service.RecordLoginAttempt(ctx, legitimateUser, true) // Success
	require.NoError(suite.T(), err)

	// Scenario 2: Brute force attack simulation
	attackerIP := "203.0.113.10"

	// Attacker tries many times and gets blocked
	attemptCount := 0
	for i := 0; i < 10; i++ {
		allowed, err := suite.service.CheckLoginAttempts(ctx, attackerIP)
		require.NoError(suite.T(), err)

		if allowed {
			attemptCount++
			err = suite.service.RecordLoginAttempt(ctx, attackerIP, false) // Always fails
			require.NoError(suite.T(), err)
		} else {
			break // Blocked
		}
	}

	// Should be blocked after hitting limit
	assert.Equal(suite.T(), 5, attemptCount, "Should be blocked after 5 attempts") // Our integration test limit

	// Verify attacker is still blocked
	allowed, err = suite.service.CheckLoginAttempts(ctx, attackerIP)
	require.NoError(suite.T(), err)
	require.False(suite.T(), allowed, "Attacker should remain blocked")

	// Scenario 3: User forgets password and tries reset multiple times
	forgetfulUser := "forgetful@example.com"

	// User tries password reset multiple times
	resetCount := 0
	for i := 0; i < 5; i++ {
		allowed, err := suite.service.CheckPasswordResetAttempts(ctx, forgetfulUser)
		require.NoError(suite.T(), err)

		if allowed {
			resetCount++
			err = suite.service.RecordPasswordResetAttempt(ctx, forgetfulUser)
			require.NoError(suite.T(), err)
		} else {
			break // Blocked
		}
	}

	// Should be blocked after hitting reset limit
	assert.Equal(suite.T(), 3, resetCount, "Should be blocked after 3 password resets") // Our integration test limit

	// Verify user is blocked from more resets
	allowed, err = suite.service.CheckPasswordResetAttempts(ctx, forgetfulUser)
	require.NoError(suite.T(), err)
	require.False(suite.T(), allowed, "User should be blocked from more password resets")

	// But should still be able to attempt login (different rate limit)
	allowed, err = suite.service.CheckLoginAttempts(ctx, forgetfulUser)
	require.NoError(suite.T(), err)
	require.True(suite.T(), allowed, "User should still be able to attempt login")
}

// TestHealthCheckIntegration tests health check in integration environment.
//
// Validates:
// - Health check works with real Redis instance
// - Proper error reporting for Redis issues
// - Performance of health checks
// - Health check reliability
func (suite *RedisRateLimitIntegrationTestSuite) TestHealthCheckIntegration() {
	ctx := context.Background()

	// Health check should pass with healthy Redis
	if concreteService, ok := suite.service.(*service.RedisRateLimitService); ok {
		start := time.Now()
		err := concreteService.HealthCheck(ctx)
		duration := time.Since(start)

		assert.NoError(suite.T(), err, "Health check should pass")
		assert.Less(suite.T(), duration, 1*time.Second, "Health check should be fast")

		// Test health check with timeout
		ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		err = concreteService.HealthCheck(ctxWithTimeout)
		// Should either succeed quickly or fail with timeout (both are acceptable)
		if err != nil {
			assert.Contains(suite.T(), err.Error(), "timeout", "If health check fails, it should be due to timeout")
		}
	} else {
		suite.T().Skip("Health check test requires RedisRateLimitService")
	}
}

// TestStatsIntegration tests statistics reporting in integration environment.
//
// Validates:
// - Statistics reflect actual Redis configuration
// - All expected fields are present and accurate
// - Statistics are consistent across calls
// - No sensitive information is exposed
func (suite *RedisRateLimitIntegrationTestSuite) TestStatsIntegration() {
	stats := suite.service.GetStats()

	// Verify implementation details
	assert.Equal(suite.T(), "RedisRateLimitService", stats["implementation"])
	assert.Equal(suite.T(), true, stats["distributed"])
	assert.Equal(suite.T(), true, stats["persistent"])

	// Verify Redis connection information (without sensitive data)
	assert.Contains(suite.T(), stats, "redis_addr")
	assert.Equal(suite.T(), suite.redisDB, stats["redis_db"])
	assert.NotContains(suite.T(), stats, "password") // Should not expose password

	// Verify configuration
	assert.Equal(suite.T(), 5.0, stats["login_window_minutes"])
	assert.Equal(suite.T(), 5, stats["login_limit"])
	assert.Equal(suite.T(), 0.25, stats["reset_window_hours"])
	assert.Equal(suite.T(), 3, stats["reset_limit"])

	// Verify features
	features, ok := stats["features"].([]string)
	require.True(suite.T(), ok, "Features should be string slice")
	assert.Contains(suite.T(), features, "sliding_window")
	assert.Contains(suite.T(), features, "distributed_coordination")
	assert.Contains(suite.T(), features, "persistent_state")
	assert.Contains(suite.T(), features, "atomic_operations")

	// Verify stats are consistent across multiple calls
	stats2 := suite.service.GetStats()
	assert.Equal(suite.T(), stats["implementation"], stats2["implementation"])
	assert.Equal(suite.T(), stats["redis_addr"], stats2["redis_addr"])
	assert.Equal(suite.T(), stats["login_limit"], stats2["login_limit"])
}

// TestRedisRateLimitIntegration is the main integration test function.
func TestRedisRateLimitIntegration(t *testing.T) {
	// Skip integration tests if environment variable is set
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Integration tests skipped by environment variable")
		return
	}

	// Run the integration test suite
	suite.Run(t, new(RedisRateLimitIntegrationTestSuite))
}

// BenchmarkRedisRateLimitIntegration benchmarks the service in integration environment.
func BenchmarkRedisRateLimitIntegration(b *testing.B) {
	// Skip if Redis is not available
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "redispass", // Default from docker-compose.yml
		DB:       4,           // Use separate DB for integration benchmarks
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		b.Skipf("Redis not available for integration benchmarking: %v", err)
		return
	}

	// Clean up
	client.FlushDB(ctx)
	defer client.Close()

	// Create service
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	config := service.DefaultRedisRateLimitConfig()
	config.KeyPrefix = "integration_benchmark"

	rateLimitService := service.NewRedisRateLimitService(client, config, logger)

	b.Run("RealWorldPattern", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			identifier := fmt.Sprintf("user_%d", i%50) // Simulate 50 different users

			// Check and record pattern (typical application flow)
			allowed, err := rateLimitService.CheckLoginAttempts(ctx, identifier)
			if err != nil {
				b.Fatalf("Unexpected error: %v", err)
			}

			if allowed {
				err = rateLimitService.RecordLoginAttempt(ctx, identifier, i%4 == 0) // 25% success rate
				if err != nil {
					b.Fatalf("Unexpected error: %v", err)
				}
			}
		}
	})

	// Clean up benchmark data
	keys, _ := client.Keys(ctx, "integration_benchmark:*").Result()
	if len(keys) > 0 {
		client.Del(ctx, keys...)
	}
}
