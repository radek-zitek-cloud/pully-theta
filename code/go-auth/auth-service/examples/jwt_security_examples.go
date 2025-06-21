// Package examples demonstrates usage of the enhanced JWT security service.
// This file provides practical examples for integrating the JWT service into applications.
package examples

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"auth-service/internal/domain"
	"auth-service/internal/security"
)

// ExampleJWTServiceUsage demonstrates comprehensive usage of the JWT security service.
// This example shows the complete lifecycle of JWT tokens including generation,
// validation, and revocation.
func ExampleJWTServiceUsage() {
	// Initialize Redis client for token blacklisting
	// In production, configure with proper Redis settings
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // No password for local development
		DB:       0,  // Default DB
	})

	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}

	// Create Redis-based token blacklist
	blacklist := security.NewRedisTokenBlacklist(redisClient)

	// Initialize JWT service with production-ready configuration
	jwtService := security.NewJWTService(
		[]byte("your-super-secret-key-must-be-at-least-32-bytes-long"), // Secret key
		"auth-service",    // Issuer
		"api.example.com", // Audience
		blacklist,         // Token blacklist
		15*time.Minute,    // Access token TTL
		7*24*time.Hour,    // Refresh token TTL
	)

	// Example user for token generation
	user := &domain.User{
		ID:              uuid.New(),
		Email:           "user@example.com",
		FirstName:       "John",
		LastName:        "Doe",
		IsEmailVerified: true,
		IsActive:        true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Step 1: Generate token pair for authentication
	fmt.Println("=== Token Generation ===")
	authResponse, err := jwtService.GenerateTokenPair(user)
	if err != nil {
		log.Fatalf("Token generation failed: %v", err)
	}

	fmt.Printf("Access Token (first 50 chars): %s...\n", authResponse.AccessToken[:50])
	fmt.Printf("Refresh Token (first 50 chars): %s...\n", authResponse.RefreshToken[:50])
	fmt.Printf("Token Type: %s\n", authResponse.TokenType)
	fmt.Printf("Expires In: %d seconds\n", authResponse.ExpiresIn)
	fmt.Printf("User ID: %s\n", authResponse.User.ID)
	fmt.Printf("User Email: %s\n", authResponse.User.Email)

	// Step 2: Validate access token (typical API request flow)
	fmt.Println("\n=== Token Validation ===")
	validatedUser, err := jwtService.ValidateToken(ctx, authResponse.AccessToken)
	if err != nil {
		log.Fatalf("Token validation failed: %v", err)
	}

	fmt.Printf("Validated User ID: %s\n", validatedUser.ID)
	fmt.Printf("Validated User Email: %s\n", validatedUser.Email)

	// Step 3: Demonstrate token revocation (logout scenario)
	fmt.Println("\n=== Token Revocation ===")
	err = jwtService.RevokeToken(ctx, authResponse.AccessToken)
	if err != nil {
		log.Fatalf("Token revocation failed: %v", err)
	}

	fmt.Println("Token successfully revoked")

	// Step 4: Attempt to validate revoked token (should fail)
	fmt.Println("\n=== Revoked Token Validation ===")
	_, err = jwtService.ValidateToken(ctx, authResponse.AccessToken)
	if err != nil {
		fmt.Printf("Expected error for revoked token: %v\n", err)
	} else {
		log.Fatal("ERROR: Revoked token was accepted!")
	}

	fmt.Println("\n=== JWT Service Example Complete ===")
}

// ExampleTokenBlacklistOperations demonstrates direct blacklist operations.
// This example shows how to work with the token blacklist interface directly.
func ExampleTokenBlacklistOperations() {
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	// Create blacklist instance
	blacklist := security.NewRedisTokenBlacklist(redisClient)

	ctx := context.Background()
	exampleToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.token"

	// Add token to blacklist
	expiry := time.Now().Add(1 * time.Hour)
	err := blacklist.Add(ctx, exampleToken, expiry)
	if err != nil {
		log.Fatalf("Failed to add token to blacklist: %v", err)
	}

	fmt.Println("Token added to blacklist")

	// Check if token is blacklisted
	isBlacklisted := blacklist.IsBlacklisted(ctx, exampleToken)
	fmt.Printf("Token is blacklisted: %t\n", isBlacklisted)

	// Check non-blacklisted token
	otherToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.other.token"
	isOtherBlacklisted := blacklist.IsBlacklisted(ctx, otherToken)
	fmt.Printf("Other token is blacklisted: %t\n", isOtherBlacklisted)
}

// ExampleErrorHandling demonstrates proper error handling with the JWT service.
// This example shows how to handle different types of JWT-related errors.
func ExampleErrorHandling() {
	// Initialize minimal JWT service for error testing
	blacklist := &MockTokenBlacklist{}
	jwtService := security.NewJWTService(
		[]byte("test-secret-key-must-be-32-bytes"),
		"test-issuer",
		"test-audience",
		blacklist,
		15*time.Minute,
		7*24*time.Hour,
	)

	ctx := context.Background()

	// Test invalid token validation
	fmt.Println("=== Error Handling Examples ===")

	// Example 1: Empty token
	_, err := jwtService.ValidateToken(ctx, "")
	if err != nil {
		fmt.Printf("Empty token error: %v\n", err)
	}

	// Example 2: Malformed token
	_, err = jwtService.ValidateToken(ctx, "not.a.valid.jwt")
	if err != nil {
		fmt.Printf("Malformed token error: %v\n", err)
	}

	// Example 3: Token with wrong signing method
	wrongToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.invalid"
	_, err = jwtService.ValidateToken(ctx, wrongToken)
	if err != nil {
		fmt.Printf("Wrong signing method error: %v\n", err)
	}

	fmt.Println("Error handling examples complete")
}

// MockTokenBlacklist provides a simple in-memory blacklist for testing.
// This implementation is suitable for unit tests but not production use.
type MockTokenBlacklist struct {
	blacklisted map[string]time.Time
}

// Add implements TokenBlacklist.Add for testing purposes.
func (m *MockTokenBlacklist) Add(ctx context.Context, token string, expiry time.Time) error {
	if m.blacklisted == nil {
		m.blacklisted = make(map[string]time.Time)
	}
	m.blacklisted[token] = expiry
	return nil
}

// IsBlacklisted implements TokenBlacklist.IsBlacklisted for testing purposes.
func (m *MockTokenBlacklist) IsBlacklisted(ctx context.Context, token string) bool {
	if m.blacklisted == nil {
		return false
	}
	expiry, exists := m.blacklisted[token]
	if !exists {
		return false
	}
	// Check if token is still within blacklist period
	return time.Now().Before(expiry)
}
