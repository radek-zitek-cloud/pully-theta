// Package password provides comprehensive password management functionality for the
// authentication service. This package consolidates all password-related operations
// including validation, changes, resets, and security policies.
//
// The package is structured around four main components:
//
// 1. Service: Core business logic for password operations
// 2. Handler: HTTP endpoints for password management APIs
// 3. Validator: Password strength validation and policy enforcement
// 4. ResetService: Password reset flow management with tokens
//
// # Architecture Overview
//
// The password package follows the Clean Architecture pattern with clear separation
// of concerns:
//
//	┌─────────────────┐    ┌─────────────────┐
//	│     Handler     │    │     Service     │
//	│  (HTTP Layer)   │────│ (Business Logic)│
//	└─────────────────┘    └─────────────────┘
//	                              │
//	                        ┌─────────────────┐
//	                        │   ResetService  │
//	                        │   & Validator   │
//	                        └─────────────────┘
//	                              │
//	                    ┌─────────────────────┐
//	                    │   Domain/Repository │
//	                    │    (Data Layer)     │
//	                    └─────────────────────┘
//
// # Security Features
//
// The password package implements comprehensive security measures:
//
// - Bcrypt hashing with configurable cost factor
// - Password strength validation with customizable policies
// - Context-aware validation to prevent personal information in passwords
// - Time-limited password reset tokens with secure generation
// - Rate limiting support for reset operations
// - Comprehensive audit logging for all operations
// - All refresh tokens revoked after password changes
// - Protection against enumeration attacks
//
// # Usage Examples
//
// Creating a password service:
//
//	// Create password service with default secure settings
//	passwordService, err := password.NewDefaultService(
//	    userRepo, refreshTokenRepo, resetTokenRepo,
//	    emailService, logger, config)
//	if err != nil {
//	    log.Fatal("Failed to create password service:", err)
//	}
//
// Setting up HTTP handlers:
//
//	// Create password handler
//	passwordHandler, err := password.NewHandler(passwordService, logger, config)
//	if err != nil {
//	    log.Fatal("Failed to create password handler:", err)
//	}
//
//	// Register routes with Gin
//	v1 := router.Group("/api/v1")
//	passwordHandler.RegisterRoutes(v1)
//
// Password validation:
//
//		// Basic password validation
//		err := passwordService.ValidatePassword("MySecurePass123!")
//		if err != nil {
//		    log.Printf("Password validation failed: %v", err)
//		}
//
//		// Context-aware validation
//		err = passwordService.ValidatePasswordWithContext(
//		    "MySecurePass123!", "user@example.com", "John Doe")
//	    if err != nil {
//	        log.Printf("Password contains personal information: %v", err)
//	    }
//
// Password strength scoring:
//
//	score := passwordService.GetPasswordStrengthScore("MySecurePass123!")
//	if score < 60 {
//	    log.Warn("Password strength below recommended threshold")
//	}
//
// # API Endpoints
//
// The package exposes the following REST endpoints:
//
// - POST /password/change - Change user password (authenticated)
// - POST /password/reset/request - Request password reset (public)
// - POST /password/reset/complete - Complete password reset (public)
// - POST /password/validate - Validate password strength (public)
//
// # Configuration
//
// The password package supports extensive configuration through ServiceConfig:
//
//	config := password.ServiceConfig{
//	    ValidationConfig: password.ValidationConfig{
//	        MinLength:           12,
//	        MaxLength:           128,
//	        RequireUppercase:    true,
//	        RequireLowercase:    true,
//	        RequireDigits:       true,
//	        RequireSpecialChars: true,
//	        SpecialCharSet:      "!@#$%^&*()_+-=[]{}|;:,.<>?",
//	    },
//	    ResetConfig: password.ResetConfig{
//	        TokenTTL:              time.Hour,
//	        MaxAttemptsPerIP:      5,
//	        MaxAttemptsPerEmail:   3,
//	        TokenLength:           32,
//	        RequireEmailVerified:  true,
//	    },
//	    BcryptCost:      12,
//	    RevokeAllTokens: true,
//	}
//
// # Error Handling
//
// The package uses domain-specific errors for consistent error handling:
//
// - domain.ErrUserNotFound: User doesn't exist
// - domain.ErrInvalidCredentials: Current password incorrect
// - domain.ErrWeakPassword: Password doesn't meet requirements
// - domain.ErrAccountInactive: Account is disabled
// - domain.ErrTokenExpired: Reset token has expired
// - domain.ErrInvalidToken: Reset token is invalid
//
// # Audit Logging
//
// All password operations are logged with structured metadata:
//
// - User ID and operation type
// - Client IP address and user agent
// - Success/failure status and error details
// - Timestamps and correlation IDs
//
// # Performance Considerations
//
// - Bcrypt operations are CPU-intensive; consider cost factor tuning
// - Database operations are optimized with proper indexing
// - Password validation is O(n) where n is password length
// - Reset token cleanup should be run periodically
//
// # Testing
//
// The package is designed for comprehensive testing with:
//
// - Dependency injection for all external services
// - Interface-based design for easy mocking
// - Comprehensive error scenarios covered
// - Integration tests for end-to-end flows
//
// # Thread Safety
//
// All components in this package are thread-safe and can be used concurrently
// without additional synchronization. The underlying bcrypt library and
// database operations are thread-safe.
//
// # Future Enhancements
//
// Planned improvements include:
//
// - Password history tracking to prevent reuse
// - Advanced password policies (dictionary checks, entropy analysis)
// - Breached password detection via HaveIBeenPwned API
// - Passwordless authentication options
// - Multi-factor authentication integration
//
// For detailed documentation of individual components, see:
// - service.go: Core business logic and password operations
// - handler.go: HTTP API endpoints and request handling
// - validator.go: Password strength validation and policies
// - reset.go: Password reset token management and email flows
package password
