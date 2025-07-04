package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "auth-service/docs" // Import generated swagger docs
	"auth-service/internal/api"
	"auth-service/internal/config"
	"auth-service/internal/middleware"
	"auth-service/internal/password"
	"auth-service/internal/repository"
	"auth-service/internal/security"
	"auth-service/internal/service"
)

// Version information injected at build time via ldflags
// These variables provide comprehensive build and version metadata
// for monitoring, debugging, and operational purposes.
//
// Usage in build:
//
//	go build -ldflags "-X main.Version=v1.2.3 -X main.BuildTime=2025-06-20T14:30:00Z"
//
// The version information is exposed through:
// - Application logs during startup
// - Health check endpoints (/health, /health/ready, /health/live)
// - Swagger documentation metadata
// - Prometheus metrics labels
var (
	// Version is the full version string (e.g., "v1.2.3-build.42+abcd123")
	Version = "dev"

	// BuildTime is the RFC3339 timestamp when the binary was built
	BuildTime = "unknown"

	// GitCommit is the short commit hash from git
	GitCommit = "unknown"

	// GitBranch is the git branch name the build was made from
	GitBranch = "unknown"

	// BuildUser is the username who built the binary
	BuildUser = "unknown"

	// BuildHost is the hostname where the binary was built
	BuildHost = "unknown"

	// SemanticVersion is the semantic version (e.g., "1.2.3")
	SemanticVersion = "1.0.0"

	// BuildNumber is the incremental build number
	BuildNumber = "0"
)

// @title           Authentication Service API
// @version         1.0.0
// @description     A comprehensive authentication and user management microservice built with Go and Gin.
// @description     This service provides secure user registration, login, JWT token management,
// @description     password reset functionality, and comprehensive audit logging.

// @contact.name   API Support
// @contact.url    https://github.com/your-org/auth-service
// @contact.email  support@example.com

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:6910
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// @tag.name auth
// @tag.description Authentication operations including registration, login, logout, and token refresh

// @tag.name user
// @tag.description User management operations including profile updates and password changes

// @tag.name health
// @tag.description Health check and monitoring endpoints

// main is the entry point for the authentication service.
// This function sets up all dependencies, initializes the HTTP server,
// and handles graceful shutdown.
//
// The application follows these initialization steps:
// 1. Load configuration from environment variables
// 2. Initialize structured logging
// 3. Connect to PostgreSQL database
// 4. Initialize repository layer
// 5. Initialize service layer with dependencies
// 6. Set up HTTP routes and middleware
// 7. Start HTTP server with graceful shutdown
//
// Environment variables required:
// - DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME: Database connection
// - JWT_SECRET: JWT signing secret (minimum 32 characters)
// - PORT: HTTP server port (optional, defaults to 8080)
//
// The server supports graceful shutdown on SIGINT and SIGTERM signals,
// allowing in-flight requests to complete before terminating.
func main() {
	// Load configuration from environment variables
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize structured logger
	logger := initializeLogger(cfg)
	logger.WithFields(logrus.Fields{
		"version":          Version,
		"semantic_version": SemanticVersion,
		"build_number":     BuildNumber,
		"build_time":       BuildTime,
		"git_commit":       GitCommit,
		"git_branch":       GitBranch,
		"build_user":       BuildUser,
		"build_host":       BuildHost,
		"environment":      cfg.Server.Environment,
		"port":             cfg.Server.Port,
	}).Info("Starting authentication service")

	// Connect to PostgreSQL database
	db, err := initializeDatabase(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize database")
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.WithError(err).Error("Failed to close database connection")
		}
	}()

	// Initialize repository layer
	userRepo, err := repository.NewPostgreSQLUserRepository(db, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize user repository")
	}

	// Initialize refresh token repository
	refreshTokenRepo := repository.NewPostgreSQLRefreshTokenRepository(db, logger)

	// Initialize password reset token repository
	passwordResetRepo := repository.NewPostgreSQLPasswordResetTokenRepository(db, logger)

	// Initialize audit log repository
	auditRepo := repository.NewPostgreSQLAuditLogRepository(db, logger)

	// Initialize service layer dependencies

	// Initialize email service
	emailConfig := service.EmailConfig{
		Host:        cfg.Email.Host,
		Port:        cfg.Email.Port,
		Username:    cfg.Email.Username,
		Password:    cfg.Email.Password,
		FromAddress: cfg.Email.FromEmail,
		FromName:    "Auth Service", // Default name since config doesn't have FromName
		UseTLS:      cfg.Email.UseTLS,
		Timeout:     30 * time.Second, // Default timeout
	}

	emailService, err := service.NewSMTPEmailService(emailConfig, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize email service")
	}

	// Initialize rate limiting service
	rateLimitService, err := initializeRateLimitService(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize rate limiting service")
	}

	// Initialize metrics handler before auth service (needed for metrics recording)
	metricsHandler, err := api.NewMetricsHandler(logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize metrics handler")
	}

	// Initialize enhanced JWT security service with Redis blacklisting
	jwtService, err := initializeJWTService(cfg, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize JWT security service")
	}

	// Initialize authentication service
	authService, err := service.NewAuthService(
		userRepo,
		refreshTokenRepo,
		passwordResetRepo,
		auditRepo,
		logger,
		cfg,
		emailService,
		rateLimitService,
		metricsHandler.GetAuthMetricsRecorder(),
		jwtService,
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize auth service")
	}

	// Initialize HTTP handlers
	authHandler, err := api.NewAuthHandler(authService, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize auth handler")
	}

	// Initialize password service configuration
	passwordConfig := password.ServiceConfig{
		ValidationConfig: password.ValidationConfig{
			MinLength:           12,                           // Minimum 12 characters for strong passwords
			MaxLength:           128,                          // Maximum 128 characters
			RequireUppercase:    true,                         // Require uppercase letters
			RequireLowercase:    true,                         // Require lowercase letters
			RequireDigits:       true,                         // Require digits
			RequireSpecialChars: true,                         // Require special characters
			SpecialCharSet:      "!@#$%^&*()_+-=[]{}|;:,.<>?", // Allowed special chars
		},
		ResetConfig: password.ResetConfig{
			TokenTTL:             24 * time.Hour, // 24 hours for password reset tokens
			MaxAttemptsPerIP:     5,              // Maximum 5 attempts per IP
			MaxAttemptsPerEmail:  3,              // Maximum 3 attempts per email
			TokenLength:          32,             // 32 bytes = 256 bits for secure tokens
			RequireEmailVerified: true,           // Require verified email for reset
		},
		BcryptCost:      12,   // Bcrypt cost factor (2^12 iterations)
		RevokeAllTokens: true, // Revoke all refresh tokens on password change
	}

	// Initialize password service
	passwordService, err := password.NewService(
		userRepo,
		refreshTokenRepo,
		passwordResetRepo,
		emailService,
		logger,
		cfg,
		passwordConfig,
	)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize password service")
	}

	// Initialize password handler
	passwordHandler, err := password.NewHandler(passwordService, logger, cfg)
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize password handler")
	}

	// Create version information for health handler
	versionInfo := &api.VersionInfo{
		Version:         Version,
		SemanticVersion: SemanticVersion,
		BuildNumber:     BuildNumber,
		BuildTime:       BuildTime,
		GitCommit:       GitCommit,
		GitBranch:       GitBranch,
		BuildUser:       BuildUser,
		BuildHost:       BuildHost,
	}

	// Initialize health handler with version information
	healthHandler := api.NewHealthHandler(db, logger, versionInfo)

	// Set up HTTP router with middleware
	router := setupRouter(cfg, authHandler, passwordHandler, healthHandler, metricsHandler, jwtService, logger)

	// Create HTTP server with timeouts
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logger.WithFields(logrus.Fields{
			"address": server.Addr,
			"env":     cfg.Server.Environment,
		}).Info("HTTP server starting")

		serverErrors <- server.ListenAndServe()
	}()

	// Wait for interrupt signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		logger.WithError(err).Fatal("Server failed to start")

	case sig := <-shutdown:
		logger.WithField("signal", sig.String()).Info("Received shutdown signal")

		// Create context for shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		if err := server.Shutdown(ctx); err != nil {
			logger.WithError(err).Error("Failed to shutdown server gracefully")

			// Force close if graceful shutdown fails
			if err := server.Close(); err != nil {
				logger.WithError(err).Fatal("Failed to force close server")
			}
		}

		logger.Info("Server shutdown completed")
	}
}

// initializeLogger sets up structured logging with the configured format and level.
// This function configures the logger based on the environment and requirements.
//
// Configuration options:
// - Log level: debug, info, warn, error
// - Log format: json (for production), text (for development)
// - Output destination: stdout (default)
//
// Parameters:
//   - cfg: Application configuration
//
// Returns:
//   - Configured logrus logger instance
func initializeLogger(cfg *config.Config) *logrus.Logger {
	logger := logrus.New()

	// Set log level
	switch cfg.Logging.Level {
	case "debug":
		logger.SetLevel(logrus.DebugLevel)
	case "info":
		logger.SetLevel(logrus.InfoLevel)
	case "warn":
		logger.SetLevel(logrus.WarnLevel)
	case "error":
		logger.SetLevel(logrus.ErrorLevel)
	default:
		logger.SetLevel(logrus.InfoLevel)
	}

	// Set log format
	if cfg.Logging.Format == "json" || cfg.IsProduction() {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
		})
	}

	// Set output destination (for now, always stdout)
	logger.SetOutput(os.Stdout)

	return logger
}

// initializeDatabase establishes a connection to PostgreSQL with connection pooling.
// This function configures the database connection with proper timeouts,
// connection limits, and health checks.
//
// Connection features:
// - Connection pooling for performance
// - Connection lifetime management
// - Health check validation
// - Proper error handling and logging
//
// Parameters:
//   - cfg: Application configuration with database settings
//   - logger: Logger for database connection events
//
// Returns:
//   - Configured database connection pool
//   - Error if connection fails or configuration is invalid
func initializeDatabase(cfg *config.Config, logger *logrus.Logger) (*sql.DB, error) {
	logger.WithFields(logrus.Fields{
		"host":     cfg.Database.Host,
		"port":     cfg.Database.Port,
		"database": cfg.Database.Database,
		"user":     cfg.Database.Username,
	}).Info("Connecting to PostgreSQL database")

	// Open database connection
	db, err := sql.Open("postgres", cfg.GetDatabaseURL())
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool for optimal performance and resource management
	// These settings help prevent database connection exhaustion and ensure
	// connections are properly managed throughout the application lifecycle
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)       // Limit total concurrent connections
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)       // Maintain ready connections for performance
	db.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime) // Prevent stale connections
	db.SetConnMaxIdleTime(cfg.Database.ConnMaxIdleTime) // Release unused connections

	logger.WithFields(logrus.Fields{
		"max_open_conns":     cfg.Database.MaxOpenConns,
		"max_idle_conns":     cfg.Database.MaxIdleConns,
		"conn_max_lifetime":  cfg.Database.ConnMaxLifetime,
		"conn_max_idle_time": cfg.Database.ConnMaxIdleTime,
	}).Debug("Database connection pool configured")

	// Test database connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database connection test failed: %w", err)
	}

	logger.Info("Database connection established successfully")
	return db, nil
}

// setupRouter configures the HTTP router with all routes and middleware.
// This function sets up the complete routing table with proper middleware
// for CORS, logging, authentication, and error handling.
//
// Middleware stack (in order):
// 1. Request logging with correlation IDs
// 2. CORS headers for cross-origin requests
// 3. Rate limiting for abuse prevention
// 4. JWT authentication for protected routes
// 5. Error recovery and handling
//
// Routes:
// - Public routes: health check, register, login, password reset, metrics
// - Protected routes: logout, profile, password change, token refresh
//
// Parameters:
//   - cfg: Application configuration
//   - authHandler: Handler for authentication endpoints
//   - passwordHandler: Handler for password management endpoints
//   - healthHandler: Handler for health check endpoints
//   - metricsHandler: Handler for Prometheus metrics endpoint
//   - logger: Logger for middleware and request logging
//
// Returns:
//   - Configured Gin router with all routes and middleware
func setupRouter(cfg *config.Config, authHandler *api.AuthHandler, passwordHandler *password.Handler, healthHandler *api.HealthHandler, metricsHandler *api.MetricsHandler, jwtService *security.JWTService, logger *logrus.Logger) *gin.Engine {
	// Set Gin mode based on environment
	if cfg.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Create router instance
	router := gin.New()

	// Initialize enhanced JWT middleware with security service
	jwtMiddleware := middleware.NewJWTMiddleware(jwtService, cfg, logger)

	// Add global middleware
	router.Use(gin.Recovery())                               // Panic recovery
	router.Use(middleware.MetricsMiddleware(metricsHandler)) // HTTP metrics recording
	router.Use(requestLoggingMiddleware(logger))
	router.Use(corsMiddleware(cfg))
	router.Use(securityHeadersMiddleware())

	// Backward compatibility: Health and metrics endpoints at root level
	// These are commonly expected by monitoring systems and load balancers
	router.GET("/health", healthHandler.HealthCheck)
	router.GET("/health/live", healthHandler.LivenessCheck)
	router.GET("/health/ready", healthHandler.ReadinessCheck)
	router.GET("/metrics", metricsHandler.ServeHTTP)

	// API version 1 routes
	v1 := router.Group("/api/v1")
	{
		// Health and metrics endpoints under versioned API for consistency
		v1.GET("/health", healthHandler.HealthCheck)
		v1.GET("/health/live", healthHandler.LivenessCheck)
		v1.GET("/health/ready", healthHandler.ReadinessCheck)
		v1.GET("/metrics", metricsHandler.ServeHTTP)

		// Authentication routes (public)
		auth := v1.Group("/auth")
		{
			// Public routes that should reject authenticated users
			publicAuth := auth.Group("")
			publicAuth.Use(jwtMiddleware.RequireNoAuth())
			{
				publicAuth.POST("/register", authHandler.Register)
				publicAuth.POST("/login", authHandler.Login)
			}

			// Public routes that allow both authenticated and unauthenticated users
			auth.POST("/password/forgot", passwordHandler.RequestPasswordReset)
			auth.POST("/password/reset", passwordHandler.CompletePasswordReset)

			// Refresh token endpoint - special case, validates refresh tokens
			auth.POST("/refresh", authHandler.RefreshToken)

			// Protected routes requiring authentication
			protected := auth.Group("")
			protected.Use(jwtMiddleware.RequireAuth())
			{
				protected.GET("/me", authHandler.Me)
				protected.PUT("/me", authHandler.UpdateProfile)
				protected.POST("/logout", authHandler.Logout)
				protected.POST("/logout-all", authHandler.LogoutAll)
				protected.PUT("/password/change", passwordHandler.ChangePassword)
			}
		}
	}

	// Swagger documentation route (only enable if configured)
	if cfg.Swagger.Enabled {
		router.GET(cfg.Swagger.Path+"/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		logger.WithField("path", cfg.Swagger.Path).Info("Swagger UI enabled")
	}

	return router
}

// Middleware functions would be implemented here...
// For brevity, I'm creating placeholder functions

func requestLoggingMiddleware(logger *logrus.Logger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Custom logging format - could be enhanced with correlation IDs
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC3339),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// initializeRateLimitService creates the appropriate rate limiting service based on configuration.
//
// This function supports multiple rate limiting backends:
// - "memory": In-memory rate limiting (suitable for single-instance deployments)
// - "redis": Redis-based rate limiting (recommended for production and multi-instance deployments)
//
// Parameters:
//   - cfg: Application configuration containing rate limiting and Redis settings
//   - logger: Structured logger for debugging and monitoring
//
// Returns:
//   - service.RateLimitService: Configured rate limiting service
//   - error: Configuration or connection errors
//
// The Redis implementation provides:
// - Persistent rate limiting state across service restarts
// - Distributed coordination across multiple instances
// - Sliding window algorithm for accurate rate limiting
// - Automatic cleanup of expired entries
//
// Example configuration:
//   - RATE_LIMIT_TYPE=redis (for production)
//   - RATE_LIMIT_TYPE=memory (for development/testing)
func initializeRateLimitService(cfg *config.Config, logger *logrus.Logger) (service.RateLimitService, error) {
	// Get base rate limiting configuration
	rateLimitConfig := service.DefaultRateLimitConfig()

	switch cfg.Security.RateLimitType {
	case "redis":
		// Create Redis client
		redisClient := redis.NewClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
			Password:     cfg.Redis.Password,
			DB:           cfg.Redis.DB,
			MaxRetries:   cfg.Redis.MaxRetries,
			PoolSize:     cfg.Redis.PoolSize,
			MinIdleConns: cfg.Redis.MinIdleConns,
		})

		// Test Redis connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := redisClient.Ping(ctx).Err(); err != nil {
			redisClient.Close()
			return nil, fmt.Errorf("failed to connect to Redis at %s:%s: %w",
				cfg.Redis.Host, cfg.Redis.Port, err)
		}

		// Create Redis rate limiting configuration
		redisConfig := service.RedisRateLimitConfig{
			RateLimitConfig: rateLimitConfig,
			KeyPrefix:       "auth_service",
			Pipeline:        true,
			MaxRetries:      3,
		}

		logger.WithFields(logrus.Fields{
			"type":       "redis",
			"redis_addr": fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
			"redis_db":   cfg.Redis.DB,
			"key_prefix": redisConfig.KeyPrefix,
		}).Info("Initializing Redis-based rate limiting service")

		return service.NewRedisRateLimitService(redisClient, redisConfig, logger), nil

	case "memory":
		logger.WithFields(logrus.Fields{
			"type": "memory",
		}).Info("Initializing in-memory rate limiting service")

		return service.NewInMemoryRateLimitService(rateLimitConfig, logger), nil

	default:
		return nil, fmt.Errorf("unsupported rate limit type: %s (supported: memory, redis)", cfg.Security.RateLimitType)
	}
}

func corsMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*") // Configure based on cfg.CORS
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func securityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Next()
	}
}

// initializeJWTService creates and configures the enhanced JWT security service.
// This function sets up the JWT service with Redis-based token blacklisting for enterprise-grade security.
//
// Features initialized:
// - JWT token generation with HMAC-SHA256 signing
// - Redis-based distributed token blacklisting
// - Configurable token expiration times
// - Comprehensive token validation
// - Protection against common JWT attacks
//
// The function automatically creates a Redis client for token blacklisting,
// separate from the rate limiting Redis client to avoid conflicts.
//
// Parameters:
//   - cfg: Application configuration containing JWT and Redis settings
//   - logger: Structured logger for service operations
//
// Returns:
//   - *security.JWTService: Configured JWT service ready for production use
//   - error: Configuration or connection errors
//
// Environment variables used:
//   - JWT_SECRET: Secret key for token signing (minimum 32 bytes)
//   - JWT_ISSUER: Token issuer identifier (defaults to "auth-service")
//   - JWT_ACCESS_TOKEN_EXPIRY: Access token lifetime (defaults to 15 minutes)
//   - JWT_REFRESH_TOKEN_EXPIRY: Refresh token lifetime (defaults to 7 days)
//   - REDIS_HOST, REDIS_PORT: Redis connection for blacklist
//
// Security considerations:
// - Uses separate Redis database for JWT blacklist (DB 1)
// - Validates JWT secret key length for security
// - Enables comprehensive token validation features
// - Provides immediate token revocation capabilities
//
// Usage:
//
//	jwtService, err := initializeJWTService(cfg, logger)
//	if err != nil {
//	    return fmt.Errorf("JWT service init failed: %w", err)
//	}
func initializeJWTService(cfg *config.Config, logger *logrus.Logger) (*security.JWTService, error) {
	// Validate JWT secret key for security
	if len(cfg.JWT.Secret) < 32 {
		return nil, fmt.Errorf("JWT secret key must be at least 32 bytes for security, got %d bytes", len(cfg.JWT.Secret))
	}

	// Create dedicated Redis client for JWT blacklisting
	// Use a separate database (DB 1) to avoid conflicts with rate limiting (DB 0)
	redisClient := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password:     cfg.Redis.Password,
		DB:           1, // Use separate DB for JWT blacklist
		MaxRetries:   cfg.Redis.MaxRetries,
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		PoolTimeout:  10 * time.Second,
	})

	// Test Redis connection for JWT blacklist
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		redisClient.Close()
		return nil, fmt.Errorf("failed to connect to Redis for JWT blacklist at %s:%s DB=1: %w",
			cfg.Redis.Host, cfg.Redis.Port, err)
	}

	// Create Redis-based token blacklist
	blacklist := security.NewRedisTokenBlacklist(redisClient)

	// Set issuer to service name if not configured
	issuer := cfg.JWT.Issuer
	if issuer == "" {
		issuer = "auth-service"
	}

	// Set audience to service name if not configured
	audience := issuer

	// Initialize JWT service with production-ready configuration
	jwtService := security.NewJWTService(
		[]byte(cfg.JWT.Secret),     // Secret key for HMAC signing
		issuer,                     // Token issuer identifier
		audience,                   // Token audience identifier
		blacklist,                  // Redis-based token blacklist
		cfg.JWT.AccessTokenExpiry,  // Access token lifetime
		cfg.JWT.RefreshTokenExpiry, // Refresh token lifetime
	)

	logger.WithFields(logrus.Fields{
		"issuer":               issuer,
		"audience":             audience,
		"access_token_expiry":  cfg.JWT.AccessTokenExpiry,
		"refresh_token_expiry": cfg.JWT.RefreshTokenExpiry,
		"redis_addr":           fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		"redis_db":             1,
		"blacklist_enabled":    true,
	}).Info("Enhanced JWT security service initialized successfully")

	return jwtService, nil
}
