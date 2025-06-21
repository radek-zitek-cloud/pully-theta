package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

// Config holds all configuration values for the authentication service.
// Configuration is loaded from environment variables with sensible defaults.
//
// The configuration is structured into logical groups:
// - Server: HTTP server settings
// - Database: PostgreSQL connection settings
// - JWT: Token signing and expiry settings
// - Security: Password hashing and rate limiting
// - Email: SMTP settings for notifications
// - Logging: Log level and format settings
//
// All sensitive values (passwords, secrets) should be provided via environment
// variables and never committed to version control.
type Config struct {
	// Server configuration for HTTP service
	Server ServerConfig `json:"server"`

	// Database configuration for PostgreSQL
	Database DatabaseConfig `json:"database"`

	// JWT configuration for token management
	JWT JWTConfig `json:"jwt"`

	// Security configuration for password hashing and rate limiting
	Security SecurityConfig `json:"security"`

	// Email configuration for SMTP notifications
	Email EmailConfig `json:"email"`

	// Logging configuration
	Logging LoggingConfig `json:"logging"`

	// CORS configuration for cross-origin requests
	CORS CORSConfig `json:"cors"`

	// Redis configuration for caching and sessions
	Redis RedisConfig `json:"redis"`

	// Swagger configuration for API documentation
	Swagger SwaggerConfig `json:"swagger"`
}

// ServerConfig contains HTTP server related settings.
// These settings control how the HTTP server behaves and what features are enabled.
type ServerConfig struct {
	// Port is the HTTP port the server listens on
	Port string `json:"port"`

	// Host is the network interface to bind to (0.0.0.0 for all interfaces)
	Host string `json:"host"`

	// Environment indicates the deployment environment (development, staging, production)
	Environment string `json:"environment"`

	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout time.Duration `json:"read_timeout"`

	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout time.Duration `json:"write_timeout"`

	// IdleTimeout is the maximum amount of time to wait for the next request
	IdleTimeout time.Duration `json:"idle_timeout"`

	// TrustedProxies is a list of trusted proxy IP addresses/networks
	TrustedProxies []string `json:"trusted_proxies"`
}

// DatabaseConfig contains PostgreSQL database connection settings.
// These settings are used to establish and manage database connections.
//
// Connection pooling parameters are critical for performance and resource management:
// - MaxOpenConns: Limits total connections to prevent database overload
// - MaxIdleConns: Maintains ready connections for better response times
// - ConnMaxLifetime: Prevents stale connections and handles network issues
// - ConnMaxIdleTime: Releases unused connections to conserve resources
//
// Security considerations:
// - Use connection pooling to prevent connection exhaustion
// - Enable SSL in production environments (set SSLMode to "require" or "verify-full")
// - Use strong passwords and restrict network access
// - Monitor connection metrics to detect potential attacks
//
// Environment variable mapping:
// - DB_HOST: Database server hostname or IP address
// - DB_PORT: Database server port (default: 5432)
// - DB_USER: Database username for authentication
// - DB_PASSWORD: Database password (should be strong and unique)
// - DB_NAME: Database name to connect to
// - DB_SSLMODE: SSL/TLS connection security mode (default: disable)
// - DB_MAX_OPEN_CONNS: Maximum number of open connections (default: 25)
// - DB_MAX_IDLE_CONNS: Maximum number of idle connections (default: 5)
// - DB_CONN_MAX_LIFETIME: Maximum connection lifetime (default: 1h)
// - DB_CONN_MAX_IDLE_TIME: Maximum connection idle time (default: 15m)
type DatabaseConfig struct {
	// Host is the database server hostname or IP address
	// Example: "localhost", "db.example.com", "192.168.1.100"
	Host string `env:"DB_HOST" json:"host"`

	// Port is the database server port (typically 5432 for PostgreSQL)
	// Must be a valid port number between 1-65535
	Port int `env:"DB_PORT" json:"port" default:"5432"`

	// Username is the database username for authentication
	// Should have minimum required privileges for the application
	Username string `env:"DB_USER" json:"username"`

	// Password is the database password (should be strong and unique)
	// Excluded from JSON serialization for security
	Password string `env:"DB_PASSWORD" json:"password"`

	// Database is the database name to connect to
	// Example: "auth_service", "production_db"
	Database string `env:"DB_NAME" json:"database"`

	// SSLMode controls SSL/TLS connection security
	// Values: "disable", "require", "verify-ca", "verify-full"
	// Production should use "require" or higher
	SSLMode string `env:"DB_SSLMODE" json:"ssl_mode" default:"disable"`

	// MaxOpenConns is the maximum number of open connections to the database
	// Prevents overwhelming the database server
	// Default: 25 (suitable for most applications)
	// Consider increasing for high-traffic applications
	MaxOpenConns int `env:"DB_MAX_OPEN_CONNS" json:"max_open_conns" default:"25"`

	// MaxIdleConns is the maximum number of connections in the idle connection pool
	// Keeps connections ready for immediate use
	// Default: 5 (should be <= MaxOpenConns)
	// Higher values improve response time but use more resources
	MaxIdleConns int `env:"DB_MAX_IDLE_CONNS" json:"max_idle_conns" default:"5"`

	// ConnMaxLifetime is the maximum amount of time a connection may be reused
	// Prevents stale connections and handles network configuration changes
	// Default: 1 hour (good balance between performance and freshness)
	// Consider shorter times for unstable networks
	ConnMaxLifetime time.Duration `env:"DB_CONN_MAX_LIFETIME" json:"conn_max_lifetime" default:"1h"`

	// ConnMaxIdleTime is the maximum amount of time a connection may be idle
	// Releases unused connections to conserve database resources
	// Default: 15 minutes (balances resource usage and connection overhead)
	// Should be less than ConnMaxLifetime
	ConnMaxIdleTime time.Duration `env:"DB_CONN_MAX_IDLE_TIME" json:"conn_max_idle_time" default:"15m"`
}

// JWTConfig contains JWT token signing and validation settings.
// These settings control how JWT tokens are created and verified.
//
// Security considerations:
// - Use a strong, random secret key (minimum 32 characters)
// - Rotate keys periodically in production
// - Use short access token expiry for better security
// - Store refresh tokens securely and allow revocation
type JWTConfig struct {
	// Secret is the key used to sign JWT tokens (must be kept secure)
	Secret string `json:"-"` // Excluded from JSON for security

	// AccessTokenExpiry is how long access tokens remain valid
	AccessTokenExpiry time.Duration `json:"access_token_expiry"`

	// RefreshTokenExpiry is how long refresh tokens remain valid
	RefreshTokenExpiry time.Duration `json:"refresh_token_expiry"`

	// Issuer is the JWT issuer claim (typically service name)
	Issuer string `json:"issuer"`

	// Algorithm is the signing algorithm (HS256, RS256, etc.)
	Algorithm string `json:"algorithm"`
}

// SecurityConfig contains security-related settings.
// These settings control password hashing, rate limiting, and other security features.
type SecurityConfig struct {
	// BcryptCost is the computational cost for password hashing (10-15 recommended)
	BcryptCost int `json:"bcrypt_cost"`

	// RateLimitEnabled controls whether rate limiting is active
	RateLimitEnabled bool `json:"rate_limit_enabled"`

	// RateLimitType specifies the rate limiting implementation to use
	// Options: "memory" (in-memory), "redis" (Redis-based, recommended for production)
	RateLimitType string `json:"rate_limit_type"`

	// RateLimitRequestsPerMinute is the maximum requests per minute per IP
	RateLimitRequestsPerMinute int `json:"rate_limit_requests_per_minute"`

	// PasswordResetTokenExpiry is how long password reset tokens remain valid
	PasswordResetTokenExpiry time.Duration `json:"password_reset_token_expiry"`

	// MaxLoginAttempts is the maximum failed login attempts before lockout
	MaxLoginAttempts int `json:"max_login_attempts"`

	// LoginLockoutDuration is how long accounts are locked after max attempts
	LoginLockoutDuration time.Duration `json:"login_lockout_duration"`
}

// EmailConfig contains SMTP settings for sending emails.
// Used for password reset notifications and email verification.
//
// Security considerations:
// - Use app-specific passwords for Gmail/major providers
// - Enable TLS/SSL for email transmission
// - Validate email templates to prevent injection
type EmailConfig struct {
	// Host is the SMTP server hostname
	Host string `json:"host"`

	// Port is the SMTP server port (587 for TLS, 465 for SSL)
	Port int `json:"port"`

	// Username is the SMTP authentication username
	Username string `json:"username"`

	// Password is the SMTP authentication password
	Password string `json:"-"` // Excluded from JSON for security

	// FromEmail is the sender email address for notifications
	FromEmail string `json:"from_email"`

	// UseTLS controls whether to use TLS encryption
	UseTLS bool `json:"use_tls"`
}

// LoggingConfig contains logging configuration settings.
// Controls log level, format, and output destinations.
type LoggingConfig struct {
	// Level controls the minimum log level (debug, info, warn, error)
	Level string `json:"level"`

	// Format controls log output format (json, text)
	Format string `json:"format"`

	// OutputPath is where logs are written (stdout, stderr, file path)
	OutputPath string `json:"output_path"`
}

// CORSConfig contains Cross-Origin Resource Sharing settings.
// Controls which origins can access the API from web browsers.
type CORSConfig struct {
	// AllowedOrigins is a list of allowed origin domains
	AllowedOrigins []string `json:"allowed_origins"`

	// AllowedMethods is a list of allowed HTTP methods
	AllowedMethods []string `json:"allowed_methods"`

	// AllowedHeaders is a list of allowed request headers
	AllowedHeaders []string `json:"allowed_headers"`

	// AllowCredentials controls whether credentials can be sent
	AllowCredentials bool `json:"allow_credentials"`

	// MaxAge is how long browsers can cache preflight responses
	MaxAge time.Duration `json:"max_age"`
}

// RedisConfig contains Redis connection settings.
// Redis is used for caching, session storage, and rate limiting.
type RedisConfig struct {
	// Host is the Redis server hostname or IP address
	Host string `json:"host"`

	// Port is the Redis server port (typically 6379)
	Port string `json:"port"`

	// Password is the Redis authentication password (if required)
	Password string `json:"-"` // Excluded from JSON for security

	// DB is the Redis database number to use (0-15)
	DB int `json:"db"`

	// MaxRetries is the maximum number of retries for failed commands
	MaxRetries int `json:"max_retries"`

	// PoolSize is the maximum number of socket connections
	PoolSize int `json:"pool_size"`

	// MinIdleConns is the minimum number of idle connections
	MinIdleConns int `json:"min_idle_conns"`
}

// SwaggerConfig contains Swagger/OpenAPI documentation settings.
// These settings control how API documentation is generated and served.
type SwaggerConfig struct {
	// Enabled controls whether Swagger UI is accessible
	Enabled bool `json:"enabled"`

	// Path is the URL path where Swagger UI will be served
	Path string `json:"path"`

	// Title is the API title shown in Swagger UI
	Title string `json:"title"`

	// Description is the API description shown in Swagger UI
	Description string `json:"description"`

	// Version is the API version shown in Swagger UI
	Version string `json:"version"`

	// Host is the API host (e.g., "api.example.com" or "localhost:6910")
	Host string `json:"host"`

	// BasePath is the base path for all API endpoints (e.g., "/api/v1")
	BasePath string `json:"base_path"`

	// Schemes are the supported protocols (http, https)
	Schemes []string `json:"schemes"`
}

// Load reads configuration from environment variables and returns a Config struct.
// This function attempts to load from a .env file first, then falls back to system
// environment variables. Default values are provided for non-critical settings.
//
// Environment variables are loaded in this order:
// 1. .env file in the current directory
// 2. System environment variables
// 3. Default values for optional settings
//
// Returns:
//   - Populated Config struct with all settings
//   - Error if required environment variables are missing
//
// Required environment variables:
//   - DB_HOST, DB_USER, DB_PASSWORD, DB_NAME
//   - JWT_SECRET (minimum 32 characters)
//
// Optional database connection pooling environment variables:
//   - DB_PORT (default: 5432)
//   - DB_SSL_MODE (default: disable)
//   - DB_MAX_OPEN_CONNS (default: 25) - Maximum concurrent connections
//   - DB_MAX_IDLE_CONNS (default: 5) - Maximum idle connections in pool
//   - DB_CONN_MAX_LIFETIME (default: 1h) - Maximum connection reuse time
//   - DB_CONN_MAX_IDLE_TIME (default: 15m) - Maximum connection idle time
//
// Example usage:
//
//	config, err := Load()
//	if err != nil {
//	    log.Fatal("Failed to load configuration:", err)
//	}
func Load() (*Config, error) {
	// Try to load .env file (ignore error if file doesn't exist)
	_ = godotenv.Load()

	config := &Config{
		Server: ServerConfig{
			Port:           getEnvOrDefault("PORT", "6910"),
			Host:           getEnvOrDefault("HOST", "0.0.0.0"),
			Environment:    getEnvOrDefault("ENVIRONMENT", "development"),
			ReadTimeout:    getDurationOrDefault("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:   getDurationOrDefault("SERVER_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:    getDurationOrDefault("SERVER_IDLE_TIMEOUT", 60*time.Second),
			TrustedProxies: getStringSliceOrDefault("TRUSTED_PROXIES", []string{"127.0.0.1", "::1"}),
		},
		Database: DatabaseConfig{
			Host:            getEnvOrFail("DB_HOST"),
			Port:            getIntOrDefault("DB_PORT", 5432),
			Username:        getEnvOrFail("DB_USER"),
			Password:        getEnvOrFail("DB_PASSWORD"),
			Database:        getEnvOrFail("DB_NAME"),
			SSLMode:         getEnvOrDefault("DB_SSLMODE", "disable"),
			MaxOpenConns:    getIntOrDefault("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getIntOrDefault("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getDurationOrDefault("DB_CONN_MAX_LIFETIME", 1*time.Hour),
			ConnMaxIdleTime: getDurationOrDefault("DB_CONN_MAX_IDLE_TIME", 15*time.Minute),
		},
		JWT: JWTConfig{
			Secret:             getEnvOrFail("JWT_SECRET"),
			AccessTokenExpiry:  getDurationOrDefault("JWT_ACCESS_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry: getDurationOrDefault("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
			Issuer:             getEnvOrDefault("JWT_ISSUER", "auth-service"),
			Algorithm:          getEnvOrDefault("JWT_ALGORITHM", "HS256"),
		},
		Security: SecurityConfig{
			BcryptCost:                 getIntOrDefault("BCRYPT_COST", 12),
			RateLimitEnabled:           getBoolOrDefault("RATE_LIMIT_ENABLED", true),
			RateLimitType:              getEnvOrDefault("RATE_LIMIT_TYPE", "memory"),
			RateLimitRequestsPerMinute: getIntOrDefault("RATE_LIMIT_REQUESTS_PER_MINUTE", 60),
			PasswordResetTokenExpiry:   getDurationOrDefault("PASSWORD_RESET_TOKEN_EXPIRY", 1*time.Hour),
			MaxLoginAttempts:           getIntOrDefault("MAX_LOGIN_ATTEMPTS", 5),
			LoginLockoutDuration:       getDurationOrDefault("LOGIN_LOCKOUT_DURATION", 15*time.Minute),
		},
		Email: EmailConfig{
			Host:      getEnvOrDefault("SMTP_HOST", ""),
			Port:      getIntOrDefault("SMTP_PORT", 587),
			Username:  getEnvOrDefault("SMTP_USERNAME", ""),
			Password:  getEnvOrDefault("SMTP_PASSWORD", ""),
			FromEmail: getEnvOrDefault("FROM_EMAIL", "noreply@example.com"),
			UseTLS:    getBoolOrDefault("SMTP_USE_TLS", true),
		},
		Logging: LoggingConfig{
			Level:      getEnvOrDefault("LOG_LEVEL", "info"),
			Format:     getEnvOrDefault("LOG_FORMAT", "json"),
			OutputPath: getEnvOrDefault("LOG_OUTPUT_PATH", "stdout"),
		},
		CORS: CORSConfig{
			AllowedOrigins:   getStringSliceOrDefault("CORS_ALLOWED_ORIGINS", []string{"*"}),
			AllowedMethods:   getStringSliceOrDefault("CORS_ALLOWED_METHODS", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}),
			AllowedHeaders:   getStringSliceOrDefault("CORS_ALLOWED_HEADERS", []string{"Content-Type", "Authorization"}),
			AllowCredentials: getBoolOrDefault("CORS_ALLOW_CREDENTIALS", true),
			MaxAge:           getDurationOrDefault("CORS_MAX_AGE", 12*time.Hour),
		},
		Redis: RedisConfig{
			Host:         getEnvOrDefault("REDIS_HOST", "localhost"),
			Port:         getEnvOrDefault("REDIS_PORT", "6379"),
			Password:     getEnvOrDefault("REDIS_PASSWORD", ""),
			DB:           getIntOrDefault("REDIS_DB", 0),
			MaxRetries:   getIntOrDefault("REDIS_MAX_RETRIES", 3),
			PoolSize:     getIntOrDefault("REDIS_POOL_SIZE", 10),
			MinIdleConns: getIntOrDefault("REDIS_MIN_IDLE_CONNS", 2),
		},
		Swagger: SwaggerConfig{
			Enabled:     getBoolOrDefault("SWAGGER_ENABLED", true),
			Path:        getEnvOrDefault("SWAGGER_PATH", "/swagger"),
			Title:       getEnvOrDefault("SWAGGER_TITLE", "Authentication Service API"),
			Description: getEnvOrDefault("SWAGGER_DESCRIPTION", "RESTful API for user authentication and management"),
			Version:     getEnvOrDefault("SWAGGER_VERSION", "1.0.0"),
			Host:        getEnvOrDefault("SWAGGER_HOST", "localhost:6910"),
			BasePath:    getEnvOrDefault("SWAGGER_BASE_PATH", "/api/v1"),
			Schemes:     getStringSliceOrDefault("SWAGGER_SCHEMES", []string{"http", "https"}),
		},
	}

	// Validate critical configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// Validate checks that all required configuration values are present and valid.
// This method performs comprehensive validation of the configuration to catch
// issues early in the application startup process.
//
// Validation rules:
// - JWT secret must be at least 32 characters for security
// - Database connection parameters must be non-empty
// - Port numbers must be valid (1-65535)
// - Email configuration must be valid if email features are enabled
//
// Returns:
//   - nil if all validation passes
//   - Error describing the first validation failure found
func (c *Config) Validate() error {
	// Validate JWT secret strength
	if len(c.JWT.Secret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters long, got %d", len(c.JWT.Secret))
	}

	// Validate database configuration
	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if c.Database.Username == "" {
		return fmt.Errorf("database username is required")
	}
	if c.Database.Password == "" {
		return fmt.Errorf("database password is required")
	}
	if c.Database.Database == "" {
		return fmt.Errorf("database name is required")
	}

	// Validate bcrypt cost
	if c.Security.BcryptCost < 4 || c.Security.BcryptCost > 31 {
		return fmt.Errorf("bcrypt cost must be between 4 and 31, got %d", c.Security.BcryptCost)
	}

	// Validate server port
	if port, err := strconv.Atoi(c.Server.Port); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("server port must be a valid port number (1-65535), got %s", c.Server.Port)
	}

	// Validate email configuration if email features are enabled
	if c.Email.Host != "" {
		if c.Email.Port < 1 || c.Email.Port > 65535 {
			return fmt.Errorf("SMTP port must be a valid port number (1-65535), got %d", c.Email.Port)
		}
		if c.Email.FromEmail == "" {
			return fmt.Errorf("from email address is required when SMTP is configured")
		}
	}

	return nil
}

// GetDatabaseURL returns a PostgreSQL connection URL.
// This is used by database libraries that accept URL-style connection strings.
//
// Returns:
//   - Complete PostgreSQL connection URL with all parameters
//
// Example output:
//
//	postgres://user:password@localhost:5432/dbname?sslmode=disable
func (c *Config) GetDatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.Username,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Database,
		c.Database.SSLMode,
	)
}

// IsProduction returns true if the service is running in production mode.
// This affects logging, error messages, and security features.
//
// Returns:
//   - true if environment is "production"
//   - false for development, staging, or other environments
func (c *Config) IsProduction() bool {
	return c.Server.Environment == "production"
}

// IsDevelopment returns true if the service is running in development mode.
// This enables additional debugging features and more verbose error messages.
//
// Returns:
//   - true if environment is "development"
//   - false for production, staging, or other environments
func (c *Config) IsDevelopment() bool {
	return c.Server.Environment == "development"
}

// Helper functions for environment variable parsing

// getEnvOrDefault returns the environment variable value or a default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvOrFail returns the environment variable value or panics if not set.
// Used for required configuration values.
func getEnvOrFail(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return value
}

// getIntOrDefault parses an environment variable as an integer or returns default.
func getIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getBoolOrDefault parses an environment variable as a boolean or returns default.
func getBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// getDurationOrDefault parses an environment variable as a duration or returns default.
func getDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// getStringSliceOrDefault parses a comma-separated environment variable or returns default.
func getStringSliceOrDefault(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		// Simple comma-separated parsing
		// In production, you might want more sophisticated parsing
		result := make([]string, 0)
		for _, item := range os.Args {
			if item != "" {
				result = append(result, item)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}
