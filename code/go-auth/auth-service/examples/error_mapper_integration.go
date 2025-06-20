package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"auth-service/internal/api"
	"auth-service/internal/domain"
)

// AuthService interface for the example (in real code, this would be imported)
type AuthService interface {
	Login(ctx context.Context, req *domain.LoginRequest) (*domain.AuthResponse, error)
	Register(ctx context.Context, req *domain.RegisterRequest) (*domain.User, error)
}

// Example showing how to integrate the HTTPErrorMapper into existing handlers
// This demonstrates the refactored approach for consistent error handling

// ExampleAuthHandler demonstrates how to use the error mapper in practice
type ExampleAuthHandler struct {
	authService AuthService // Your existing auth service interface
	errorMapper *api.HTTPErrorMapper
	logger      *logrus.Logger
}

// NewExampleAuthHandler creates a new handler with the error mapper
func NewExampleAuthHandler(authService AuthService, logger *logrus.Logger) *ExampleAuthHandler {
	return &ExampleAuthHandler{
		authService: authService,
		errorMapper: api.NewHTTPErrorMapper(logger),
		logger:      logger,
	}
}

// LoginHandler demonstrates error handling with the centralized error mapper
func (h *ExampleAuthHandler) LoginHandler(c *gin.Context) {
	// Extract request ID from middleware (implement your own or use existing)
	requestID := getRequestID(c)

	// Parse request body
	var loginReq domain.LoginRequest
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		// Use error mapper for validation errors
		h.errorMapper.MapError(c, domain.ErrValidationFailed, "login_request_parsing", requestID)
		return
	}

	// Call authentication service
	authResponse, err := h.authService.Login(c.Request.Context(), &loginReq)
	if err != nil {
		// Error mapper automatically determines the correct HTTP status code
		// and provides appropriate error messages based on error type
		h.errorMapper.MapError(c, err, "user_authentication", requestID)
		return
	}

	// Success response
	c.JSON(http.StatusOK, authResponse)
}

// RegisterHandler demonstrates error handling with validation details
func (h *ExampleAuthHandler) RegisterHandler(c *gin.Context) {
	requestID := getRequestID(c)

	var registerReq domain.RegisterRequest
	if err := c.ShouldBindJSON(&registerReq); err != nil {
		h.errorMapper.MapError(c, domain.ErrValidationFailed, "register_request_parsing", requestID)
		return
	}

	// Example of custom validation with detailed error information
	validationErrors := make(map[string]string)

	if registerReq.Email == "" {
		validationErrors["email"] = "Email is required"
	} else if !isValidEmail(registerReq.Email) {
		validationErrors["email"] = "Please provide a valid email address"
	}

	if len(registerReq.Password) < 8 {
		validationErrors["password"] = "Password must be at least 8 characters long"
	}

	// If validation errors exist, use MapErrorWithDetails
	if len(validationErrors) > 0 {
		h.errorMapper.MapErrorWithDetails(c, domain.ErrValidationFailed, "user_registration_validation", requestID, validationErrors)
		return
	}

	// Call registration service
	user, err := h.authService.Register(c.Request.Context(), &registerReq)
	if err != nil {
		h.errorMapper.MapError(c, err, "user_registration", requestID)
		return
	}

	c.JSON(http.StatusCreated, user)
}

// ProtectedHandler demonstrates authorization error handling
func (h *ExampleAuthHandler) ProtectedHandler(c *gin.Context) {
	requestID := getRequestID(c)

	// Extract user from middleware (implement your own JWT middleware)
	user, exists := c.Get("user")
	if !exists {
		h.errorMapper.MapError(c, domain.ErrUnauthorized, "missing_user_context", requestID)
		return
	}

	// Check user permissions
	if !hasRequiredPermissions(user) {
		h.errorMapper.MapError(c, domain.ErrInsufficientPermissions, "permission_check", requestID)
		return
	}

	// Continue with protected operation...
	c.JSON(http.StatusOK, gin.H{"message": "Protected resource accessed successfully"})
}

// SetupRoutes demonstrates how to integrate the handlers with routes
func SetupRoutes(handler *ExampleAuthHandler) *gin.Engine {
	r := gin.New()

	// Middleware for request ID generation
	r.Use(requestIDMiddleware())

	// API routes
	api := r.Group("/api/v1")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/login", handler.LoginHandler)
			auth.POST("/register", handler.RegisterHandler)
			auth.GET("/protected", handler.ProtectedHandler)
		}
	}

	return r
}

// Helper functions (implement these according to your needs)

func getRequestID(c *gin.Context) string {
	// Extract request ID from context or generate one
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return "unknown"
}

func isValidEmail(email string) bool {
	// Implement email validation logic
	return len(email) > 0 && len(email) < 255 // Simplified
}

func hasRequiredPermissions(user interface{}) bool {
	// Implement permission checking logic
	return true // Simplified
}

func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate or extract request ID
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID() // Implement this
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

func generateRequestID() string {
	// Implement request ID generation (UUID, etc.)
	return "req_example_123"
}

// Example of how the error responses would look:

/*
Example API Error Responses:

1. Validation Error:
POST /api/v1/auth/register
{
    "error": "validation_error",
    "message": "Invalid input provided",
    "request_id": "req_12345",
    "timestamp": "2025-06-20T23:15:30Z",
    "details": {
        "email": "Please provide a valid email address",
        "password": "Password must be at least 8 characters long"
    }
}

2. Authentication Error:
POST /api/v1/auth/login
{
    "error": "authentication_error",
    "message": "Authentication failed",
    "request_id": "req_12346",
    "timestamp": "2025-06-20T23:15:30Z"
}

3. Authorization Error:
GET /api/v1/auth/protected
{
    "error": "authorization_error",
    "message": "Access denied",
    "request_id": "req_12347",
    "timestamp": "2025-06-20T23:15:30Z"
}

4. Rate Limit Error:
POST /api/v1/auth/login
{
    "error": "rate_limit_error",
    "message": "Too many requests",
    "request_id": "req_12348",
    "timestamp": "2025-06-20T23:15:30Z"
}

5. Infrastructure Error:
POST /api/v1/auth/register
{
    "error": "service_unavailable",
    "message": "Service temporarily unavailable",
    "request_id": "req_12349",
    "timestamp": "2025-06-20T23:15:30Z"
}
*/
