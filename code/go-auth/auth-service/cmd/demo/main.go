package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "auth-service/docs" // Import generated swagger docs
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

// @host      localhost:8081
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Create Gin router
	r := gin.Default()

	// Add Swagger route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "auth-service",
			"version": "1.0.0",
		})
	})

	// API v1 routes (demo endpoints)
	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			// Demo register endpoint
			auth.POST("/register", demoRegister)
			auth.POST("/login", demoLogin)
		}
	}

	log.Println("🚀 Authentication Service Demo with Swagger UI")
	log.Println("📖 Swagger UI available at: http://localhost:8081/swagger/index.html")
	log.Println("💗 Health check at: http://localhost:8081/health")
	log.Println("🔧 Server starting on :8081")

	if err := r.Run(":8081"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Register Demo Endpoint
// @Summary      Register a new user
// @Description  Create a new user account with email, password, and profile information
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        user  body      DemoRegisterRequest   true  "User registration data"
// @Success      201   {object}  DemoRegisterResponse  "User successfully registered"
// @Failure      400   {object}  DemoErrorResponse     "Bad request - validation errors"
// @Failure      409   {object}  DemoErrorResponse     "Conflict - email already exists"
// @Router       /auth/register [post]
func demoRegister(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Demo: User registered successfully",
		"user": gin.H{
			"id":                "123e4567-e89b-12d3-a456-426614174000",
			"email":             "demo@example.com",
			"first_name":        "Demo",
			"last_name":         "User",
			"is_email_verified": false,
			"is_active":         true,
		},
	})
}

// Login Demo Endpoint
// @Summary      Authenticate user
// @Description  Authenticate user with email and password, returns JWT tokens
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        credentials  body      DemoLoginRequest   true  "User login credentials"
// @Success      200          {object}  DemoLoginResponse  "Authentication successful"
// @Failure      400          {object}  DemoErrorResponse  "Bad request - validation errors"
// @Failure      401          {object}  DemoErrorResponse  "Unauthorized - invalid credentials"
// @Router       /auth/login [post]
func demoLogin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"access_token":  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.token",
		"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.refresh",
		"token_type":    "Bearer",
		"expires_in":    900,
		"user": gin.H{
			"id":         "123e4567-e89b-12d3-a456-426614174000",
			"email":      "demo@example.com",
			"first_name": "Demo",
			"last_name":  "User",
		},
	})
}

// Demo Request/Response Types for Swagger

// DemoRegisterRequest represents user registration data
type DemoRegisterRequest struct {
	Email           string `json:"email" example:"user@example.com"`
	Password        string `json:"password" example:"SecurePass123!"`
	PasswordConfirm string `json:"password_confirm" example:"SecurePass123!"`
	FirstName       string `json:"first_name" example:"John"`
	LastName        string `json:"last_name" example:"Doe"`
}

// DemoLoginRequest represents user login credentials
type DemoLoginRequest struct {
	Email      string `json:"email" example:"user@example.com"`
	Password   string `json:"password" example:"SecurePass123!"`
	RememberMe bool   `json:"remember_me" example:"false"`
}

// DemoRegisterResponse represents registration success response
type DemoRegisterResponse struct {
	Success bool     `json:"success" example:"true"`
	Message string   `json:"message" example:"User registered successfully"`
	User    DemoUser `json:"user"`
}

// DemoLoginResponse represents login success response
type DemoLoginResponse struct {
	AccessToken  string   `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string   `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	TokenType    string   `json:"token_type" example:"Bearer"`
	ExpiresIn    int64    `json:"expires_in" example:"900"`
	User         DemoUser `json:"user"`
}

// DemoUser represents user information
type DemoUser struct {
	ID              string `json:"id" example:"123e4567-e89b-12d3-a456-426614174000"`
	Email           string `json:"email" example:"user@example.com"`
	FirstName       string `json:"first_name" example:"John"`
	LastName        string `json:"last_name" example:"Doe"`
	IsEmailVerified bool   `json:"is_email_verified" example:"true"`
	IsActive        bool   `json:"is_active" example:"true"`
}

// DemoErrorResponse represents error response
type DemoErrorResponse struct {
	Error   string `json:"error" example:"validation_error"`
	Message string `json:"message" example:"The provided email address is invalid"`
}
