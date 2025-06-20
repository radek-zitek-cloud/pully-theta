package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title           Authentication Service API
// @version         1.0.0
// @description     A comprehensive authentication and user management microservice
// @description     This demo showcases the Swagger UI integration

// @contact.name   API Support
// @contact.email  support@example.com

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:9847
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	r := gin.Default()

	// Add Swagger route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"service": "auth-service-demo",
			"version": "1.0.0",
		})
	})

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/register", demoRegister)
			auth.POST("/login", demoLogin)
		}
	}

	log.Println("🚀 Auth Service Demo with Swagger UI")
	log.Println("📖 Swagger UI: http://localhost:9847/swagger/index.html")
	log.Println("💗 Health: http://localhost:9847/health")
	log.Println("🔧 Starting on :9847")

	if err := r.Run(":9847"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// @Summary      Register a new user
// @Description  Create a new user account
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        user  body      RegisterRequest   true  "User registration data"
// @Success      201   {object}  RegisterResponse  "User registered successfully"
// @Failure      400   {object}  ErrorResponse     "Bad request"
// @Router       /auth/register [post]
func demoRegister(c *gin.Context) {
	c.JSON(http.StatusCreated, gin.H{
		"success": true,
		"message": "Demo: User registered successfully",
		"user": gin.H{
			"id":         "123e4567-e89b-12d3-a456-426614174000",
			"email":      "demo@example.com",
			"first_name": "Demo",
			"last_name":  "User",
		},
	})
}

// @Summary      Authenticate user
// @Description  Authenticate user and return tokens
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        credentials  body      LoginRequest   true  "Login credentials"
// @Success      200          {object}  LoginResponse  "Authentication successful"
// @Failure      401          {object}  ErrorResponse  "Unauthorized"
// @Router       /auth/login [post]
func demoLogin(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"access_token":  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.token",
		"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.refresh",
		"token_type":    "Bearer",
		"expires_in":    900,
		"user": gin.H{
			"id":    "123e4567-e89b-12d3-a456-426614174000",
			"email": "demo@example.com",
		},
	})
}

// Swagger types
type RegisterRequest struct {
	Email     string `json:"email" example:"user@example.com"`
	Password  string `json:"password" example:"SecurePass123!"`
	FirstName string `json:"first_name" example:"John"`
	LastName  string `json:"last_name" example:"Doe"`
}

type LoginRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"SecurePass123!"`
}

type RegisterResponse struct {
	Success bool        `json:"success" example:"true"`
	Message string      `json:"message" example:"User registered successfully"`
	User    interface{} `json:"user"`
}

type LoginResponse struct {
	AccessToken  string      `json:"access_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	RefreshToken string      `json:"refresh_token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	TokenType    string      `json:"token_type" example:"Bearer"`
	ExpiresIn    int64       `json:"expires_in" example:"900"`
	User         interface{} `json:"user"`
}

type ErrorResponse struct {
	Error   string `json:"error" example:"validation_error"`
	Message string `json:"message" example:"Invalid request"`
}
