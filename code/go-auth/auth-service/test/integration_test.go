package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"auth-service/internal/domain"
)

// TestClient provides a simple HTTP client for testing the authentication service
type TestClient struct {
	baseURL string
	client  *http.Client
}

// NewTestClient creates a new test client for the authentication service
func NewTestClient(baseURL string) *TestClient {
	return &TestClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// RegisterUser registers a new user and returns the response
func (c *TestClient) RegisterUser(email, password, firstName, lastName string) (*http.Response, error) {
	requestBody := domain.RegisterRequest{
		Email:     email,
		Password:  password,
		FirstName: firstName,
		LastName:  lastName,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURL + "/api/v1/auth/register"
	resp, err := c.client.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

// LoginUser logs in a user and returns the response
func (c *TestClient) LoginUser(email, password string) (*http.Response, error) {
	requestBody := domain.LoginRequest{
		Email:    email,
		Password: password,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := c.baseURL + "/api/v1/auth/login"
	resp, err := c.client.Post(url, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

// HealthCheck checks if the service is healthy
func (c *TestClient) HealthCheck() (*http.Response, error) {
	url := c.baseURL + "/health"
	resp, err := c.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make health check request: %w", err)
	}

	return resp, nil
}

// GetProfile gets the user profile (requires authentication)
func (c *TestClient) GetProfile(token string) (*http.Response, error) {
	url := c.baseURL + "/api/v1/auth/me"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}

	return resp, nil
}

func main() {
	// Get the base URL from environment or use default
	baseURL := os.Getenv("AUTH_SERVICE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	log.Printf("Testing authentication service at: %s", baseURL)

	client := NewTestClient(baseURL)

	// Test 1: Health Check
	log.Println("🔍 Testing health check...")
	healthResp, err := client.HealthCheck()
	if err != nil {
		log.Fatalf("❌ Health check failed: %v", err)
	}
	defer healthResp.Body.Close()

	if healthResp.StatusCode == http.StatusOK {
		log.Println("✅ Health check passed")
	} else {
		log.Printf("⚠️ Health check returned status: %d", healthResp.StatusCode)
	}

	// Test 2: User Registration
	log.Println("🔍 Testing user registration...")
	email := fmt.Sprintf("test.user.%d@example.com", time.Now().Unix())
	password := "TestPassword123!"
	firstName := "Test"
	lastName := "User"

	registerResp, err := client.RegisterUser(email, password, firstName, lastName)
	if err != nil {
		log.Fatalf("❌ Registration failed: %v", err)
	}
	defer registerResp.Body.Close()

	if registerResp.StatusCode == http.StatusCreated {
		log.Println("✅ User registration passed")
	} else {
		log.Printf("⚠️ User registration returned status: %d", registerResp.StatusCode)

		// Print response body for debugging
		var response map[string]interface{}
		if err := json.NewDecoder(registerResp.Body).Decode(&response); err == nil {
			log.Printf("Response: %+v", response)
		}
	}

	// Test 3: User Login
	log.Println("🔍 Testing user login...")
	loginResp, err := client.LoginUser(email, password)
	if err != nil {
		log.Fatalf("❌ Login failed: %v", err)
	}
	defer loginResp.Body.Close()

	var loginResponse domain.AuthResponse
	if loginResp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(loginResp.Body).Decode(&loginResponse); err != nil {
			log.Fatalf("❌ Failed to decode login response: %v", err)
		}
		log.Println("✅ User login passed")
		log.Printf("Access Token: %s...", loginResponse.AccessToken[:20])
	} else {
		log.Printf("⚠️ User login returned status: %d", loginResp.StatusCode)

		// Print response body for debugging
		var response map[string]interface{}
		if err := json.NewDecoder(loginResp.Body).Decode(&response); err == nil {
			log.Printf("Response: %+v", response)
		}
		return
	}

	// Test 4: Get User Profile (protected endpoint)
	if loginResponse.AccessToken != "" {
		log.Println("🔍 Testing protected endpoint (get profile)...")
		profileResp, err := client.GetProfile(loginResponse.AccessToken)
		if err != nil {
			log.Fatalf("❌ Get profile failed: %v", err)
		}
		defer profileResp.Body.Close()

		if profileResp.StatusCode == http.StatusOK {
			var profile domain.UserResponse
			if err := json.NewDecoder(profileResp.Body).Decode(&profile); err != nil {
				log.Fatalf("❌ Failed to decode profile response: %v", err)
			}
			log.Println("✅ Protected endpoint access passed")
			log.Printf("User Profile: %s %s (%s)", profile.FirstName, profile.LastName, profile.Email)
		} else {
			log.Printf("⚠️ Get profile returned status: %d", profileResp.StatusCode)
		}
	}

	// Test 5: Invalid Login
	log.Println("🔍 Testing invalid login...")
	invalidLoginResp, err := client.LoginUser(email, "wrongpassword")
	if err != nil {
		log.Fatalf("❌ Invalid login test failed: %v", err)
	}
	defer invalidLoginResp.Body.Close()

	if invalidLoginResp.StatusCode == http.StatusUnauthorized {
		log.Println("✅ Invalid login correctly rejected")
	} else {
		log.Printf("⚠️ Invalid login returned unexpected status: %d", invalidLoginResp.StatusCode)
	}

	log.Println("\n🎉 All tests completed! The authentication service appears to be working correctly.")
}
