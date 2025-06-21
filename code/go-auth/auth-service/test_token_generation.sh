#!/bin/bash
# Quick script to test JWT token generation and inspect the payload

cd /home/radekzitek/Code/zitek.cloud/pully-theta/code/go-auth/auth-service

# Create a simple Go program to generate and inspect tokens
cat > /tmp/token_test.go << 'EOF'
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func main() {
	// Simulate our current token generation logic
	testUserID := uuid.New()
	now := time.Now().UTC()
	
	claims := jwt.MapClaims{
		"user_id":    testUserID,           // This is the key addition
		"sub":        testUserID.String(),
		"email":      "test@example.com",
		"token_type": "access",
		"iss":        "auth-service",
		"aud":        "auth-service",
		"exp":        now.Add(15 * time.Minute).Unix(),
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret"))
	if err != nil {
		log.Fatalf("Failed to sign token: %v", err)
	}

	fmt.Printf("Generated token: %s\n", tokenString)
	
	// Extract and decode payload
	parts := strings.Split(tokenString, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Fatalf("Failed to decode payload: %v", err)
	}

	fmt.Printf("\nDecoded payload:\n%s\n", string(payload))

	// Parse as JSON to verify structure
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	fmt.Println("\nToken fields:")
	for key, value := range data {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Check if user_id exists
	if userID, exists := data["user_id"]; exists {
		fmt.Printf("\n✅ user_id field EXISTS: %v\n", userID)
	} else {
		fmt.Printf("\n❌ user_id field MISSING\n")
	}
}
EOF

# Run the test
cd /tmp && go mod init token_test 2>/dev/null || true
go mod tidy 2>/dev/null || true
go run token_test.go 2>/dev/null || echo "Go modules issue, trying direct run..."
