#!/bin/bash

# Test script for the Go Authentication Service
# This script sets up a test environment and runs basic integration tests

set -e

echo "🚀 Starting Go Authentication Service Test Suite"
echo "================================================"

# Check if we're in the right directory
if [ ! -f "cmd/server/main.go" ]; then
    echo "❌ Error: Please run this script from the auth-service directory"
    exit 1
fi

# Build the service
echo "🔨 Building authentication service..."
go build -o bin/auth-service ./cmd/server

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Check if PostgreSQL is available
echo "🔍 Checking PostgreSQL availability..."

# Try to connect to PostgreSQL using environment variables or defaults
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-postgres}
DB_PASSWORD=${DB_PASSWORD:-testpassword}
DB_NAME=${DB_NAME:-auth_service_test}

# Check if we can connect to PostgreSQL
if command -v pg_isready >/dev/null 2>&1; then
    if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" >/dev/null 2>&1; then
        echo "✅ PostgreSQL is available"
    else
        echo "⚠️ PostgreSQL is not available. Starting with Docker..."
        
        # Start PostgreSQL with Docker if available
        if command -v docker >/dev/null 2>&1; then
            echo "🐳 Starting PostgreSQL container..."
            docker run -d \
                --name auth-service-test-db \
                -e POSTGRES_USER="$DB_USER" \
                -e POSTGRES_PASSWORD="$DB_PASSWORD" \
                -e POSTGRES_DB="$DB_NAME" \
                -p "$DB_PORT:5432" \
                postgres:15-alpine >/dev/null 2>&1 || true
            
            # Wait for PostgreSQL to be ready
            echo "⏳ Waiting for PostgreSQL to be ready..."
            for i in {1..30}; do
                if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" >/dev/null 2>&1; then
                    echo "✅ PostgreSQL is ready"
                    break
                fi
                sleep 1
            done
        else
            echo "❌ Docker not available. Please start PostgreSQL manually."
            echo "   Connection details: $DB_HOST:$DB_PORT, user: $DB_USER, database: $DB_NAME"
            exit 1
        fi
    fi
else
    echo "⚠️ pg_isready not found. Assuming PostgreSQL is available..."
fi

# Run database migrations
echo "📊 Running database migrations..."

# Check if migrate tool is available
if command -v migrate >/dev/null 2>&1; then
    DATABASE_URL="postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/$DB_NAME?sslmode=disable"
    
    # Create database if it doesn't exist
    psql "postgres://$DB_USER:$DB_PASSWORD@$DB_HOST:$DB_PORT/postgres?sslmode=disable" \
        -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || true
    
    # Run migrations
    migrate -path migrations -database "$DATABASE_URL" up
    
    if [ $? -eq 0 ]; then
        echo "✅ Database migrations completed"
    else
        echo "⚠️ Database migrations failed or already applied"
    fi
else
    echo "⚠️ migrate tool not found. Skipping migrations."
    echo "   Install with: go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
fi

# Set up test environment
echo "🔧 Setting up test environment..."
export ENV_FILE=".env.test"

# Start the service in the background
echo "🚀 Starting authentication service..."
./bin/auth-service &
SERVICE_PID=$!

# Function to cleanup on exit
cleanup() {
    echo "🧹 Cleaning up..."
    if [ ! -z "$SERVICE_PID" ]; then
        kill $SERVICE_PID 2>/dev/null || true
    fi
    
    # Stop test database container if we started it
    if command -v docker >/dev/null 2>&1; then
        docker stop auth-service-test-db >/dev/null 2>&1 || true
        docker rm auth-service-test-db >/dev/null 2>&1 || true
    fi
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Wait for service to start
echo "⏳ Waiting for service to start..."
for i in {1..30}; do
    if curl -s http://localhost:8080/health >/dev/null 2>&1; then
        echo "✅ Service is ready"
        break
    fi
    sleep 1
done

# Check if service started successfully
if ! curl -s http://localhost:8080/health >/dev/null 2>&1; then
    echo "❌ Service failed to start"
    exit 1
fi

# Run integration tests
echo "🧪 Running integration tests..."
cd test
go run integration_test.go
cd ..

echo ""
echo "🎉 All tests completed successfully!"
echo "================================================"
