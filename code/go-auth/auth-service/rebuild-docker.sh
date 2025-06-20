#!/bin/bash

# rebuild-docker.sh
# Script to cleanly rebuild Docker containers for the auth service

set -e

echo "🧹 Cleaning up existing containers and images..."

# Stop and remove containers
docker-compose down

# Remove the specific auth-service image to force rebuild
docker rmi auth-service-auth-service 2>/dev/null || echo "Image not found, skipping..."

# Clean up any dangling images
docker image prune -f

echo "🔨 Building containers with Swagger support..."

# Build and start services
docker-compose build --no-cache auth-service
docker-compose up -d

echo "⏳ Waiting for services to be healthy..."

# Wait for services to be ready
sleep 10

echo "🔍 Checking service health..."

# Check if the service is responding
if curl -f -s http://localhost:18080/health > /dev/null; then
    echo "✅ Auth service is healthy!"
    echo "📖 Swagger UI: http://localhost:18080/swagger/index.html"
    echo "💗 Health endpoint: http://localhost:18080/health"
else
    echo "❌ Auth service is not responding"
    echo "📋 Checking logs..."
    docker-compose logs auth-service
    exit 1
fi

echo "🎉 Rebuild complete!"
echo ""
echo "Available services:"
echo "🔐 Auth Service: http://localhost:18080"
echo "📖 Swagger UI: http://localhost:18080/swagger/index.html"
echo "🐘 PostgreSQL: localhost:5432"
echo "🟥 Redis: localhost:6379"
echo ""
echo "To view logs: docker-compose logs -f auth-service"
echo "To stop: docker-compose down"
