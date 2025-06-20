#!/bin/bash

# 🧪 Postman Collection Validation Script
# Validates the structure and integrity of the Postman collection

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTION_FILE="$SCRIPT_DIR/Go-Auth-Microservice.postman_collection.json"
ENVIRONMENT_FILE="$SCRIPT_DIR/Go-Auth-Environment.postman_environment.json"

echo "🔍 Validating Postman Collection Files..."

# Check if files exist
if [[ ! -f "$COLLECTION_FILE" ]]; then
    echo "❌ Collection file not found: $COLLECTION_FILE"
    exit 1
fi

if [[ ! -f "$ENVIRONMENT_FILE" ]]; then
    echo "❌ Environment file not found: $ENVIRONMENT_FILE"
    exit 1
fi

echo "✅ Files exist"

# Validate JSON syntax
echo "🔍 Validating JSON syntax..."

if ! jq empty "$COLLECTION_FILE" 2>/dev/null; then
    echo "❌ Invalid JSON in collection file"
    exit 1
fi

if ! jq empty "$ENVIRONMENT_FILE" 2>/dev/null; then
    echo "❌ Invalid JSON in environment file"
    exit 1
fi

echo "✅ JSON syntax is valid"

# Validate collection structure
echo "🔍 Validating collection structure..."

COLLECTION_NAME=$(jq -r '.info.name' "$COLLECTION_FILE")
ENDPOINT_COUNT=$(jq '.item | length' "$COLLECTION_FILE")
FOLDER_COUNT=$(jq '.item | map(select(.item != null)) | length' "$COLLECTION_FILE")

echo "📋 Collection: $COLLECTION_NAME"
echo "📁 Folders: $FOLDER_COUNT"
echo "🔗 Total endpoints: $(jq '[.item[] | select(.item != null) | .item[] | select(.request != null)] | length' "$COLLECTION_FILE")"

# Validate environment structure
echo "🔍 Validating environment structure..."

ENVIRONMENT_NAME=$(jq -r '.name' "$ENVIRONMENT_FILE")
VARIABLE_COUNT=$(jq '.values | length' "$ENVIRONMENT_FILE")

echo "🌍 Environment: $ENVIRONMENT_NAME"
echo "🔧 Variables: $VARIABLE_COUNT"

# Check for required environment variables
REQUIRED_VARS=("base_url" "test_email" "test_password" "access_token" "refresh_token")
echo "🔍 Checking required variables..."

for var in "${REQUIRED_VARS[@]}"; do
    if jq -e ".values[] | select(.key == \"$var\")" "$ENVIRONMENT_FILE" > /dev/null; then
        echo "✅ Found variable: $var"
    else
        echo "❌ Missing required variable: $var"
        exit 1
    fi
done

# Check for authentication endpoints
echo "🔍 Checking authentication endpoints..."

AUTH_ENDPOINTS=("Register New User" "User Login" "Refresh Access Token" "User Logout")
for endpoint in "${AUTH_ENDPOINTS[@]}"; do
    if jq -e ".item[] | select(.name == \"🔐 Authentication\") | .item[] | select(.name == \"$endpoint\")" "$COLLECTION_FILE" > /dev/null; then
        echo "✅ Found endpoint: $endpoint"
    else
        echo "❌ Missing endpoint: $endpoint"
        exit 1
    fi
done

# Check for password management endpoints
echo "🔍 Checking password management endpoints..."

PASSWORD_ENDPOINTS=("Change Password" "Forgot Password Request" "Reset Password with Token")
for endpoint in "${PASSWORD_ENDPOINTS[@]}"; do
    if jq -e ".item[] | select(.name == \"🔑 Password Management\") | .item[] | select(.name == \"$endpoint\")" "$COLLECTION_FILE" > /dev/null; then
        echo "✅ Found endpoint: $endpoint"
    else
        echo "❌ Missing endpoint: $endpoint"
        exit 1
    fi
done

# Check for health endpoints
echo "🔍 Checking health endpoints..."

HEALTH_ENDPOINTS=("Basic Health Check" "Readiness Check" "Liveness Check" "Metrics (Prometheus)")
for endpoint in "${HEALTH_ENDPOINTS[@]}"; do
    if jq -e ".item[] | select(.name == \"🏥 Health & Monitoring\") | .item[] | select(.name == \"$endpoint\")" "$COLLECTION_FILE" > /dev/null; then
        echo "✅ Found endpoint: $endpoint"
    else
        echo "❌ Missing endpoint: $endpoint"
        exit 1
    fi
done

# Check for test scripts
echo "🔍 Checking test scripts..."

TEST_SCRIPT_COUNT=$(jq '[.item[].item[]? | select(.event != null) | .event[] | select(.listen == "test")] | length' "$COLLECTION_FILE")
echo "🧪 Test scripts found: $TEST_SCRIPT_COUNT"

if [[ $TEST_SCRIPT_COUNT -lt 10 ]]; then
    echo "⚠️  Low number of test scripts detected"
else
    echo "✅ Good test coverage"
fi

# Validate base URLs and variables
echo "🔍 Checking URL consistency..."

BASE_URL_USAGE=$(jq '[.item[].item[]?.request?.url?.raw] | map(select(. != null and contains("{{base_url}}"))) | length' "$COLLECTION_FILE")
echo "🌐 Endpoints using {{base_url}}: $BASE_URL_USAGE"

if [[ $BASE_URL_USAGE -lt 10 ]]; then
    echo "⚠️  Some endpoints might not be using the base_url variable"
else
    echo "✅ Good variable usage"
fi

echo ""
echo "🎉 Validation completed successfully!"
echo ""
echo "📋 Summary:"
echo "  Collection: $COLLECTION_NAME"
echo "  Environment: $ENVIRONMENT_NAME"
echo "  Folders: $FOLDER_COUNT"
echo "  Variables: $VARIABLE_COUNT"
echo "  Test Scripts: $TEST_SCRIPT_COUNT"
echo "  Base URL Usage: $BASE_URL_USAGE"
echo ""
echo "✅ Your Postman collection is ready to use!"
echo ""
echo "🚀 Next steps:"
echo "  1. Import both files into Postman"
echo "  2. Select the environment"
echo "  3. Update base_url to match your service"
echo "  4. Run the authentication flow"
echo ""
echo "📚 For detailed instructions, see: postman/README.md"
