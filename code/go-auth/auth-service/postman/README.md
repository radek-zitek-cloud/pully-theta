# 🚀 Go Authentication Microservice - Postman Collection

## 📋 Overview

This Postman collection provides comprehensive testing capabilities for the Go Authentication Microservice. It includes all API endpoints with automated testing, token management, and detailed documentation.

## 📁 Collection Contents

### 🔐 Authentication Endpoints
- **Register New User** - Create user accounts with validation
- **User Login** - Authenticate and obtain JWT tokens  
- **Refresh Access Token** - Renew expired access tokens
- **User Logout** - Revoke tokens and end sessions

### 🔑 Password Management
- **Change Password** - Update password for authenticated users
- **Forgot Password Request** - Initiate password reset flow
- **Reset Password with Token** - Complete password reset process

### 👤 User Profile
- **Get Current User Profile** - Retrieve user information
- **Update User Profile** - Modify user details

### 🏥 Health & Monitoring
- **Basic Health Check** - Service availability status
- **Readiness Check** - Dependency health verification
- **Liveness Check** - Service responsiveness validation
- **Metrics (Prometheus)** - Application and system metrics

## 🛠️ Setup Instructions

### 1. Import Collection and Environment

1. **Import the collection file:**
   ```
   Go-Auth-Microservice.postman_collection.json
   ```

2. **Import the environment file:**
   ```
   Go-Auth-Environment.postman_environment.json
   ```

3. **Select the environment** in Postman's environment dropdown

### 2. Configure Environment Variables

Update the following variables in your environment:

| Variable | Description | Default Value | Required |
|----------|-------------|---------------|----------|
| `base_url` | Service API base URL | `http://localhost:8080` | ✅ |
| `test_email` | Test user email | `test.user@example.com` | ✅ |
| `test_password` | Test user password | `TestPassword123!` | ✅ |
| `access_token` | JWT access token | *Auto-set* | ❌ |
| `refresh_token` | JWT refresh token | *Auto-set* | ❌ |
| `user_id` | Current user ID | *Auto-set* | ❌ |
| `user_email` | Current user email | *Auto-set* | ❌ |
| `reset_token` | Password reset token | *Manual* | ❌ |

### 3. Start Your Service

Ensure your Go authentication service is running:

```bash
# Using Docker Compose (recommended)
docker-compose up -d auth-service

# Or using Go directly
go run cmd/server/main.go

# Or using the built binary
./bin/auth-service
```

## 🎯 Usage Workflows

### 🔄 Complete Authentication Flow

1. **Register New User**
   - Creates account and returns tokens
   - Tokens automatically stored in environment

2. **User Login** (alternative to registration)
   - Authenticates existing user
   - Updates stored tokens

3. **Use Authenticated Endpoints**
   - Profile management
   - Password changes
   - All endpoints use stored tokens automatically

4. **Token Refresh**
   - Renews expired access tokens
   - Automatically updates stored tokens

5. **Logout**
   - Revokes tokens and clears environment

### 🔑 Password Reset Flow

1. **Forgot Password Request**
   - Sends reset token to email
   - Returns success regardless of email existence

2. **Check Email**
   - Retrieve reset token from email
   - Copy token to `reset_token` environment variable

3. **Reset Password with Token**
   - Completes password reset
   - Invalidates reset token

### 🏥 Health Monitoring Flow

1. **Basic Health Check**
   - Quick service availability check
   - Used by load balancers

2. **Readiness Check**
   - Verifies all dependencies
   - Used by orchestration platforms

3. **Liveness Check**
   - Confirms service responsiveness
   - Detects deadlocks or hangs

4. **Metrics Collection**
   - Prometheus-format metrics
   - For monitoring and alerting

## ✅ Automated Testing Features

### 🧪 Test Coverage

Each request includes comprehensive automated tests:

- **Status Code Validation** - Ensures correct HTTP responses
- **Response Structure** - Validates JSON schema and required fields
- **Data Type Checking** - Confirms field types and formats
- **Business Logic** - Tests authentication rules and constraints
- **Security Validation** - Ensures no sensitive data exposure
- **Performance** - Checks response times are acceptable

### 🔄 Automatic Token Management

- **Token Storage** - Access and refresh tokens stored automatically
- **Token Refresh** - Expired tokens renewed seamlessly
- **Token Cleanup** - Tokens cleared on logout
- **Security** - Tokens marked as secret in environment

### 📊 Test Reporting

Tests provide detailed feedback:
- ✅ **Pass/Fail Status** - Clear test results
- 📝 **Error Details** - Specific failure information  
- 🎯 **Business Logic** - Validates authentication flows
- 🔍 **Debug Info** - Console logs for troubleshooting

## 🔧 Advanced Configuration

### 🌐 Environment Setup

#### Development Environment
```json
{
  \"base_url\": \"http://localhost:8080\",
  \"test_email\": \"dev.user@localhost\",
  \"test_password\": \"DevPassword123!\"
}
```

#### Staging Environment
```json
{
  \"base_url\": \"https://auth-staging.example.com\",
  \"test_email\": \"staging.test@example.com\",
  \"test_password\": \"StagingPassword123!\"
}
```

#### Production Testing (Caution!)
```json
{
  \"base_url\": \"https://auth.example.com\",
  \"test_email\": \"prod.test@example.com\",
  \"test_password\": \"ProductionPassword123!\"
}
```

### 🔒 Security Considerations

1. **Sensitive Data**
   - Access tokens marked as secret
   - Passwords in environment variables
   - Never commit credentials to version control

2. **Production Testing**
   - Use dedicated test accounts
   - Avoid testing against production databases
   - Monitor test activity in logs

3. **Token Management**
   - Tokens expire automatically (15 minutes for access)
   - Refresh tokens have longer lifetime (7 days)
   - Logout clears all stored tokens

## 🚀 Integration with CI/CD

### Newman (Command Line)

Run collection from command line:

```bash
# Install Newman
npm install -g newman

# Run collection
newman run Go-Auth-Microservice.postman_collection.json \\
    -e Go-Auth-Environment.postman_environment.json \\
    --reporters html,cli \\
    --reporter-html-export test-results.html
```

### GitHub Actions

```yaml
name: API Testing
on: [push, pull_request]
jobs:
  api-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run API Tests
        run: |
          newman run postman/Go-Auth-Microservice.postman_collection.json \\
            -e postman/Go-Auth-Environment.postman_environment.json \\
            --reporters html,junit \\
            --reporter-junit-export test-results.xml
```

## 📚 Documentation and Examples

### 🔍 Request Examples

Each endpoint includes:
- **Purpose and Use Cases** - When and why to use the endpoint
- **Authentication Requirements** - Token requirements and security
- **Request Body Examples** - Sample payloads with validation rules
- **Response Examples** - Success and error response formats
- **Security Considerations** - Important security notes
- **Error Handling** - Common error scenarios and responses

### 🧪 Test Examples

Test scripts demonstrate:
- **Status Code Validation**
- **Response Structure Testing**
- **Data Type Verification**
- **Business Logic Validation**
- **Token Management**
- **Error Handling**

## 🐛 Troubleshooting

### Common Issues

1. **Connection Refused**
   - Verify service is running on correct port
   - Check `base_url` environment variable
   - Ensure no firewall blocking connections

2. **Authentication Failures**
   - Verify tokens are not expired
   - Check if user account exists
   - Ensure correct password in environment

3. **Test Failures**
   - Check service logs for errors
   - Verify database connectivity
   - Ensure all dependencies are running

4. **Environment Issues**
   - Confirm environment is selected in Postman
   - Verify all required variables are set
   - Check variable scoping (environment vs global)

### Debug Tips

- **Console Logs** - Check Postman console for debug output
- **Service Logs** - Monitor application logs during testing
- **Network Tab** - Inspect raw HTTP requests/responses
- **Test Results** - Review detailed test failure messages

## 📈 Monitoring and Metrics

### Health Check Usage

- **Load Balancers** - Use `/health` for simple checks
- **Kubernetes** - Use `/health/ready` and `/health/live` for probes
- **Monitoring** - Use `/metrics` for Prometheus scraping

### Performance Baselines

Expected response times:
- **Health Checks** - < 100ms
- **Authentication** - < 500ms
- **Profile Operations** - < 300ms
- **Password Operations** - < 1000ms (due to bcrypt)

## 🤝 Contributing

### Adding New Tests

1. **Follow Naming Convention** - Descriptive test names
2. **Include Documentation** - Detailed endpoint descriptions
3. **Add Validation** - Comprehensive test coverage
4. **Update Environment** - Add required variables
5. **Test Thoroughly** - Verify all scenarios work

### Best Practices

- **Atomic Tests** - Each test validates one specific aspect
- **Clear Assertions** - Use descriptive error messages
- **Cleanup** - Restore state after tests
- **Documentation** - Update README for new features

---

## 📞 Support

For issues or questions:
- Check service logs for error details
- Review Postman console output
- Verify environment configuration
- Test with curl/HTTPie for comparison

**Happy Testing! 🎉**
