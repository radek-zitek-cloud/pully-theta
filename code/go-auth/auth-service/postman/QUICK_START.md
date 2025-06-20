# 📮 Postman Collection - Quick Reference

## 🎯 Files Created

```
postman/
├── Go-Auth-Microservice.postman_collection.json     # Main collection file
├── Go-Auth-Environment.postman_environment.json     # Environment variables
├── README.md                                         # Comprehensive documentation
└── validate-collection.sh                           # Validation script
```

## ⚡ Quick Start

1. **Import into Postman:**
   - Import `Go-Auth-Microservice.postman_collection.json`
   - Import `Go-Auth-Environment.postman_environment.json`

2. **Configure Environment:**
   - Select "Go Auth Microservice Environment"
   - Update `base_url` to your service URL (default: `http://localhost:8080`)

3. **Test Authentication Flow:**
   - Run "Register New User" (creates account + stores tokens)
   - Or run "User Login" (authenticates + stores tokens)
   - Use other endpoints (tokens auto-injected)

## 📊 Collection Stats

- **13 Endpoints** across 4 categories
- **13 Test Scripts** with comprehensive validation
- **8 Environment Variables** with auto-management
- **100% Coverage** of all documented API endpoints

## 🧪 Testing Features

### Automated Tests Include:
- ✅ Status code validation
- ✅ Response structure verification
- ✅ Data type checking
- ✅ Token management (store/refresh/clear)
- ✅ Security validation (no sensitive data exposure)
- ✅ Performance monitoring (response times)
- ✅ Business logic validation

### Token Management:
- 🔄 **Auto-Storage** - Tokens saved from login/register
- 🔄 **Auto-Injection** - Bearer tokens added to authenticated requests
- 🔄 **Auto-Refresh** - Expired tokens renewed seamlessly
- 🔄 **Auto-Cleanup** - Tokens cleared on logout

## 🗂️ Endpoint Categories

### 🔐 Authentication (4 endpoints)
- Register New User
- User Login  
- Refresh Access Token
- User Logout

### 🔑 Password Management (3 endpoints)
- Change Password
- Forgot Password Request
- Reset Password with Token

### 👤 User Profile (2 endpoints)
- Get Current User Profile
- Update User Profile

### 🏥 Health & Monitoring (4 endpoints)
- Basic Health Check
- Readiness Check
- Liveness Check
- Metrics (Prometheus)

## 🌍 Environment Variables

| Variable | Description | Auto-Set | Required |
|----------|-------------|----------|----------|
| `base_url` | Service API URL | ❌ | ✅ |
| `test_email` | Test user email | ❌ | ✅ |
| `test_password` | Test password | ❌ | ✅ |
| `access_token` | JWT access token | ✅ | ❌ |
| `refresh_token` | JWT refresh token | ✅ | ❌ |
| `user_id` | Current user ID | ✅ | ❌ |
| `user_email` | Current user email | ✅ | ❌ |
| `reset_token` | Password reset token | ❌ | ❌ |

## 🚀 Newman CLI Usage

```bash
# Install Newman
npm install -g newman

# Run collection
newman run Go-Auth-Microservice.postman_collection.json \
    -e Go-Auth-Environment.postman_environment.json \
    --reporters html,cli

# With custom environment
newman run Go-Auth-Microservice.postman_collection.json \
    -e Go-Auth-Environment.postman_environment.json \
    --env-var "base_url=http://localhost:8080" \
    --env-var "test_email=newman@test.com"
```

## 🔍 Validation

Run the validation script to verify collection integrity:

```bash
cd postman/
./validate-collection.sh
```

## 📚 Documentation

For complete documentation see:
- `postman/README.md` - Full usage guide
- Collection descriptions - Detailed endpoint docs
- Request examples - Sample payloads and responses

---

**🎉 Ready to test your authentication microservice!**
