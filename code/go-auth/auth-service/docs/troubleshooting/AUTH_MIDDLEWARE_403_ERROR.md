# Authentication Middleware Troubleshooting Guide

## Issue: "This endpoint requires no authentication" Error (403)

### **Problem Description**
When making login/register requests via Postman, you receive:
```json
{
  "error": "forbidden",
  "message": "This endpoint requires no authentication",
  "timestamp": "2025-06-20T18:19:02.575360384Z"
}
```

### **Root Cause**
The `RequireNoAuth()` middleware is designed to **reject requests from already authenticated users** attempting to access login/register endpoints. This error occurs when:

1. **Postman includes an Authorization header** with a valid JWT token
2. **Collection-level authentication** is set in Postman  
3. **Environment variables** automatically inject auth tokens
4. **Previous successful login** left a token that's being reused

### **Immediate Solutions**

#### **Option 1: Fix Postman Configuration (Recommended)**

1. **Check Request Authorization**:
   - Open your login/register request in Postman
   - Go to "Authorization" tab → Set to "No Auth"

2. **Check Collection Authorization**:
   - Right-click collection → "Edit" → "Authorization" 
   - Set to "No Auth" or ensure individual requests override properly

3. **Check Environment Variables**:
   - Look for variables like `{{authToken}}`, `{{bearerToken}}`
   - Clear these variables or ensure they're not used in login/register requests

4. **Check Headers Tab**:
   - Remove any manual "Authorization" headers in login/register requests

#### **Option 2: Use Different Postman Requests**
Create separate requests for:
- **Initial login** (no auth)
- **Authenticated operations** (with auth)

### **Technical Solution (Implemented)**

The middleware has been updated to be more user-friendly:

```go
// OLD BEHAVIOR: Rejected ANY authorization header
// NEW BEHAVIOR: Only rejects VALID, non-expired access tokens
```

**What's now allowed:**
- ✅ No authorization header
- ✅ Malformed authorization headers  
- ✅ Invalid JWT tokens
- ✅ Expired JWT tokens
- ✅ Refresh tokens (non-access tokens)

**What's still rejected:**
- ❌ Valid, non-expired access tokens (user is already authenticated)

### **Testing the Fix**

Test these scenarios to verify the fix:

```bash
# 1. No auth header (should work)
curl -X POST http://localhost:6910/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'

# 2. Invalid token (should work)  
curl -X POST http://localhost:6910/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalid-token" \
  -d '{"email": "user@example.com", "password": "password"}'

# 3. Malformed header (should work)
curl -X POST http://localhost:6910/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "Authorization: NotBearer malformed" \
  -d '{"email": "user@example.com", "password": "password"}'

# 4. Valid token (should be rejected with 403)
curl -X POST http://localhost:6910/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <valid-jwt-token>" \
  -d '{"email": "user@example.com", "password": "password"}'
```

### **Monitoring and Debugging**

Check the service logs for these messages:

```
# Debug level - allowed requests
DEBUG "Invalid token format in auth header, allowing request"
DEBUG "Invalid/expired token in auth header, allowing request" 
DEBUG "Non-access token in auth header, allowing request"

# Warning level - rejected requests  
WARN "Authenticated user attempted to access auth endpoint"
```

### **Best Practices for Postman Collections**

1. **Separate Authentication Flows**:
   ```
   📁 Auth Service Collection
   ├── 📂 Public Endpoints (No Auth)
   │   ├── POST Login
   │   ├── POST Register  
   │   └── POST Forgot Password
   ├── 📂 Protected Endpoints (Bearer Token)
   │   ├── GET Profile
   │   ├── PUT Update Profile
   │   └── POST Logout
   ```

2. **Environment Setup**:
   ```json
   {
     "authToken": "",
     "baseUrl": "http://localhost:6910"
   }
   ```

3. **Test Scripts** (for automatic token management):
   ```javascript
   // In login request "Tests" tab
   if (pm.response.code === 200) {
       const response = pm.response.json();
       pm.environment.set("authToken", response.access_token);
   }
   ```

### **Error Message Updates**

The error message has been improved for clarity:

```json
// OLD MESSAGE
{"message": "This endpoint requires no authentication"}

// NEW MESSAGE  
{"message": "This endpoint requires no authentication. You are already authenticated."}
```

This makes it clearer that the issue is being already authenticated, not a general authentication problem.

### **Security Considerations**

This change maintains security while improving UX:

- ✅ **Still prevents double-login** from authenticated users
- ✅ **Allows expired token holders** to re-authenticate  
- ✅ **Handles edge cases** gracefully (malformed tokens, etc.)
- ✅ **Provides clear error messages** for debugging
- ✅ **Maintains audit logging** for security monitoring

### **Related Files Modified**

- `internal/middleware/auth.go` - Updated `RequireNoAuth()` method
- This troubleshooting guide

### **Next Steps**

1. **Test with Postman** using the solutions above
2. **Check service logs** if issues persist
3. **Verify database connectivity** if getting 503 errors
4. **Review Postman collection structure** for proper auth flow

The authentication middleware is now more robust and user-friendly while maintaining security.

---

## Additional Common Issues

### **Database Constraint Violation on Registration**

#### **Problem Description**
When attempting user registration, you receive:
```json
{
  "error": "service_unavailable",
  "message": "Service temporarily unavailable",
  "request_id": "req_d5a23aaf-e028-4997-a5cd-bae5547c77bb",
  "timestamp": "2025-06-20T18:22:09.821124957Z"
}
```

With logs showing:
```
ERRO Failed to create user error="pq: new row for relation \"users\" violates check constraint \"chk_users_first_name_length\""
```

#### **Root Cause**
**JSON field name mismatch** between the request payload and the expected DTO structure:

**❌ Common Mistake (camelCase):**
```json
{
  "email": "user@example.com",
  "password": "TestPassword123!",
  "firstName": "John",     // WRONG: camelCase
  "lastName": "Doe"        // WRONG: camelCase
}
```

**✅ Correct Format (snake_case):**
```json
{
  "email": "user@example.com",
  "password": "TestPassword123!",
  "password_confirm": "TestPassword123!",  // REQUIRED
  "first_name": "John",     // CORRECT: snake_case
  "last_name": "Doe"        // CORRECT: snake_case
}
```

#### **Why This Happens**
1. The Go struct uses snake_case JSON tags: `json:"first_name"`
2. When camelCase is sent, Go can't map the fields
3. FirstName/LastName become empty strings
4. Database constraint `chk_users_first_name_length` requires length >= 1
5. Empty strings violate the constraint, causing the error

#### **Solution**
**Update your request payload to use snake_case:**

```bash
# ✅ CORRECT - Registration with proper field names
curl -X POST http://localhost:6910/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "TestPassword123!",
    "password_confirm": "TestPassword123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

#### **Postman Collection Fix**
Update your Postman request body:

```json
{
  "email": "{{$randomEmail}}",
  "password": "TestPassword123!",
  "password_confirm": "TestPassword123!",
  "first_name": "{{$randomFirstName}}",
  "last_name": "{{$randomLastName}}"
}
```

#### **API Documentation Reference**
All registration endpoints expect snake_case field names:

| Field | JSON Key | Type | Required | Validation |
|-------|----------|------|----------|------------|
| Email | `email` | string | ✅ | Valid email format, max 255 chars |
| Password | `password` | string | ✅ | Min 8 chars, max 128 chars |
| Password Confirm | `password_confirm` | string | ✅ | Must match `password` exactly |
| First Name | `first_name` | string | ✅ | Min 1 char, max 100 chars |
| Last Name | `last_name` | string | ✅ | Min 1 char, max 100 chars |

#### **Validation Enhancement Recommendation**
Consider adding field validation that provides clearer error messages for missing required fields rather than letting it fail at the database level.

---

The authentication service now handles both middleware authentication issues and provides clear guidance for proper request formatting.
