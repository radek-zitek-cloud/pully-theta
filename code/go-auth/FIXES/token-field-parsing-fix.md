# Password Reset Token Field Not Parsing - Solution

## 🐛 **Issue Analysis**

Based on the debug logs, the issue is **very specific**:

```
DEBU[...] Parsed confirm reset password request email=radek@zitek.cloud has_password=true request_id=... token_length=0 token_present=false
```

**Findings**:
- ✅ JSON parsing works (email and password are parsed correctly)
- ❌ Only the `token` field is not being parsed
- ✅ Request reaches the handler successfully
- ❌ `token` field is empty after `c.ShouldBindJSON(&req)`

## 🔍 **Root Cause Investigation**

### **Possible Causes**:
1. **Validation Tag Interference**: The `validate:"required"` tag on token field
2. **Duplicate Content-Type Headers**: Your curl has duplicate headers
3. **JSON Field Parsing Issue**: Gin-specific binding problem
4. **Hidden Characters**: Invisible characters in the JSON

## ✅ **Solution Applied**

### **1. Removed Validation Tag from Token Field**
```go
// Before:
Token string `json:"token" validate:"required" example:"..."`

// After:
Token string `json:"token" example:"..."`
```

**Reason**: Validation tags can sometimes interfere with JSON parsing in Gin. The validation is better handled in the service layer anyway.

### **2. Enhanced Debug Logging**
Added comprehensive debugging to see exactly what's being received:
- Raw request body logging
- Generic JSON map parsing
- Field-by-field analysis

### **3. Moved Token Validation to Service Layer**
```go
// Early validation with clear error message
if req.Token == "" {
    s.logger.Error("Password reset token is empty in request")
    s.auditLogFailure(ctx, nil, "user.password.reset.confirm.failure", "Empty reset token", clientIP, userAgent, domain.ErrInvalidToken)
    return domain.ErrInvalidToken
}
```

## 🧪 **Testing Steps**

### **1. Fix Your Curl Request**
Remove the duplicate Content-Type header:

```bash
# WRONG (duplicate header):
curl --location 'http://localhost:6910/api/v1/auth/password/reset' \
--header 'Content-Type: application/json' \
--header 'Content-Type: application/json' \  # <- Remove this line
--data-raw '{...}'

# CORRECT:
curl --location 'http://localhost:6910/api/v1/auth/password/reset' \
--header 'Content-Type: application/json' \
--data-raw '{
  "token": "816aebd48a69a25f11c15ab1548174bcdf2cc3025c4d88bf67fbc58ff8c0eb40",
  "email": "radek@zitek.cloud",
  "new_password": "user1234",
  "new_password_confirm": "user1234"
}'
```

### **2. Check Debug Logs**
With DEBUG logging enabled, you should now see:

```
DEBU[...] Raw request body received raw_body="{\"token\":\"816ae...\",\"email\":\"radek@...\"}"
DEBU[...] Generic JSON parsing token_in_map=816aebd48a69a25f11c15ab1548174bcdf2cc3025c4d88bf67fbc58ff8c0eb40
DEBU[...] Parsed confirm reset password request token_present=true token_length=64
```

### **3. Test with Different Formats**
Try different JSON formats to isolate the issue:

```bash
# Test 1: Inline JSON (no pretty formatting)
curl -X POST http://localhost:6910/api/v1/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token":"816aebd48a69a25f11c15ab1548174bcdf2cc3025c4d88bf67fbc58ff8c0eb40","email":"radek@zitek.cloud","new_password":"user1234","new_password_confirm":"user1234"}'

# Test 2: Simple token
curl -X POST http://localhost:6910/api/v1/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token":"simple_test_token","email":"radek@zitek.cloud","new_password":"user1234","new_password_confirm":"user1234"}'
```

## 🎯 **Most Likely Fix**

The issue is most likely the **duplicate Content-Type header** in your curl request. HTTP parsers can behave unexpectedly with duplicate headers.

**Try this exact curl command**:
```bash
curl -X POST http://localhost:6910/api/v1/auth/password/reset \
  -H "Content-Type: application/json" \
  -d '{"token":"816aebd48a69a25f11c15ab1548174bcdf2cc3025c4d88bf67fbc58ff8c0eb40","email":"radek@zitek.cloud","new_password":"user1234","new_password_confirm":"user1234"}'
```

## 🔧 **If Issue Persists**

1. **Check Debug Logs**: The new logging will show exactly what JSON is received
2. **Try Postman**: Use the Postman collection instead of curl
3. **Test Health Endpoint**: Ensure service is running correctly
4. **Check Token Source**: Verify the token value is correct

## 📋 **Verification**

After applying the fix, you should see:
```
DEBU[...] Parsed confirm reset password request token_present=true token_length=64
DEBU[...] Password reset confirmation request details token_present=true
```

Instead of:
```
DEBU[...] Parsed confirm reset password request token_present=false token_length=0
ERRO[...] Password reset token is empty in request
```

---

**Fixed on**: June 20, 2025  
**Status**: 🔧 Ready for Testing  
**Primary Fix**: Remove duplicate Content-Type header from curl request  
**Secondary Fix**: Removed validation tag interference from Token field
