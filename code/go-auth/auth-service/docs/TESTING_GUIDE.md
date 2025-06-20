# Testing Guide for Go Authentication Microservice

## Overview

This document outlines the comprehensive testing strategy and implementation for the Go authentication microservice. The testing approach covers unit tests for domain entities, DTOs, and the service layer with extensive mocking and validation.

## Test Structure

### Test Directories

```
internal/
├── domain/
│   └── test/
│       ├── entities_test.go    # Entity business logic tests
│       └── dtos_test.go        # Data Transfer Object tests
└── service/
    └── test/
        ├── auth_service_test.go # Service layer unit tests
        └── mocks.go            # Custom mock implementations
```

## Test Coverage

### Domain Layer Tests

#### Entity Tests (`entities_test.go`)
- **User Entity Tests**: Creation, validation, business logic (GetFullName, IsDeleted)
- **RefreshToken Entity Tests**: Creation, expiration logic, validation states
- **PasswordResetToken Entity Tests**: Creation, expiration, usage tracking
- **AuditLog Entity Tests**: Creation with user context and anonymous operations
- **Performance Tests**: UUID generation, timezone handling

#### DTO Tests (`dtos_test.go`)
- **Request DTOs**: RegisterRequest, LoginRequest, ChangePasswordRequest, etc.
- **Response DTOs**: AuthResponse, UserResponse, ErrorResponse, etc.
- **Serialization/Deserialization**: JSON marshaling, field mapping
- **Validation**: Email normalization, required fields, data consistency
- **Performance Tests**: Serialization speed benchmarks

### Service Layer Tests

#### AuthService Tests (`auth_service_test.go`)
- **Service Creation**: Constructor validation, dependency injection
- **User Registration**: Success scenarios, validation, email conflicts
- **User Authentication**: Login success/failure, rate limiting, inactive users
- **Token Management**: Refresh token generation, validation, expiration
- **User Operations**: Profile updates, user retrieval by ID/email
- **Logout Operations**: Token revocation, session cleanup
- **Error Handling**: Various failure scenarios, proper error responses

## Testing Patterns and Best Practices

### Test Suite Structure
All tests use `testify/suite` for organized test execution:
- `SetupSuite()`: One-time setup for test suite
- `SetupTest()`: Per-test initialization
- `TearDownTest()`: Per-test cleanup

### Mocking Strategy
Custom mocks are implemented in `internal/service/test/mocks.go`:
- **Repository Mocks**: User, RefreshToken, PasswordResetToken, AuditLog repositories
- **Service Mocks**: Email service, rate limiting service
- **External Service Mocks**: Metrics recorder, audit logger

### Test Data Management
- Consistent test users with realistic data
- UUID generation for entity IDs
- Proper timestamp handling for time-sensitive operations
- Configurable test scenarios for different business cases

### Assertion Patterns
- **Positive Assertions**: Verify successful operations, expected data
- **Negative Assertions**: Confirm proper error handling
- **Security Assertions**: Validate authentication, authorization flows
- **Performance Assertions**: Ensure operations complete within reasonable time

## Running Tests

### Individual Test Suites
```bash
# Run domain entity tests
go test -v ./internal/domain/test

# Run service layer tests  
go test -v ./internal/service/test

# Run all unit tests
go test -v ./internal/domain/test ./internal/service/test
```

### With Coverage
```bash
# Generate coverage report
go test -coverprofile=coverage.out ./internal/service/test ./internal/domain/test

# View coverage summary
go tool cover -func=coverage.out

# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html
```

## Test Coverage Metrics

Current test coverage includes:
- **Domain Entities**: 100% method coverage for business logic
- **Service Layer**: ~43.2% overall, focusing on critical authentication paths
- **Critical Paths**: Registration, login, token refresh, logout fully tested
- **Error Scenarios**: Invalid inputs, security violations, rate limiting

## Testing Philosophy

### Security-First Testing
- All authentication flows are thoroughly tested
- Security edge cases are explicitly validated
- Mock expectations verify security logging and audit trails

### Business Logic Validation
- Core business rules are tested with multiple scenarios
- Edge cases and boundary conditions are covered
- Error handling ensures graceful degradation

### Maintainability Focus
- Tests are self-documenting with clear naming
- Mock objects mirror production interfaces exactly
- Test data is realistic and consistent

## Future Testing Enhancements

### Integration Tests
- Database integration with test containers
- Email service integration testing
- Rate limiting service integration
- End-to-end API testing

### Performance Tests
- Load testing for authentication endpoints
- Stress testing for concurrent user operations
- Memory usage and goroutine leak detection

### Security Tests
- Penetration testing scenarios
- SQL injection and XSS prevention validation
- JWT token security and expiration handling

## Dependencies

### Test Libraries
- `github.com/stretchr/testify` - Assertion library and test suites
- `github.com/google/uuid` - UUID generation for entities
- `golang.org/x/crypto/bcrypt` - Password hashing in test scenarios

### Mock Dependencies
All external dependencies are mocked to ensure:
- Fast test execution
- Deterministic test results
- Isolation from external services
- Ability to test error scenarios

## Best Practices for Adding New Tests

1. **Follow Naming Conventions**: Use descriptive test names that explain the scenario
2. **Use Table-Driven Tests**: For multiple similar scenarios
3. **Mock External Dependencies**: Keep tests isolated and fast
4. **Test Both Success and Failure**: Ensure comprehensive coverage
5. **Validate Security Aspects**: Always test authentication and authorization
6. **Document Complex Test Logic**: Add comments for intricate test scenarios
7. **Keep Tests Independent**: Each test should be able to run in isolation

This testing strategy ensures the authentication microservice is reliable, secure, and maintainable while providing confidence for production deployments.
