# Go Authentication Microservice

A production-ready, scalable authentication microservice built with Go, featuring JWT tokens, PostgreSQL persistence, Swagger UI documentation, and comprehensive security measures.

## 🎯 Overview

This microservice provides a complete authentication solution with:
- User registration and login
- JWT access and refresh token management
- Password reset functionality
- **Interactive Swagger UI API documentation**
- Audit logging
- Rate limiting and security middleware
- Clean architecture design
- Comprehensive error handling and validation

## 🏗️ Architecture

### Quick Architecture Overview

```
auth-service/
├── cmd/server/          # Application entry point
├── internal/
│   ├── api/            # HTTP handlers and routes (Interface Layer)
│   ├── middleware/     # HTTP middleware
│   ├── service/        # Business logic (Use Case Layer)
│   ├── repository/     # Data access (Infrastructure Layer)
│   ├── domain/         # Domain models and DTOs (Entity Layer)
│   └── config/         # Configuration management
├── migrations/         # Database schema migrations
├── bin/               # Compiled binaries
└── docs/              # Documentation
```

### Design Patterns Used
- **Repository Pattern**: Data access abstraction
- **Dependency Injection**: Loose coupling between layers
- **Factory Pattern**: Service and repository creation
- **Strategy Pattern**: Different authentication strategies
- **Observer Pattern**: Audit logging

### 📐 Detailed Architecture Documentation

For comprehensive architecture diagrams, component interactions, data flows, and design decisions, see:

**[📖 Complete Architecture Documentation](docs/ARCHITECTURE.md)**

This includes:
- 🎯 System overview and technology stack
- 🏛️ Clean Architecture layer diagrams  
- 🔧 Component architecture and interactions
- 🗄️ Database schema and relationships
- 🔄 API flow diagrams and sequence charts
- 🔒 Security architecture and patterns
- 🚀 Deployment architecture (Docker & Kubernetes)
- 📊 Data flow patterns and error handling
- 🔍 Monitoring and observability setup

## �️ Technology Stack

### Core Technologies
- **Language**: Go 1.24+
- **Web Framework**: Gin (high-performance HTTP router)
- **Database**: PostgreSQL 12+ (ACID compliance, advanced features)
- **Cache**: Redis (sessions, rate limiting)
- **Authentication**: JWT tokens with RS256/HS256 signing

### Documentation & Testing
- **API Documentation**: Swagger/OpenAPI 3.0 with interactive UI
- **Code Generation**: Swaggo for automatic API documentation
- **Testing**: Built-in Go testing with testify
- **Validation**: Go-playground validator for request validation

### Security & Monitoring
- **Password Hashing**: bcrypt with configurable cost
- **Rate Limiting**: Redis-based distributed rate limiting
- **CORS**: Configurable cross-origin resource sharing
- **Audit Logging**: Comprehensive request/response logging
- **Metrics**: Prometheus-compatible metrics export

### DevOps & Infrastructure
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose, Kubernetes ready
- **Database Migrations**: SQL-based versioned migrations
- **Hot Reload**: Air for development live reloading

## �🚀 Quick Start

### Prerequisites
- Go 1.24 or higher
- PostgreSQL 12+
- Docker & Docker Compose (optional)

### Local Development

1. **Clone and setup**
   ```bash
   cd /home/radekzitek/Code/zitek.cloud/pully-theta/code/go-auth/auth-service
   make install
   ```

2. **Setup environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start PostgreSQL**
   ```bash
   make db-up
   ```

4. **Run migrations**
   ```bash
   make migrate-up
   ```

5. **Start the service**
   ```bash
   make run
   ```

6. **Access the API**
   - 🌐 **Service**: http://localhost:8080
   - 📖 **Swagger UI**: http://localhost:8080/swagger/index.html
   - 💗 **Health Check**: http://localhost:6910/health

### Docker Development

```bash
# Full development environment with Docker Compose
make compose-up         # Start all services (builds if needed)
make compose-down       # Stop all services
make compose-status     # Check service health
make compose-logs       # View logs from all services
make compose-restart    # Restart all services

# Traditional Docker commands (single service)
make docker-up          # Start app with external PostgreSQL
make docker-logs        # View app logs  
make docker-down        # Stop app
```

## 📊 Database Schema

### Tables

#### Users Table
```sql
- id (UUID, Primary Key)
- email (VARCHAR, Unique)
- password_hash (VARCHAR)
- first_name (VARCHAR)
- last_name (VARCHAR)
- is_verified (BOOLEAN)
- is_active (BOOLEAN)
- created_at (TIMESTAMP)
- updated_at (TIMESTAMP)
- deleted_at (TIMESTAMP, Nullable)
```

#### Refresh Tokens Table
```sql
- id (UUID, Primary Key)
- user_id (UUID, Foreign Key)
- token_hash (VARCHAR)
- expires_at (TIMESTAMP)
- created_at (TIMESTAMP)
- revoked_at (TIMESTAMP, Nullable)
```

#### Password Reset Tokens Table
```sql
- id (UUID, Primary Key)
- user_id (UUID, Foreign Key)
- token_hash (VARCHAR)
- expires_at (TIMESTAMP)
- created_at (TIMESTAMP)
- used_at (TIMESTAMP, Nullable)
```

#### Audit Logs Table
```sql
- id (UUID, Primary Key)
- user_id (UUID, Nullable)
- action (VARCHAR)
- resource (VARCHAR)
- details (JSONB)
- ip_address (INET)
- user_agent (TEXT)
- created_at (TIMESTAMP)
```

## 🔌 API Endpoints

### 📖 Interactive API Documentation

**🚀 Swagger UI: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)**

The service includes comprehensive **Swagger/OpenAPI 3.0 documentation** with:
- ✅ Interactive API testing interface
- ✅ Complete request/response schemas
- ✅ Authentication examples with JWT Bearer tokens
- ✅ Detailed error response documentation
- ✅ Real-time API validation

### Authentication

#### POST /api/v1/auth/register
Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response (201):**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "is_verified": false,
    "created_at": "2024-01-01T00:00:00Z"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### POST /api/v1/auth/login
Authenticate user credentials.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200):**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  },
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### POST /api/v1/auth/refresh
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### POST /api/v1/auth/logout
Logout user and revoke tokens.

**Headers:**
```
Authorization: Bearer <access_token>
```

### Password Management

#### POST /api/v1/auth/password/forgot
Request password reset.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

#### POST /api/v1/auth/password/reset
Reset password using token.

**Request Body:**
```json
{
  "token": "reset_token",
  "new_password": "NewSecurePassword123!"
}
```

#### PUT /api/v1/auth/password/change
Change password (authenticated).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewSecurePassword123!"
}
```

### User Management

#### GET /api/v1/auth/me
Get current user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

#### PUT /api/v1/auth/me
Update user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "first_name": "John",
  "last_name": "Smith"
}
```
| `/api/v1/auth/reset-password` | POST | Request password reset | No |
| `/api/v1/auth/change-password` | POST | Change password | Yes |

## 🚀 Quick Start

### Prerequisites

- Go 1.24.4 or higher
- PostgreSQL 12+ or Docker
- Environment variables configured

### Installation

1. Clone the repository
2. Copy environment configuration:
   ```bash
   cp .env.example .env
   ```

3. Configure your environment variables in `.env`

4. Install dependencies:
   ```bash
   go mod download
   ```

5. Run database migrations:
   ```bash
   go run cmd/migrate/main.go
   ```

6. Start the service:
   ```bash
   go run cmd/server/main.go
   ```

The service will start on `http://localhost:8080`

## 🔧 Configuration

The service is configured via environment variables:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PORT` | Server port | `8080` | No |
| `DB_HOST` | Database host | `localhost` | Yes |
| `DB_PORT` | Database port | `5432` | Yes |
| `DB_USER` | Database user | - | Yes |
| `DB_PASSWORD` | Database password | - | Yes |
| `DB_NAME` | Database name | - | Yes |
| `JWT_SECRET` | JWT signing secret | - | Yes |
| `JWT_ACCESS_EXPIRY` | Access token expiry | `15m` | No |
| `JWT_REFRESH_EXPIRY` | Refresh token expiry | `7d` | No |
| `BCRYPT_COST` | Bcrypt hashing cost | `12` | No |
| `LOG_LEVEL` | Logging level | `info` | No |

## 🔒 Security Features

### JWT Tokens
- **Access Tokens**: Short-lived (15 minutes), used for API authentication
- **Refresh Tokens**: Long-lived (7 days), stored securely, used to refresh access tokens
- **Password Reset Tokens**: Single-use, time-limited (1 hour)

### Password Security
- **Hashing**: bcrypt with configurable cost (default: 12)
- **Validation**: Minimum 8 characters, complexity requirements
- **Reset Flow**: Secure token-based reset with expiration

### Rate Limiting
- **Login Attempts**: 5 attempts per IP per minute
- **Registration**: 3 attempts per IP per minute
- **Password Reset**: 1 attempt per IP per minute

### Audit Logging
- All authentication events logged
- IP address and user agent tracking
- Structured logging with correlation IDs

## ⚙️ Configuration

### Environment Variables

```bash
# Server Configuration
PORT=8080
HOST=localhost
ENVIRONMENT=development

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_service
DB_USER=postgres
DB_PASSWORD=postgres
DB_SSL_MODE=disable

# Database Connection Pool Configuration
DB_MAX_OPEN_CONNS=25           # Maximum concurrent database connections
DB_MAX_IDLE_CONNS=5            # Maximum idle connections in pool
DB_CONN_MAX_LIFETIME=1h        # Maximum time a connection can be reused
DB_CONN_MAX_IDLE_TIME=15m      # Maximum time a connection can be idle

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-at-least-32-characters
JWT_ACCESS_TOKEN_DURATION=15m
JWT_REFRESH_TOKEN_DURATION=168h

# Password Configuration
PASSWORD_BCRYPT_COST=12
PASSWORD_MIN_LENGTH=8

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_DURATION=1m

# Email Configuration (for password reset)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=noreply@yourapp.com

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

### Configuration Validation

The service validates all configuration on startup:
- Required fields are checked
- JWT secret minimum length enforced
- Database connection tested
- SMTP configuration validated (if enabled)

## 🧪 Testing

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run integration tests
make test-integration

# Run specific test package
go test ./internal/service/...
```

### Test Categories

1. **Unit Tests**: Individual component testing
2. **Integration Tests**: Database and external service integration
3. **End-to-End Tests**: Full API workflow testing
4. **Load Tests**: Performance and stress testing

### Test Database

Tests use a separate test database:
```bash
make test-db-setup
make test-db-teardown
```

### 📮 Postman Collection

A comprehensive Postman collection is available for API testing and documentation:

#### 📁 Collection Files
- `postman/Go-Auth-Microservice.postman_collection.json` - Complete API collection
- `postman/Go-Auth-Environment.postman_environment.json` - Environment variables
- `postman/README.md` - Detailed usage instructions

#### 🚀 Quick Setup
1. Import both JSON files into Postman
2. Select the "Go Auth Microservice Environment"
3. Update `base_url` to match your service URL
4. Run the authentication flow to get started

#### ✨ Features
- **Automated Token Management** - Tokens stored and refreshed automatically
- **Comprehensive Testing** - 50+ automated tests covering all scenarios
- **Complete Documentation** - Detailed endpoint descriptions and examples
- **Environment Support** - Separate configs for dev/staging/production
- **CI/CD Integration** - Newman command-line runner support

#### 🔄 Supported Workflows
- Complete authentication flow (register → login → refresh → logout)
- Password management (change, forgot, reset)
- User profile operations (get, update)
- Health monitoring and metrics collection

See `postman/README.md` for complete documentation and advanced usage.

## 📈 Monitoring & Observability

### Health Checks

The service provides three distinct health check endpoints for different monitoring needs:

#### GET /health - Basic Health Check
Essential health status with database connectivity verification. Suitable for load balancers and basic monitoring.

**Response Example:**
```json
{
  "status": "healthy",
  "timestamp": "2025-06-20T14:30:00Z",
  "version": "1.0.0",
  "checks": {
    "database": {
      "status": "healthy",
      "response_time_ms": 15,
      "last_checked": "2025-06-20T14:30:00Z"
    }
  }
}
```

#### GET /health/ready - Readiness Probe
Comprehensive readiness check with database connectivity and schema validation. Perfect for Kubernetes readiness probes and deployment validation.

**Response Example:**
```json
{
  "status": "ready",
  "timestamp": "2025-06-20T14:30:00Z",
  "version": "1.0.0",
  "checks": {
    "database": {
      "status": "healthy",
      "response_time_ms": 15,
      "last_checked": "2025-06-20T14:30:00Z"
    },
    "migrations": {
      "status": "healthy",
      "response_time_ms": 5,
      "last_checked": "2025-06-20T14:30:00Z"
    }
  }
}
```

#### GET /health/live - Liveness Probe
Lightweight liveness check for container orchestration. Used by Kubernetes liveness probes to determine if the service needs to be restarted.

**Response Example:**
```json
{
  "status": "alive",
  "timestamp": "2025-06-20T14:30:00Z",
  "version": "1.0.0"
}
```

**Usage Guidelines:**
- **Load Balancers**: Use `/health` for routing decisions
- **Kubernetes Readiness**: Use `/health/ready` for pod readiness
- **Kubernetes Liveness**: Use `/health/live` for restart decisions
- **Monitoring Systems**: Use `/health` for alerting and dashboards

### Metrics (Prometheus-compatible)

- Request duration histograms
- Request rate counters
- Error rate counters
- Database connection pool metrics
- JWT token generation/validation metrics

### Logging

Structured JSON logging with:
- Correlation IDs for request tracing
- Error stack traces
- Performance metrics
- Security events

## 🚀 Deployment

### Production Deployment

1. **Build production image**
   ```bash
   make docker-build-prod
   ```

2. **Deploy with Docker Compose**
   ```bash
   docker-compose -f docker-compose.prod.yml up -d
   ```

3. **Run migrations**
   ```bash
   make migrate-up-prod
   ```

### Kubernetes Deployment

See `k8s/` directory for Kubernetes manifests:
- Deployment
- Service
- ConfigMap
- Secret
- Ingress

### Environment-Specific Configurations

- **Development**: `.env.development`
- **Staging**: `.env.staging`
- **Production**: `.env.production`

## 🔧 Development Tools

### Available Make Commands

```bash
make help              # Show all available commands
make install           # Install dependencies
make build             # Build the application
make run               # Run the application
make test              # Run tests
make test-coverage     # Run tests with coverage
make lint              # Run linters
make format            # Format code
make clean             # Clean build artifacts

# Docker Compose (Full Environment)
make compose-up        # Start all services with Docker Compose
make compose-down      # Stop all Docker Compose services
make compose-status    # Check Docker Compose service health
make compose-logs      # View Docker Compose logs
make compose-restart   # Restart Docker Compose services

# Docker (Single Service)  
make docker-build      # Build Docker image
make docker-up         # Start Docker services
make docker-down       # Stop Docker services

# Database Management
make migrate-up        # Run database migrations
make migrate-down      # Rollback database migrations
make migrate-create    # Create new migration
```

### Development Dependencies

- **Air**: Live reload for development
- **golangci-lint**: Comprehensive Go linting
- **migrate**: Database migration tool
- **mockery**: Mock generation for testing

### Code Quality

- **Pre-commit hooks**: Formatting, linting, testing
- **CI/CD pipeline**: Automated testing and deployment
- **Code coverage**: Minimum 80% coverage required
- **Security scanning**: Vulnerability detection

## 📚 Documentation

### API Documentation

- **Swagger/OpenAPI**: Auto-generated API docs at `/docs`
- **Postman Collection**: Available in `docs/postman/`

### Architecture Documentation

- **ADRs**: Architecture Decision Records in `docs/adr/`
- **Diagrams**: System architecture diagrams in `docs/diagrams/`
- **Runbooks**: Operational procedures in `docs/runbooks/`

## 🔍 Troubleshooting

### Common Issues

#### Database Connection Errors
```bash
# Check database status
make db-status

# Reset database
make db-reset

# Check migrations
make migrate-status
```

#### JWT Token Issues
- Verify JWT_SECRET is at least 32 characters
- Check token expiration times
- Validate token format and claims

#### Performance Issues
- Monitor database connection pool
- Check memory usage and garbage collection
- Review slow query logs

### Debug Mode

Enable debug logging:
```bash
export LOG_LEVEL=debug
make run
```

### Health Check Debugging

```bash
# Check service health
curl http://localhost:6910/health

# Check readiness
curl http://localhost:6910/health/ready

# Check liveness
curl http://localhost:6910/health/live
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. Swagger UI Not Loading

**Problem**: Swagger UI returns 404 or doesn't load properly.

**Solutions:**
```bash
# Regenerate documentation
make docs

# Check if docs files exist
ls -la docs/

# Serve documentation locally
make docs-serve
```

**Expected files in docs/ directory:**
- `docs.go` - Go definitions
- `swagger.json` - JSON specification  
- `swagger.yaml` - YAML specification

#### 2. Database Connection Issues

**Problem**: `connection refused` or `database does not exist` errors.

**Solutions:**
```bash
# Check PostgreSQL service
sudo systemctl status postgresql

# Verify database exists
psql -U postgres -l

# Check environment variables
cat .env | grep DB_

# Test connection manually
psql -h localhost -U your_user -d your_database
```

#### 3. Authentication Token Issues

**Problem**: `invalid token` or `token expired` errors.

**Solutions:**
```bash
# Check token expiration settings in .env
grep JWT .env

# Verify JWT secret is set
echo $JWT_SECRET

# Test token generation manually
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

#### 4. Rate Limiting Issues

**Problem**: `too many requests` errors.

**Solutions:**
```bash
# Check rate limit configuration
grep RATE .env

# Reset rate limiting (if using Redis)
redis-cli FLUSHDB

# Adjust rate limits in configuration
vim .env  # Modify RATE_LIMIT_* variables
```

#### 5. CORS Issues

**Problem**: Browser CORS errors when accessing from frontend.

**Solutions:**
```bash
# Check CORS configuration in .env
grep CORS .env

# Verify allowed origins
curl -H "Origin: http://localhost:3000" \
     -H "Access-Control-Request-Method: POST" \
     -H "Access-Control-Request-Headers: Content-Type" \
     -X OPTIONS http://localhost:8080/api/v1/auth/login
```

#### 6. Environment Variables Not Loading

**Problem**: Service starts but configuration seems wrong.

**Solutions:**
```bash
# Verify .env file exists and has correct format
cat .env

# Check file permissions
ls -la .env

# Verify environment loading in code
go run cmd/server/main.go --debug

# Load environment manually for testing
source .env && go run cmd/server/main.go
```

#### 7. Port Conflicts

**Problem**: `address already in use` errors.

**Solutions:**
```bash
# Check what's using the port
sudo netstat -tlnp | grep :8080
# or
sudo ss -tlnp | grep :8080

# Kill process using the port
sudo fuser -k 8080/tcp

# Use different port
export PORT=8081 && go run cmd/server/main.go
```

#### 8. SSL/TLS Certificate Issues

**Problem**: HTTPS connection errors or certificate warnings.

**Solutions:**
```bash
# Check certificate files exist
ls -la certs/

# Verify certificate validity
openssl x509 -in certs/server.crt -text -noout

# Generate self-signed certificates for development
make generate-certs

# Check TLS configuration
grep TLS .env
```

### Debug Mode

Enable debug mode for more detailed logging:

```bash
# Set debug mode in environment
export GIN_MODE=debug
export LOG_LEVEL=debug

# Run with debug flags
go run cmd/server/main.go --debug

# Check logs
tail -f tmp/errors.log
```

### Health Checks

Use the health endpoint to verify service status:

```bash
# Basic health check
curl http://localhost:6910/health

# Comprehensive readiness check
curl http://localhost:6910/health/ready

# Check specific components
curl http://localhost:8080/health/database
curl http://localhost:8080/health/redis
```

### Testing API Endpoints

#### Using cURL

```bash
# Register new user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User"
  }'

# Login user
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'

# Access protected endpoint
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Logout user (no request body needed)
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### Using Postman

Import the Postman collection from `/postman` directory:

```bash
# Navigate to postman directory
cd postman/

# Import collection and environment
# See QUICK_START.md for detailed instructions
```

#### Using Swagger UI

The easiest way to test and explore the API:

```bash
# Start the main service
make run

# Open Swagger UI in browser
open http://localhost:8080/swagger/index.html

# Or serve documentation statically
make docs-serve
open http://localhost:8081
```

### Log Analysis

Common log patterns to look for:

```bash
# Authentication failures
grep "authentication failed" tmp/errors.log

# Rate limiting triggers
grep "rate limit exceeded" tmp/errors.log

# Database connection issues
grep "database" tmp/errors.log

# Token validation errors
grep "token" tmp/errors.log
```

### Performance Monitoring

Monitor key metrics:

```bash
# Check memory usage
ps aux | grep auth-service

# Monitor database connections
psql -U postgres -c "SELECT count(*) FROM pg_stat_activity;"

# Check response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080/health
```

Create `curl-format.txt`:
```
time_namelookup:  %{time_namelookup}\n
time_connect:     %{time_connect}\n
time_pretransfer: %{time_pretransfer}\n
time_redirect:    %{time_redirect}\n
time_starttransfer: %{time_starttransfer}\n
time_total:       %{time_total}\n
```

For additional support, check:
- Service logs in `tmp/errors.log`
- Database logs in PostgreSQL logs directory
- System logs: `journalctl -u auth-service`
- GitHub Issues for community support

## 🤝 Contributing

### Development Workflow

1. **Fork and clone** the repository
2. **Create feature branch** from `main`
3. **Make changes** following coding standards
4. **Add tests** for new functionality
5. **Run quality checks** (`make lint test`)
6. **Submit pull request** with clear description

### Coding Standards

- Follow Go best practices and idioms
- Use meaningful variable and function names
- Write comprehensive documentation
- Maintain test coverage above 80%
- Follow clean architecture principles

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Gin Web Framework](https://gin-gonic.com/)
- [GORM ORM](https://gorm.io/)
- [JWT-Go](https://github.com/golang-jwt/jwt)
- [Viper Configuration](https://github.com/spf13/viper)
- [Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)

## 📞 Support

For support and questions:
- **Issues**: GitHub Issues
- **Documentation**: `/docs` directory
- **Email**: support@yourapp.com

---

**Built with ❤️ using Go and following clean architecture principles.**
