# Go Authentication Microservice

A production-ready, scalable authentication microservice built with Go, featuring JWT tokens, PostgreSQL persistence, and comprehensive security measures.

## 🎯 Overview

This microservice provides a complete authentication solution with:
- User registration and login
- JWT access and refresh token management
- Password reset functionality
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

## 🚀 Quick Start

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

### Docker Development

```bash
# Start all services
make docker-up

# View logs
make docker-logs

# Stop services
make docker-down
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
DB_MAX_CONNECTIONS=25
DB_MAX_IDLE_CONNECTIONS=5
DB_CONNECTION_MAX_LIFETIME=5m

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

#### GET /health
Basic health check endpoint.

#### GET /health/ready
Readiness check (database connectivity).

#### GET /health/live
Liveness check (service responsiveness).

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
make docker-build      # Build Docker image
make docker-up         # Start Docker services
make docker-down       # Stop Docker services
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
curl http://localhost:8080/health

# Check readiness
curl http://localhost:8080/health/ready

# Check liveness
curl http://localhost:8080/health/live
```

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
