package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// MetricsHandler handles Prometheus metrics collection and exposure.
// This handler provides comprehensive metrics for monitoring the authentication service
// including request counters, response times, database operations, and business metrics.
//
// Metrics Categories:
// - HTTP Request Metrics: request count, duration, status codes
// - Database Metrics: connection pool stats, query performance
// - Authentication Metrics: login attempts, token operations, password operations
// - Business Metrics: user registrations, active sessions, security events
//
// All metrics follow Prometheus naming conventions and include relevant labels
// for filtering and aggregation in monitoring dashboards.
//
// Interface Implementations:
// - MetricsRecorder: For HTTP middleware integration
// - AuthMetricsRecorder: For auth service integration
type MetricsHandler struct {
	logger           *logrus.Logger
	promRegistry     *prometheus.Registry
	httpRequestTotal *prometheus.CounterVec
	httpDuration     *prometheus.HistogramVec
	dbConnections    *prometheus.GaugeVec
	authOperations   *prometheus.CounterVec
	activeUsers      prometheus.Gauge
	tokenOperations  *prometheus.CounterVec
}

// NewMetricsHandler creates a new metrics handler with all required Prometheus collectors.
// This initializes the metrics registry and registers all custom metrics for the auth service.
//
// The handler sets up comprehensive instrumentation including:
// - HTTP request/response metrics with method, path, and status code labels
// - Database connection pool and operation metrics
// - Authentication-specific metrics for monitoring security events
// - Business metrics for tracking user activity and service health
//
// Parameters:
//   - logger: Logger instance for metrics-related logging
//
// Returns:
//   - Configured MetricsHandler instance
//   - Error if metrics registration fails
//
// Example:
//
//	metricsHandler, err := NewMetricsHandler(logger)
//	if err != nil {
//	    log.Fatal("Failed to initialize metrics:", err)
//	}
//
// Time Complexity: O(1)
// Space Complexity: O(1)
func NewMetricsHandler(logger *logrus.Logger) (*MetricsHandler, error) {
	// Create a new Prometheus registry for isolation
	registry := prometheus.NewRegistry()

	// HTTP request metrics with comprehensive labels
	httpRequestTotal := promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_service_http_requests_total",
			Help: "Total number of HTTP requests processed by the auth service",
		},
		[]string{"method", "path", "status_code"},
	)

	// HTTP request duration histogram for performance monitoring
	httpDuration := promauto.With(registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "auth_service_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets, // Standard buckets: 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
		},
		[]string{"method", "path"},
	)

	// Database connection pool metrics
	dbConnections := promauto.With(registry).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "auth_service_db_connections",
			Help: "Current database connection pool statistics",
		},
		[]string{"state"}, // open, idle, in_use, max_open, max_idle
	)

	// Authentication operation metrics for security monitoring
	authOperations := promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_service_auth_operations_total",
			Help: "Total number of authentication operations",
		},
		[]string{"operation", "result"}, // operation: login, register, logout, refresh; result: success, failure, error
	)

	// Active authenticated users gauge
	activeUsers := promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Name: "auth_service_active_users",
			Help: "Current number of active authenticated users",
		},
	)

	// Token operation metrics for JWT monitoring
	tokenOperations := promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_service_token_operations_total",
			Help: "Total number of JWT token operations",
		},
		[]string{"operation", "token_type", "result"}, // operation: generate, validate, refresh, revoke; token_type: access, refresh
	)

	// Register Go runtime metrics (memory, GC, goroutines)
	registry.MustRegister(prometheus.NewGoCollector())

	// Register process metrics (CPU, memory, file descriptors)
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	handler := &MetricsHandler{
		logger:           logger,
		promRegistry:     registry,
		httpRequestTotal: httpRequestTotal,
		httpDuration:     httpDuration,
		dbConnections:    dbConnections,
		authOperations:   authOperations,
		activeUsers:      activeUsers,
		tokenOperations:  tokenOperations,
	}

	logger.Info("Metrics handler initialized with Prometheus collectors")
	return handler, nil
}

// GetAuthMetricsRecorder returns the metrics handler as an AuthMetricsRecorder interface.
// This method provides a type-safe way for the auth service to record business metrics
// without directly depending on the full MetricsHandler implementation.
//
// Returns:
//   - AuthMetricsRecorder interface for recording auth-specific metrics
//
// Example:
//
//	authMetrics := metricsHandler.GetAuthMetricsRecorder()
//	authService := service.NewAuthService(userRepo, ..., authMetrics)
func (m *MetricsHandler) GetAuthMetricsRecorder() AuthMetricsRecorder {
	return m
}

// ServeHTTP handles the /metrics endpoint to expose Prometheus metrics.
// This endpoint provides metrics in the standard Prometheus text format
// for scraping by monitoring systems.
//
// The endpoint exposes:
// - Application-specific metrics (auth operations, user counts, etc.)
// - HTTP request/response metrics
// - Database connection pool metrics
// - Go runtime metrics (memory, GC, goroutines)
// - Process metrics (CPU, memory, file descriptors)
//
// Security considerations:
// - This endpoint should be protected in production environments
// - Consider rate limiting to prevent abuse
// - May expose sensitive operational information
//
// @Summary      Get Prometheus metrics
// @Description  Returns Prometheus metrics in text format for monitoring and alerting
// @Tags         health
// @Produce      text/plain
// @Success      200  {string}  string  "Metrics in Prometheus format"
// @Router       /metrics [get]
func (m *MetricsHandler) ServeHTTP(c *gin.Context) {
	// Update database connection metrics before serving
	m.updateDatabaseMetrics()

	// Create Prometheus HTTP handler with custom registry
	handler := promhttp.HandlerFor(m.promRegistry, promhttp.HandlerOpts{
		EnableOpenMetrics: true, // Support both Prometheus and OpenMetrics formats
		Registry:          m.promRegistry,
	})

	// Log metrics request for monitoring
	m.logger.WithFields(logrus.Fields{
		"client_ip":    c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
		"content_type": "text/plain",
	}).Debug("Serving Prometheus metrics")

	// Serve metrics using Prometheus handler
	handler.ServeHTTP(c.Writer, c.Request)
}

// RecordHTTPRequest records metrics for an HTTP request.
// This should be called from middleware to track all HTTP operations.
//
// Parameters:
//   - method: HTTP method (GET, POST, PUT, DELETE, etc.)
//   - path: Request path (should be normalized to avoid high cardinality)
//   - statusCode: HTTP response status code
//   - duration: Request processing duration in seconds
//
// Example:
//
//	metricsHandler.RecordHTTPRequest("POST", "/api/v1/auth/login", 200, 0.156)
func (m *MetricsHandler) RecordHTTPRequest(method, path string, statusCode int, duration float64) {
	// Record request count with labels
	m.httpRequestTotal.WithLabelValues(
		method,
		path,
		fmt.Sprintf("%d", statusCode),
	).Inc()

	// Record request duration
	m.httpDuration.WithLabelValues(method, path).Observe(duration)
}

// RecordAuthOperation records metrics for authentication operations.
// This tracks success/failure rates for security monitoring and alerting.
//
// Parameters:
//   - operation: Type of auth operation (login, register, logout, refresh)
//   - result: Operation result (success, failure, error)
//
// Example:
//
//	metricsHandler.RecordAuthOperation("login", "success")
//	metricsHandler.RecordAuthOperation("login", "failure")
func (m *MetricsHandler) RecordAuthOperation(operation, result string) {
	m.authOperations.WithLabelValues(operation, result).Inc()

	m.logger.WithFields(logrus.Fields{
		"operation": operation,
		"result":    result,
	}).Debug("Recorded auth operation metric")
}

// RecordTokenOperation records metrics for JWT token operations.
// This helps monitor token lifecycle and performance.
//
// Parameters:
//   - operation: Token operation (generate, validate, refresh, revoke)
//   - tokenType: Type of token (access, refresh)
//   - result: Operation result (success, failure, error)
//
// Example:
//
//	metricsHandler.RecordTokenOperation("generate", "access", "success")
//	metricsHandler.RecordTokenOperation("validate", "refresh", "failure")
func (m *MetricsHandler) RecordTokenOperation(operation, tokenType, result string) {
	m.tokenOperations.WithLabelValues(operation, tokenType, result).Inc()
}

// SetActiveUsers updates the active users gauge.
// This should be called periodically or when user sessions change.
//
// Parameters:
//   - count: Current number of active users
//
// Example:
//
//	metricsHandler.SetActiveUsers(1523)
func (m *MetricsHandler) SetActiveUsers(count float64) {
	m.activeUsers.Set(count)

	m.logger.WithField("active_users", count).Debug("Updated active users metric")
}

// updateDatabaseMetrics collects and updates database connection pool metrics.
// This is called before serving metrics to ensure current values.
//
// Note: This is a placeholder implementation. In a real application,
// you would inject the database connection pool and collect actual metrics.
func (m *MetricsHandler) updateDatabaseMetrics() {
	// TODO: Implement actual database metrics collection
	// This would typically require access to sql.DB.Stats()

	// Placeholder values - replace with actual database stats
	m.dbConnections.WithLabelValues("open").Set(10)
	m.dbConnections.WithLabelValues("idle").Set(5)
	m.dbConnections.WithLabelValues("in_use").Set(5)
	m.dbConnections.WithLabelValues("max_open").Set(25)
	m.dbConnections.WithLabelValues("max_idle").Set(10)
}

// AuthMetricsRecorder defines the interface for recording authentication metrics.
// This interface allows the auth service to record business metrics without
// directly depending on the metrics implementation.
type AuthMetricsRecorder interface {
	// RecordAuthOperation records metrics for authentication operations.
	RecordAuthOperation(operation, result string)

	// RecordTokenOperation records metrics for JWT token operations.
	RecordTokenOperation(operation, tokenType, result string)

	// SetActiveUsers updates the active users gauge.
	SetActiveUsers(count float64)

	// Registration metrics
	RecordRegistrationAttempt()
	RecordRegistrationSuccess()
	RecordRegistrationFailure(reason string)

	// Login metrics
	RecordLoginAttempt()
	RecordLoginSuccess()
	RecordLoginFailure(reason string)

	// Logout metrics
	RecordLogoutAttempt()
	RecordLogoutSuccess()
	RecordLogoutFailure(reason string)
}

// Registration metrics implementation
func (m *MetricsHandler) RecordRegistrationAttempt() {
	m.RecordAuthOperation("register", "attempt")
}

func (m *MetricsHandler) RecordRegistrationSuccess() {
	m.RecordAuthOperation("register", "success")
}

func (m *MetricsHandler) RecordRegistrationFailure(reason string) {
	m.RecordAuthOperation("register", "failure")
}

// Login metrics implementation
func (m *MetricsHandler) RecordLoginAttempt() {
	m.RecordAuthOperation("login", "attempt")
}

func (m *MetricsHandler) RecordLoginSuccess() {
	m.RecordAuthOperation("login", "success")
}

func (m *MetricsHandler) RecordLoginFailure(reason string) {
	m.RecordAuthOperation("login", "failure")
}

// Logout metrics implementation
func (m *MetricsHandler) RecordLogoutAttempt() {
	m.RecordAuthOperation("logout", "attempt")
}

func (m *MetricsHandler) RecordLogoutSuccess() {
	m.RecordAuthOperation("logout", "success")
}

func (m *MetricsHandler) RecordLogoutFailure(reason string) {
	m.RecordAuthOperation("logout", "failure")
}
