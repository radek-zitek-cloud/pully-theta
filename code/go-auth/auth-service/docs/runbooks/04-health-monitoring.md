# 🔍 Health Monitoring & Alerting

## 📋 **Purpose**
Comprehensive health monitoring and alerting guide for the Go Authentication Service, covering monitoring setup, metrics collection, alerting rules, and incident response procedures.

## 👥 **Audience**
- Site Reliability Engineers
- DevOps Engineers
- Platform Engineers
- On-call Engineers

## ⚡ **Prerequisites**
- Understanding of Prometheus, Grafana, and alerting concepts
- Access to monitoring infrastructure
- Knowledge of Go service architecture
- Familiarity with container orchestration (if applicable)

---

## 📊 **Service Health Indicators**

### 🎯 **Service Level Indicators (SLIs)**

#### **Availability**
- **Definition**: Percentage of successful requests vs total requests
- **Target**: 99.9% (8.76 hours downtime per year)
- **Measurement**: `(successful_requests / total_requests) * 100`

#### **Latency**
- **P50 Latency**: 50% of requests complete within 100ms
- **P95 Latency**: 95% of requests complete within 500ms
- **P99 Latency**: 99% of requests complete within 1000ms

#### **Error Rate**
- **Definition**: Percentage of requests resulting in 5xx errors
- **Target**: < 0.1% error rate
- **Measurement**: `(5xx_errors / total_requests) * 100`

#### **Throughput**
- **Definition**: Requests per second the service can handle
- **Target**: Handle peak traffic with headroom
- **Measurement**: `requests_per_second`

### 🔧 **Key Performance Indicators (KPIs)**

#### **Authentication Success Rate**
```promql
# Successful authentications vs total attempts
rate(auth_requests_total{status="success"}[5m]) / 
rate(auth_requests_total[5m]) * 100
```

#### **Token Generation Latency**
```promql
# Time to generate JWT tokens
histogram_quantile(0.95, 
  rate(token_generation_duration_seconds_bucket[5m])
)
```

#### **Database Connection Health**
```promql
# Active database connections
db_connections_active / db_connections_max * 100
```

#### **Memory Usage**
```promql
# Memory usage percentage
(go_memstats_alloc_bytes / go_memstats_sys_bytes) * 100
```

---

## 📈 **Monitoring Setup**

### 🔧 **Metrics Collection**

#### **Application Metrics**
The service exposes metrics at `/metrics` endpoint using Prometheus format:

```go
// Example metrics exposed by the service
auth_requests_total{method="POST", endpoint="/login", status="success"} 1234
auth_requests_total{method="POST", endpoint="/login", status="error"} 12
auth_request_duration_seconds{method="POST", endpoint="/login", le="0.1"} 800
auth_request_duration_seconds{method="POST", endpoint="/login", le="0.5"} 1200
token_generation_duration_seconds{type="access", le="0.01"} 950
token_generation_duration_seconds{type="refresh", le="0.01"} 980
db_queries_total{operation="select", table="users", status="success"} 5678
```

#### **Prometheus Configuration**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alerts/auth_service_alerts.yml"

scrape_configs:
  - job_name: 'auth-service'
    static_configs:
      - targets: ['auth-service:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
    scrape_timeout: 10s
    
  - job_name: 'auth-service-health'
    static_configs:
      - targets: ['auth-service:8080']
    metrics_path: '/health'
    scrape_interval: 30s
```

### 📊 **Grafana Dashboards**

#### **Main Service Dashboard**
```json
{
  "dashboard": {
    "title": "Auth Service - Overview",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(auth_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(auth_requests_total{status=~\"4..|5..\"}[5m]) / rate(auth_requests_total[5m]) * 100"
          }
        ],
        "thresholds": "1,5",
        "colors": ["green", "yellow", "red"]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(auth_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P50"
          },
          {
            "expr": "histogram_quantile(0.95, rate(auth_request_duration_seconds_bucket[5m]))",
            "legendFormat": "P95"
          }
        ]
      }
    ]
  }
}
```

#### **Database Dashboard**
```json
{
  "dashboard": {
    "title": "Auth Service - Database",
    "panels": [
      {
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "db_connections_active",
            "legendFormat": "Active"
          },
          {
            "expr": "db_connections_idle",
            "legendFormat": "Idle"
          }
        ]
      },
      {
        "title": "Query Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(db_queries_total{status=\"success\"}[5m])",
            "legendFormat": "Successful Queries"
          },
          {
            "expr": "rate(db_queries_total{status=\"error\"}[5m])",
            "legendFormat": "Failed Queries"
          }
        ]
      }
    ]
  }
}
```

---

## 🚨 **Alerting Rules**

### ⚠️ **Critical Alerts**

#### **Service Down**
```yaml
# alerts/auth_service_alerts.yml
groups:
  - name: auth_service_critical
    rules:
      - alert: AuthServiceDown
        expr: up{job="auth-service"} == 0
        for: 1m
        labels:
          severity: critical
          team: backend
          service: auth-service
        annotations:
          summary: "Auth Service is down"
          description: "Auth service has been down for more than 1 minute"
          runbook_url: "https://docs.company.com/runbooks/auth-service-down"
```

#### **High Error Rate**
```yaml
      - alert: HighErrorRate
        expr: |
          (
            rate(auth_requests_total{status=~"5.."}[5m]) / 
            rate(auth_requests_total[5m])
          ) * 100 > 5
        for: 2m
        labels:
          severity: critical
          team: backend
          service: auth-service
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }}% for the last 5 minutes"
          runbook_url: "https://docs.company.com/runbooks/high-error-rate"
```

#### **Database Connection Issues**
```yaml
      - alert: DatabaseConnectionHigh
        expr: |
          (
            db_connections_active / 
            db_connections_max
          ) * 100 > 80
        for: 3m
        labels:
          severity: critical
          team: backend
          service: auth-service
        annotations:
          summary: "Database connection pool nearly exhausted"
          description: "Database connections at {{ $value }}% of maximum"
          runbook_url: "https://docs.company.com/runbooks/database-connections"
```

### ⚡ **Warning Alerts**

#### **High Latency**
```yaml
  - name: auth_service_warning
    rules:
      - alert: HighLatency
        expr: |
          histogram_quantile(0.95, 
            rate(auth_request_duration_seconds_bucket[5m])
          ) > 0.5
        for: 5m
        labels:
          severity: warning
          team: backend
          service: auth-service
        annotations:
          summary: "High latency detected"
          description: "95th percentile latency is {{ $value }}s"
          runbook_url: "https://docs.company.com/runbooks/high-latency"
```

#### **Memory Usage High**
```yaml
      - alert: HighMemoryUsage
        expr: |
          (
            go_memstats_alloc_bytes / 
            go_memstats_sys_bytes
          ) * 100 > 80
        for: 10m
        labels:
          severity: warning
          team: backend
          service: auth-service
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }}%"
          runbook_url: "https://docs.company.com/runbooks/memory-usage"
```

#### **Certificate Expiry**
```yaml
      - alert: TLSCertificateExpiry
        expr: |
          (ssl_certificate_expiry_timestamp - time()) / 86400 < 30
        for: 1h
        labels:
          severity: warning
          team: platform
          service: auth-service
        annotations:
          summary: "TLS certificate expiring soon"
          description: "Certificate expires in {{ $value }} days"
          runbook_url: "https://docs.company.com/runbooks/certificate-renewal"
```

---

## 🔔 **Notification Channels**

### 📱 **Alertmanager Configuration**
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'smtp.company.com:587'
  smtp_from: 'alerts@company.com'

route:
  group_by: ['alertname', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'default'
  routes:
    - match:
        severity: critical
      receiver: 'critical-alerts'
      continue: true
    - match:
        severity: warning
      receiver: 'warning-alerts'

receivers:
  - name: 'default'
    email_configs:
      - to: 'team@company.com'
        subject: '{{ .GroupLabels.service }} Alert'
        body: |
          {{ range .Alerts }}
          Alert: {{ .Annotations.summary }}
          Description: {{ .Annotations.description }}
          {{ end }}

  - name: 'critical-alerts'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#critical-alerts'
        title: 'CRITICAL: {{ .GroupLabels.service }}'
        text: |
          {{ range .Alerts }}
          🚨 {{ .Annotations.summary }}
          {{ .Annotations.description }}
          Runbook: {{ .Annotations.runbook_url }}
          {{ end }}
    pagerduty_configs:
      - service_key: 'YOUR_PAGERDUTY_SERVICE_KEY'
        description: '{{ .GroupLabels.service }} Critical Alert'

  - name: 'warning-alerts'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#warnings'
        title: 'WARNING: {{ .GroupLabels.service }}'
        text: |
          {{ range .Alerts }}
          ⚠️ {{ .Annotations.summary }}
          {{ .Annotations.description }}
          {{ end }}
```

---

## 🔍 **Health Check Endpoints**

### 🏥 **Health Check Implementation**

#### **Basic Health Check**
```bash
# Simple availability check
curl -f http://auth-service:8080/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2025-06-20T14:30:00Z",
  "version": "1.2.3",
  "checks": {
    "database": "healthy",
    "redis": "healthy",
    "external_services": "healthy"
  }
}
```

#### **Detailed Health Check**
```bash
# Comprehensive health information
curl http://auth-service:8080/health/detailed

# Expected response:
{
  "status": "healthy",
  "timestamp": "2025-06-20T14:30:00Z",
  "version": "1.2.3",
  "uptime": "48h15m30s",
  "checks": {
    "database": {
      "status": "healthy",
      "response_time": "2ms",
      "connection_pool": {
        "active": 5,
        "idle": 10,
        "max": 50
      }
    },
    "redis": {
      "status": "healthy",
      "response_time": "1ms"
    },
    "memory": {
      "status": "healthy",
      "usage_percent": 45.2,
      "allocated_mb": 128,
      "system_mb": 284
    },
    "goroutines": {
      "status": "healthy",
      "count": 25
    }
  },
  "metrics": {
    "requests_total": 125847,
    "requests_per_second": 42.3,
    "error_rate_percent": 0.02,
    "average_response_time_ms": 45
  }
}
```

### 🔧 **Kubernetes Health Checks**

#### **Liveness Probe**
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  template:
    spec:
      containers:
        - name: auth-service
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
```

#### **Readiness Probe**
```yaml
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 2
```

#### **Startup Probe**
```yaml
          startupProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 10
```

---

## 📋 **Monitoring Checklist**

### ✅ **Daily Checks**
- [ ] Review error rate trends
- [ ] Check response time percentiles
- [ ] Verify database connection health
- [ ] Monitor memory usage patterns
- [ ] Review active alert count

### ✅ **Weekly Checks**
- [ ] Analyze traffic patterns
- [ ] Review capacity planning metrics
- [ ] Check certificate expiry dates
- [ ] Validate backup success rates
- [ ] Review security audit logs

### ✅ **Monthly Checks**
- [ ] Review and update SLI/SLO targets
- [ ] Analyze incident response times
- [ ] Update monitoring dashboard
- [ ] Review alerting rule effectiveness
- [ ] Conduct monitoring system health check

---

## 🚨 **Incident Response Procedures**

### 🔥 **Critical Incident Response**

#### **Service Down Response**
```bash
# 1. Immediate Assessment (within 2 minutes)
# Check service status
kubectl get pods -n auth-service -l app=auth-service

# Check recent deployments
kubectl rollout history deployment/auth-service -n auth-service

# Check logs
kubectl logs -n auth-service -l app=auth-service --tail=100

# 2. Quick Mitigation (within 5 minutes)
# Restart pods if needed
kubectl rollout restart deployment/auth-service -n auth-service

# Scale up if resource issue
kubectl scale deployment auth-service --replicas=6 -n auth-service

# Rollback if recent deployment
kubectl rollout undo deployment/auth-service -n auth-service

# 3. Communication (within 10 minutes)
# Update status page
# Notify stakeholders via Slack/email
# Create incident ticket
```

#### **High Error Rate Response**
```bash
# 1. Identify Error Sources
# Check error logs
kubectl logs -n auth-service -l app=auth-service | grep -i error

# Check database connectivity
kubectl exec deployment/auth-service -n auth-service -- \
  wget -qO- http://localhost:8080/health/detailed

# Check dependency status
curl -f http://external-service/health

# 2. Quick Fixes
# Increase timeout values (if applicable)
# Restart problematic pods
# Enable circuit breaker (if implemented)

# 3. Monitoring
# Watch error rate metrics
# Monitor downstream services
# Track recovery progress
```

### ⚠️ **Warning Alert Response**

#### **High Latency Investigation**
```bash
# Check current load
kubectl top pods -n auth-service

# Review recent query patterns
kubectl logs -n auth-service -l app=auth-service | grep -i "slow\|timeout"

# Check database performance
# (Connect to database and run performance queries)

# Monitor improvement
watch 'curl -s http://prometheus:9090/api/v1/query?query=histogram_quantile\(0.95,rate\(auth_request_duration_seconds_bucket\[5m\]\)\)'
```

### 📊 **Post-Incident Analysis**

#### **Incident Report Template**
```markdown
# Incident Report: [Date] - [Brief Description]

## Summary
- **Start Time**: YYYY-MM-DD HH:MM UTC
- **End Time**: YYYY-MM-DD HH:MM UTC
- **Duration**: X hours Y minutes
- **Severity**: Critical/High/Medium/Low
- **Impact**: Description of user impact

## Timeline
- HH:MM - Alert triggered
- HH:MM - Investigation started
- HH:MM - Root cause identified
- HH:MM - Mitigation applied
- HH:MM - Service restored

## Root Cause
Detailed explanation of what caused the incident.

## Resolution
Steps taken to resolve the incident.

## Prevention
Action items to prevent similar incidents:
- [ ] Action item 1
- [ ] Action item 2

## Lessons Learned
Key takeaways and improvements identified.
```

---

## 🛠️ **Monitoring Tools Setup**

### 📊 **Prometheus Setup**
```bash
# Install Prometheus using Helm
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --values prometheus-values.yaml
```

### 📈 **Grafana Setup**
```bash
# Access Grafana
kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring

# Import auth service dashboard
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @auth-service-dashboard.json
```

### 🔔 **Alertmanager Setup**
```bash
# Update alertmanager configuration
kubectl create configmap alertmanager-config \
  --from-file=alertmanager.yml \
  -n monitoring

# Restart alertmanager
kubectl rollout restart statefulset/alertmanager-prometheus-kube-prometheus-alertmanager \
  -n monitoring
```

---

## 📚 **Monitoring Queries**

### 🔍 **Common Prometheus Queries**

#### **Service Performance**
```promql
# Request rate
rate(auth_requests_total[5m])

# Error percentage
rate(auth_requests_total{status=~"5.."}[5m]) / rate(auth_requests_total[5m]) * 100

# Average response time
rate(auth_request_duration_seconds_sum[5m]) / rate(auth_request_duration_seconds_count[5m])

# 95th percentile response time
histogram_quantile(0.95, rate(auth_request_duration_seconds_bucket[5m]))
```

#### **Resource Usage**
```promql
# CPU usage
rate(process_cpu_seconds_total[5m]) * 100

# Memory usage
process_resident_memory_bytes

# Goroutine count
go_goroutines

# GC duration
rate(go_gc_duration_seconds_sum[5m])
```

#### **Database Metrics**
```promql
# Database connections
db_connections_active
db_connections_idle

# Query rate
rate(db_queries_total[5m])

# Query duration
histogram_quantile(0.95, rate(db_query_duration_seconds_bucket[5m]))
```

---

## 📚 **References**

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [Alertmanager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [SRE Best Practices](https://sre.google/books/)
- [Kubernetes Monitoring](https://kubernetes.io/docs/tasks/debug-application-cluster/resource-monitoring/)

---

**📅 Last Updated**: June 20, 2025  
**👤 Maintained By**: SRE Team  
**🔄 Next Review**: July 20, 2025
