# 🔧 Service Management

## 📋 **Purpose**
Procedures for starting, stopping, managing, and monitoring the Go Authentication Service in various environments.

## 👥 **Audience**
- Operations Engineers
- DevOps Engineers
- Development Team
- System Administrators

## ⚡ **Prerequisites**
- Access to target environment
- Required permissions for service management
- Basic understanding of Docker/Kubernetes
- Service configuration files

---

## 🚀 **Service Lifecycle Management**

### 🔄 **Local Development (Docker Compose)**

#### **Start Services**
```bash
# Start all services (detached mode)
make compose-up

# Start services with build
make compose-up-build

# Start with logs visible
docker compose up

# Start specific service
docker compose up auth-service
```

#### **Stop Services**
```bash
# Stop all services
make compose-down

# Stop and remove volumes
make compose-down-volumes

# Stop specific service
docker compose stop auth-service
```

#### **Restart Services**
```bash
# Restart authentication service only
make compose-restart

# Restart all services
docker compose restart

# Restart with new build
make compose-down && make compose-up-build
```

#### **Service Status**
```bash
# Check status of all services
make compose-status

# Detailed container information
docker compose ps -a

# Check resource usage
docker stats
```

### 🐳 **Docker Container Management**

#### **Direct Container Operations**
```bash
# Start container
docker run -d \
  --name auth-service \
  --env-file .env \
  -p 6910:6910 \
  --restart unless-stopped \
  auth-service:latest

# Stop container
docker stop auth-service

# Restart container
docker restart auth-service

# Remove container
docker rm auth-service

# Force remove (if stuck)
docker rm -f auth-service
```

#### **Container Monitoring**
```bash
# View container logs
docker logs auth-service

# Follow logs in real-time
docker logs -f auth-service

# View last 100 lines
docker logs --tail 100 auth-service

# Container stats
docker stats auth-service

# Container inspection
docker inspect auth-service
```

### ☸️ **Kubernetes Service Management**

#### **Deployment Operations**
```bash
# Apply deployment
kubectl apply -f k8s/auth-service.yaml

# Scale deployment
kubectl scale deployment auth-service --replicas=3 -n auth-service

# Update deployment
kubectl set image deployment/auth-service \
  auth-service=auth-service:v1.1.0 -n auth-service

# Restart deployment
kubectl rollout restart deployment/auth-service -n auth-service

# Delete deployment
kubectl delete deployment auth-service -n auth-service
```

#### **Pod Management**
```bash
# List pods
kubectl get pods -n auth-service

# Describe pod
kubectl describe pod <pod-name> -n auth-service

# Get pod logs
kubectl logs <pod-name> -n auth-service

# Follow logs
kubectl logs -f deployment/auth-service -n auth-service

# Execute commands in pod
kubectl exec -it <pod-name> -n auth-service -- /bin/sh

# Delete pod (triggers recreation)
kubectl delete pod <pod-name> -n auth-service
```

#### **Service Operations**
```bash
# List services
kubectl get services -n auth-service

# Describe service
kubectl describe service auth-service -n auth-service

# Port forward for testing
kubectl port-forward service/auth-service 6910:6910 -n auth-service

# Delete service
kubectl delete service auth-service -n auth-service
```

---

## 📊 **Health Monitoring**

### 🏥 **Health Check Endpoints**

#### **Basic Health Check**
```bash
# Check service health
curl -f http://localhost:6910/health

# Expected response
{
  "status": "healthy",
  "timestamp": "2025-06-20T10:30:00Z",
  "version": "v1.0.0",
  "uptime": "2h30m45s",
  "checks": {
    "database": "healthy"
  }
}
```

#### **Readiness Check**
```bash
# Check if service is ready to accept traffic
curl -f http://localhost:6910/health/ready

# Expected response
{
  "status": "ready",
  "timestamp": "2025-06-20T10:30:00Z",
  "checks": {
    "database": "connected",
    "migrations": "up_to_date"
  }
}
```

#### **Liveness Check**
```bash
# Check if service is alive
curl -f http://localhost:6910/health/live

# Expected response
{
  "status": "alive",
  "timestamp": "2025-06-20T10:30:00Z",
  "version": "v1.0.0"
}
```

### 📈 **Metrics Collection**

#### **Prometheus Metrics**
```bash
# View metrics endpoint
curl http://localhost:6910/metrics

# Key metrics to monitor:
# - http_requests_total
# - http_request_duration_seconds
# - auth_active_users
# - auth_login_attempts_total
# - auth_failed_logins_total
# - database_connections_active
```

#### **Custom Health Check Script**
```bash
#!/bin/bash
# health-check.sh

HOST=${1:-localhost:6910}
TIMEOUT=${2:-10}

echo "🔍 Checking service health at $HOST"

# Basic health check
if curl -f --max-time $TIMEOUT "$HOST/health" > /dev/null 2>&1; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Readiness check
if curl -f --max-time $TIMEOUT "$HOST/health/ready" > /dev/null 2>&1; then
    echo "✅ Readiness check passed"
else
    echo "⚠️ Service not ready"
    exit 1
fi

# Liveness check
if curl -f --max-time $TIMEOUT "$HOST/health/live" > /dev/null 2>&1; then
    echo "✅ Liveness check passed"
else
    echo "❌ Service not responding"
    exit 1
fi

echo "🎉 All health checks passed"
```

---

## 📝 **Log Management**

### 🔍 **Log Access**

#### **Docker Compose Logs**
```bash
# View all service logs
make compose-logs

# View auth service logs only
make compose-logs-app

# Follow logs in real-time
docker compose logs -f auth-service

# View logs with timestamps
docker compose logs -t auth-service

# View last 50 lines
docker compose logs --tail 50 auth-service
```

#### **Container Logs**
```bash
# View container logs
docker logs auth-service

# Follow logs
docker logs -f auth-service

# View logs with timestamps
docker logs -t auth-service

# Filter logs by time
docker logs --since "2025-06-20T10:00:00" auth-service
docker logs --until "2025-06-20T11:00:00" auth-service
```

#### **Kubernetes Logs**
```bash
# View deployment logs
kubectl logs deployment/auth-service -n auth-service

# Follow deployment logs
kubectl logs -f deployment/auth-service -n auth-service

# View specific pod logs
kubectl logs <pod-name> -n auth-service

# View previous container logs
kubectl logs <pod-name> --previous -n auth-service

# Multiple containers in pod
kubectl logs <pod-name> -c auth-service -n auth-service
```

### 📊 **Log Analysis**

#### **Common Log Patterns**
```bash
# Filter for errors
docker logs auth-service 2>&1 | grep "ERROR"

# Filter for authentication events
docker logs auth-service 2>&1 | grep "login\|logout\|register"

# Filter for database events
docker logs auth-service 2>&1 | grep "database"

# Filter for HTTP requests
docker logs auth-service 2>&1 | grep "HTTP"
```

#### **Log Level Configuration**
```bash
# Change log level (requires restart)
export LOG_LEVEL=debug
docker restart auth-service

# Available log levels:
# - trace
# - debug
# - info (default)
# - warn
# - error
# - fatal
```

---

## 🔧 **Configuration Management**

### ⚙️ **Environment Variables**

#### **Runtime Configuration Updates**
```bash
# View current environment
docker exec auth-service env | grep -E "(JWT|DB|LOG)"

# Update environment variable (requires restart)
docker stop auth-service
docker run -d \
  --name auth-service \
  -e LOG_LEVEL=debug \
  -e BCRYPT_COST=10 \
  auth-service:latest
```

#### **Configuration Validation**
```bash
# Validate configuration before starting
./scripts/validate-config.sh .env

# Check required environment variables
make env-check

# Test configuration
docker run --rm \
  --env-file .env \
  auth-service:latest \
  ./auth-service --config-check
```

### 🗂️ **Configuration Files**

#### **Docker Compose Configuration**
```yaml
# Override specific settings
# docker-compose.override.yml
version: '3.8'
services:
  auth-service:
    environment:
      - LOG_LEVEL=debug
      - BCRYPT_COST=10
    volumes:
      - ./custom-config.yaml:/app/config.yaml
```

#### **Kubernetes ConfigMap Updates**
```bash
# Update ConfigMap
kubectl create configmap auth-config \
  --from-env-file=.env \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods to pick up new config
kubectl rollout restart deployment/auth-service -n auth-service
```

---

## 🛠️ **Database Operations**

### 📊 **Database Connectivity**

#### **Connection Testing**
```bash
# Test database connection from container
docker exec auth-service pg_isready -h postgres -p 5432

# Test connection with credentials
docker exec auth-service psql \
  -h postgres -U authuser -d authdb -c "SELECT 1;"

# Connection from Kubernetes
kubectl exec deployment/auth-service -n auth-service -- \
  pg_isready -h postgres-service -p 5432
```

#### **Database Status Checks**
```bash
# Check database migrations
make db-migrate-status

# List tables
docker exec postgres psql -U authuser -d authdb \
  -c "\dt"

# Check table row counts
docker exec postgres psql -U authuser -d authdb \
  -c "SELECT 
    schemaname,tablename,n_tup_ins as inserts,
    n_tup_upd as updates,n_tup_del as deletes
    FROM pg_stat_user_tables;"
```

### 🔄 **Migration Management**
```bash
# Run pending migrations
make db-migrate-up

# Rollback one migration
make db-migrate-down

# Reset database (DANGER!)
make db-reset

# Check migration status
docker exec postgres psql -U authuser -d authdb \
  -c "SELECT * FROM schema_migrations ORDER BY version;"
```

---

## 🚨 **Emergency Procedures**

### 🔥 **Service Recovery**

#### **Quick Service Restart**
```bash
# Docker Compose
make compose-restart

# Docker Container
docker restart auth-service

# Kubernetes
kubectl rollout restart deployment/auth-service -n auth-service
```

#### **Emergency Scale Up**
```bash
# Kubernetes horizontal scaling
kubectl scale deployment auth-service --replicas=10 -n auth-service

# Docker Compose scaling
docker compose up -d --scale auth-service=3
```

#### **Emergency Rollback**
```bash
# Kubernetes rollback
kubectl rollout undo deployment/auth-service -n auth-service

# Docker rollback to previous image
docker stop auth-service
docker run -d --name auth-service auth-service:previous-version
```

### 🚑 **Health Recovery Actions**

#### **Database Recovery**
```bash
# Restart database
docker restart postgres

# Clear connection pool
docker exec auth-service pkill -f "auth-service"
docker restart auth-service

# Force migration check
make db-migrate-force-check
```

#### **Memory/CPU Issues**
```bash
# Check resource usage
docker stats auth-service

# Restart with resource limits
docker stop auth-service
docker run -d \
  --name auth-service \
  --memory="512m" \
  --cpus="0.5" \
  auth-service:latest

# Kubernetes resource limits
kubectl patch deployment auth-service -n auth-service -p '
{
  "spec": {
    "template": {
      "spec": {
        "containers": [{
          "name": "auth-service",
          "resources": {
            "limits": {"memory": "512Mi", "cpu": "500m"},
            "requests": {"memory": "256Mi", "cpu": "250m"}
          }
        }]
      }
    }
  }
}'
```

---

## 📋 **Operational Checklists**

### ✅ **Daily Health Check**
- [ ] Service health endpoints responding
- [ ] Database connectivity confirmed
- [ ] No error spikes in logs
- [ ] Memory and CPU usage normal
- [ ] Disk space adequate
- [ ] SSL certificates valid

### ✅ **Weekly Maintenance**
- [ ] Log rotation completed
- [ ] Database performance reviewed
- [ ] Security patches applied
- [ ] Backup verification
- [ ] Monitoring alerts tested

### ✅ **Monthly Review**
- [ ] Performance metrics analyzed
- [ ] Capacity planning updated
- [ ] Security audit completed
- [ ] Documentation updated
- [ ] Disaster recovery tested

---

## 📚 **Automation Scripts**

### 🔄 **Service Management Scripts**

#### **Auto-restart Script**
```bash
#!/bin/bash
# auto-restart.sh
SERVICE_NAME="auth-service"
HEALTH_URL="http://localhost:6910/health"

while true; do
    if ! curl -f "$HEALTH_URL" > /dev/null 2>&1; then
        echo "Service unhealthy, restarting..."
        docker restart "$SERVICE_NAME"
        sleep 30
    fi
    sleep 60
done
```

#### **Backup Script**
```bash
#!/bin/bash
# backup.sh
BACKUP_DIR="/backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Database backup
docker exec postgres pg_dump -U authuser authdb > "$BACKUP_DIR/database.sql"

# Configuration backup
cp .env "$BACKUP_DIR/env.backup"
cp docker-compose.yml "$BACKUP_DIR/compose.backup"

echo "Backup completed: $BACKUP_DIR"
```

---

## 📞 **Support Contacts**

### 🚨 **Emergency Escalation**
1. **Level 1**: On-call Engineer
2. **Level 2**: Service Owner
3. **Level 3**: Architecture Team
4. **Level 4**: CTO/VP Engineering

### 📱 **Contact Information**
- **Pager Duty**: [PagerDuty Service Key]
- **Slack Channel**: #auth-service-alerts
- **Email**: auth-service-team@company.com
- **Wiki**: [Internal Wiki Link]

---

**📅 Last Updated**: June 20, 2025  
**👤 Maintained By**: Operations Team  
**🔄 Next Review**: July 20, 2025
