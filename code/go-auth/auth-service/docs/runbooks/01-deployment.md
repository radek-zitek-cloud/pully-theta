# 🚀 Deployment Guide

## 📋 **Purpose**
Complete deployment procedures for the Go Authentication Service across all environments (development, staging, production).

## 👥 **Audience**
- DevOps Engineers
- Site Reliability Engineers
- Development Team Leaders
- System Administrators

## ⚡ **Prerequisites**
- Docker and Docker Compose installed
- Access to target environment
- Database credentials and access
- SSL certificates (for production)
- Environment-specific configuration files

---

## 🏗️ **Environment Types**

### 🔧 **Development Environment**

#### **Using Docker Compose (Recommended)**
```bash
# Clone repository
git clone <repository-url>
cd auth-service

# Copy environment configuration
cp .env.example .env

# Edit configuration as needed
nano .env

# Start all services
make compose-up-build

# Verify deployment
make status
```

#### **Manual Setup**
```bash
# Install dependencies
make setup

# Start database
make db-up

# Run migrations
make db-migrate-up

# Start service
make run
```

### 🧪 **Staging Environment**

#### **Prerequisites**
- Staging database configured
- SSL certificates available
- Environment variables configured

#### **Deployment Steps**
```bash
# 1. Build versioned image
make version-bump-patch
make docker-build

# 2. Tag for staging
docker tag auth-service:latest auth-service:staging

# 3. Deploy to staging
docker-compose -f docker-compose.staging.yml up -d

# 4. Run health checks
curl https://staging-auth.company.com/health/ready

# 5. Run smoke tests
./scripts/smoke-tests.sh staging
```

### 🏭 **Production Environment**

#### **Pre-Deployment Checklist**
- [ ] Security scan completed
- [ ] Load testing passed
- [ ] Database migrations tested
- [ ] Rollback plan prepared
- [ ] Monitoring alerts configured
- [ ] SSL certificates valid

#### **Blue-Green Deployment**
```bash
# 1. Prepare new version
make version-bump-minor
make docker-build
make docker-push

# 2. Deploy to green environment
kubectl apply -f k8s/auth-service-green.yaml

# 3. Verify green deployment
kubectl get pods -l app=auth-service-green
curl https://green-auth.company.com/health/ready

# 4. Switch traffic (gradual)
kubectl patch service auth-service -p '{"spec":{"selector":{"version":"green"}}}'

# 5. Monitor and verify
# Wait 10 minutes, monitor metrics

# 6. Cleanup old version
kubectl delete deployment auth-service-blue
```

---

## 🐳 **Docker Deployment**

### **Single Container**
```bash
# Build image
docker build -t auth-service:latest .

# Run container
docker run -d \
  --name auth-service \
  --env-file .env \
  -p 6910:6910 \
  auth-service:latest

# Check status
docker logs auth-service
```

### **Docker Compose (Full Stack)**
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  auth-service:
    image: auth-service:${VERSION}
    restart: unless-stopped
    environment:
      - ENVIRONMENT=production
      - DB_HOST=postgres
      - JWT_SECRET=${JWT_SECRET}
    ports:
      - "6910:6910"
    depends_on:
      - postgres
      - redis
    
  postgres:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${DB_NAME}
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass ${REDIS_PASSWORD}

volumes:
  postgres_data:
```

---

## ☸️ **Kubernetes Deployment**

### **Namespace Setup**
```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-service
```

### **ConfigMap and Secrets**
```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: auth-service
data:
  ENVIRONMENT: "production"
  PORT: "6910"
  DB_HOST: "postgres-service"
  DB_PORT: "5432"
  DB_NAME: "authdb"
  LOG_LEVEL: "info"

---
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secrets
  namespace: auth-service
type: Opaque
stringData:
  DB_PASSWORD: "your-secure-password"
  JWT_SECRET: "your-jwt-secret-key"
  JWT_REFRESH_SECRET: "your-refresh-secret-key"
```

### **Deployment**
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: auth-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: auth-service:v1.0.0
        ports:
        - containerPort: 6910
        envFrom:
        - configMapRef:
            name: auth-config
        - secretRef:
            name: auth-secrets
        livenessProbe:
          httpGet:
            path: /health/live
            port: 6910
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 6910
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 250m
            memory: 256Mi
```

### **Service and Ingress**
```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: auth-service
spec:
  selector:
    app: auth-service
  ports:
  - port: 6910
    targetPort: 6910
  type: ClusterIP

---
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-service
  namespace: auth-service
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - auth.company.com
    secretName: auth-tls
  rules:
  - host: auth.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 6910
```

---

## 🔍 **Post-Deployment Verification**

### **Health Checks**
```bash
# Basic health check
curl -f http://localhost:6910/health || exit 1

# Readiness check
curl -f http://localhost:6910/health/ready || exit 1

# Liveness check
curl -f http://localhost:6910/health/live || exit 1
```

### **Functional Tests**
```bash
# Test user registration
curl -X POST http://localhost:6910/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!",
    "password_confirm": "TestPass123!",
    "first_name": "Test",
    "last_name": "User"
  }'

# Test user login
curl -X POST http://localhost:6910/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'
```

### **Performance Verification**
```bash
# Load test with Apache Bench
ab -n 1000 -c 10 http://localhost:6910/health

# Response time check
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:6910/health
```

---

## 🔄 **Rollback Procedures**

### **Docker Rollback**
```bash
# Stop current version
docker stop auth-service

# Start previous version
docker run -d \
  --name auth-service \
  --env-file .env \
  -p 6910:6910 \
  auth-service:previous-tag
```

### **Kubernetes Rollback**
```bash
# Check rollout history
kubectl rollout history deployment/auth-service -n auth-service

# Rollback to previous version
kubectl rollout undo deployment/auth-service -n auth-service

# Rollback to specific revision
kubectl rollout undo deployment/auth-service --to-revision=2 -n auth-service
```

---

## 🚨 **Emergency Procedures**

### **Complete Service Failure**
1. **Immediate Actions**
   ```bash
   # Check service status
   kubectl get pods -n auth-service
   
   # Check logs
   kubectl logs -f deployment/auth-service -n auth-service
   ```

2. **Escalation Path**
   - Alert on-call engineer
   - Create incident ticket
   - Notify stakeholders

3. **Recovery Actions**
   ```bash
   # Scale up replicas
   kubectl scale deployment auth-service --replicas=5 -n auth-service
   
   # Restart deployment
   kubectl rollout restart deployment/auth-service -n auth-service
   ```

### **Database Connection Issues**
1. **Verify Database Connectivity**
   ```bash
   # Test database connection
   kubectl exec -it deployment/auth-service -n auth-service -- \
     pg_isready -h postgres-service -p 5432
   ```

2. **Check Database Status**
   ```bash
   # Check database pod
   kubectl get pods -l app=postgres -n auth-service
   
   # Check database logs
   kubectl logs -f deployment/postgres -n auth-service
   ```

---

## 📊 **Monitoring Integration**

### **Prometheus Metrics**
```yaml
# ServiceMonitor for Prometheus
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: auth-service
  namespace: auth-service
spec:
  selector:
    matchLabels:
      app: auth-service
  endpoints:
  - port: metrics
    path: /metrics
```

### **Grafana Dashboard**
- Import dashboard ID: [Custom Dashboard ID]
- Key metrics to monitor:
  - Request rate and latency
  - Error rate
  - Active users
  - Database connections

---

## 📝 **Deployment Checklist**

### **Pre-Deployment**
- [ ] Code review completed
- [ ] Security scan passed
- [ ] Unit tests passed
- [ ] Integration tests passed
- [ ] Database migrations tested
- [ ] Configuration validated
- [ ] SSL certificates verified
- [ ] Monitoring configured

### **During Deployment**
- [ ] Health checks passing
- [ ] Logs monitored
- [ ] Metrics collected
- [ ] No error alerts
- [ ] Performance within SLA

### **Post-Deployment**
- [ ] Functional tests passed
- [ ] Load tests completed
- [ ] Monitoring dashboards updated
- [ ] Documentation updated
- [ ] Team notified
- [ ] Rollback plan ready

---

## 📚 **References**

- [Docker Documentation](https://docs.docker.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Prometheus Monitoring](https://prometheus.io/docs/)
- [Service Configuration Guide](../CONFIGURATION.md)
- [Architecture Documentation](../ARCHITECTURE.md)

---

**📅 Last Updated**: June 20, 2025  
**👤 Maintained By**: DevOps Team  
**🔄 Next Review**: July 20, 2025
