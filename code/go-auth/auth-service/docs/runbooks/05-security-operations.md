# 🔐 Security Operations

## 📋 **Purpose**
Comprehensive security operations guide for the Go Authentication Service, covering security monitoring, incident response, vulnerability management, and compliance procedures.

## 👥 **Audience**
- Security Engineers
- DevOps Engineers
- Site Reliability Engineers
- Compliance Officers
- Backend Developers

## ⚡ **Prerequisites**
- Understanding of authentication and authorization concepts
- Knowledge of security best practices
- Familiarity with JWT tokens and OAuth2
- Experience with security monitoring tools

---

## 🛡️ **Security Architecture Overview**

### 🏗️ **Security Layers**

#### **Network Security**
- **TLS/SSL Encryption**: All traffic encrypted in transit
- **Network Segmentation**: Service isolated in private network
- **Firewall Rules**: Strict ingress/egress controls
- **DDoS Protection**: Rate limiting and traffic filtering

#### **Application Security**
- **JWT Token Security**: Signed tokens with expiration
- **Password Security**: Bcrypt hashing with salt
- **Input Validation**: Comprehensive request validation
- **SQL Injection Prevention**: Parameterized queries

#### **Infrastructure Security**
- **Container Security**: Minimal base images, non-root user
- **Secret Management**: External secret store integration
- **Access Control**: RBAC for all resources
- **Audit Logging**: Comprehensive security event logging

---

## 🔍 **Security Monitoring**

### 📊 **Security Metrics**

#### **Authentication Metrics**
```promql
# Failed login attempts
rate(auth_requests_total{endpoint="/login", status="unauthorized"}[5m])

# Brute force detection
increase(auth_requests_total{endpoint="/login", status="unauthorized"}[1m]) > 10

# Password reset requests
rate(auth_requests_total{endpoint="/password/reset"}[5m])

# Account lockout events
rate(auth_account_lockouts_total[5m])
```

#### **Security Event Metrics**
```promql
# Suspicious IP activities
rate(security_events_total{type="suspicious_ip"}[5m])

# Token validation failures
rate(token_validation_failures_total[5m])

# Privilege escalation attempts
rate(security_events_total{type="privilege_escalation"}[5m])

# Data access violations
rate(security_events_total{type="unauthorized_access"}[5m])
```

### 🚨 **Security Alerts**

#### **Critical Security Alerts**
```yaml
# security_alerts.yml
groups:
  - name: security_critical
    rules:
      - alert: BruteForceAttack
        expr: |
          increase(auth_requests_total{endpoint="/login", status="unauthorized"}[5m]) > 50
        for: 1m
        labels:
          severity: critical
          team: security
          service: auth-service
        annotations:
          summary: "Brute force attack detected"
          description: "{{ $value }} failed login attempts in 5 minutes"
          runbook_url: "https://docs.company.com/runbooks/brute-force-response"

      - alert: SuspiciousTokenActivity
        expr: |
          rate(token_validation_failures_total[5m]) > 1
        for: 2m
        labels:
          severity: critical
          team: security
          service: auth-service
        annotations:
          summary: "High rate of token validation failures"
          description: "{{ $value }} token validation failures per second"
          runbook_url: "https://docs.company.com/runbooks/token-security"

      - alert: AccountEnumerationAttempt
        expr: |
          increase(auth_requests_total{endpoint="/login", status="not_found"}[10m]) > 100
        for: 5m
        labels:
          severity: warning
          team: security
          service: auth-service
        annotations:
          summary: "Possible account enumeration attack"
          description: "{{ $value }} user not found responses in 10 minutes"
```

#### **Security Incident Response**
```yaml
      - alert: PrivilegeEscalationAttempt
        expr: |
          rate(security_events_total{type="privilege_escalation"}[5m]) > 0
        for: 0s
        labels:
          severity: critical
          team: security
          service: auth-service
        annotations:
          summary: "Privilege escalation attempt detected"
          description: "Unauthorized privilege escalation detected"
          runbook_url: "https://docs.company.com/runbooks/privilege-escalation"

      - alert: DataExfiltrationAttempt
        expr: |
          rate(audit_logs_total{action="bulk_data_access"}[5m]) > 0.1
        for: 1m
        labels:
          severity: critical
          team: security
          service: auth-service
        annotations:
          summary: "Potential data exfiltration detected"
          description: "Unusual bulk data access pattern detected"
```

---

## 🔐 **Access Control Management**

### 👤 **User Account Security**

#### **Account Lifecycle Management**
```sql
-- Create new user with security defaults
INSERT INTO users (
    email, 
    password_hash, 
    first_name, 
    last_name, 
    is_active, 
    is_email_verified,
    created_at,
    password_changed_at
) VALUES (
    'user@company.com',
    '$2a$12$hashed_password_here',  -- Bcrypt with cost 12
    'John',
    'Doe',
    FALSE,  -- Inactive until email verification
    FALSE,  -- Requires email verification
    NOW(),
    NOW()
);

-- Account activation after email verification
UPDATE users 
SET is_active = TRUE, 
    is_email_verified = TRUE,
    email_verified_at = NOW()
WHERE email = 'user@company.com' 
AND verification_token = 'provided_token';
```

#### **Password Security Enforcement**
```sql
-- Password history tracking (prevent reuse)
CREATE TABLE password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Check password reuse (last 12 passwords)
SELECT COUNT(*) 
FROM password_history 
WHERE user_id = $1 
AND password_hash = $2
AND created_at > NOW() - INTERVAL '1 year'
ORDER BY created_at DESC 
LIMIT 12;
```

#### **Account Lockout Policy**
```sql
-- Account lockout tracking
CREATE TABLE account_lockouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Check lockout status
SELECT 
    failed_attempts,
    locked_until,
    CASE 
        WHEN locked_until > NOW() THEN TRUE 
        ELSE FALSE 
    END as is_locked
FROM account_lockouts 
WHERE user_id = $1 
ORDER BY updated_at DESC 
LIMIT 1;
```

### 🔑 **Token Security Management**

#### **JWT Token Security**
```go
// Token security configuration
type TokenConfig struct {
    AccessTokenTTL  time.Duration // 15 minutes
    RefreshTokenTTL time.Duration // 30 days
    SigningMethod   string        // RS256
    PublicKey       *rsa.PublicKey
    PrivateKey      *rsa.PrivateKey
    Issuer          string
    Audience        []string
}

// Token validation security checks
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
    // Parse and validate token
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        // Verify signing method
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return s.config.PublicKey, nil
    })
    
    if err != nil {
        s.logSecurityEvent("token_validation_failure", map[string]interface{}{
            "error": err.Error(),
            "token_preview": tokenString[:min(len(tokenString), 20)] + "...",
        })
        return nil, err
    }
    
    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return nil, errors.New("invalid token")
    }
    
    // Additional security validations
    if err := s.validateTokenClaims(claims); err != nil {
        return nil, err
    }
    
    return claims, nil
}
```

#### **Refresh Token Security**
```sql
-- Secure refresh token storage
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash VARCHAR(255) NOT NULL,  -- SHA-256 hash of actual token
    family_id UUID NOT NULL,           -- Token family for rotation
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    revoked_at TIMESTAMP,
    device_fingerprint TEXT,
    ip_address INET,
    user_agent TEXT
);

-- Token rotation on use
UPDATE refresh_tokens 
SET revoked_at = NOW()
WHERE family_id = $1 
AND revoked_at IS NULL;

INSERT INTO refresh_tokens (
    user_id, token_hash, family_id, expires_at, device_fingerprint, ip_address
) VALUES ($1, $2, $3, $4, $5, $6);
```

---

## 🔍 **Security Auditing**

### 📋 **Audit Logging**

#### **Security Event Logging**
```sql
-- Comprehensive audit log structure
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    session_id UUID,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    request_id UUID,
    success BOOLEAN,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Index for security queries
CREATE INDEX idx_audit_logs_security 
ON audit_logs (action, created_at, ip_address, success);

CREATE INDEX idx_audit_logs_user_timeline 
ON audit_logs (user_id, created_at);
```

#### **Critical Events to Log**
```go
// Security events that must be logged
var SecurityEvents = []string{
    "login_attempt",
    "login_success", 
    "login_failure",
    "password_change",
    "password_reset_request",
    "password_reset_complete",
    "account_lockout",
    "account_unlock",
    "token_refresh",
    "token_revocation",
    "privilege_escalation_attempt",
    "unauthorized_access_attempt",
    "bulk_data_access",
    "suspicious_activity",
}

// Example security event logging
func (s *Service) LogSecurityEvent(userID, action string, details map[string]interface{}) {
    event := AuditLog{
        UserID:    userID,
        Action:    action,
        Details:   details,
        IPAddress: s.getClientIP(),
        UserAgent: s.getUserAgent(),
        Timestamp: time.Now(),
    }
    
    // Log to database
    s.auditRepo.Create(event)
    
    // Send to SIEM if critical event
    if s.isCriticalSecurityEvent(action) {
        s.siemClient.SendEvent(event)
    }
}
```

### 📊 **Security Analytics**

#### **Behavioral Analysis Queries**
```sql
-- Detect unusual login patterns
WITH user_login_patterns AS (
    SELECT 
        user_id,
        extract(hour from created_at) as login_hour,
        ip_address,
        COUNT(*) as login_count
    FROM audit_logs 
    WHERE action = 'login_success'
    AND created_at > NOW() - INTERVAL '30 days'
    GROUP BY user_id, login_hour, ip_address
),
suspicious_logins AS (
    SELECT 
        user_id,
        ip_address,
        login_hour,
        login_count
    FROM user_login_patterns
    WHERE login_hour NOT BETWEEN 6 AND 22  -- Outside normal hours
    OR login_count = 1  -- Single login from IP (potential compromise)
)
SELECT 
    u.email,
    sl.ip_address,
    sl.login_hour,
    sl.login_count,
    'unusual_login_pattern' as security_flag
FROM suspicious_logins sl
JOIN users u ON u.id = sl.user_id;

-- Geographic anomaly detection
WITH user_locations AS (
    SELECT 
        user_id,
        ip_address,
        created_at,
        LAG(ip_address) OVER (PARTITION BY user_id ORDER BY created_at) as prev_ip
    FROM audit_logs
    WHERE action = 'login_success'
    AND created_at > NOW() - INTERVAL '7 days'
)
SELECT 
    user_id,
    ip_address,
    prev_ip,
    created_at,
    'geographic_anomaly' as security_flag
FROM user_locations
WHERE ip_address != prev_ip
AND prev_ip IS NOT NULL;

-- Failed login concentration by IP
SELECT 
    ip_address,
    COUNT(DISTINCT user_id) as targeted_users,
    COUNT(*) as failed_attempts,
    MIN(created_at) as first_attempt,
    MAX(created_at) as last_attempt
FROM audit_logs
WHERE action = 'login_failure'
AND created_at > NOW() - INTERVAL '1 hour'
GROUP BY ip_address
HAVING COUNT(*) > 20  -- Potential brute force
ORDER BY failed_attempts DESC;
```

---

## 🛡️ **Vulnerability Management**

### 🔍 **Security Scanning**

#### **Container Security Scanning**
```bash
# Dockerfile security best practices
FROM golang:1.21-alpine AS builder

# Create non-root user
RUN adduser -D -g '' appuser

# Set working directory
WORKDIR /app

# Copy and build application
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM scratch

# Copy CA certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy non-root user
COPY --from=builder /etc/passwd /etc/passwd

# Copy application
COPY --from=builder /app/main /app/main

# Use non-root user
USER appuser

# Expose port
EXPOSE 8080

# Run application
ENTRYPOINT ["/app/main"]
```

#### **Vulnerability Scanning Pipeline**
```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'auth-service:latest'
          format: 'sarif'
          output: 'trivy-results.sarif'
          
      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
          
      - name: Run Gosec security scanner
        uses: securecodewarrior/github-action-gosec@master
        with:
          args: '-fmt sarif -out gosec-results.sarif ./...'
          
      - name: Upload Gosec scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'gosec-results.sarif'
```

### 🔐 **Dependency Security**

#### **Go Module Security Scanning**
```bash
# Check for known vulnerabilities
go list -json -deps ./... | nancy sleuth

# Update dependencies to patch vulnerabilities
go get -u all
go mod tidy

# Audit dependencies
go mod download -x

# Check for direct dependency vulnerabilities
govulncheck ./...
```

#### **Dependency Management Policy**
```yaml
# dependabot.yml
version: 2
updates:
  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "security"
      - "dependencies"
    commit-message:
      prefix: "security"
      include: "scope"
```

---

## 🚨 **Incident Response**

### 🔥 **Security Incident Classification**

#### **Severity Levels**
- **P0 - Critical**: Active data breach, complete service compromise
- **P1 - High**: Successful unauthorized access, privilege escalation
- **P2 - Medium**: Failed attack attempts, suspicious activities
- **P3 - Low**: Policy violations, minor security events

#### **Response Procedures**

**P0 - Critical Security Incident**
```bash
# IMMEDIATE ACTIONS (within 5 minutes)
# 1. Isolate affected systems
kubectl scale deployment auth-service --replicas=0 -n auth-service

# 2. Preserve evidence
kubectl logs deployment/auth-service -n auth-service > incident-logs-$(date +%Y%m%d-%H%M%S).log

# 3. Revoke all tokens
psql "$DATABASE_URL" -c "
UPDATE refresh_tokens SET revoked_at = NOW() WHERE revoked_at IS NULL;
DELETE FROM active_sessions;
"

# 4. Notify security team
curl -X POST https://hooks.slack.com/services/YOUR/SECURITY/WEBHOOK \
  -d '{"text": "🚨 CRITICAL SECURITY INCIDENT - Auth Service Compromised"}'

# 5. Create war room
# (Create incident channel, invite responders)
```

**P1 - High Security Incident**
```bash
# RESPONSE ACTIONS (within 15 minutes)
# 1. Investigate scope
grep -E "(failed|unauthorized|suspicious)" incident-logs-*.log

# 2. Identify affected users
psql "$DATABASE_URL" -c "
SELECT DISTINCT user_id, ip_address, created_at
FROM audit_logs 
WHERE created_at > NOW() - INTERVAL '1 hour'
AND action IN ('login_failure', 'unauthorized_access')
ORDER BY created_at DESC;
"

# 3. Implement temporary controls
# Enable rate limiting, update firewall rules

# 4. Notify stakeholders
# Send notifications to affected users if needed
```

### 🔍 **Forensic Analysis**

#### **Evidence Collection**
```bash
# Collect system state
kubectl get all -n auth-service -o yaml > system-state-$(date +%Y%m%d-%H%M%S).yaml

# Collect recent logs
kubectl logs --since=24h -l app=auth-service -n auth-service > recent-logs.txt

# Collect audit trail
psql "$DATABASE_URL" -c "
COPY (
    SELECT * FROM audit_logs 
    WHERE created_at > NOW() - INTERVAL '24 hours'
    ORDER BY created_at
) TO STDOUT WITH CSV HEADER
" > audit-trail-$(date +%Y%m%d).csv

# Collect network information
kubectl get networkpolicies -n auth-service -o yaml > network-policies.yaml
```

#### **Analysis Queries**
```sql
-- Timeline of security events
SELECT 
    created_at,
    user_id,
    action,
    ip_address,
    success,
    details
FROM audit_logs
WHERE created_at BETWEEN '2025-06-20 14:00:00' AND '2025-06-20 16:00:00'
ORDER BY created_at;

-- Identify attack patterns
SELECT 
    ip_address,
    action,
    COUNT(*) as event_count,
    MIN(created_at) as first_seen,
    MAX(created_at) as last_seen,
    array_agg(DISTINCT user_id) as targeted_users
FROM audit_logs
WHERE created_at > NOW() - INTERVAL '1 hour'
AND success = FALSE
GROUP BY ip_address, action
ORDER BY event_count DESC;

-- User impact assessment
SELECT 
    u.email,
    COUNT(CASE WHEN al.success = TRUE THEN 1 END) as successful_actions,
    COUNT(CASE WHEN al.success = FALSE THEN 1 END) as failed_actions,
    MAX(al.created_at) as last_activity
FROM users u
JOIN audit_logs al ON u.id = al.user_id
WHERE al.created_at > NOW() - INTERVAL '24 hours'
GROUP BY u.id, u.email
ORDER BY failed_actions DESC;
```

---

## 🔒 **Compliance & Reporting**

### 📋 **Compliance Requirements**

#### **GDPR Compliance**
```sql
-- Data retention policy (GDPR Article 5)
DELETE FROM audit_logs 
WHERE created_at < NOW() - INTERVAL '2 years'
AND action NOT IN ('data_deletion', 'gdpr_request');

-- Right to be forgotten implementation
UPDATE users 
SET 
    email = 'deleted-' || id || '@example.com',
    first_name = 'DELETED',
    last_name = 'DELETED',
    is_active = FALSE,
    deleted_at = NOW()
WHERE id = $1;

-- Personal data export (GDPR Article 20)
SELECT 
    json_build_object(
        'personal_data', json_build_object(
            'email', u.email,
            'first_name', u.first_name,
            'last_name', u.last_name,
            'created_at', u.created_at
        ),
        'activity_log', (
            SELECT json_agg(
                json_build_object(
                    'action', action,
                    'timestamp', created_at,
                    'ip_address', ip_address
                )
            )
            FROM audit_logs 
            WHERE user_id = u.id
        )
    ) as user_data
FROM users u
WHERE u.id = $1;
```

#### **SOC 2 Compliance**
```sql
-- Access control monitoring (CC6.1)
SELECT 
    'access_control_review' as control,
    COUNT(*) as total_access_events,
    COUNT(CASE WHEN success = FALSE THEN 1 END) as failed_access_attempts,
    (COUNT(CASE WHEN success = FALSE THEN 1 END)::float / COUNT(*) * 100) as failure_rate
FROM audit_logs
WHERE created_at > NOW() - INTERVAL '30 days'
AND action LIKE '%access%';

-- Logical and physical access controls (CC6.2)
SELECT 
    'privileged_access_review' as control,
    action,
    COUNT(*) as occurrence_count,
    array_agg(DISTINCT ip_address) as source_ips
FROM audit_logs
WHERE created_at > NOW() - INTERVAL '30 days'
AND action IN ('admin_access', 'privilege_escalation', 'system_configuration')
GROUP BY action;
```

### 📊 **Security Reporting**

#### **Daily Security Report**
```bash
#!/bin/bash
# daily-security-report.sh

REPORT_DATE=$(date +%Y-%m-%d)
REPORT_FILE="security-report-$REPORT_DATE.md"

cat > "$REPORT_FILE" << EOF
# Security Report - $REPORT_DATE

## Summary
$(psql "$DATABASE_URL" -t -c "
SELECT 
    'Total Events: ' || COUNT(*) || '\n' ||
    'Failed Logins: ' || COUNT(CASE WHEN action = 'login_failure' THEN 1 END) || '\n' ||
    'Successful Logins: ' || COUNT(CASE WHEN action = 'login_success' THEN 1 END) || '\n' ||
    'Unique Users: ' || COUNT(DISTINCT user_id) || '\n' ||
    'Unique IPs: ' || COUNT(DISTINCT ip_address)
FROM audit_logs
WHERE created_at::date = CURRENT_DATE;
")

## Top Failed Login Sources
$(psql "$DATABASE_URL" -t -c "
SELECT ip_address || ' (' || COUNT(*) || ' attempts)'
FROM audit_logs
WHERE created_at::date = CURRENT_DATE
AND action = 'login_failure'
GROUP BY ip_address
ORDER BY COUNT(*) DESC
LIMIT 10;
")

## Security Alerts
$(curl -s 'http://prometheus:9090/api/v1/alerts' | jq -r '.data.alerts[] | select(.labels.service=="auth-service") | .annotations.summary')

EOF

echo "Security report generated: $REPORT_FILE"
```

#### **Weekly Security Metrics**
```sql
-- Weekly security KPIs
WITH weekly_metrics AS (
    SELECT 
        date_trunc('week', created_at) as week,
        COUNT(*) as total_events,
        COUNT(CASE WHEN action = 'login_failure' THEN 1 END) as failed_logins,
        COUNT(CASE WHEN action = 'login_success' THEN 1 END) as successful_logins,
        COUNT(DISTINCT user_id) as active_users,
        COUNT(DISTINCT ip_address) as unique_ips
    FROM audit_logs
    WHERE created_at > NOW() - INTERVAL '8 weeks'
    GROUP BY date_trunc('week', created_at)
)
SELECT 
    week,
    total_events,
    failed_logins,
    successful_logins,
    round(failed_logins::numeric / NULLIF(failed_logins + successful_logins, 0) * 100, 2) as failure_rate_percent,
    active_users,
    unique_ips
FROM weekly_metrics
ORDER BY week DESC;
```

---

## 🛠️ **Security Tools & Automation**

### 🔧 **Security Automation Scripts**

#### **Automated Threat Response**
```bash
#!/bin/bash
# automated-threat-response.sh

# Configuration
ALERT_THRESHOLD=50
BAN_DURATION=3600  # 1 hour
LOG_FILE="/var/log/auth-service/security.log"

# Function to ban IP address
ban_ip() {
    local ip=$1
    local duration=$2
    
    echo "$(date): Banning IP $ip for $duration seconds" >> "$LOG_FILE"
    
    # Add to firewall (example with iptables)
    iptables -A INPUT -s "$ip" -j DROP
    
    # Schedule removal
    echo "iptables -D INPUT -s $ip -j DROP" | at now + ${duration} seconds
    
    # Notify security team
    curl -X POST https://hooks.slack.com/services/YOUR/SECURITY/WEBHOOK \
        -d "{\"text\": \"🚫 Auto-banned IP: $ip for excessive failed logins\"}"
}

# Check for brute force attacks
while true; do
    psql "$DATABASE_URL" -t -c "
        SELECT ip_address, COUNT(*) 
        FROM audit_logs 
        WHERE action = 'login_failure' 
        AND created_at > NOW() - INTERVAL '10 minutes'
        GROUP BY ip_address 
        HAVING COUNT(*) > $ALERT_THRESHOLD;
    " | while read ip count; do
        if [[ -n "$ip" ]]; then
            ban_ip "$ip" "$BAN_DURATION"
        fi
    done
    
    sleep 60  # Check every minute
done
```

#### **Security Health Check**
```bash
#!/bin/bash
# security-health-check.sh

echo "🔐 Security Health Check - $(date)"

# Check SSL certificate expiry
CERT_DAYS=$(echo | openssl s_client -servername auth-service.company.com -connect auth-service.company.com:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2 | xargs -I{} date -d {} +%s)
CURRENT_TIME=$(date +%s)
DAYS_TO_EXPIRY=$(( (CERT_DAYS - CURRENT_TIME) / 86400 ))

if [ $DAYS_TO_EXPIRY -lt 30 ]; then
    echo "⚠️  SSL certificate expires in $DAYS_TO_EXPIRY days"
else
    echo "✅ SSL certificate valid for $DAYS_TO_EXPIRY days"
fi

# Check for failed security controls
FAILED_LOGINS=$(psql "$DATABASE_URL" -t -c "
    SELECT COUNT(*) 
    FROM audit_logs 
    WHERE action = 'login_failure' 
    AND created_at > NOW() - INTERVAL '1 hour';
")

if [ "$FAILED_LOGINS" -gt 100 ]; then
    echo "⚠️  High number of failed logins: $FAILED_LOGINS in last hour"
else
    echo "✅ Failed login rate normal: $FAILED_LOGINS in last hour"
fi

# Check token health
TOKEN_FAILURES=$(psql "$DATABASE_URL" -t -c "
    SELECT COUNT(*) 
    FROM audit_logs 
    WHERE action = 'token_validation_failure' 
    AND created_at > NOW() - INTERVAL '1 hour';
")

if [ "$TOKEN_FAILURES" -gt 50 ]; then
    echo "⚠️  High token validation failures: $TOKEN_FAILURES"
else
    echo "✅ Token validation healthy: $TOKEN_FAILURES failures"
fi

echo "🎉 Security health check completed"
```

---

## 📚 **Security Best Practices**

### 🔒 **Development Security**

- **Secure Coding Standards**: Follow OWASP guidelines
- **Code Review**: Security-focused peer review process
- **Static Analysis**: Automated security scanning in CI/CD
- **Dependency Management**: Regular security updates
- **Secret Management**: Never commit secrets to code

### 🛡️ **Operational Security**

- **Principle of Least Privilege**: Minimal necessary permissions
- **Defense in Depth**: Multiple security layers
- **Zero Trust**: Verify every request and user
- **Continuous Monitoring**: Real-time security event monitoring
- **Incident Preparedness**: Regular security drills and training

### 📊 **Monitoring & Alerting**

- **Security Metrics**: Track security-related KPIs
- **Behavioral Analytics**: Detect anomalous patterns
- **Threat Intelligence**: Integrate external threat feeds
- **Compliance Monitoring**: Automated compliance checks
- **Security Dashboards**: Real-time security visibility

---

## 📚 **References**

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)
- [GDPR Compliance Guide](https://gdpr.eu/)
- [SOC 2 Security Framework](https://www.aicpa.org/soc2)

---

**📅 Last Updated**: June 20, 2025  
**👤 Maintained By**: Security Team  
**🔄 Next Review**: July 20, 2025
