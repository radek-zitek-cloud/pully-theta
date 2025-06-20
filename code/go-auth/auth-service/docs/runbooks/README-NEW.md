# 📚 Operations Runbooks

## 📋 **Overview**
This directory contains comprehensive operational runbooks for the Go Authentication Service. These runbooks provide step-by-step procedures for deployment, monitoring, maintenance, troubleshooting, and incident response.

Each runbook is designed to be self-contained while referencing other relevant procedures when needed. Follow the production-ready guidelines and always prioritize security and data integrity.

## 📂 **Available Runbooks**

### 🔧 **Core Operations**
- **[Deployment Guide](./01-deployment.md)** - Complete deployment procedures for all environments
- **[Service Management](./02-service-management.md)** - Starting, stopping, and managing the service
- **[Database Operations](./03-database-operations.md)** - Database setup, migrations, and maintenance

### 🔍 **Monitoring & Security** 
- **[Health Monitoring](./04-health-monitoring.md)** - Health checks, metrics, and monitoring setup
- **[Security Operations](./05-security-operations.md)** - Security procedures and incident response

### 📊 **Planned Runbooks** (Coming Soon)
- **[Troubleshooting Guide](./06-troubleshooting.md)** - Common issues and their solutions
- **[Backup & Recovery](./07-backup-recovery.md)** - Data backup and disaster recovery procedures
- **[Log Management](./08-log-management.md)** - Log collection, analysis, and retention
- **[Metrics & Alerting](./09-metrics-alerting.md)** - Metrics collection and alerting setup

## 🎯 **Quick Reference**

### **Emergency Contacts**
- **Development Team**: [Your Team Contact]
- **DevOps Team**: [DevOps Contact]
- **On-Call Engineer**: [On-Call Contact]

### **Critical Commands**
```bash
# Check service status
make status

# View service logs
make compose-logs-app

# Restart service
make compose-restart

# Check health
curl http://localhost:6910/health
```

### **Important URLs**
- **Health Check**: `http://localhost:6910/health`
- **Swagger UI**: `http://localhost:6910/swagger/index.html`
- **Metrics**: `http://localhost:6910/metrics`
- **Database**: `localhost:5432` (development)

## 🚨 **Emergency Procedures**

### **Service Down**
1. Check health endpoints: `/health`, `/health/ready`, `/health/live`
2. Review logs: `make compose-logs-app`
3. Restart service: `make compose-restart`
4. Escalate if issue persists

### **Database Issues**
1. Check database connectivity: `make db-status`
2. Review database logs
3. Check migration status: `make db-migrate-status`
4. Contact DBA if needed

### **Security Incident**
1. Immediately revoke compromised tokens
2. Review audit logs for suspicious activity
3. Follow security incident response procedures
4. Contact security team

## 📝 **Document Structure**

Each runbook follows a standardized structure:

- **📋 Purpose**: What the runbook covers
- **👥 Audience**: Who should use this runbook
- **⚡ Prerequisites**: Required knowledge and access
- **📋 Procedures**: Step-by-step instructions
- **🚨 Troubleshooting**: Common issues and solutions
- **📚 References**: Related documentation

## 🔧 **How to Use These Runbooks**

1. **Identify the Issue**: Determine which runbook applies to your situation
2. **Check Prerequisites**: Ensure you have the required access and knowledge
3. **Follow Procedures**: Execute steps in order, don't skip unless explicitly allowed
4. **Document Actions**: Record what you did and the results
5. **Update Runbooks**: If procedures change, update the documentation

## 📋 **Runbook Maintenance**

- **Review Schedule**: Monthly review of all runbooks
- **Update Process**: Submit PRs for changes, require review
- **Testing**: Validate procedures in non-production environments
- **Version Control**: Track changes and maintain history

## 🎯 **SLA/SLO Targets**

- **Availability**: 99.9% uptime
- **Response Time**: P95 < 500ms
- **Error Rate**: < 0.1% of requests
- **Recovery Time**: < 15 minutes for P0 incidents

## 📊 **Metrics and Monitoring**

Key metrics tracked:
- Request rate and latency
- Error rates by endpoint
- Database connection health
- Authentication success rates
- Security events and incidents

## 🔒 **Security Considerations**

All operational procedures must:
- Follow principle of least privilege
- Maintain audit trails
- Protect sensitive data
- Follow change management processes
- Include security impact assessment

---

**📅 Last Updated**: June 20, 2025  
**👤 Maintained By**: DevOps Team  
**🔄 Next Review**: July 20, 2025

For questions or improvements, please contact the DevOps team or submit a pull request.
