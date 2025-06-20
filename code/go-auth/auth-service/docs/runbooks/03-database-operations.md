# 🗄️ Database Operations

## 📋 **Purpose**
Complete database operations guide for the Go Authentication Service, covering setup, maintenance, migrations, and troubleshooting.

## 👥 **Audience**
- Database Administrators
- DevOps Engineers
- Backend Developers
- Site Reliability Engineers

## ⚡ **Prerequisites**
- PostgreSQL client tools installed
- Database access credentials
- Understanding of SQL and database concepts
- Access to migration tools

---

## 🏗️ **Database Setup**

### 📊 **Database Schema Overview**

#### **Core Tables**
```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    is_email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP NULL
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    revoked_at TIMESTAMP NULL,
    device_info TEXT,
    ip_address INET
);

-- Password reset tokens table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    used_at TIMESTAMP NULL,
    ip_address INET
);

-- Audit logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### 🚀 **Initial Setup**

#### **Local Development Setup**
```bash
# Start PostgreSQL container
make db-up

# Wait for database to be ready
sleep 10

# Run migrations
make db-migrate-up

# Verify setup
make db-status
```

#### **Production Database Setup**
```bash
# Connect to production database
psql -h prod-db-host -U admin -d postgres

# Create database and user
CREATE DATABASE authdb;
CREATE USER authuser WITH ENCRYPTED PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE authdb TO authuser;
GRANT CONNECT ON DATABASE authdb TO authuser;

# Switch to authdb
\c authdb

# Grant schema permissions
GRANT ALL ON SCHEMA public TO authuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO authuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO authuser;

# Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
```

---

## 🔄 **Migration Management**

### 📝 **Migration Files Structure**
```
migrations/
├── 001_create_users_table.up.sql
├── 001_create_users_table.down.sql
├── 002_create_refresh_tokens_table.up.sql
├── 002_create_refresh_tokens_table.down.sql
├── 003_create_password_reset_tokens_table.up.sql
├── 003_create_password_reset_tokens_table.down.sql
├── 004_create_audit_logs_table.up.sql
├── 004_create_audit_logs_table.down.sql
└── 005_add_indexes.up.sql
```

### ⬆️ **Running Migrations**

#### **Apply All Pending Migrations**
```bash
# Local development
make db-migrate-up

# Production (with manual verification)
migrate -path ./migrations \
        -database "postgres://authuser:password@prod-host:5432/authdb?sslmode=require" \
        up

# Kubernetes environment
kubectl exec deployment/auth-service -n auth-service -- \
  migrate -path /app/migrations \
          -database "$DATABASE_URL" \
          up
```

#### **Apply Specific Migration**
```bash
# Apply up to specific version
migrate -path ./migrations \
        -database "$DATABASE_URL" \
        goto 3

# Apply one migration
migrate -path ./migrations \
        -database "$DATABASE_URL" \
        up 1
```

### ⬇️ **Rolling Back Migrations**

#### **Rollback One Migration**
```bash
# Local development
make db-migrate-down

# Manual rollback
migrate -path ./migrations \
        -database "$DATABASE_URL" \
        down 1
```

#### **Rollback to Specific Version**
```bash
# Rollback to version 2
migrate -path ./migrations \
        -database "$DATABASE_URL" \
        goto 2

# Force version (dangerous!)
migrate -path ./migrations \
        -database "$DATABASE_URL" \
        force 2
```

### 📊 **Migration Status**

#### **Check Migration Status**
```bash
# Using migrate tool
migrate -path ./migrations \
        -database "$DATABASE_URL" \
        version

# Using SQL query
psql "$DATABASE_URL" -c "
SELECT version, dirty 
FROM schema_migrations 
ORDER BY version DESC 
LIMIT 5;"
```

#### **Migration History**
```sql
-- View all applied migrations
SELECT version, dirty 
FROM schema_migrations 
ORDER BY version;

-- Check for dirty migrations
SELECT * FROM schema_migrations WHERE dirty = true;
```

---

## 🔍 **Database Monitoring**

### 📈 **Performance Metrics**

#### **Connection Statistics**
```sql
-- Current connections
SELECT 
    datname,
    numbackends as connections,
    xact_commit as commits,
    xact_rollback as rollbacks,
    blks_read,
    blks_hit,
    temp_files,
    temp_bytes
FROM pg_stat_database 
WHERE datname = 'authdb';

-- Connection details
SELECT 
    pid,
    usename,
    application_name,
    client_addr,
    state,
    query_start,
    state_change
FROM pg_stat_activity 
WHERE datname = 'authdb';
```

#### **Table Statistics**
```sql
-- Table sizes and statistics
SELECT 
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes,
    n_live_tup as live_rows,
    n_dead_tup as dead_rows,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables
ORDER BY n_live_tup DESC;

-- Table sizes
SELECT 
    tablename,
    pg_size_pretty(pg_total_relation_size(tablename::regclass)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(tablename::regclass) DESC;
```

#### **Index Usage**
```sql
-- Index usage statistics
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    pg_size_pretty(pg_relation_size(indexname::regclass)) as size
FROM pg_stat_user_indexes
ORDER BY idx_tup_read DESC;

-- Unused indexes
SELECT 
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexname::regclass)) as size
FROM pg_stat_user_indexes
WHERE idx_tup_read = 0
AND idx_tup_fetch = 0;
```

### 🚨 **Alert Queries**

#### **Performance Alerts**
```sql
-- Long running queries (> 5 minutes)
SELECT 
    pid,
    usename,
    query_start,
    now() - query_start as duration,
    query
FROM pg_stat_activity 
WHERE state = 'active'
AND now() - query_start > interval '5 minutes';

-- Blocked queries
SELECT 
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS blocking_statement
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity 
    ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks 
    ON blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
JOIN pg_catalog.pg_stat_activity blocking_activity 
    ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;
```

#### **Space Alerts**
```sql
-- Database size monitoring
SELECT 
    datname,
    pg_size_pretty(pg_database_size(datname)) as size,
    pg_database_size(datname) as size_bytes
FROM pg_database 
WHERE datname = 'authdb';

-- Tables growing rapidly
SELECT 
    tablename,
    n_tup_ins as new_rows_since_analyze,
    last_analyze,
    now() - last_analyze as time_since_analyze
FROM pg_stat_user_tables
WHERE n_tup_ins > 10000
AND (last_analyze IS NULL OR now() - last_analyze > interval '1 day');
```

---

## 🛠️ **Maintenance Operations**

### 🧹 **Routine Maintenance**

#### **VACUUM Operations**
```sql
-- Manual vacuum for specific table
VACUUM VERBOSE users;

-- Vacuum with analyze
VACUUM ANALYZE users;

-- Full vacuum (requires exclusive lock)
VACUUM FULL users;

-- Check if autovacuum is working
SELECT 
    schemaname,
    tablename,
    last_vacuum,
    last_autovacuum,
    vacuum_count,
    autovacuum_count
FROM pg_stat_user_tables
ORDER BY last_autovacuum DESC NULLS LAST;
```

#### **ANALYZE Operations**
```sql
-- Update table statistics
ANALYZE users;

-- Analyze all tables
ANALYZE;

-- Check statistics age
SELECT 
    tablename,
    last_analyze,
    now() - last_analyze as age
FROM pg_stat_user_tables
ORDER BY last_analyze DESC NULLS LAST;
```

#### **REINDEX Operations**
```sql
-- Reindex specific index
REINDEX INDEX users_email_idx;

-- Reindex table
REINDEX TABLE users;

-- Reindex concurrently (PostgreSQL 12+)
REINDEX INDEX CONCURRENTLY users_email_idx;
```

### 🗂️ **Index Management**

#### **Create Performance Indexes**
```sql
-- Users table indexes
CREATE INDEX CONCURRENTLY idx_users_email_active 
ON users (email) WHERE is_active = true AND deleted_at IS NULL;

CREATE INDEX CONCURRENTLY idx_users_created_at 
ON users (created_at);

-- Refresh tokens indexes
CREATE INDEX CONCURRENTLY idx_refresh_tokens_user_id_active 
ON refresh_tokens (user_id) WHERE revoked_at IS NULL;

CREATE INDEX CONCURRENTLY idx_refresh_tokens_expires_at 
ON refresh_tokens (expires_at);

-- Audit logs indexes
CREATE INDEX CONCURRENTLY idx_audit_logs_user_id_created 
ON audit_logs (user_id, created_at);

CREATE INDEX CONCURRENTLY idx_audit_logs_action_created 
ON audit_logs (action, created_at);
```

#### **Monitor Index Performance**
```sql
-- Index hit ratio
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    CASE 
        WHEN idx_tup_read = 0 THEN 0
        ELSE round(idx_tup_fetch::numeric / idx_tup_read * 100, 2)
    END as hit_ratio_percent
FROM pg_stat_user_indexes
ORDER BY idx_tup_read DESC;
```

---

## 🔒 **Security Operations**

### 👤 **User Management**

#### **Create Database Users**
```sql
-- Create read-only user for monitoring
CREATE USER monitoring_user WITH PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE authdb TO monitoring_user;
GRANT USAGE ON SCHEMA public TO monitoring_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO monitoring_user;

-- Create backup user
CREATE USER backup_user WITH PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE authdb TO backup_user;
GRANT USAGE ON SCHEMA public TO backup_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO backup_user;

-- Create migration user (limited privileges)
CREATE USER migration_user WITH PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE authdb TO migration_user;
GRANT USAGE, CREATE ON SCHEMA public TO migration_user;
GRANT ALL ON ALL TABLES IN SCHEMA public TO migration_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO migration_user;
```

#### **Audit User Access**
```sql
-- Review user permissions
SELECT 
    grantee,
    table_schema,
    table_name,
    privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
ORDER BY grantee, table_name;

-- Active connections by user
SELECT 
    usename,
    count(*) as connection_count,
    array_agg(DISTINCT application_name) as applications,
    array_agg(DISTINCT client_addr) as client_addresses
FROM pg_stat_activity
WHERE datname = 'authdb'
GROUP BY usename;
```

### 🔐 **Data Encryption**

#### **Enable SSL**
```sql
-- Check SSL status
SELECT name, setting 
FROM pg_settings 
WHERE name IN ('ssl', 'ssl_cert_file', 'ssl_key_file');

-- Force SSL connections
ALTER DATABASE authdb SET ssl = on;

-- Check SSL connections
SELECT 
    pid,
    usename,
    ssl,
    client_addr
FROM pg_stat_ssl
JOIN pg_stat_activity USING (pid)
WHERE datname = 'authdb';
```

#### **Sensitive Data Handling**
```sql
-- Verify password hashes are encrypted
SELECT 
    id,
    email,
    length(password_hash) as hash_length,
    substring(password_hash, 1, 10) as hash_prefix
FROM users 
LIMIT 5;

-- Check for any plaintext passwords (should return 0)
SELECT count(*) 
FROM users 
WHERE password_hash !~ '^\$2[ayb]\$[0-9]{2}\$';
```

---

## 💾 **Backup and Recovery**

### 📁 **Backup Procedures**

#### **Logical Backups**
```bash
# Full database backup
pg_dump -h localhost -U authuser -d authdb \
        --no-password \
        --verbose \
        --format=custom \
        --file="authdb_backup_$(date +%Y%m%d_%H%M%S).backup"

# Schema-only backup
pg_dump -h localhost -U authuser -d authdb \
        --schema-only \
        --file="authdb_schema_$(date +%Y%m%d).sql"

# Data-only backup
pg_dump -h localhost -U authuser -d authdb \
        --data-only \
        --file="authdb_data_$(date +%Y%m%d).sql"

# Specific table backup
pg_dump -h localhost -U authuser -d authdb \
        --table=users \
        --file="users_backup_$(date +%Y%m%d).sql"
```

#### **Automated Backup Script**
```bash
#!/bin/bash
# backup-database.sh

set -e

BACKUP_DIR="/backups/$(date +%Y/%m/%d)"
RETENTION_DAYS=30
DB_NAME="authdb"
DB_USER="authuser"
DB_HOST="localhost"

mkdir -p "$BACKUP_DIR"

# Create backup
echo "Starting backup at $(date)"
pg_dump -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" \
        --format=custom \
        --verbose \
        --file="$BACKUP_DIR/authdb_$(date +%H%M%S).backup"

# Compress old backups
find /backups -name "*.backup" -mtime +1 -exec gzip {} \;

# Clean up old backups
find /backups -name "*.backup.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed at $(date)"
```

### 🔄 **Recovery Procedures**

#### **Full Database Restore**
```bash
# Drop and recreate database (DANGER!)
dropdb -h localhost -U admin authdb
createdb -h localhost -U admin authdb

# Restore from backup
pg_restore -h localhost -U authuser -d authdb \
           --verbose \
           --clean \
           --if-exists \
           backup_file.backup
```

#### **Point-in-Time Recovery**
```bash
# Stop the database service
sudo systemctl stop postgresql

# Restore base backup
tar -xzf base_backup.tar.gz -C /var/lib/postgresql/data/

# Create recovery configuration
cat > /var/lib/postgresql/data/recovery.conf << EOF
restore_command = 'cp /backup/wal/%f %p'
recovery_target_time = '2025-06-20 14:30:00'
EOF

# Start database in recovery mode
sudo systemctl start postgresql
```

#### **Table-Level Recovery**
```bash
# Create temporary database
createdb temp_restore

# Restore backup to temporary database
pg_restore -d temp_restore backup_file.backup

# Copy specific table data
pg_dump -t users temp_restore | psql -d authdb

# Clean up
dropdb temp_restore
```

---

## 🚨 **Troubleshooting**

### 🔧 **Common Issues**

#### **Connection Problems**
```bash
# Test basic connectivity
pg_isready -h localhost -p 5432

# Test with credentials
psql -h localhost -U authuser -d authdb -c "SELECT 1;"

# Check connection limits
psql -h localhost -U admin -d postgres -c "
SELECT 
    setting as max_connections,
    (SELECT count(*) FROM pg_stat_activity) as current_connections
FROM pg_settings 
WHERE name = 'max_connections';"
```

#### **Performance Issues**
```sql
-- Find slow queries
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    rows
FROM pg_stat_statements
ORDER BY total_time DESC
LIMIT 10;

-- Check for table locks
SELECT 
    l.mode,
    l.granted,
    a.usename,
    a.query,
    a.query_start
FROM pg_locks l
JOIN pg_stat_activity a ON l.pid = a.pid
WHERE l.relation::regclass::text LIKE '%users%';
```

#### **Space Issues**
```sql
-- Check database size
SELECT 
    pg_size_pretty(pg_database_size('authdb')) as database_size;

-- Find largest tables
SELECT 
    tablename,
    pg_size_pretty(pg_total_relation_size(tablename::regclass)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(tablename::regclass) DESC;

-- Check for bloated tables
SELECT 
    schemaname,
    tablename,
    n_dead_tup,
    n_live_tup,
    round(n_dead_tup::float / NULLIF(n_live_tup + n_dead_tup, 0) * 100, 2) as dead_ratio
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY dead_ratio DESC;
```

### 🔄 **Recovery Actions**

#### **Reset Dirty Migration**
```bash
# Check dirty state
migrate -path ./migrations -database "$DATABASE_URL" version

# Force clean state (CAREFUL!)
migrate -path ./migrations -database "$DATABASE_URL" force 4

# Re-run migration
migrate -path ./migrations -database "$DATABASE_URL" up
```

#### **Connection Pool Reset**
```sql
-- Kill all connections to database
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = 'authdb' AND pid <> pg_backend_pid();

-- Reset statistics
SELECT pg_stat_reset();
```

#### **Emergency User Creation**
```sql
-- Create emergency admin user
INSERT INTO users (email, password_hash, first_name, last_name, is_active, is_email_verified)
VALUES (
    'admin@emergency.com',
    '$2a$12$emergency_hash_here',  -- Use proper bcrypt hash
    'Emergency',
    'Admin',
    true,
    true
);
```

---

## 📊 **Monitoring Scripts**

### 📈 **Health Check Script**
```bash
#!/bin/bash
# db-health-check.sh

DB_URL="postgres://authuser:password@localhost:5432/authdb"

echo "🔍 Database Health Check - $(date)"

# Connection test
if psql "$DB_URL" -c "SELECT 1;" > /dev/null 2>&1; then
    echo "✅ Database connection: OK"
else
    echo "❌ Database connection: FAILED"
    exit 1
fi

# Migration status
CURRENT_VERSION=$(migrate -path ./migrations -database "$DB_URL" version 2>/dev/null)
echo "📊 Migration version: $CURRENT_VERSION"

# Table counts
psql "$DB_URL" -c "
SELECT 
    'users' as table_name,
    count(*) as row_count
FROM users
UNION ALL
SELECT 
    'refresh_tokens',
    count(*)
FROM refresh_tokens
UNION ALL
SELECT 
    'audit_logs',
    count(*)
FROM audit_logs;"

# Performance metrics
psql "$DB_URL" -c "
SELECT 
    'connections' as metric,
    count(*) as value
FROM pg_stat_activity
WHERE datname = 'authdb'
UNION ALL
SELECT 
    'database_size',
    pg_database_size('authdb');"

echo "🎉 Health check completed"
```

---

## 📚 **References**

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Migration Tool Documentation](https://github.com/golang-migrate/migrate)
- [PostgreSQL Performance Tuning](https://wiki.postgresql.org/wiki/Performance_Optimization)
- [Security Best Practices](https://www.postgresql.org/docs/current/security.html)

---

**📅 Last Updated**: June 20, 2025  
**👤 Maintained By**: Database Team  
**🔄 Next Review**: July 20, 2025
