-- Migration: 004_create_audit_logs_table.down.sql
-- Description: Rollback audit_logs table creation
-- Author: Auth Service Team
-- Date: 2023-01-01

-- Drop function
DROP FUNCTION IF EXISTS cleanup_old_audit_logs(INTEGER);

-- Drop trigger and function
DROP TRIGGER IF EXISTS tr_audit_logs_prevent_updates ON audit_logs;
DROP FUNCTION IF EXISTS prevent_audit_log_updates();

-- Drop indexes
DROP INDEX IF EXISTS idx_audit_logs_metadata;
DROP INDEX IF EXISTS idx_audit_logs_failed_events;
DROP INDEX IF EXISTS idx_audit_logs_created_at;
DROP INDEX IF EXISTS idx_audit_logs_ip_address;
DROP INDEX IF EXISTS idx_audit_logs_success;
DROP INDEX IF EXISTS idx_audit_logs_user_id;
DROP INDEX IF EXISTS idx_audit_logs_event_type;

-- Drop table
DROP TABLE IF EXISTS audit_logs;
