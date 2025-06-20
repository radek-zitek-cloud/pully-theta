-- Migration: 004_create_audit_logs_table.up.sql
-- Description: Create the audit_logs table for security and compliance logging
-- Author: Auth Service Team
-- Date: 2023-01-01

CREATE TABLE IF NOT EXISTS audit_logs (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- User association (optional - some events may not be user-specific)
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    
    -- Event information
    event_type VARCHAR(100) NOT NULL,
    event_description TEXT NOT NULL,
    
    -- Request context
    ip_address INET NOT NULL,
    user_agent TEXT NULL,
    
    -- Additional event data (stored as JSONB for flexibility)
    metadata JSONB NULL DEFAULT '{}',
    
    -- Event outcome
    success BOOLEAN NOT NULL,
    
    -- Timestamp (immutable once created)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance and analytics
-- Index for event type queries
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type 
ON audit_logs (event_type, created_at DESC);

-- Index for user-specific audit trails
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id 
ON audit_logs (user_id, created_at DESC) 
WHERE user_id IS NOT NULL;

-- Index for success/failure analysis
CREATE INDEX IF NOT EXISTS idx_audit_logs_success 
ON audit_logs (success, event_type, created_at DESC);

-- Index for IP-based analysis
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address 
ON audit_logs (ip_address, created_at DESC);

-- Index for time-based queries and cleanup
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at 
ON audit_logs (created_at DESC);

-- Index for failed events (security monitoring)
CREATE INDEX IF NOT EXISTS idx_audit_logs_failed_events 
ON audit_logs (event_type, ip_address, created_at DESC) 
WHERE success = FALSE;

-- GIN index for metadata queries (JSONB)
CREATE INDEX IF NOT EXISTS idx_audit_logs_metadata 
ON audit_logs USING GIN (metadata);

-- Add comments for documentation
COMMENT ON TABLE audit_logs IS 'Security and audit log entries for compliance and monitoring';
COMMENT ON COLUMN audit_logs.id IS 'Primary key using UUID';
COMMENT ON COLUMN audit_logs.user_id IS 'Optional foreign key to users table';
COMMENT ON COLUMN audit_logs.event_type IS 'Categorized event type (e.g., user.login.success)';
COMMENT ON COLUMN audit_logs.event_description IS 'Human-readable event description';
COMMENT ON COLUMN audit_logs.ip_address IS 'IP address where event originated';
COMMENT ON COLUMN audit_logs.user_agent IS 'User agent string from request';
COMMENT ON COLUMN audit_logs.metadata IS 'Additional event data in JSON format';
COMMENT ON COLUMN audit_logs.success IS 'Whether the audited operation was successful';
COMMENT ON COLUMN audit_logs.created_at IS 'Immutable timestamp when event occurred';

-- Add constraints for data integrity
ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_event_type_format 
CHECK (event_type ~ '^[a-z]+(\.[a-z]+)*\.(success|failure|info)$');

ALTER TABLE audit_logs ADD CONSTRAINT chk_audit_logs_event_description_length 
CHECK (char_length(event_description) >= 1 AND char_length(event_description) <= 1000);

-- Prevent updates to audit logs (append-only for security)
CREATE OR REPLACE FUNCTION prevent_audit_log_updates()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit logs are immutable and cannot be updated';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_audit_logs_prevent_updates ON audit_logs;
CREATE TRIGGER tr_audit_logs_prevent_updates
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_log_updates();

-- Function for automatic cleanup of old audit logs (if needed for compliance)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 2555) -- ~7 years default
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_logs 
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
