-- Migration: 002_create_refresh_tokens_table.up.sql
-- Description: Create the refresh_tokens table for JWT token management
-- Author: Auth Service Team
-- Date: 2023-01-01

CREATE TABLE IF NOT EXISTS refresh_tokens (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- User association
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Token data
    token TEXT NOT NULL UNIQUE,
    device_info TEXT NOT NULL DEFAULT '',
    ip_address INET NOT NULL,
    
    -- Token status
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
-- Index for token lookups (primary use case)
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token 
ON refresh_tokens (token);

-- Index for user token queries
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id 
ON refresh_tokens (user_id, is_revoked, expires_at);

-- Index for cleanup of expired tokens
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at 
ON refresh_tokens (expires_at) 
WHERE is_revoked = FALSE;

-- Index for revoked token cleanup
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked 
ON refresh_tokens (is_revoked, created_at);

-- Composite index for active user tokens
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_active 
ON refresh_tokens (user_id, expires_at, is_revoked) 
WHERE is_revoked = FALSE;

-- Add comments for documentation
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for user session management';
COMMENT ON COLUMN refresh_tokens.id IS 'Primary key using UUID';
COMMENT ON COLUMN refresh_tokens.user_id IS 'Foreign key to users table';
COMMENT ON COLUMN refresh_tokens.token IS 'JWT refresh token string';
COMMENT ON COLUMN refresh_tokens.device_info IS 'User agent or device information';
COMMENT ON COLUMN refresh_tokens.ip_address IS 'IP address where token was created';
COMMENT ON COLUMN refresh_tokens.is_revoked IS 'Whether token has been revoked';
COMMENT ON COLUMN refresh_tokens.expires_at IS 'Token expiration timestamp';
COMMENT ON COLUMN refresh_tokens.created_at IS 'Token creation timestamp';
COMMENT ON COLUMN refresh_tokens.updated_at IS 'Last modification timestamp';

-- Add constraints
ALTER TABLE refresh_tokens ADD CONSTRAINT chk_refresh_tokens_expires_future 
CHECK (expires_at > created_at);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_refresh_tokens_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_refresh_tokens_updated_at ON refresh_tokens;
CREATE TRIGGER tr_refresh_tokens_updated_at
    BEFORE UPDATE ON refresh_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_refresh_tokens_updated_at();
