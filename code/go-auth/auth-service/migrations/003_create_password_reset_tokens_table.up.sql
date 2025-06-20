-- Migration: 003_create_password_reset_tokens_table.up.sql
-- Description: Create the password_reset_tokens table for password reset functionality
-- Author: Auth Service Team
-- Date: 2023-01-01

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    -- Primary identifier
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- User association
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Token data
    token VARCHAR(128) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    
    -- Token status
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Create indexes for performance
-- Index for token lookups (primary use case)
CREATE UNIQUE INDEX IF NOT EXISTS idx_password_reset_tokens_token 
ON password_reset_tokens (token);

-- Index for user token queries
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user_id 
ON password_reset_tokens (user_id, is_used, expires_at);

-- Index for cleanup of expired tokens
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at 
ON password_reset_tokens (expires_at);

-- Index for email-based lookups
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_email 
ON password_reset_tokens (email, is_used, expires_at);

-- Add comments for documentation
COMMENT ON TABLE password_reset_tokens IS 'Password reset tokens for secure password recovery';
COMMENT ON COLUMN password_reset_tokens.id IS 'Primary key using UUID';
COMMENT ON COLUMN password_reset_tokens.user_id IS 'Foreign key to users table';
COMMENT ON COLUMN password_reset_tokens.token IS 'Secure random token for password reset';
COMMENT ON COLUMN password_reset_tokens.email IS 'Email address for verification';
COMMENT ON COLUMN password_reset_tokens.ip_address IS 'IP address where reset was requested';
COMMENT ON COLUMN password_reset_tokens.is_used IS 'Whether token has been consumed';
COMMENT ON COLUMN password_reset_tokens.expires_at IS 'Token expiration timestamp';
COMMENT ON COLUMN password_reset_tokens.created_at IS 'Token creation timestamp';
COMMENT ON COLUMN password_reset_tokens.updated_at IS 'Last modification timestamp';

-- Add constraints
ALTER TABLE password_reset_tokens ADD CONSTRAINT chk_password_reset_tokens_expires_future 
CHECK (expires_at > created_at);

ALTER TABLE password_reset_tokens ADD CONSTRAINT chk_password_reset_tokens_token_length 
CHECK (char_length(token) >= 32);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_password_reset_tokens_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_password_reset_tokens_updated_at ON password_reset_tokens;
CREATE TRIGGER tr_password_reset_tokens_updated_at
    BEFORE UPDATE ON password_reset_tokens
    FOR EACH ROW
    EXECUTE FUNCTION update_password_reset_tokens_updated_at();
