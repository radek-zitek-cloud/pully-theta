-- Migration: 001_create_users_table.up.sql
-- Description: Create the users table with all required fields for authentication
-- Author: Auth Service Team
-- Date: 2023-01-01

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    -- Primary identifier using UUID for global uniqueness and security
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- User credentials and identification
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    
    -- User profile information
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    
    -- Account status fields
    is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Security and audit timestamps
    last_login_at TIMESTAMP WITH TIME ZONE NULL,
    password_changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Audit timestamps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE NULL -- For soft deletion
);

-- Create indexes for performance optimization
-- Email index for login lookups (case-insensitive)
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower 
ON users (LOWER(email)) 
WHERE deleted_at IS NULL;

-- Composite index for active user queries
CREATE INDEX IF NOT EXISTS idx_users_active 
ON users (is_active, deleted_at) 
WHERE deleted_at IS NULL;

-- Index for soft deletion queries
CREATE INDEX IF NOT EXISTS idx_users_deleted_at 
ON users (deleted_at) 
WHERE deleted_at IS NOT NULL;

-- Index for last login timestamp (for cleanup and analytics)
CREATE INDEX IF NOT EXISTS idx_users_last_login 
ON users (last_login_at) 
WHERE deleted_at IS NULL;

-- Index for created_at for pagination and sorting
CREATE INDEX IF NOT EXISTS idx_users_created_at 
ON users (created_at DESC) 
WHERE deleted_at IS NULL;

-- Add comments for documentation
COMMENT ON TABLE users IS 'User accounts table with soft deletion support';
COMMENT ON COLUMN users.id IS 'Primary key using UUID for global uniqueness';
COMMENT ON COLUMN users.email IS 'User email address - unique and used for login';
COMMENT ON COLUMN users.password_hash IS 'Bcrypt hash of user password';
COMMENT ON COLUMN users.first_name IS 'User given name';
COMMENT ON COLUMN users.last_name IS 'User family name';
COMMENT ON COLUMN users.is_email_verified IS 'Whether user has verified their email address';
COMMENT ON COLUMN users.is_active IS 'Whether user account is active and can authenticate';
COMMENT ON COLUMN users.last_login_at IS 'Timestamp of users last successful login';
COMMENT ON COLUMN users.password_changed_at IS 'Timestamp when password was last changed';
COMMENT ON COLUMN users.created_at IS 'Account creation timestamp';
COMMENT ON COLUMN users.updated_at IS 'Last modification timestamp';
COMMENT ON COLUMN users.deleted_at IS 'Soft deletion timestamp - NULL means not deleted';

-- Add constraints for data integrity
ALTER TABLE users ADD CONSTRAINT chk_users_email_format 
CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$');

ALTER TABLE users ADD CONSTRAINT chk_users_first_name_length 
CHECK (char_length(first_name) >= 1 AND char_length(first_name) <= 100);

ALTER TABLE users ADD CONSTRAINT chk_users_last_name_length 
CHECK (char_length(last_name) >= 1 AND char_length(last_name) <= 100);

ALTER TABLE users ADD CONSTRAINT chk_users_password_hash_length 
CHECK (char_length(password_hash) >= 60); -- bcrypt hashes are 60 characters

-- Function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at on row modifications
DROP TRIGGER IF EXISTS tr_users_updated_at ON users;
CREATE TRIGGER tr_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_users_updated_at();
