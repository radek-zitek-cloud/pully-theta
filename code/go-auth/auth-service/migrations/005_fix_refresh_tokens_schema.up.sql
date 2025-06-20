-- Migration: 005_fix_refresh_tokens_schema.up.sql
-- Description: Fix refresh tokens table schema to match repository expectations
-- Author: Auth Service Team
-- Date: 2025-06-20
-- 
-- This migration fixes a schema mismatch where the repository expects a 'token_hash'
-- column but the original migration created a 'token' column. This ensures the
-- application code and database schema are aligned.

-- Step 1: Add the new token_hash column if it doesn't exist
DO $$ 
BEGIN
    -- Check if token_hash column exists, if not add it
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'refresh_tokens' 
        AND column_name = 'token_hash'
    ) THEN
        -- Add the token_hash column
        ALTER TABLE refresh_tokens 
        ADD COLUMN token_hash VARCHAR(64) NOT NULL DEFAULT '';
        
        -- Add a unique constraint on token_hash
        ALTER TABLE refresh_tokens 
        ADD CONSTRAINT uq_refresh_tokens_token_hash UNIQUE (token_hash);
        
        -- Create index for performance (if not exists)
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash 
        ON refresh_tokens (token_hash);
        
        -- Add comment for documentation
        COMMENT ON COLUMN refresh_tokens.token_hash IS 'SHA-256 hash of the JWT refresh token for secure storage';
        
        RAISE NOTICE 'Added token_hash column to refresh_tokens table';
    ELSE
        RAISE NOTICE 'token_hash column already exists in refresh_tokens table';
    END IF;
END $$;

-- Step 2: Remove the old token column if it exists and token_hash is populated
DO $$
BEGIN
    -- Check if the old token column exists
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'refresh_tokens' 
        AND column_name = 'token'
    ) THEN
        -- Check if we have any data in the table
        IF EXISTS (SELECT 1 FROM refresh_tokens LIMIT 1) THEN
            -- If there's data, we need to be careful about migration
            -- For safety, we'll keep both columns temporarily
            RAISE NOTICE 'Found existing data in refresh_tokens table. Manual intervention may be required.';
            RAISE NOTICE 'Please ensure all refresh tokens are migrated to use token_hash column.';
        ELSE
            -- No data exists, safe to drop the old column
            ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS token;
            RAISE NOTICE 'Removed old token column from refresh_tokens table';
        END IF;
    ELSE
        RAISE NOTICE 'Old token column does not exist in refresh_tokens table';
    END IF;
END $$;

-- Step 3: Update indexes to ensure optimal performance
-- Drop the old token index if it exists
DROP INDEX IF EXISTS idx_refresh_tokens_token;

-- Ensure we have the correct indexes for token_hash operations
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash_unique
ON refresh_tokens (token_hash);

-- Update the composite indexes to work with the new schema
DROP INDEX IF EXISTS idx_refresh_tokens_user_active;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_active 
ON refresh_tokens (user_id, expires_at, is_revoked) 
WHERE is_revoked = FALSE;

-- Step 4: Add validation constraints
-- Ensure token_hash is properly formatted (64 character hex string)
DO $$
BEGIN
    -- Add constraint to validate token_hash format (SHA-256 produces 64 hex chars)
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints 
        WHERE constraint_name = 'chk_refresh_tokens_token_hash_format' 
        AND table_name = 'refresh_tokens'
    ) THEN
        ALTER TABLE refresh_tokens 
        ADD CONSTRAINT chk_refresh_tokens_token_hash_format 
        CHECK (length(token_hash) = 64 AND token_hash ~ '^[a-f0-9]{64}$');
        
        RAISE NOTICE 'Added token_hash format validation constraint';
    END IF;
END $$;

-- Step 5: Update table and column comments for documentation
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for user session management with secure token hashing';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'SHA-256 hash of the JWT refresh token (64 hex characters)';

-- Final verification query (commented out for production)
-- SELECT column_name, data_type, is_nullable, column_default 
-- FROM information_schema.columns 
-- WHERE table_name = 'refresh_tokens' 
-- ORDER BY ordinal_position;
