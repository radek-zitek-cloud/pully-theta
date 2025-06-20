-- Migration: 005_fix_refresh_tokens_schema.down.sql
-- Description: Rollback refresh tokens schema fix
-- Author: Auth Service Team
-- Date: 2025-06-20
--
-- This migration rolls back the schema fix and restores the original token column
-- WARNING: This will cause data loss if refresh tokens exist with token_hash values

-- Step 1: Remove the token_hash column and related constraints
DO $$
BEGIN
    -- Drop the token_hash format constraint
    ALTER TABLE refresh_tokens 
    DROP CONSTRAINT IF EXISTS chk_refresh_tokens_token_hash_format;
    
    -- Drop the unique constraint on token_hash
    ALTER TABLE refresh_tokens 
    DROP CONSTRAINT IF EXISTS uq_refresh_tokens_token_hash;
    
    -- Drop indexes related to token_hash
    DROP INDEX IF EXISTS idx_refresh_tokens_token_hash;
    DROP INDEX IF EXISTS idx_refresh_tokens_token_hash_unique;
    
    -- Drop the token_hash column
    ALTER TABLE refresh_tokens 
    DROP COLUMN IF EXISTS token_hash;
    
    RAISE NOTICE 'Removed token_hash column and related constraints';
END $$;

-- Step 2: Restore the original token column
DO $$
BEGIN
    -- Add back the original token column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'refresh_tokens' 
        AND column_name = 'token'
    ) THEN
        ALTER TABLE refresh_tokens 
        ADD COLUMN token TEXT NOT NULL DEFAULT '';
        
        -- Add unique constraint
        ALTER TABLE refresh_tokens 
        ADD CONSTRAINT uq_refresh_tokens_token UNIQUE (token);
        
        -- Create the original index
        CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_token 
        ON refresh_tokens (token);
        
        -- Add comment
        COMMENT ON COLUMN refresh_tokens.token IS 'JWT refresh token string';
        
        RAISE NOTICE 'Restored original token column';
    END IF;
END $$;

-- Step 3: Restore original table comment
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for user session management';

-- Step 4: Recreate original composite index
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_active 
ON refresh_tokens (user_id, expires_at, is_revoked) 
WHERE is_revoked = FALSE;
