-- Migration: 006_fix_password_reset_tokens_hash_column.up.sql
-- Description: Fix the password reset tokens table to use token_hash instead of token column
-- This migration addresses the schema mismatch between the migration (token) and repository code (token_hash)
-- Author: Auth Service Team
-- Date: 2025-06-20

-- Begin transaction to ensure atomicity
BEGIN;

-- Rename the token column to token_hash for consistency with repository expectations
-- This maintains data integrity while fixing the column name mismatch
ALTER TABLE password_reset_tokens 
RENAME COLUMN token TO token_hash;

-- Update the unique index to use the new column name
-- First drop the old index, then create the new one
DROP INDEX IF EXISTS idx_password_reset_tokens_token;

-- Create new unique index on token_hash column for performance
-- This ensures fast token lookups and maintains uniqueness constraint
CREATE UNIQUE INDEX IF NOT EXISTS idx_password_reset_tokens_token_hash 
ON password_reset_tokens (token_hash);

-- Update column comment to reflect the new name and purpose
COMMENT ON COLUMN password_reset_tokens.token_hash IS 'Hashed secure random token for password reset (SHA-256)';

-- Commit the transaction
COMMIT;
