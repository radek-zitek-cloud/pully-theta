-- Migration: 006_fix_password_reset_tokens_hash_column.down.sql
-- Description: Rollback the password reset tokens table column rename
-- This migration reverts the token_hash column back to token
-- Author: Auth Service Team
-- Date: 2025-06-20

-- Begin transaction to ensure atomicity
BEGIN;

-- Rename the token_hash column back to token for rollback
ALTER TABLE password_reset_tokens 
RENAME COLUMN token_hash TO token;

-- Update the unique index to use the original column name
-- First drop the current index, then create the original one
DROP INDEX IF EXISTS idx_password_reset_tokens_token_hash;

-- Recreate the original unique index on token column
CREATE UNIQUE INDEX IF NOT EXISTS idx_password_reset_tokens_token 
ON password_reset_tokens (token);

-- Restore original column comment
COMMENT ON COLUMN password_reset_tokens.token IS 'Secure random token for password reset';

-- Commit the transaction
COMMIT;
