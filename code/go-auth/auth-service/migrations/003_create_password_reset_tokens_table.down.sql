-- Migration: 003_create_password_reset_tokens_table.down.sql
-- Description: Rollback password_reset_tokens table creation
-- Author: Auth Service Team
-- Date: 2023-01-01

-- Drop trigger and function
DROP TRIGGER IF EXISTS tr_password_reset_tokens_updated_at ON password_reset_tokens;
DROP FUNCTION IF EXISTS update_password_reset_tokens_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_password_reset_tokens_email;
DROP INDEX IF EXISTS idx_password_reset_tokens_expires_at;
DROP INDEX IF EXISTS idx_password_reset_tokens_user_id;
DROP INDEX IF EXISTS idx_password_reset_tokens_token;

-- Drop table
DROP TABLE IF EXISTS password_reset_tokens;
