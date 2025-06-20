-- Migration: 002_create_refresh_tokens_table.down.sql
-- Description: Rollback refresh_tokens table creation
-- Author: Auth Service Team
-- Date: 2023-01-01

-- Drop trigger and function
DROP TRIGGER IF EXISTS tr_refresh_tokens_updated_at ON refresh_tokens;
DROP FUNCTION IF EXISTS update_refresh_tokens_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_refresh_tokens_user_active;
DROP INDEX IF EXISTS idx_refresh_tokens_revoked;
DROP INDEX IF EXISTS idx_refresh_tokens_expires_at;
DROP INDEX IF EXISTS idx_refresh_tokens_user_id;
DROP INDEX IF EXISTS idx_refresh_tokens_token;

-- Drop table
DROP TABLE IF EXISTS refresh_tokens;
