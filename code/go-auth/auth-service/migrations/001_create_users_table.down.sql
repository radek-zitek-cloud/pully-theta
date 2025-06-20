-- Migration: 001_create_users_table.down.sql
-- Description: Rollback users table creation
-- Author: Auth Service Team
-- Date: 2023-01-01

-- Drop trigger and function
DROP TRIGGER IF EXISTS tr_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_users_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_users_created_at;
DROP INDEX IF EXISTS idx_users_last_login;
DROP INDEX IF EXISTS idx_users_deleted_at;
DROP INDEX IF EXISTS idx_users_active;
DROP INDEX IF EXISTS idx_users_email_lower;

-- Drop table
DROP TABLE IF EXISTS users;
