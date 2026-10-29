-- ============================================================================
-- Migration: 001_add_password_hash.sql
-- Description: Adds nullable password_hash VARCHAR(255) column to user tables
-- Target: Neon PostgreSQL (student, warden, technician)
-- Safety:
--   - Wrapped in a transaction (atomic)
--   - Uses ADD COLUMN IF NOT EXISTS (idempotent, safe to run)
--   - Nullable by design: preserves all existing data without dummy hashes
-- ============================================================================

BEGIN;

-- 1. Student Table
ALTER TABLE student 
  ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

-- 2. Warden Table
ALTER TABLE warden 
  ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

-- 3. Technician Table
ALTER TABLE technician 
  ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

COMMIT;
