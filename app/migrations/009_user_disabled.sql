-- 009_user_disabled.sql — an admin can disable an account; it keeps its history but cannot log in.
ALTER TABLE users ADD COLUMN disabled_at TEXT;
