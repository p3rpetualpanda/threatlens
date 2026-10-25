-- 003_session_csrf.sql — per-session CSRF synchronizer token (spec §6.4).
-- Existing sessions (none before M2) would get '', which never matches a real token.
ALTER TABLE sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT '';
